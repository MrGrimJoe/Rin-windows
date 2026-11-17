#include "rin/mesh_engine.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>

#ifdef _WIN32
// Without these, <windows.h> defaults to pulling in the old <winsock.h>,
// which conflicts with asio's <winsock2.h> in this same translation unit
// (MeshEngine sits on top of TcpTransport, which uses asio) -- exactly
// the C1189 "WinSock.h has already been included" error this caused.
// main_gui.cpp and win32_shell.cpp already do this correctly; this file
// was the one that missed it.
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <shellapi.h>
#include <windows.h>
#endif

#include "rin/audit_logger.hpp"

#include <nlohmann/json.hpp>

using nlohmann::json;

namespace rin {

namespace {
int64_t now_millis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
}  // namespace

MeshEngine::MeshEngine(asio::io_context& io) : io_(io), tcp_(io), udp_(io), relay_(io) {
    file_transfer_ = std::make_unique<FileTransferEngine>(
        [this](const ReceivedFileRecord& rec) {
            if (rec.local_file_path.empty()) {
                log_event("File \"" + rec.file_name + "\" from " + rec.sender_name +
                          " FAILED (incomplete or integrity check failed)");
            } else {
                log_event("File \"" + rec.file_name + "\" from " + rec.sender_name +
                          " saved -> " + rec.local_file_path);
#ifdef _WIN32
                // Open the containing folder in Explorer so the user can find it.
                std::string cmd = "explorer /select,\"" + rec.local_file_path + "\"";
                ::system(cmd.c_str());
#endif
            }
        },
        [this](const std::string& ip, int port, const MeshPacket& packet) {
            return tcp_.send_packet(ip, port, packet);
        });
}

bool MeshEngine::try_load_persisted(const std::string& db_path) {
    std::string path = db_path.empty() ? PersistenceStore::default_db_path() : db_path;

    try {
        store_ = std::make_unique<PersistenceStore>(path);
    } catch (const PersistenceException& e) {
        // A corrupt or unreadable database file must not crash the app or
        // block it from running -- fall through to "no saved identity"
        // exactly as if this were a genuine first launch. The person can
        // still use the app this session; they'll just need to
        // create/join a mesh again, same as any other fresh install.
        MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::Connection,
                                          "Could not open persistence store at '" + path + "': " + e.what() +
                                              " -- continuing without saved state.");
        store_.reset();
        return false;
    }

    auto loaded = store_->load_identity();
    if (!loaded.has_value()) {
        return false;  // store opened fine, just genuinely nothing saved yet (first launch)
    }

    identity_ = *loaded;

    try {
        auto devices = store_->load_all_devices();
        std::lock_guard<std::mutex> lock(devices_mutex_);
        devices_.clear();
        for (auto& device : devices) {
            devices_[device.public_key] = device;
        }
    } catch (const PersistenceException& e) {
        // Identity loaded fine but the device list didn't -- proceed with
        // just the identity rather than discarding a good identity load
        // over a bad device-list read. The person keeps their mesh
        // membership; they'll need to re-add devices this session.
        MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::Connection,
                                          "Loaded identity but failed to load trusted devices: " +
                                              std::string(e.what()));
    }

    log_event("Loaded saved mesh \"" + identity_.mesh_name + "\" (fingerprint " +
              identity_.local_fingerprint + ")");
    return true;
}

void MeshEngine::create_initial_mesh(const std::string& mesh_name, const std::string& device_name) {
    KeyPair keys = CryptoEngine::generate_identity_keypair();
    std::string mesh_secret = CryptoEngine::generate_ephemeral_secret();

    identity_.mesh_name = mesh_name.empty() ? "My Mesh" : mesh_name;
    identity_.local_device_name = device_name;
    identity_.local_public_key = keys.public_key_b64;
    identity_.local_private_key = keys.private_key_b64;
    identity_.local_fingerprint = keys.fingerprint;
    identity_.mesh_secret = mesh_secret;
    identity_.port = kDefaultTcpPort;

    TrustedDevice self;
    self.public_key = keys.public_key_b64;
    self.name = device_name + " (This Device)";
    self.platform = PlatformType::Windows;
    self.connection_state = ConnectionState::Active;
    self.active_rail = TransportRail::Lan;
    self.is_self = true;

    {
        std::lock_guard<std::mutex> lock(devices_mutex_);
        devices_[self.public_key] = self;
    }

    // Persistence failures here are intentionally non-fatal: a fresh
    // mesh identity was already generated and is usable for the rest of
    // this session even if it can't be saved to disk (e.g. a read-only
    // filesystem, or try_load_persisted() was never called so store_ is
    // still null). The person just won't see it again after a restart --
    // annoying, not catastrophic, and never worth crashing over.
    if (!store_) {
        try {
            store_ = std::make_unique<PersistenceStore>(PersistenceStore::default_db_path());
        } catch (const PersistenceException&) {
            store_.reset();
        }
    }
    if (store_) {
        try {
            store_->save_identity(identity_);
            store_->upsert_device(self);
        } catch (const PersistenceException& e) {
            MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::Connection,
                                              "Failed to persist new mesh identity: " + std::string(e.what()));
        }
    }

    log_event("Mesh \"" + identity_.mesh_name + "\" initialized locally (fingerprint " +
              identity_.local_fingerprint + ")");
}

void MeshEngine::configure_relay(const std::string& host, int port) {
    relay_host_ = host;
    relay_port_ = port;
}

void MeshEngine::start() {
    identity_.port = tcp_.start(
        [this](const MeshPacket& packet, const std::string& remote_ip) {
            on_packet_received(packet, remote_ip);
        },
        [this](const MeshPacket& packet) { return verify_packet_signature(packet); });

    std::array<uint8_t, 32> mesh_key =
        CryptoEngine::derive_mesh_encryption_key(identity_.mesh_secret, identity_.mesh_name);
    udp_.start(mesh_key, identity_.local_public_key, identity_.port, /*stun_ip=*/"",
               /*stun_port=*/0, [this](const DiscoveredPeer& peer) { on_peer_discovered(peer); });

    // Relay registration uses the exact same packet-verification and
    // dispatch path as a direct TCP connection (on_packet_received /
    // verify_packet_signature) -- a packet arriving via relay is treated
    // identically to one arriving via LAN once it's been signature-
    // checked, except with an empty remote_ip (relay-delivered packets
    // have no direct address to reply on -- see handle_discovery_challenge).
    // Entirely no-op if configure_relay() was never called.
    relay_.start(
        relay_host_, relay_port_, identity_.local_public_key,
        [this](const MeshPacket& packet, const std::string& remote_ip) {
            on_packet_received(packet, remote_ip);
        },
        [this](const MeshPacket& packet) { return verify_packet_signature(packet); });

    log_event("Listening on TCP " + std::to_string(identity_.port) + ", UDP beacon on " +
              std::to_string(kUdpBeaconPort) +
              (relay_.is_configured()
                   ? ", relay fallback via " + relay_.host() + ":" + std::to_string(relay_.port())
                   : ""));
}

void MeshEngine::stop() {
    tcp_.stop();
    udp_.stop();
    relay_.stop();
}

std::optional<int64_t> MeshEngine::send_with_fallback(const TrustedDevice& device,
                                                        const MeshPacket& packet) {
    if (device.ip_address.has_value()) {
        auto latency = tcp_.send_packet(*device.ip_address, device.port, packet);
        if (latency.has_value()) return latency;
    }

    if (!relay_.is_configured()) return std::nullopt;

    MeshPacket relay_packet = packet;
    relay_packet.rail = TransportRail::Relay;
    auto latency = relay_.send_via_relay(device.public_key, relay_packet);
    if (latency.has_value()) {
        MeshAuditLogger::instance().log_connection_established("Relay", relay_.host(),
                                                                  relay_.port(), packet.sender_name);
    } else {
        MeshAuditLogger::instance().log_connection_failed(
            "Relay", relay_.host(), relay_.port(), "relay forward failed or peer not registered",
            packet.sender_name);
    }
    return latency;
}

std::string MeshEngine::build_join_token_json() const {
    QrJoinToken token;
    token.mesh_name = identity_.mesh_name;
    token.host_public_key = identity_.local_public_key;
    token.host_device_name = identity_.local_device_name;
    token.ephemeral_token = CryptoEngine::generate_ephemeral_token();
    token.mesh_secret = identity_.mesh_secret;
    token.host_port = identity_.port;
    // Without this the scanning device has no address to reach us at and
    // falls back to a non-LAN rail (Android's completeJoinHandshake picks
    // INTERNET_P2P when hostIp is absent), so the JOIN_ACCEPT is never
    // delivered. Omitted (not faked) when no LAN address can be found.
    token.host_ip = detect_local_lan_ip();
    token.timestamp_ms = now_millis();
    return token.to_json();
}

bool MeshEngine::complete_join_handshake(const QrJoinToken& token) {
    if (!token.host_ip.has_value()) {
        log_event("Join handshake failed: token has no host IP (scan a token that includes one, "
                  "or resolve the host via UDP discovery first)");
        return false;
    }

    MeshAuditLogger::instance().log_handshake_initiated(*token.host_ip, token.host_device_name,
                                                          token.ephemeral_token);

    PlatformType platform = PlatformType::Android;
    auto contains_ci = [](const std::string& haystack, const std::string& needle) {
        std::string h = haystack, n = needle;
        std::transform(h.begin(), h.end(), h.begin(), ::tolower);
        std::transform(n.begin(), n.end(), n.begin(), ::tolower);
        return h.find(n) != std::string::npos;
    };
    if (contains_ci(token.host_device_name, "pc") || contains_ci(token.host_device_name, "windows")) {
        platform = PlatformType::Windows;
    } else if (contains_ci(token.host_device_name, "mac")) {
        platform = PlatformType::MacOS;
    } else if (contains_ci(token.host_device_name, "tab") || contains_ci(token.host_device_name, "ipad")) {
        platform = PlatformType::Tablet;
    }

    TrustedDevice host_device;
    host_device.public_key = token.host_public_key;
    host_device.name = token.host_device_name;
    host_device.platform = platform;
    host_device.connection_state = ConnectionState::Connected;
    host_device.active_rail = TransportRail::Lan;
    host_device.ip_address = *token.host_ip;
    host_device.port = token.host_port;
    host_device.latency_ms = 2;
    host_device.is_self = false;

    {
        std::lock_guard<std::mutex> lock(devices_mutex_);
        devices_[host_device.public_key] = host_device;
    }
    if (store_) {
        try {
            store_->upsert_device(host_device);
        } catch (const PersistenceException& e) {
            MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::Connection,
                                              "Failed to persist joined device: " + std::string(e.what()));
        }
    }

    // Adopt the mesh secret AND name carried in the token. This is the ONLY
    // place a mesh secret should ever travel, inside the QR-bootstrapped
    // token. The name matters as much as the secret: it is the HKDF salt in
    // derive_mesh_encryption_key, so a joiner that keeps its own placeholder
    // name (e.g. "Joining...") derives a DIFFERENT mesh key than the host and
    // every mesh-key packet (clipboard, discovery challenge, beacon tag) fails
    // to decrypt/match.
    std::string active_secret = identity_.mesh_secret;
    bool mesh_changed = false;
    if (token.mesh_secret.has_value() && !token.mesh_secret->empty() &&
        token.mesh_secret != identity_.mesh_secret) {
        identity_.mesh_secret = *token.mesh_secret;
        active_secret = *token.mesh_secret;
        mesh_changed = true;
    }
    if (!token.mesh_name.empty() && token.mesh_name != identity_.mesh_name) {
        identity_.mesh_name = token.mesh_name;
        mesh_changed = true;
    }
    if (mesh_changed) {
        // Beacons started before this join are still tagged for the old mesh.
        udp_.set_mesh_key(CryptoEngine::derive_mesh_encryption_key(identity_.mesh_secret, identity_.mesh_name));
        if (store_) {
            try {
                store_->save_identity(identity_);
            } catch (const PersistenceException& e) {
                MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::Connection,
                                                  "Failed to persist adopted mesh name/secret: " + std::string(e.what()));
            }
        }
    }

    auto mesh_key = CryptoEngine::derive_mesh_encryption_key(active_secret, identity_.mesh_name);
    std::string encrypted = CryptoEngine::encrypt_payload(token.ephemeral_token, mesh_key);
    std::string sig = CryptoEngine::sign(encrypted, identity_.local_private_key);

    MeshPacket packet;
    packet.session_id = CryptoEngine::generate_session_id();
    packet.sequence = next_sequence();
    packet.type = PacketType::JoinAccept;
    packet.sender_key = identity_.local_public_key;
    packet.sender_name = identity_.local_device_name;
    packet.target_key = token.host_public_key;
    packet.payload = encrypted;
    packet.signature = sig;
    packet.rail = TransportRail::Lan;
    packet.timestamp_ms = now_millis();

    auto latency = tcp_.send_packet(*token.host_ip, token.host_port, packet);
    if (!latency.has_value()) {
        log_event("Join handshake to " + token.host_device_name + " failed: unreachable");
        MeshAuditLogger::instance().log_connection_failed("LAN", *token.host_ip, token.host_port,
                                                            "unreachable or timed out",
                                                            token.host_device_name);
        return false;
    }

    log_event("Authenticated " + token.host_device_name + " into " + identity_.mesh_name);
    MeshAuditLogger::instance().log_handshake_completed(token.host_device_name, token.host_public_key,
                                                          "LAN");
    return true;
}

void MeshEngine::broadcast_clipboard(const std::string& text) {
    std::vector<TrustedDevice> targets = trusted_devices();
    if (targets.empty()) return;

    auto mesh_key = CryptoEngine::derive_mesh_encryption_key(identity_.mesh_secret, identity_.mesh_name);
    std::string encrypted = CryptoEngine::encrypt_payload(text, mesh_key);
    std::string sig = CryptoEngine::sign(encrypted, identity_.local_private_key);

    for (const auto& device : targets) {
        if (device.is_self || !device.ip_address.has_value()) continue;

        MeshPacket packet;
        packet.session_id = CryptoEngine::generate_session_id();
        packet.sequence = next_sequence();
        packet.type = PacketType::ClipboardSync;
        packet.sender_key = identity_.local_public_key;
        packet.sender_name = identity_.local_device_name;
        packet.target_key = device.public_key;
        packet.payload = encrypted;
        packet.signature = sig;
        packet.rail = TransportRail::Lan;
        packet.timestamp_ms = now_millis();

        send_with_fallback(device, packet);
    }
    log_event("Broadcast clipboard to " + std::to_string(targets.size()) + " device(s)");
}

void MeshEngine::send_browser_handoff(const std::string& url,
                                       const std::optional<std::string>& target_device_key) {
    std::optional<TrustedDevice> target;
    {
        std::lock_guard<std::mutex> lock(devices_mutex_);
        if (target_device_key.has_value()) {
            auto it = devices_.find(*target_device_key);
            if (it != devices_.end()) target = it->second;
        }
    }

    std::string session_id = CryptoEngine::generate_session_id();
    std::array<uint8_t, 32> key;
    if (target.has_value()) {
        key = CryptoEngine::derive_peer_session_key(identity_.local_private_key, target->public_key,
                                                     session_id);
    } else {
        key = CryptoEngine::derive_mesh_encryption_key(identity_.mesh_secret, identity_.mesh_name);
    }

    std::string encrypted = CryptoEngine::encrypt_payload(url, key);
    std::string sig = CryptoEngine::sign(encrypted, identity_.local_private_key);

    auto send_to = [&](const TrustedDevice& device) {
        if (!device.ip_address.has_value()) return;
        MeshPacket packet;
        packet.session_id = session_id;
        packet.sequence = next_sequence();
        packet.type = PacketType::BrowserHandoff;
        packet.sender_key = identity_.local_public_key;
        packet.sender_name = identity_.local_device_name;
        packet.target_key = device.public_key;
        packet.payload = encrypted;
        packet.signature = sig;
        packet.rail = TransportRail::Lan;
        packet.timestamp_ms = now_millis();
        send_with_fallback(device, packet);
    };

    if (target.has_value()) {
        send_to(*target);
    } else {
        for (const auto& device : trusted_devices()) {
            if (!device.is_self) send_to(device);
        }
    }
    log_event("Sent browser handoff: " + url);
}

void MeshEngine::send_file(const std::string& local_path, const std::string& target_device_key,
                            std::function<void(float, int64_t, int64_t)> on_progress) {
    std::optional<TrustedDevice> target;
    {
        std::lock_guard<std::mutex> lock(devices_mutex_);
        auto it = devices_.find(target_device_key);
        if (it != devices_.end()) target = it->second;
    }
    if (!target.has_value()) {
        log_event("File send failed: target device not found");
        return;
    }
    // Run on a detached thread so the caller (console/GUI) isn't blocked
    // for the duration of the multi-chunk transfer.
    std::thread([this, local_path, t = *target, on_progress]() mutable {
        bool ok = file_transfer_->send_file(local_path, t, identity_, on_progress);
        log_event(ok ? "File send complete: " + local_path
                     : "File send failed: " + local_path);
    }).detach();
}

void MeshEngine::revoke_device(const std::string& public_key) {
    auto mesh_key = CryptoEngine::derive_mesh_encryption_key(identity_.mesh_secret, identity_.mesh_name);
    std::string encrypted = CryptoEngine::encrypt_payload(public_key, mesh_key);
    std::string sig = CryptoEngine::sign(encrypted, identity_.local_private_key);

    for (const auto& device : trusted_devices()) {
        if (device.is_self || device.public_key == public_key || !device.ip_address.has_value()) continue;

        MeshPacket packet;
        packet.session_id = CryptoEngine::generate_session_id();
        packet.sequence = next_sequence();
        packet.type = PacketType::Revocation;
        packet.sender_key = identity_.local_public_key;
        packet.sender_name = identity_.local_device_name;
        packet.payload = encrypted;
        packet.signature = sig;
        packet.rail = TransportRail::Lan;
        packet.timestamp_ms = now_millis();
        send_with_fallback(device, packet);
    }

    {
        std::lock_guard<std::mutex> lock(devices_mutex_);
        devices_.erase(public_key);
    }
    if (store_) {
        try {
            store_->remove_device(public_key);
        } catch (const PersistenceException& e) {
            MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::Connection,
                                              "Failed to persist device revocation: " + std::string(e.what()));
        }
    }
    log_event("Signed and broadcast revocation for device " + public_key.substr(0, 8));
}

std::vector<TrustedDevice> MeshEngine::trusted_devices() const {
    std::lock_guard<std::mutex> lock(devices_mutex_);
    std::vector<TrustedDevice> result;
    result.reserve(devices_.size());
    for (const auto& [key, device] : devices_) result.push_back(device);
    return result;
}

std::vector<MeshEvent> MeshEngine::recent_events(size_t max) const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    if (events_.size() <= max) return events_;
    return std::vector<MeshEvent>(events_.end() - static_cast<long>(max), events_.end());
}

bool MeshEngine::verify_packet_signature(const MeshPacket& packet) const {
    // HELLO/HEARTBEAT payloads travel in plaintext on Android too (see
    // processIncomingPacket), but the signature itself still covers the
    // ciphertext/plaintext payload field exactly as sent -- verify
    // unconditionally, matching Android's handleIncomingConnection which
    // verifies every packet type before any dispatch happens.
    bool valid = !packet.sender_key.empty() &&
                 CryptoEngine::verify(packet.payload, packet.signature, packet.sender_key);
    MeshAuditLogger::instance().log_signature_verification(valid, packet.sender_name, packet.sender_key,
                                                             packet.sequence);
    return valid;
}

std::string MeshEngine::decrypt_packet_payload(const MeshPacket& packet) const {
    if (packet.type == PacketType::Heartbeat || packet.type == PacketType::Hello) {
        return packet.payload;
    }

    // Mirrors the current Android processIncomingPacket exactly: a packet
    // explicitly targeted at our key (ECDH path) either decrypts with the
    // derived peer session key or is a HARD failure -- it does NOT fall
    // through to a mesh-key retry. Silently reinterpreting a failed
    // targeted decrypt as "maybe it was actually broadcast" was the
    // original debuggability wrinkle; both sides now treat it as the
    // security-relevant failure it is and log it as such.
    if (packet.target_key.has_value() && *packet.target_key == identity_.local_public_key &&
        !packet.sender_key.empty()) {
        try {
            auto peer_key = CryptoEngine::derive_peer_session_key(
                identity_.local_private_key, packet.sender_key, packet.session_id);
            std::string plain = CryptoEngine::decrypt_payload(packet.payload, peer_key);
            MeshAuditLogger::instance().log_ecdh_decryption_success(packet.sequence, packet.sender_name,
                                                                       packet.sender_key, packet.session_id);
            return plain;
        } catch (const CryptoException& e) {
            MeshAuditLogger::instance().log_ecdh_decryption_failure(
                packet.sequence, packet.sender_name, packet.sender_key, packet.session_id, e.what());
            throw;  // hard failure -- caller (on_packet_received) drops the packet, no mesh-key retry
        }
    }

    auto mesh_key = CryptoEngine::derive_mesh_encryption_key(identity_.mesh_secret, identity_.mesh_name);
    try {
        std::string plain = CryptoEngine::decrypt_payload(packet.payload, mesh_key);
        MeshAuditLogger::instance().log_broadcast_decryption_success(packet.sequence, to_wire_string(packet.type),
                                                                        packet.sender_name);
        return plain;
    } catch (const CryptoException& e) {
        MeshAuditLogger::instance().log_broadcast_decryption_failure(packet.sequence, to_wire_string(packet.type),
                                                                        packet.sender_name, e.what());
        throw;
    }
}

void MeshEngine::on_packet_received(const MeshPacket& packet, const std::string& remote_ip) {
    // Discovery challenge/response bypass normal decrypt entirely (their
    // payloads ARE mesh-key ciphertext, but via the plain derived mesh
    // key, not the per-peer ECDH session key the generic path below would
    // reach for since these packets carry a targetKey). Each has its own
    // attempt-and-see decrypt with its own fail-closed handling, not a
    // hard "drop the whole packet" the way a generic broadcast-decrypt
    // failure gets treated. Matches Android's identical bypass in
    // handleIncomingConnection/processIncomingPacket.
    if (packet.type == PacketType::DiscoveryChallenge) {
        handle_discovery_challenge(packet, remote_ip);
        return;
    }
    if (packet.type == PacketType::DiscoveryResponse) {
        handle_discovery_response(packet, remote_ip);
        return;
    }

    std::string plain;
    try {
        plain = decrypt_packet_payload(packet);
    } catch (const CryptoException&) {
        // Already logged with full category/context by decrypt_packet_payload
        // (ECDH vs. broadcast failure) via MeshAuditLogger -- avoid a
        // second, less specific log_event() here.
        return;
    }

    switch (packet.type) {
        case PacketType::ClipboardSync: {
            log_event("Clipboard synced from " + packet.sender_name + ": \"" +
                      plain.substr(0, 60) + (plain.size() > 60 ? "..." : "") + "\"");
#ifdef _WIN32
            // Write to the Windows system clipboard so the user can immediately
            // Ctrl+V -- the core feature promise of clipboard sync.
            if (!plain.empty() && OpenClipboard(nullptr)) {
                EmptyClipboard();
                // Clipboard requires a moveable global memory handle. Allocate
                // enough for the UTF-8 string + NUL terminator.
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, plain.size() + 1);
                if (hMem) {
                    void* ptr = GlobalLock(hMem);
                    if (ptr) {
                        memcpy(ptr, plain.c_str(), plain.size() + 1);
                        GlobalUnlock(hMem);
                        // CF_TEXT for the plain UTF-8 path; a future improvement
                        // can also set CF_UNICODETEXT after a MultiByteToWideChar
                        // conversion for applications that prefer wide strings.
                        if (!SetClipboardData(CF_TEXT, hMem)) {
                            GlobalFree(hMem);
                            log_event("[WARN] Clipboard write failed (SetClipboardData returned NULL)");
                        }
                    } else {
                        GlobalFree(hMem);
                    }
                }
                CloseClipboard();
            }
#endif
            break;
        }
        case PacketType::BrowserHandoff: {
            log_event("URL handoff received from " + packet.sender_name + ": " + plain);
#ifdef _WIN32
            // Validate it looks like a URL before handing to ShellExecute --
            // ShellExecute will silently succeed on garbage strings (it treats
            // them as file-open attempts), which is not what we want.
            bool looks_like_url = plain.rfind("http://", 0) == 0 ||
                                   plain.rfind("https://", 0) == 0 ||
                                   plain.rfind("ftp://", 0) == 0;
            if (looks_like_url) {
                // SW_SHOWNORMAL: open in whatever the user's default browser is,
                // activated in the foreground. Matches Android's
                // Intent.ACTION_VIEW behavior.
                HINSTANCE result = ShellExecuteA(nullptr, "open", plain.c_str(),
                                                  nullptr, nullptr, SW_SHOWNORMAL);
                if (reinterpret_cast<intptr_t>(result) <= 32) {
                    // ShellExecute returns <= 32 on failure (Win32 legacy API
                    // convention -- it predates HRESULT and uses raw integers).
                    log_event("[WARN] Failed to open URL in browser (ShellExecute returned " +
                              std::to_string(reinterpret_cast<intptr_t>(result)) + ")");
                }
            } else {
                log_event("[WARN] URL handoff payload doesn't look like a URL, skipping browser open: " +
                          plain.substr(0, 60));
            }
#endif
            break;
        }
        case PacketType::FileStart:
            file_transfer_->handle_file_start(plain, packet.sender_key, packet.sender_name);
            break;
        case PacketType::FileChunk:
            file_transfer_->handle_file_chunk(plain, packet.sender_key);
            break;
        case PacketType::FileComplete:
            file_transfer_->handle_file_complete(plain, packet.sender_name);
            break;
        case PacketType::Revocation: {
            {
                std::lock_guard<std::mutex> lock(devices_mutex_);
                devices_.erase(plain);
            }
            if (store_) {
                try {
                    store_->remove_device(plain);
                } catch (const PersistenceException& e) {
                    MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::Connection,
                                                      "Failed to persist remote revocation: " + std::string(e.what()));
                }
            }
            log_event("Device revoked from mesh: " + plain.substr(0, 8));
            break;
        }
        case PacketType::Heartbeat: {
            std::lock_guard<std::mutex> lock(devices_mutex_);
            auto it = devices_.find(packet.sender_key);
            if (it != devices_.end()) it->second.connection_state = ConnectionState::Connected;
            break;
        }
        case PacketType::JoinRequest:
        case PacketType::JoinAccept:
            log_event("Join handshake packet from " + packet.sender_name);
            break;
        case PacketType::Hello:
            log_event("Mesh peer discovery from " + packet.sender_name);
            break;
        case PacketType::Ack:
            break;
        case PacketType::DiscoveryChallenge:
        case PacketType::DiscoveryResponse:
            // Unreachable in practice -- both are intercepted and
            // returned-from at the top of this function, before
            // decrypt_packet_payload() even runs. Listed here only so
            // this switch stays exhaustive (no -Wswitch warning) if that
            // early-return logic is ever refactored.
            break;
    }
}

void MeshEngine::on_peer_discovered(const DiscoveredPeer& peer) {
    // SECURITY FIX (was: auto-trust any peer whose beacon signature
    // verified against ITSELF -- see git history for the prior
    // fingerprint+signature design this replaces). A meshTag match is
    // only a HINT that a beacon is probably from our mesh; it grants
    // nothing on its own. If the sender's public key is already in our
    // trust store, this just refreshes its connection info. If it's
    // genuinely new, this hands off to the discovery challenge/response
    // handshake below, which requires the peer to prove it holds the
    // real mesh secret (by decrypting a nonce we encrypt with it) before
    // anything gets added to the trust store. Mirrors Android's
    // onPeerDiscoveredNeedsVerification exactly.
    std::array<uint8_t, 32> mesh_key =
        CryptoEngine::derive_mesh_encryption_key(identity_.mesh_secret, identity_.mesh_name);

    int64_t now_bucket = now_millis() / 1000 / kBeaconTagWindowSeconds;
    bool tag_matches = false;
    for (int64_t bucket = now_bucket - 1; bucket <= now_bucket + 1; ++bucket) {
        if (CryptoEngine::derive_beacon_tag(mesh_key, bucket) == peer.mesh_tag) {
            tag_matches = true;
            break;
        }
    }
    if (!tag_matches) return;  // not our mesh (or a stale/foreign tag) -- ignore, no logging (very common)

    if (peer.public_key.empty()) return;

    std::unique_lock<std::mutex> lock(devices_mutex_);
    auto it = devices_.find(peer.public_key);
    if (it != devices_.end()) {
        // Already trusted from a prior handshake -- just refresh
        // reachability, no new proof needed.
        it->second.ip_address = peer.ip;
        it->second.port = peer.port;
        it->second.connection_state = ConnectionState::Connected;
        TrustedDevice updated = it->second;
        lock.unlock();
        if (store_) {
            try {
                store_->upsert_device(updated);
            } catch (const PersistenceException& e) {
                MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::Connection,
                                                  "Failed to persist updated device: " + std::string(e.what()));
            }
        }
        return;
    }
    lock.unlock();

    // Tie-break: if both sides see each other's beacon around the same
    // time, both would otherwise send a challenge -- harmless but
    // wasteful and racy to reason about. Only the side whose own public
    // key sorts lexicographically greater initiates; the other side
    // waits to receive a challenge instead. Must match Android's
    // tie-break exactly (same comparison, same direction).
    if (!(identity_.local_public_key > peer.public_key)) {
        return;  // waiting for their challenge instead
    }

    std::string nonce = CryptoEngine::generate_discovery_nonce();
    {
        std::lock_guard<std::mutex> plock(pending_challenges_mutex_);
        // emplace (not operator[]/assignment) so a concurrent caller that
        // already reserved this slot doesn't get overwritten -- mirrors
        // Android's ConcurrentHashMap.putIfAbsent race-closing behavior.
        auto result = pending_challenges_.emplace(
            peer.public_key, PendingChallenge{nonce, peer.ip, peer.port, now_millis()});
        if (!result.second) return;  // someone else's concurrent call already reserved this slot
    }

    MeshAuditLogger::instance().log_discovery_beacon_matched(peer.ip, peer.port, peer.public_key);
    send_discovery_challenge(peer.ip, peer.port, peer.public_key, nonce);
}

void MeshEngine::send_discovery_challenge(const std::string& ip, int port,
                                            const std::string& peer_public_key,
                                            const std::string& nonce) {
    std::array<uint8_t, 32> mesh_key =
        CryptoEngine::derive_mesh_encryption_key(identity_.mesh_secret, identity_.mesh_name);

    json body;
    body["nonce"] = nonce;
    body["ts"] = now_millis();
    // Every packet on this transport is one-shot (a fresh outbound TCP
    // connection per packet) -- there is no open connection to write a
    // reply on. The responder has to open its OWN new connection back to
    // us, which means it needs to know our real listening port, not just
    // our IP. Carrying it inside the encrypted body also means an
    // eavesdropper who can't decrypt learns nothing extra beyond what
    // the beacon already exposed.
    body["challengerPort"] = identity_.port;

    std::string encrypted;
    try {
        encrypted = CryptoEngine::encrypt_payload(body.dump(), mesh_key);
    } catch (const CryptoException&) {
        return;
    }

    MeshPacket packet;
    packet.session_id = CryptoEngine::generate_session_id();
    packet.sequence = next_sequence();
    packet.type = PacketType::DiscoveryChallenge;
    packet.sender_key = identity_.local_public_key;
    packet.sender_name = identity_.local_device_name;
    packet.target_key = peer_public_key;
    packet.payload = encrypted;
    packet.signature = CryptoEngine::sign(encrypted, identity_.local_private_key);
    packet.rail = TransportRail::Lan;
    packet.timestamp_ms = now_millis();

    tcp_.send_packet(ip, port, packet);  // fire-and-forget: the challenger doesn't need an ACK,
                                          // only the encrypted DiscoveryResponse itself
    MeshAuditLogger::instance().log_discovery_challenge_sent(ip, port, peer_public_key);
}

void MeshEngine::handle_discovery_challenge(const MeshPacket& packet, const std::string& remote_ip) {
    std::array<uint8_t, 32> mesh_key =
        CryptoEngine::derive_mesh_encryption_key(identity_.mesh_secret, identity_.mesh_name);

    std::string decrypted;
    try {
        decrypted = CryptoEngine::decrypt_payload(packet.payload, mesh_key);
    } catch (const CryptoException& e) {
        MeshAuditLogger::instance().log_discovery_rejected(
            remote_ip, 0, packet.sender_key,
            std::string("could not decrypt DISCOVERY_CHALLENGE payload with our mesh key: ") + e.what());
        return;
    }

    std::string nonce;
    int challenger_port = kDefaultTcpPort;
    try {
        json body = json::parse(decrypted);
        nonce = body.value("nonce", "");
        challenger_port = body.value("challengerPort", kDefaultTcpPort);
    } catch (const json::exception&) {
        return;  // malformed decrypted body -- ignore, matches Android
    }
    if (nonce.empty()) return;
    if (remote_ip.empty()) {
        MeshAuditLogger::instance().log_discovery_rejected(
            "", 0, packet.sender_key, "no direct remote address to reply to (relay-delivered?)");
        return;
    }

    json response_body;
    response_body["nonce"] = nonce;  // echo back exactly what we decrypted
    response_body["ts"] = now_millis();
    response_body["deviceName"] = identity_.local_device_name;

    std::string encrypted;
    try {
        encrypted = CryptoEngine::encrypt_payload(response_body.dump(), mesh_key);
    } catch (const CryptoException&) {
        return;
    }

    MeshPacket response;
    response.session_id = packet.session_id;
    response.sequence = next_sequence();
    response.type = PacketType::DiscoveryResponse;
    response.sender_key = identity_.local_public_key;
    response.sender_name = identity_.local_device_name;
    response.target_key = packet.sender_key;
    response.payload = encrypted;
    response.signature = CryptoEngine::sign(encrypted, identity_.local_private_key);
    response.rail = TransportRail::Lan;
    response.timestamp_ms = now_millis();
    tcp_.send_packet(remote_ip, challenger_port, response);

    // We now know enough to trust THEM too, symmetrically: they proved
    // they hold the mesh secret by sending a challenge we could decrypt
    // in the first place (only a real member could have derived the same
    // mesh key to construct it). Promote immediately rather than waiting
    // on a challenge of our own -- the tie-break rule means we are, by
    // construction, the side that does NOT initiate here, so this is the
    // only place our side of the pair gets promoted.
    promote_to_trusted(packet.sender_key, packet.sender_name, remote_ip, challenger_port);
}

void MeshEngine::handle_discovery_response(const MeshPacket& packet, const std::string& remote_ip) {
    PendingChallenge pending;
    {
        std::lock_guard<std::mutex> lock(pending_challenges_mutex_);
        auto it = pending_challenges_.find(packet.sender_key);
        if (it == pending_challenges_.end()) {
            // No outstanding challenge for this key -- either a stale/
            // duplicate response, or an unsolicited one. Fail closed:
            // ignore rather than trust.
            MeshAuditLogger::instance().log_discovery_rejected(
                remote_ip, 0, packet.sender_key, "DISCOVERY_RESPONSE with no matching outstanding challenge");
            return;
        }
        pending = it->second;
    }

    std::array<uint8_t, 32> mesh_key =
        CryptoEngine::derive_mesh_encryption_key(identity_.mesh_secret, identity_.mesh_name);

    std::string decrypted;
    try {
        decrypted = CryptoEngine::decrypt_payload(packet.payload, mesh_key);
    } catch (const CryptoException& e) {
        // Deliberately do NOT remove the pending entry here -- with a
        // reserved slot per peer, there should only ever be one
        // legitimate outstanding challenge, so a response that fails to
        // decrypt is a stray/replayed/forged packet, not the real
        // answer. Removing on a bad response would let an attacker DoS a
        // legitimate in-flight handshake just by lobbing garbage back at
        // the challenger first.
        MeshAuditLogger::instance().log_discovery_rejected(
            pending.ip, pending.port, packet.sender_key,
            std::string("could not decrypt DISCOVERY_RESPONSE payload with our mesh key: ") + e.what());
        return;
    }

    std::string echoed_nonce;
    std::string device_name;
    try {
        json body = json::parse(decrypted);
        echoed_nonce = body.value("nonce", "");
        device_name = body.value("deviceName", "");
    } catch (const json::exception&) {
        return;  // same reasoning as above -- don't remove on a malformed reply
    }

    if (echoed_nonce.empty() || echoed_nonce != pending.nonce) {
        // Same reasoning again: a mismatched nonce means THIS response
        // isn't the one we're waiting for, not that the real one won't
        // still arrive -- the pending entry stays.
        MeshAuditLogger::instance().log_discovery_rejected(pending.ip, pending.port, packet.sender_key,
                                                              "echoed nonce did not match what we sent");
        return;
    }

    // Genuine match -- consume it now (before promoting), so a
    // duplicate/replayed copy of this same valid response can't
    // re-trigger anything once we've already acted on it.
    {
        std::lock_guard<std::mutex> lock(pending_challenges_mutex_);
        pending_challenges_.erase(packet.sender_key);
    }
    std::string resolved_name = device_name.empty() ? "Unknown Device" : device_name;
    std::string ip = remote_ip.empty() ? pending.ip : remote_ip;
    promote_to_trusted(packet.sender_key, resolved_name, ip, pending.port);
}

void MeshEngine::promote_to_trusted(const std::string& public_key, const std::string& device_name,
                                      const std::string& ip, int port) {
    TrustedDevice device;
    device.public_key = public_key;
    device.name = device_name;
    device.platform = PlatformType::Android;  // best-effort guess; refine once cross-platform discovery is tested more
    device.connection_state = ConnectionState::Connected;
    device.active_rail = TransportRail::Lan;
    device.ip_address = ip;
    device.port = port;
    device.latency_ms = 2;

    {
        std::lock_guard<std::mutex> lock(devices_mutex_);
        devices_[public_key] = device;
    }

    if (store_) {
        try {
            store_->upsert_device(device);
        } catch (const PersistenceException& e) {
            MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::Connection,
                                              "Failed to persist newly-trusted device: " + std::string(e.what()));
        }
    }

    log_event("Discovery verified, now trusted: " + device_name + " (" + ip + ":" + std::to_string(port) + ")");
    MeshAuditLogger::instance().log_discovery_verified(device_name, public_key, ip, port);
}


void MeshEngine::log_event(const std::string& message) {
    std::lock_guard<std::mutex> lock(events_mutex_);
    events_.push_back({now_millis(), message});
    std::cout << "[Rin] " << message << "\n";
}

int64_t MeshEngine::next_sequence() { return sequence_.fetch_add(1); }

}  // namespace rin
