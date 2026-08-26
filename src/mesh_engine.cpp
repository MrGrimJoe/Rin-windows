#include "rin/mesh_engine.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>

#ifdef _WIN32
#include <shellapi.h>
#include <windows.h>
#endif

#include "rin/audit_logger.hpp"

namespace rin {

namespace {
int64_t now_millis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
}  // namespace

MeshEngine::MeshEngine(asio::io_context& io) : io_(io), tcp_(io), udp_(io) {
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

void MeshEngine::start() {
    identity_.port = tcp_.start(
        [this](const MeshPacket& packet) { on_packet_received(packet); },
        [this](const MeshPacket& packet) { return verify_packet_signature(packet); });

    udp_.start(identity_.mesh_name, identity_.local_public_key, identity_.local_device_name,
               identity_.port, [this](const DiscoveredPeer& peer) { on_peer_discovered(peer); });

    log_event("Listening on TCP " + std::to_string(identity_.port) + ", UDP beacon on " +
              std::to_string(kUdpBeaconPort));
}

void MeshEngine::stop() {
    tcp_.stop();
    udp_.stop();
}

std::string MeshEngine::build_join_token_json() const {
    QrJoinToken token;
    token.mesh_name = identity_.mesh_name;
    token.host_public_key = identity_.local_public_key;
    token.host_device_name = identity_.local_device_name;
    token.ephemeral_token = CryptoEngine::generate_ephemeral_token();
    token.mesh_secret = identity_.mesh_secret;
    token.host_port = identity_.port;
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

    // Adopt the mesh secret carried in the token, matching Android's
    // completeJoinHandshake -- this is the ONLY place a mesh secret should
    // ever travel, inside the QR-bootstrapped token.
    std::string active_secret = identity_.mesh_secret;
    if (token.mesh_secret.has_value() && !token.mesh_secret->empty() &&
        token.mesh_secret != identity_.mesh_secret) {
        identity_.mesh_secret = *token.mesh_secret;
        active_secret = *token.mesh_secret;
        if (store_) {
            try {
                store_->save_identity(identity_);
            } catch (const PersistenceException& e) {
                MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::Connection,
                                                  "Failed to persist updated mesh secret: " + std::string(e.what()));
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

        tcp_.send_packet(*device.ip_address, device.port, packet);
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
        tcp_.send_packet(*device.ip_address, device.port, packet);
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
        tcp_.send_packet(*device.ip_address, device.port, packet);
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

void MeshEngine::on_packet_received(const MeshPacket& packet) {
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
    }
}

void MeshEngine::on_peer_discovered(const DiscoveredPeer& peer) {
    if (peer.mesh_name != identity_.mesh_name) return;  // different mesh entirely -- ignore

    std::lock_guard<std::mutex> lock(devices_mutex_);
    auto it = devices_.find(peer.public_key);
    if (it != devices_.end()) {
        it->second.ip_address = peer.ip;
        it->second.port = peer.port;
        it->second.connection_state = ConnectionState::Connected;
        return;
    }

    // NOTE: this auto-trusts any peer broadcasting our mesh name, matching
    // Android's handleDiscoveredPeer today. That's fine for the milestone
    // (mesh name isn't the trust boundary -- signature verification is,
    // and untrusted peers still can't produce valid signed/encrypted
    // traffic without the mesh secret or an ECDH-derivable key) but is
    // worth revisiting before broadcast features assume "in device list"
    // means "actually vetted via QR".
    TrustedDevice device;
    device.public_key = peer.public_key;
    device.name = peer.device_name;
    device.platform = PlatformType::Android;  // discovered peers are Android for now; refine once cross-Windows discovery is tested
    device.connection_state = ConnectionState::Connected;
    device.active_rail = TransportRail::Lan;
    device.ip_address = peer.ip;
    device.port = peer.port;
    device.latency_ms = 2;
    devices_[peer.public_key] = device;

    if (store_) {
        try {
            store_->upsert_device(device);
        } catch (const PersistenceException& e) {
            MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::Connection,
                                              "Failed to persist discovered device: " + std::string(e.what()));
        }
    }

    log_event("Discovered and connected to peer: " + peer.device_name + " (" + peer.ip + ":" +
              std::to_string(peer.port) + ")");
    MeshAuditLogger::instance().log_udp_beacon_discovered(peer.device_name, peer.ip, peer.port,
                                                            peer.mesh_name);
}

void MeshEngine::log_event(const std::string& message) {
    std::lock_guard<std::mutex> lock(events_mutex_);
    events_.push_back({now_millis(), message});
    std::cout << "[Rin] " << message << "\n";
}

int64_t MeshEngine::next_sequence() { return sequence_.fetch_add(1); }

}  // namespace rin
