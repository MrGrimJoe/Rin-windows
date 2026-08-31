#include "rin/audit_logger.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace rin {

namespace {
int64_t now_millis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace

std::optional<std::string> MeshAuditLogger::sanitize_key(const std::optional<std::string>& key) {
    // Audit logs must NEVER expose the full cryptographic material of a
    // key, only a short fingerprint -- the same principle CryptoEngine's
    // own fingerprint uses for the local identity.
    if (!key.has_value() || key->empty()) return std::nullopt;
    if (key->size() > 12) {
        return "key:" + key->substr(0, 4) + "..." + key->substr(key->size() - 4);
    }
    return "key:" + *key;
}

const char* to_string(AuditLevel level) {
    switch (level) {
        case AuditLevel::Info: return "INFO";
        case AuditLevel::Handshake: return "HANDSHAKE";
        case AuditLevel::SecuritySuccess: return "OK";
        case AuditLevel::SecurityWarning: return "WARN";
        case AuditLevel::SecurityError: return "ERROR";
    }
    return "UNKNOWN";
}

const char* to_string(AuditCategory category) {
    switch (category) {
        case AuditCategory::Connection: return "CONNECTION";
        case AuditCategory::DiscoveryUdp: return "DISCOVERY_UDP";
        case AuditCategory::Handshake: return "HANDSHAKE";
        case AuditCategory::DecryptionEcdh: return "DECRYPTION_ECDH";
        case AuditCategory::DecryptionBroadcast: return "DECRYPTION_BROADCAST";
        case AuditCategory::SignatureVerification: return "SIGNATURE_VERIFICATION";
        case AuditCategory::PacketRouting: return "PACKET_ROUTING";
        case AuditCategory::DeviceRevocation: return "DEVICE_REVOCATION";
    }
    return "UNKNOWN";
}

std::string AuditEvent::formatted_time() const {
    std::time_t t = timestamp_ms / 1000;
    int ms = static_cast<int>(timestamp_ms % 1000);
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d", tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, ms);
    return std::string(buf);
}

MeshAuditLogger& MeshAuditLogger::instance() {
    static MeshAuditLogger logger;
    return logger;
}

void MeshAuditLogger::log(AuditLevel level, AuditCategory category, const std::string& message,
                            const std::optional<std::string>& peer_name,
                            const std::optional<std::string>& peer_key,
                            const std::optional<std::string>& details,
                            const std::optional<std::string>& error) {
    AuditEvent event;
    event.timestamp_ms = now_millis();
    event.level = level;
    event.category = category;
    event.peer_name = peer_name;
    event.peer_key_fingerprint = sanitize_key(peer_key);
    event.message = message;
    event.details = details;
    event.error = error;

    // Console mirror of Android's Logcat output, same shape: category tag,
    // message, then optional peer/details/error suffixes -- so a person
    // watching both a `logcat` stream and this console side by side sees
    // matching lines for matching events.
    std::string line = "[" + std::string(to_string(category)) + "] " + message;
    if (event.peer_name.has_value()) {
        line += " (Peer: " + *event.peer_name;
        if (event.peer_key_fingerprint.has_value()) line += " " + *event.peer_key_fingerprint;
        line += ")";
    }
    if (event.details.has_value()) line += " | Details: " + *event.details;
    if (event.error.has_value()) line += " | Error: " + *event.error;

    const char* icon = "";
    switch (level) {
        case AuditLevel::Info: icon = ""; break;
        case AuditLevel::Handshake: icon = "[HANDSHAKE] "; break;
        case AuditLevel::SecuritySuccess: icon = "[OK] "; break;
        case AuditLevel::SecurityWarning: icon = "[WARN] "; break;
        case AuditLevel::SecurityError: icon = "[ERROR] "; break;
    }
    std::cerr << icon << line << "\n";

    std::lock_guard<std::mutex> lock(mutex_);
    event.id = next_id_++;
    if (events_.size() >= kMaxEventBuffer) {
        events_.erase(events_.begin());
    }
    events_.push_back(std::move(event));
}

void MeshAuditLogger::log_connection_attempt(const std::string& rail, const std::string& target_ip,
                                               int port, const std::optional<std::string>& peer_name) {
    log(AuditLevel::Info, AuditCategory::Connection,
        "Initiating connection over " + rail + " to " + target_ip + ":" + std::to_string(port),
        peer_name);
}

void MeshAuditLogger::log_connection_established(const std::string& rail, const std::string& target_ip,
                                                    int port,
                                                    const std::optional<std::string>& peer_name) {
    log(AuditLevel::Info, AuditCategory::Connection,
        "Connection established over " + rail + " with " + target_ip + ":" + std::to_string(port),
        peer_name);
}

void MeshAuditLogger::log_connection_failed(const std::string& rail, const std::string& target_ip,
                                              int port, const std::string& error,
                                              const std::optional<std::string>& peer_name) {
    log(AuditLevel::SecurityWarning, AuditCategory::Connection,
        "Connection failed over " + rail + " to " + target_ip + ":" + std::to_string(port), peer_name,
        std::nullopt, std::nullopt, error);
}

void MeshAuditLogger::log_udp_beacon_discovered(const std::string& device_name, const std::string& host,
                                                  int port, const std::optional<std::string>& mesh_name) {
    log(AuditLevel::Info, AuditCategory::DiscoveryUdp,
        "UDP beacon discovered peer '" + device_name + "' at " + host + ":" + std::to_string(port) +
            " (Mesh: " + mesh_name.value_or("any") + ")");
}

void MeshAuditLogger::log_handshake_initiated(const std::string& target_ip, const std::string& peer_name,
                                                const std::optional<std::string>& ephemeral_token) {
    std::string token_preview =
        ephemeral_token.has_value() && ephemeral_token->size() >= 8 ? ephemeral_token->substr(0, 8) + "..." : "auto";
    log(AuditLevel::Handshake, AuditCategory::Handshake,
        "Beginning cryptographic handshake with " + target_ip, peer_name, std::nullopt,
        "Token: " + token_preview);
}

void MeshAuditLogger::log_handshake_completed(const std::string& peer_name, const std::string& peer_key,
                                                const std::string& rail) {
    log(AuditLevel::Handshake, AuditCategory::Handshake,
        "Cryptographic handshake completed successfully over " + rail, peer_name, peer_key);
}

void MeshAuditLogger::log_ecdh_decryption_success(int64_t seq, const std::string& sender_name,
                                                     const std::string& sender_key,
                                                     const std::string& session_id) {
    log(AuditLevel::SecuritySuccess, AuditCategory::DecryptionEcdh,
        "Targeted packet #" + std::to_string(seq) + " decrypted via ECDH session key", sender_name,
        sender_key, "Session: " + session_id.substr(0, std::min<size_t>(12, session_id.size())));
}

void MeshAuditLogger::log_ecdh_decryption_failure(int64_t seq, const std::string& sender_name,
                                                     const std::string& sender_key,
                                                     const std::string& session_id,
                                                     const std::string& error) {
    log(AuditLevel::SecurityError, AuditCategory::DecryptionEcdh,
        "Targeted ECDH decryption failed on packet #" + std::to_string(seq) + ": " + error, sender_name,
        sender_key, "Session: " + session_id + ". Tag authentication mismatch or invalid peer public key.",
        error);
}

void MeshAuditLogger::log_broadcast_decryption_success(int64_t seq, const std::string& packet_type,
                                                          const std::string& sender_name) {
    log(AuditLevel::SecuritySuccess, AuditCategory::DecryptionBroadcast,
        "Broadcast " + packet_type + " packet #" + std::to_string(seq) +
            " decrypted via 256-bit Mesh Master Key",
        sender_name);
}

void MeshAuditLogger::log_broadcast_decryption_failure(int64_t seq, const std::string& packet_type,
                                                          const std::string& sender_name,
                                                          const std::string& error) {
    log(AuditLevel::SecurityError, AuditCategory::DecryptionBroadcast,
        "Mesh Master Key decryption failed for " + packet_type + " #" + std::to_string(seq) + ": " + error,
        sender_name, std::nullopt, "Dropped unauthenticated/corrupted broadcast packet.", error);
}

void MeshAuditLogger::log_signature_verification(bool is_valid, const std::string& sender_name,
                                                    const std::string& sender_key, int64_t seq) {
    if (is_valid) {
        log(AuditLevel::SecuritySuccess, AuditCategory::SignatureVerification,
            "Strict ECDSA signature verified for packet #" + std::to_string(seq), sender_name, sender_key);
    } else {
        log(AuditLevel::SecurityError, AuditCategory::SignatureVerification,
            "ECDSA signature validation FAILED for packet #" + std::to_string(seq) + " from " + sender_name,
            sender_name, sender_key, "Packet rejected. Possible tampering or key mismatch.");
    }
}

std::vector<AuditEvent> MeshAuditLogger::recent_events(size_t max) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (events_.size() <= max) return events_;
    return std::vector<AuditEvent>(events_.end() - static_cast<long>(max), events_.end());
}

void MeshAuditLogger::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.clear();
}

}  // namespace rin
