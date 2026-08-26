#pragma once
// Structured, categorized diagnostic event log for mesh transport and
// security events -- the direct C++ analogue of the Android side's
// MeshAuditLogger.kt.
//
// This exists so that when a phone and PC fail to talk to each other,
// BOTH sides produce comparable, correlatable diagnostics instead of one
// side being a black box: "signature verification failed" on Windows and
// "ECDSA signature validation FAILED" on Android are the same event,
// logged at the same point in the same pipeline stage, so a person
// debugging a failed join can line the two logs up side by side.
//
// Mirrors MeshAuditLogger.kt's design deliberately:
//  - AuditLevel / AuditCategory enums with matching semantics.
//  - Key fingerprinting (never log a raw public/private key in full).
//  - A bounded, thread-safe in-memory buffer (most recent N events),
//    exposed for a future GUI "Audit Trail" tab exactly like the
//    Android Packet Inspector's second tab.
//  - One logging call per pipeline decision point: connection
//    attempt/success/failure, discovery, handshake start/complete,
//    ECDH decrypt success/failure, broadcast decrypt success/failure,
//    signature verify pass/fail.

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace rin {

enum class AuditLevel {
    Info,
    Handshake,
    SecuritySuccess,
    SecurityWarning,
    SecurityError
};

enum class AuditCategory {
    Connection,
    DiscoveryUdp,
    Handshake,
    DecryptionEcdh,
    DecryptionBroadcast,
    SignatureVerification,
    PacketRouting,
    DeviceRevocation
};

const char* to_string(AuditLevel level);
const char* to_string(AuditCategory category);

struct AuditEvent {
    int64_t id = 0;              // monotonically increasing, assigned at log() time
    int64_t timestamp_ms = 0;
    AuditLevel level = AuditLevel::Info;
    AuditCategory category = AuditCategory::Connection;
    std::optional<std::string> peer_name;
    std::optional<std::string> peer_key_fingerprint;  // sanitized: "key:xxxx...yyyy", never the full key
    std::string message;
    std::optional<std::string> details;
    std::optional<std::string> error;

    // "HH:MM:SS.mmm" in local time, matching MeshAuditEvent.formattedTime.
    std::string formatted_time() const;
};

// Thread-safe, bounded (most recent kMaxEventBuffer) event log. One
// process-wide instance, mirroring MeshAuditLogger's Kotlin `object`
// singleton -- there is exactly one mesh identity per rin_console/rin_gui
// process, so a singleton is the right shape here too, not an
// over-engineering risk.
class MeshAuditLogger {
public:
    static constexpr size_t kMaxEventBuffer = 100;

    static MeshAuditLogger& instance();

    void log(AuditLevel level, AuditCategory category, const std::string& message,
              const std::optional<std::string>& peer_name = std::nullopt,
              const std::optional<std::string>& peer_key = std::nullopt,
              const std::optional<std::string>& details = std::nullopt,
              const std::optional<std::string>& error = std::nullopt);

    // -- Convenience wrappers matching MeshAuditLogger.kt's named helpers,
    // one per pipeline decision point -- kept as named functions (not
    // just inline log() calls at each site) so every call site reads
    // the same way on both platforms and a future contributor can grep
    // for "ECDH decryption" and find both sides at once. --------------

    void log_connection_attempt(const std::string& rail, const std::string& target_ip, int port,
                                  const std::optional<std::string>& peer_name = std::nullopt);
    void log_connection_established(const std::string& rail, const std::string& target_ip, int port,
                                      const std::optional<std::string>& peer_name = std::nullopt);
    void log_connection_failed(const std::string& rail, const std::string& target_ip, int port,
                                 const std::string& error,
                                 const std::optional<std::string>& peer_name = std::nullopt);

    void log_udp_beacon_discovered(const std::string& device_name, const std::string& host, int port,
                                     const std::optional<std::string>& mesh_name);

    void log_handshake_initiated(const std::string& target_ip, const std::string& peer_name,
                                   const std::optional<std::string>& ephemeral_token);
    void log_handshake_completed(const std::string& peer_name, const std::string& peer_key,
                                   const std::string& rail);

    void log_ecdh_decryption_success(int64_t seq, const std::string& sender_name,
                                       const std::string& sender_key, const std::string& session_id);
    void log_ecdh_decryption_failure(int64_t seq, const std::string& sender_name,
                                       const std::string& sender_key, const std::string& session_id,
                                       const std::string& error);

    void log_broadcast_decryption_success(int64_t seq, const std::string& packet_type,
                                            const std::string& sender_name);
    void log_broadcast_decryption_failure(int64_t seq, const std::string& packet_type,
                                            const std::string& sender_name, const std::string& error);

    void log_signature_verification(bool is_valid, const std::string& sender_name,
                                      const std::string& sender_key, int64_t seq);

    // -- Introspection for a future GUI audit tab / test harness ---------
    std::vector<AuditEvent> recent_events(size_t max = kMaxEventBuffer) const;
    void clear();

private:
    MeshAuditLogger() = default;

    static std::optional<std::string> sanitize_key(const std::optional<std::string>& key);

    mutable std::mutex mutex_;
    std::vector<AuditEvent> events_;
    int64_t next_id_ = 1;
};

}  // namespace rin
