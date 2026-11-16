#pragma once
// Wire protocol types.
//
// These MUST stay in exact sync with the Android side:
//   app/src/main/java/com/example/core/protocol/MeshProtocol.kt
//
// The JSON key names below (v, sess, seq, senderKey, ...) are the ones
// Android's MeshRuntimeEngine.transmitOverNetwork() / handleIncomingConnection()
// actually put on the wire -- NOT the friendlier names in the README. Do not
// "clean these up" without changing both sides at once.

#include <cstdint>
#include <optional>
#include <string>

namespace rin {

enum class ConnectionState {
    Connected,
    Active,
    Reconnecting,
    Idle,
    Offline,
    Lost,
    Discovered,
    Authenticating
};

enum class TransportRail {
    Lan,
    WifiDirect,
    Ble,
    InternetP2P,
    Relay
};

enum class PlatformType {
    Android,
    Windows,
    Linux,
    MacOS,
    Tablet
};

// Order/spelling must match PacketType.name on the Kotlin side exactly --
// the wire format sends the enum's *name*, not an ordinal.
enum class PacketType {
    Hello,
    JoinRequest,
    JoinAccept,
    ClipboardSync,
    BrowserHandoff,
    FileStart,
    FileChunk,
    FileComplete,
    Revocation,
    Heartbeat,
    Ack,
    // NEW -- discovery hardening. Sent point-to-point over TCP once a UDP
    // beacon's meshTag looks like it might be ours; both packets' payloads
    // are mesh-key AES-256-GCM ciphertext (never plaintext), so a peer
    // that can't decrypt them (doesn't hold the real mesh secret) never
    // gets promoted to trusted. See MeshEngine's discovery
    // challenge/response handling. Wire strings must match Android's
    // PacketType.DISCOVERY_CHALLENGE/DISCOVERY_RESPONSE exactly.
    DiscoveryChallenge,
    DiscoveryResponse
};

const char* to_wire_string(PacketType type);
std::optional<PacketType> packet_type_from_wire_string(const std::string& s);

const char* to_wire_string(TransportRail rail);
std::optional<TransportRail> transport_rail_from_wire_string(const std::string& s);

// One JSON object per TCP connection, newline-terminated. See transport.hpp.
struct MeshPacket {
    int version = 1;
    std::string session_id;             // "sess"
    int64_t sequence = 0;                // "seq"
    PacketType type = PacketType::Heartbeat;
    std::string sender_key;              // "senderKey" -- base64 X.509 EC public key
    std::string sender_name;             // "senderName"
    std::optional<std::string> target_key; // "targetKey"
    std::string payload;                 // "payload" -- base64 ciphertext (or plaintext for Hello/Heartbeat)
    std::string signature;               // "sig" -- "ecdsa:<base64>"
    TransportRail rail = TransportRail::Lan;
    int64_t timestamp_ms = 0;            // "ts"
};

// QR-code join bootstrap payload. Matches QrJoinToken in MeshProtocol.kt.
struct QrJoinToken {
    std::string mesh_name;
    std::string host_public_key;
    std::string host_device_name;
    std::string ephemeral_token;
    std::optional<std::string> mesh_secret;
    int host_port = 45990;
    std::optional<std::string> host_ip;
    int64_t timestamp_ms = 0;

    std::string to_json() const;
    static std::optional<QrJoinToken> from_json(const std::string& json_str);
};

struct FileTransferMetadata {
    std::string file_id;
    std::string file_name;
    int64_t file_size = 0;
    std::string mime_type;
    int total_chunks = 0;
    int chunk_size = 65536;
    std::optional<std::string> sha256_checksum;
    // Optional extension, absent on the wire unless the sender opted in:
    // "amdcf1" means individual chunks MAY be AMDC-F compressed (see
    // FileChunkPayload::raw_size). A receiver that does not know this field
    // would store compressed bytes and fail the SHA-256 check, so senders
    // only set it when the peer is known to support it.
    std::optional<std::string> compression;

    std::string to_json() const;
    static std::optional<FileTransferMetadata> from_json(const std::string& json_str);
};

struct FileChunkPayload {
    std::string file_id;
    int chunk_index = 0;
    int total_chunks = 0;
    std::string data_base64;
    // 0 = data is the raw chunk (the only form older peers produce).
    // >0 = data is AMDC-F compressed and decodes to exactly raw_size bytes.
    int raw_size = 0;

    std::string to_json() const;
    static std::optional<FileChunkPayload> from_json(const std::string& json_str);
};

// Serializes a MeshPacket to the exact JSON line Android expects, matching
// MeshRuntimeEngine.transmitOverNetwork()'s field construction order.
std::string packet_to_wire_json(const MeshPacket& packet);

// Parses one line of incoming wire JSON. Returns nullopt on malformed input
// (mirrors Android silently `continue`-ing on parse failure).
std::optional<MeshPacket> packet_from_wire_json(const std::string& json_line);

}  // namespace rin
