#include "rin/protocol.hpp"

#include <nlohmann/json.hpp>

#include <chrono>

using nlohmann::json;

namespace rin {

namespace {
int64_t now_millis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
}  // namespace

// PacketType.name on the Kotlin side -- exact casing/spelling matters,
// this is what's actually compared against on the wire.
const char* to_wire_string(PacketType type) {
    switch (type) {
        case PacketType::Hello: return "HELLO";
        case PacketType::JoinRequest: return "JOIN_REQUEST";
        case PacketType::JoinAccept: return "JOIN_ACCEPT";
        case PacketType::ClipboardSync: return "CLIPBOARD_SYNC";
        case PacketType::BrowserHandoff: return "BROWSER_HANDOFF";
        case PacketType::FileStart: return "FILE_START";
        case PacketType::FileChunk: return "FILE_CHUNK";
        case PacketType::FileComplete: return "FILE_COMPLETE";
        case PacketType::Revocation: return "REVOCATION";
        case PacketType::Heartbeat: return "HEARTBEAT";
        case PacketType::Ack: return "ACK";
    }
    return "HEARTBEAT";
}

std::optional<PacketType> packet_type_from_wire_string(const std::string& s) {
    if (s == "HELLO") return PacketType::Hello;
    if (s == "JOIN_REQUEST") return PacketType::JoinRequest;
    if (s == "JOIN_ACCEPT") return PacketType::JoinAccept;
    if (s == "CLIPBOARD_SYNC") return PacketType::ClipboardSync;
    if (s == "BROWSER_HANDOFF") return PacketType::BrowserHandoff;
    if (s == "FILE_START") return PacketType::FileStart;
    if (s == "FILE_CHUNK") return PacketType::FileChunk;
    if (s == "FILE_COMPLETE") return PacketType::FileComplete;
    if (s == "REVOCATION") return PacketType::Revocation;
    if (s == "HEARTBEAT") return PacketType::Heartbeat;
    if (s == "ACK") return PacketType::Ack;
    return std::nullopt;
}

const char* to_wire_string(TransportRail rail) {
    switch (rail) {
        case TransportRail::Lan: return "LAN";
        case TransportRail::WifiDirect: return "WIFI_DIRECT";
        case TransportRail::Ble: return "BLE";
        case TransportRail::InternetP2P: return "INTERNET_P2P";
        case TransportRail::Relay: return "RELAY";
    }
    return "LAN";
}

std::optional<TransportRail> transport_rail_from_wire_string(const std::string& s) {
    if (s == "LAN") return TransportRail::Lan;
    if (s == "WIFI_DIRECT") return TransportRail::WifiDirect;
    if (s == "BLE") return TransportRail::Ble;
    if (s == "INTERNET_P2P") return TransportRail::InternetP2P;
    if (s == "RELAY") return TransportRail::Relay;
    return std::nullopt;
}

// ---------------------------------------------------------------------
// MeshPacket <-> wire JSON
//
// Field names and construction order below mirror
// MeshRuntimeEngine.transmitOverNetwork() exactly:
//   v, sess, seq, type, senderKey, senderName, targetKey?, payload, sig,
//   rail, ts
// ---------------------------------------------------------------------

std::string packet_to_wire_json(const MeshPacket& packet) {
    json j;
    j["v"] = packet.version;
    j["sess"] = packet.session_id;
    j["seq"] = packet.sequence;
    j["type"] = to_wire_string(packet.type);
    j["senderKey"] = packet.sender_key;
    j["senderName"] = packet.sender_name;
    if (packet.target_key.has_value()) {
        j["targetKey"] = *packet.target_key;
    }
    j["payload"] = packet.payload;
    j["sig"] = packet.signature;
    j["rail"] = to_wire_string(packet.rail);
    j["ts"] = packet.timestamp_ms;
    return j.dump();
}

std::optional<MeshPacket> packet_from_wire_json(const std::string& json_line) {
    try {
        json j = json::parse(json_line);

        MeshPacket packet;
        packet.version = j.value("v", 1);
        packet.session_id = j.value("sess", "sess_default");
        packet.sequence = j.value("seq", int64_t{0});

        std::string type_str = j.value("type", "HEARTBEAT");
        auto type = packet_type_from_wire_string(type_str);
        if (!type.has_value()) return std::nullopt;  // unknown type -> drop, like Android's valueOf() would throw
        packet.type = *type;

        packet.sender_key = j.value("senderKey", "");
        packet.sender_name = j.value("senderName", "Unknown Device");

        if (j.contains("targetKey") && !j["targetKey"].is_null()) {
            packet.target_key = j["targetKey"].get<std::string>();
        }

        packet.payload = j.value("payload", "");
        packet.signature = j.value("sig", "");

        std::string rail_str = j.value("rail", "LAN");
        auto rail = transport_rail_from_wire_string(rail_str);
        packet.rail = rail.value_or(TransportRail::Lan);

        packet.timestamp_ms = j.value("ts", now_millis());

        return packet;
    } catch (const json::exception&) {
        return std::nullopt;  // malformed JSON -- caller should ignore, mirrors Android's try/catch-continue
    }
}

// ---------------------------------------------------------------------
// QrJoinToken
// ---------------------------------------------------------------------

std::string QrJoinToken::to_json() const {
    json j;
    j["meshName"] = mesh_name;
    j["hostPublicKey"] = host_public_key;
    j["hostDeviceName"] = host_device_name;
    j["ephemeralToken"] = ephemeral_token;
    if (mesh_secret.has_value()) {
        j["meshSecret"] = *mesh_secret;
    }
    j["hostPort"] = host_port;
    if (host_ip.has_value()) {
        j["hostIp"] = *host_ip;
    }
    j["timestamp"] = timestamp_ms;
    return j.dump();
}

std::optional<QrJoinToken> QrJoinToken::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);
        QrJoinToken token;
        token.mesh_name = j.at("meshName").get<std::string>();
        token.host_public_key = j.at("hostPublicKey").get<std::string>();
        token.host_device_name = j.at("hostDeviceName").get<std::string>();
        token.ephemeral_token = j.at("ephemeralToken").get<std::string>();
        if (j.contains("meshSecret") && !j["meshSecret"].is_null()) {
            token.mesh_secret = j["meshSecret"].get<std::string>();
        }
        token.host_port = j.value("hostPort", 45990);
        if (j.contains("hostIp") && !j["hostIp"].is_null()) {
            token.host_ip = j["hostIp"].get<std::string>();
        }
        token.timestamp_ms = j.value("timestamp", now_millis());
        return token;
    } catch (const json::exception&) {
        return std::nullopt;
    }
}

// ---------------------------------------------------------------------
// FileTransferMetadata
// ---------------------------------------------------------------------

std::string FileTransferMetadata::to_json() const {
    json j;
    j["fileId"] = file_id;
    j["fileName"] = file_name;
    j["fileSize"] = file_size;
    j["mimeType"] = mime_type;
    j["totalChunks"] = total_chunks;
    j["chunkSize"] = chunk_size;
    if (sha256_checksum.has_value()) {
        j["checksum"] = *sha256_checksum;
    }
    return j.dump();
}

std::optional<FileTransferMetadata> FileTransferMetadata::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);
        FileTransferMetadata meta;
        meta.file_id = j.at("fileId").get<std::string>();
        meta.file_name = j.at("fileName").get<std::string>();
        meta.file_size = j.at("fileSize").get<int64_t>();
        meta.mime_type = j.value("mimeType", "*/*");
        meta.total_chunks = j.at("totalChunks").get<int>();
        meta.chunk_size = j.value("chunkSize", 65536);
        if (j.contains("checksum") && !j["checksum"].is_null()) {
            meta.sha256_checksum = j["checksum"].get<std::string>();
        }
        return meta;
    } catch (const json::exception&) {
        return std::nullopt;
    }
}

// ---------------------------------------------------------------------
// FileChunkPayload
// ---------------------------------------------------------------------

std::string FileChunkPayload::to_json() const {
    json j;
    j["fileId"] = file_id;
    j["chunkIndex"] = chunk_index;
    j["totalChunks"] = total_chunks;
    j["data"] = data_base64;
    return j.dump();
}

std::optional<FileChunkPayload> FileChunkPayload::from_json(const std::string& json_str) {
    try {
        json j = json::parse(json_str);
        FileChunkPayload chunk;
        chunk.file_id = j.at("fileId").get<std::string>();
        chunk.chunk_index = j.at("chunkIndex").get<int>();
        chunk.total_chunks = j.at("totalChunks").get<int>();
        chunk.data_base64 = j.at("data").get<std::string>();
        return chunk;
    } catch (const json::exception&) {
        return std::nullopt;
    }
}

}  // namespace rin
