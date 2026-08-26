#include "rin/file_transfer.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <shlobj.h>
#include <windows.h>
#endif

#include <openssl/evp.h>

#include "rin/audit_logger.hpp"
#include "rin/crypto.hpp"
#include "rin/mesh_engine.hpp"

namespace rin {

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string sha256_hex(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    char buf[8192];
    while (f.read(buf, sizeof(buf)) || f.gcount()) {
        EVP_DigestUpdate(ctx, buf, static_cast<size_t>(f.gcount()));
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < digest_len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
    }
    return oss.str();
}

std::string mime_from_extension(const std::string& path) {
    auto dot = path.rfind('.');
    if (dot == std::string::npos) return "application/octet-stream";
    std::string ext = path.substr(dot + 1);
    for (char& c : ext) c = static_cast<char>(::tolower(c));
    if (ext == "pdf") return "application/pdf";
    if (ext == "png") return "image/png";
    if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
    if (ext == "gif") return "image/gif";
    if (ext == "mp4") return "video/mp4";
    if (ext == "mp3") return "audio/mpeg";
    if (ext == "txt") return "text/plain";
    if (ext == "zip") return "application/zip";
    return "application/octet-stream";
}

}  // namespace

FileTransferEngine::FileTransferEngine(FileReceivedCallback on_received, PacketSendFn send_packet)
    : on_received_(std::move(on_received)), send_packet_(std::move(send_packet)) {}

std::string FileTransferEngine::downloads_directory() {
    std::string base;
#ifdef _WIN32
    PWSTR path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Downloads, 0, nullptr, &path))) {
        int len = WideCharToMultiByte(CP_UTF8, 0, path, -1, nullptr, 0, nullptr, nullptr);
        base.resize(static_cast<size_t>(len) - 1);
        WideCharToMultiByte(CP_UTF8, 0, path, -1, base.data(), len, nullptr, nullptr);
        CoTaskMemFree(path);
    } else {
        base = ".";
    }
#else
    const char* home = std::getenv("HOME");
    base = home ? std::string(home) + "/Downloads" : ".";
#endif
    std::string dir = base + "/Rin Downloads";
    std::filesystem::create_directories(dir);
    return dir;
}

bool FileTransferEngine::send_file(const std::string& local_path, const TrustedDevice& target,
                                    const MeshIdentity& identity,
                                    std::function<void(float, int64_t, int64_t)> on_progress) {
    if (!target.ip_address.has_value()) {
        MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::PacketRouting,
                                          "File send aborted: target has no IP", target.name);
        return false;
    }

    std::ifstream f(local_path, std::ios::binary | std::ios::ate);
    if (!f) {
        MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::PacketRouting,
                                          "File send aborted: cannot open " + local_path);
        return false;
    }
    int64_t total_size = f.tellg();
    f.seekg(0);

    std::string file_name = std::filesystem::path(local_path).filename().string();
    std::string mime = mime_from_extension(local_path);
    std::string file_id = CryptoEngine::generate_ephemeral_token();  // unique per transfer
    int total_chunks = static_cast<int>((total_size + kFileChunkBytes - 1) / kFileChunkBytes);
    if (total_chunks == 0) total_chunks = 1;

    // Derive encryption key: ECDH peer session if we have the target's key,
    // mesh broadcast key otherwise -- matches Android's sendUri() logic.
    std::array<uint8_t, 32> enc_key;
    try {
        enc_key = CryptoEngine::derive_peer_session_key(identity.local_private_key, target.public_key);
    } catch (...) {
        enc_key = CryptoEngine::derive_mesh_encryption_key(identity.mesh_secret, identity.mesh_name);
    }

    // Compute SHA-256 before chunking so the receiver can verify on FILE_COMPLETE.
    std::string checksum = sha256_hex(local_path);
    f.seekg(0);

    // FILE_START
    FileTransferMetadata meta;
    meta.file_id = file_id;
    meta.file_name = file_name;
    meta.file_size = total_size;
    meta.mime_type = mime;
    meta.total_chunks = total_chunks;
    meta.chunk_size = kFileChunkBytes;
    meta.sha256_checksum = checksum;

    std::string meta_json = meta.to_json();
    std::string enc_meta = CryptoEngine::encrypt_payload(meta_json, enc_key);
    std::string sig_meta = CryptoEngine::sign(enc_meta, identity.local_private_key);

    MeshPacket start_packet;
    start_packet.session_id = CryptoEngine::generate_session_id();
    start_packet.sequence = sequence_.fetch_add(1);
    start_packet.type = PacketType::FileStart;
    start_packet.sender_key = identity.local_public_key;
    start_packet.sender_name = identity.local_device_name;
    start_packet.target_key = target.public_key;
    start_packet.payload = enc_meta;
    start_packet.signature = sig_meta;
    start_packet.rail = TransportRail::Lan;
    start_packet.timestamp_ms = now_ms();

    if (!send_packet_(*target.ip_address, target.port, start_packet).has_value()) {
        MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::PacketRouting,
                                          "FILE_START failed to reach " + target.name + " -- aborting transfer",
                                          target.name);
        return false;
    }

    // FILE_CHUNKs
    std::string session_id = start_packet.session_id;
    int64_t bytes_sent = 0;
    std::vector<char> chunk_buf(kFileChunkBytes);

    for (int chunk_idx = 0; chunk_idx < total_chunks; ++chunk_idx) {
        f.read(chunk_buf.data(), kFileChunkBytes);
        auto bytes_read = f.gcount();
        if (bytes_read <= 0) break;

        // Encode raw chunk bytes as base64 before JSON-wrapping.
        std::vector<uint8_t> raw(chunk_buf.begin(), chunk_buf.begin() + bytes_read);
        std::string chunk_b64 = base64_encode(raw);

        FileChunkPayload chunk_payload;
        chunk_payload.file_id = file_id;
        chunk_payload.chunk_index = chunk_idx;
        chunk_payload.total_chunks = total_chunks;
        chunk_payload.data_base64 = chunk_b64;

        std::string chunk_json = chunk_payload.to_json();
        std::string enc_chunk = CryptoEngine::encrypt_payload(chunk_json, enc_key);
        std::string sig_chunk = CryptoEngine::sign(enc_chunk, identity.local_private_key);

        MeshPacket chunk_packet;
        chunk_packet.session_id = session_id;
        chunk_packet.sequence = sequence_.fetch_add(1);
        chunk_packet.type = PacketType::FileChunk;
        chunk_packet.sender_key = identity.local_public_key;
        chunk_packet.sender_name = identity.local_device_name;
        chunk_packet.target_key = target.public_key;
        chunk_packet.payload = enc_chunk;
        chunk_packet.signature = sig_chunk;
        chunk_packet.rail = TransportRail::Lan;
        chunk_packet.timestamp_ms = now_ms();

        if (!send_packet_(*target.ip_address, target.port, chunk_packet).has_value()) {
            MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::PacketRouting,
                                              "FILE_CHUNK " + std::to_string(chunk_idx) + "/" +
                                                  std::to_string(total_chunks) + " failed -- aborting",
                                              target.name);
            return false;
        }

        bytes_sent += bytes_read;
        if (on_progress) {
            on_progress(static_cast<float>(bytes_sent) / static_cast<float>(total_size),
                        bytes_sent, total_size);
        }
    }

    // FILE_COMPLETE
    std::string complete_json = "{\"fileId\":\"" + file_id + "\",\"checksum\":\"" + checksum + "\"}";
    std::string enc_complete = CryptoEngine::encrypt_payload(complete_json, enc_key);
    std::string sig_complete = CryptoEngine::sign(enc_complete, identity.local_private_key);

    MeshPacket complete_packet;
    complete_packet.session_id = session_id;
    complete_packet.sequence = sequence_.fetch_add(1);
    complete_packet.type = PacketType::FileComplete;
    complete_packet.sender_key = identity.local_public_key;
    complete_packet.sender_name = identity.local_device_name;
    complete_packet.target_key = target.public_key;
    complete_packet.payload = enc_complete;
    complete_packet.signature = sig_complete;
    complete_packet.rail = TransportRail::Lan;
    complete_packet.timestamp_ms = now_ms();

    send_packet_(*target.ip_address, target.port, complete_packet);

    MeshAuditLogger::instance().log(AuditLevel::Info, AuditCategory::PacketRouting,
                                      "Sent file \"" + file_name + "\" (" +
                                          std::to_string(total_size) + " bytes, " +
                                          std::to_string(total_chunks) + " chunks) to " + target.name,
                                      target.name);
    return true;
}

void FileTransferEngine::handle_file_start(const std::string& plain_json,
                                            const std::string& sender_key,
                                            const std::string& sender_name) {
    auto meta = FileTransferMetadata::from_json(plain_json);
    if (!meta.has_value()) {
        MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::PacketRouting,
                                          "FILE_START: malformed metadata JSON -- transfer ignored",
                                          sender_name);
        return;
    }

    // Temp file alongside the real destination; renamed on FILE_COMPLETE.
    std::string temp_path = downloads_directory() + "/.rin_recv_" + meta->file_id + ".tmp";

    auto receive = std::make_shared<InFlightReceive>();
    receive->metadata = *meta;
    receive->sender_key = sender_key;
    receive->sender_name = sender_name;
    receive->temp_path = temp_path;

    // Pre-allocate: on platforms/filesystems that support sparse files this
    // is near-instant; on others it takes a moment -- still better than
    // having resize events mid-transfer interleave with chunk writes.
    try {
        std::ofstream pre(temp_path, std::ios::binary);
        if (meta->file_size > 0) {
            pre.seekp(meta->file_size - 1);
            pre.write("", 1);
        }
    } catch (...) { /* non-fatal: write will still work */ }

    {
        std::lock_guard<std::mutex> lk(in_flight_mutex_);
        in_flight_[meta->file_id] = receive;
    }

    MeshAuditLogger::instance().log(AuditLevel::Info, AuditCategory::PacketRouting,
                                      "Receiving file \"" + meta->file_name + "\" (" +
                                          std::to_string(meta->file_size) + " bytes, " +
                                          std::to_string(meta->total_chunks) + " chunks) from " + sender_name,
                                      sender_name);
}

void FileTransferEngine::handle_file_chunk(const std::string& plain_json,
                                            const std::string& sender_key) {
    auto chunk = FileChunkPayload::from_json(plain_json);
    if (!chunk.has_value()) return;

    std::shared_ptr<InFlightReceive> receive;
    {
        std::lock_guard<std::mutex> lk(in_flight_mutex_);
        auto it = in_flight_.find(chunk->file_id);
        if (it == in_flight_.end()) return;  // FILE_START was never received -- drop silently
        receive = it->second;
    }

    std::vector<uint8_t> raw_bytes = base64_decode(chunk->data_base64);
    int64_t offset = static_cast<int64_t>(chunk->chunk_index) * kFileChunkBytes;

    try {
        // RandomAccessFile equivalent: open for writing, seek, write chunk.
        std::fstream f(receive->temp_path, std::ios::binary | std::ios::in | std::ios::out);
        f.seekp(offset);
        f.write(reinterpret_cast<const char*>(raw_bytes.data()), static_cast<std::streamsize>(raw_bytes.size()));

        std::lock_guard<std::mutex> lk(receive->chunk_mutex);
        receive->received_chunks[chunk->chunk_index] = true;
    } catch (const std::exception& e) {
        MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::PacketRouting,
                                          "Chunk write failed for file " + chunk->file_id + ": " + e.what());
    }
}

void FileTransferEngine::handle_file_complete(const std::string& plain_json,
                                               const std::string& sender_name) {
    std::string file_id;
    std::string expected_checksum;
    try {
        auto j = nlohmann::json::parse(plain_json);
        file_id = j.value("fileId", "");
        expected_checksum = j.value("checksum", "");
    } catch (...) { return; }

    std::shared_ptr<InFlightReceive> receive;
    {
        std::lock_guard<std::mutex> lk(in_flight_mutex_);
        auto it = in_flight_.find(file_id);
        if (it == in_flight_.end()) return;
        receive = it->second;
        in_flight_.erase(it);
    }

    // Check all chunks arrived.
    {
        std::lock_guard<std::mutex> lk(receive->chunk_mutex);
        if (static_cast<int>(receive->received_chunks.size()) != receive->metadata.total_chunks) {
            MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::PacketRouting,
                                              "File \"" + receive->metadata.file_name + "\" incomplete: got " +
                                                  std::to_string(receive->received_chunks.size()) + "/" +
                                                  std::to_string(receive->metadata.total_chunks) + " chunks -- discarding",
                                              sender_name);
            std::filesystem::remove(receive->temp_path);
            if (on_received_) {
                ReceivedFileRecord rec{file_id, receive->metadata.file_name,
                                       receive->metadata.file_size, receive->metadata.mime_type,
                                       sender_name, "", now_ms()};
                on_received_(rec);
            }
            return;
        }
    }

    // SHA-256 integrity check.
    if (!expected_checksum.empty()) {
        std::string actual = sha256_hex(receive->temp_path);
        if (actual != expected_checksum) {
            MeshAuditLogger::instance().log(AuditLevel::SecurityError, AuditCategory::PacketRouting,
                                              "File \"" + receive->metadata.file_name +
                                                  "\" FAILED integrity check (SHA-256 mismatch) -- discarding",
                                              sender_name);
            std::filesystem::remove(receive->temp_path);
            if (on_received_) {
                ReceivedFileRecord rec{file_id, receive->metadata.file_name,
                                       receive->metadata.file_size, receive->metadata.mime_type,
                                       sender_name, "", now_ms()};
                on_received_(rec);
            }
            return;
        }
    }

    // Move from temp to final destination. Suffix-deduplicate if name exists.
    std::string dest_dir = downloads_directory();
    std::string dest = dest_dir + "/" + receive->metadata.file_name;
    if (std::filesystem::exists(dest)) {
        auto stem = std::filesystem::path(dest).stem().string();
        auto ext = std::filesystem::path(dest).extension().string();
        dest = dest_dir + "/" + stem + "_" + file_id.substr(0, 6) + ext;
    }
    try {
        std::filesystem::rename(receive->temp_path, dest);
    } catch (...) {
        try {
            std::filesystem::copy(receive->temp_path, dest);
            std::filesystem::remove(receive->temp_path);
        } catch (const std::exception& e) {
            MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::PacketRouting,
                                              "Could not move received file to downloads: " + std::string(e.what()));
            dest = "";
        }
    }

    MeshAuditLogger::instance().log(AuditLevel::Info, AuditCategory::PacketRouting,
                                      "File \"" + receive->metadata.file_name + "\" received successfully" +
                                          (dest.empty() ? " (save failed)" : " -> " + dest),
                                      sender_name);

#ifdef _WIN32
    if (!dest.empty()) {
        // Notify the Windows shell so the file appears in Explorer/Downloads
        // immediately without needing a folder refresh.
        SHChangeNotify(SHCNE_CREATE, SHCNF_PATH, dest.c_str(), nullptr);
    }
#endif

    if (on_received_) {
        ReceivedFileRecord rec{file_id, receive->metadata.file_name,
                               receive->metadata.file_size, receive->metadata.mime_type,
                               sender_name, dest, now_ms()};
        on_received_(rec);
    }
}

}  // namespace rin
