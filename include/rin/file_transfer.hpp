#pragma once
// File transfer engine -- the Windows analogue of Android's FileTransferManager.
//
// Same chunked protocol (FILE_START -> FILE_CHUNK x N -> FILE_COMPLETE),
// same 64KB chunk size, same SHA-256 integrity verification on receive.
// Send side is a plain file path on Windows (no URI/ContentResolver).
// Receive side writes to a "Rin Downloads" folder inside the user's
// Downloads directory, matching Android's Downloads folder convention.

#include <atomic>
#include <functional>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "rin/protocol.hpp"

namespace rin {

struct MeshIdentity;
struct TrustedDevice;

static constexpr int kFileChunkBytes = 64 * 1024;  // 64 KB, matches Android

struct ReceivedFileRecord {
    std::string file_id;
    std::string file_name;
    int64_t file_size = 0;
    std::string mime_type;
    std::string sender_name;
    std::string local_file_path;
    int64_t received_timestamp_ms = 0;
};

// Callback invoked once per completed receive. If the transfer failed
// integrity verification, the record still arrives (so the UI can show
// the failure) but local_file_path will be empty.
using FileReceivedCallback = std::function<void(const ReceivedFileRecord&)>;

// Callback the FileTransferEngine calls to actually send a packet -- wired
// to TcpTransport::send_packet by MeshEngine at construction time, so
// FileTransferEngine never needs to know about sockets directly.
using PacketSendFn = std::function<std::optional<int64_t>(const std::string& ip, int port,
                                                            const MeshPacket& packet)>;

class FileTransferEngine {
public:
    FileTransferEngine(FileReceivedCallback on_received, PacketSendFn send_packet);

    // -- Send side --------------------------------------------------------
    // Sends the file at local_path to one specific target peer. Calls
    // on_progress(ratio, bytes_sent, total_bytes) for each chunk, so a
    // future UI layer can show a progress bar without polling.
    // Returns false if the file can't be read or the target has no IP.
    bool send_file(const std::string& local_path, const TrustedDevice& target,
                   const MeshIdentity& identity,
                   std::function<void(float, int64_t, int64_t)> on_progress = nullptr);

    // -- Receive side (called from MeshEngine::on_packet_received) --------
    void handle_file_start(const std::string& plain_json, const std::string& sender_key,
                            const std::string& sender_name);
    void handle_file_chunk(const std::string& plain_json, const std::string& sender_key);
    void handle_file_complete(const std::string& plain_json, const std::string& sender_name);

    // Where received files land. Created on first use.
    static std::string downloads_directory();

private:
    struct InFlightReceive {
        FileTransferMetadata metadata;
        std::string sender_key;
        std::string sender_name;
        std::string temp_path;
        std::unordered_map<int, bool> received_chunks;
        mutable std::mutex chunk_mutex;
    };

    FileReceivedCallback on_received_;
    PacketSendFn send_packet_;

    mutable std::mutex in_flight_mutex_;
    std::unordered_map<std::string, std::shared_ptr<InFlightReceive>> in_flight_;

    std::atomic<int64_t> sequence_{200};
};

}  // namespace rin
