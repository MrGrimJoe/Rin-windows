// File transfer tests.
//
// These test the chunking/reassembly/checksum logic in isolation from
// a live network. The "transport" here is a direct in-process call
// between a sender-side FileTransferEngine and a receiver-side one --
// no sockets, no TCP, just verifying the protocol correctness and
// integrity guarantees that would matter over a real connection.

#include "rin/file_transfer.hpp"
#include "rin/mesh_engine.hpp"
#include "rin/crypto.hpp"

#include <asio.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

using namespace rin;
namespace fs = std::filesystem;

namespace {
int g_failures = 0;

void check(bool condition, const std::string& name) {
    if (condition) {
        std::cout << "  [PASS] " << name << "\n";
    } else {
        std::cout << "  [FAIL] " << name << "\n";
        g_failures++;
    }
}

// Write a temp file with `size` bytes of deterministic content.
std::string write_test_file(const std::string& name, size_t size) {
    std::string path = (fs::temp_directory_path() / name).string();
    std::ofstream f(path, std::ios::binary);
    for (size_t i = 0; i < size; ++i) {
        f.put(static_cast<char>(i % 251));  // deterministic, not random -- test reproducibility
    }
    return path;
}

// Read a file's contents into a string.
std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f), {});
}
}  // namespace

void run_file_transfer_tests() {
    std::cout << "\n== File transfer tests ==\n";

    // Build a minimal MeshIdentity with a real keypair for signing.
    KeyPair keys = CryptoEngine::generate_identity_keypair();
    MeshIdentity identity;
    identity.mesh_name = "File Test Mesh";
    identity.local_device_name = "Sender PC";
    identity.local_public_key = keys.public_key_b64;
    identity.local_private_key = keys.private_key_b64;
    identity.mesh_secret = CryptoEngine::generate_ephemeral_secret();
    identity.port = 45990;

    // Receiver keypair (simulates the phone).
    KeyPair recv_keys = CryptoEngine::generate_identity_keypair();
    TrustedDevice target;
    target.public_key = recv_keys.public_key_b64;
    target.name = "Receiver Phone";
    target.platform = PlatformType::Android;
    target.ip_address = "192.168.1.99";
    target.port = 45990;

    // -- Round-trip: send + receive in-process, no network ---------------
    // We wire sender -> receiver by having the PacketSendFn hand packets
    // directly to the receiver's handle_* methods, bypassing TCP entirely.
    // This tests the chunking/reassembly/crypto logic, not socket I/O.
    {
        std::string test_file = write_test_file("rin_ft_test_small.bin", 256 * 1024);  // 256 KB

        std::string received_path;
        bool received_called = false;

        // Receiver engine: uses mesh key since it doesn't have the sender's
        // private key for ECDH (real device wouldn't either unless it was
        // already in the mesh). We'll use mesh key on both sides for this test.
        FileTransferEngine receiver(
            [&](const ReceivedFileRecord& rec) {
                received_path = rec.local_file_path;
                received_called = true;
            },
            [](const std::string&, int, const MeshPacket&) -> std::optional<int64_t> {
                return std::nullopt;  // receiver never needs to send
            });

        // Sender engine: intercepts each outgoing packet and routes it
        // directly to the receiver's handlers after decrypting the payload.
        // This is a white-box test of the protocol framing, not transport.
        std::array<uint8_t, 32> mesh_key =
            CryptoEngine::derive_mesh_encryption_key(identity.mesh_secret, identity.mesh_name);

        FileTransferEngine sender(
            [](const ReceivedFileRecord&) {},
            [&](const std::string&, int, const MeshPacket& packet) -> std::optional<int64_t> {
                // Verify sig, decrypt, route to receiver.
                if (!CryptoEngine::verify(packet.payload, packet.signature, packet.sender_key)) {
                    return std::nullopt;  // bad signature -- packet dropped
                }
                std::string plain = CryptoEngine::decrypt_payload(packet.payload, mesh_key);
                switch (packet.type) {
                    case PacketType::FileStart:
                        receiver.handle_file_start(plain, packet.sender_key, packet.sender_name);
                        break;
                    case PacketType::FileChunk:
                        receiver.handle_file_chunk(plain, packet.sender_key);
                        break;
                    case PacketType::FileComplete:
                        receiver.handle_file_complete(plain, packet.sender_name);
                        break;
                    default: break;
                }
                return int64_t{1};  // fake 1ms latency
            });

        // Override target's public key to match sender's identity for
        // mesh-key encryption (ECDH would need the sender's private key
        // to derive, but for this test both sides use mesh key).
        // Easiest way: give the target a public key that can't be used for
        // ECDH with the sender's private key -- the send_file code will
        // fall back to the mesh key on the ECDH derivation failure.
        TrustedDevice bad_ecdh_target = target;
        bad_ecdh_target.public_key = "not_a_real_key_so_ecdh_fails";

        float last_progress = 0.0f;
        int progress_calls = 0;
        bool sent = sender.send_file(test_file, bad_ecdh_target, identity,
                                      [&](float ratio, int64_t, int64_t) {
                                          last_progress = ratio;
                                          progress_calls++;
                                      });

        check(sent, "send_file() returns true on successful transfer");
        check(received_called, "FileReceivedCallback is invoked when a transfer completes");
        check(!received_path.empty(), "received file has a non-empty path (was saved successfully)");
        check(progress_calls > 0, "progress callback is called at least once per chunk");
        check(last_progress >= 0.99f, "final progress value is ~1.0 (100%)");

        if (!received_path.empty() && fs::exists(received_path)) {
            std::string original = read_file(test_file);
            std::string received = read_file(received_path);
            check(original == received, "received file content is byte-for-byte identical to the original");
            fs::remove(received_path);
        }

        fs::remove(test_file);
    }

    // -- Integrity check: tampered chunk is rejected ----------------------
    {
        std::string test_file = write_test_file("rin_ft_test_tamper.bin", 32 * 1024);

        bool integrity_failed = false;
        FileTransferEngine receiver(
            [&](const ReceivedFileRecord& rec) {
                integrity_failed = rec.local_file_path.empty();
            },
            [](const std::string&, int, const MeshPacket&) -> std::optional<int64_t> {
                return std::nullopt;
            });

        std::array<uint8_t, 32> mesh_key =
            CryptoEngine::derive_mesh_encryption_key("tamper_test_secret", "tamper_test_mesh");

        // Manually build and send a FILE_START, then a tampered FILE_COMPLETE
        // that claims a different SHA-256 than the actual content.
        FileTransferMetadata meta;
        meta.file_id = "tamper_test_id";
        meta.file_name = "tamper.bin";
        meta.file_size = 32 * 1024;
        meta.total_chunks = 1;
        meta.chunk_size = 32 * 1024;
        meta.sha256_checksum = "0000000000000000000000000000000000000000000000000000000000000000";

        receiver.handle_file_start(meta.to_json(), keys.public_key_b64, "Attacker");

        // Write a real chunk so the reassembly count is satisfied.
        std::string chunk_data(32 * 1024, 'X');
        std::vector<uint8_t> raw(chunk_data.begin(), chunk_data.end());
        FileChunkPayload chunk;
        chunk.file_id = "tamper_test_id";
        chunk.chunk_index = 0;
        chunk.total_chunks = 1;
        chunk.data_base64 = base64_encode(raw);
        receiver.handle_file_chunk(chunk.to_json(), keys.public_key_b64);

        // FILE_COMPLETE with the deliberately wrong checksum.
        receiver.handle_file_complete(
            "{\"fileId\":\"tamper_test_id\",\"checksum\":\"0000000000000000000000000000000000000000000000000000000000000000\"}",
            "Attacker");

        check(integrity_failed, "a tampered/incorrect SHA-256 checksum causes the transfer to be rejected (file not saved)");

        fs::remove(test_file);
    }

    // -- Downloads directory is created and writable ----------------------
    {
        std::string dir = FileTransferEngine::downloads_directory();
        check(!dir.empty(), "downloads_directory() returns a non-empty path");
        check(fs::exists(dir), "downloads_directory() path exists after the call");
        check(fs::is_directory(dir), "downloads_directory() path is a directory");

        // Actually write a file there to confirm it's writable.
        std::string probe = dir + "/rin_write_probe.tmp";
        { std::ofstream f(probe); f << "ok"; }
        check(fs::exists(probe), "downloads directory is writable");
        fs::remove(probe);
    }

    std::cout << (g_failures == 0 ? "All file transfer tests passed.\n" : "SOME FILE TRANSFER TESTS FAILED.\n");
}

int g_file_transfer_test_failures() { return g_failures; }
