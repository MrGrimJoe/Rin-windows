#pragma once
// TCP packet transport + UDP discovery beacon.
//
// MUST stay in exact wire sync with the Android side:
//   app/src/main/java/com/example/core/transport/MeshRuntimeEngine.kt
//   app/src/main/java/com/example/core/network/UdpBeaconEngine.kt
//
// TCP framing: ONE JSON object per connection, newline-terminated
// (Android uses PrintWriter.println / BufferedReader.readLine -- i.e.
// '\n', not length-prefixed, not multiple packets per connection).
// A new TCP connection is opened per outgoing packet and closed after
// the ACK is read. This is simple and slow by design in the current
// Android implementation -- match it rather than "improving" it, or the
// two sides will disagree on framing.
//
// UDP discovery: broadcast JSON on port 45991 every 6s.
//
// v2 wire format (SECURITY/PRIVACY HARDENING -- replaces the original
// v1 format that broadcast the mesh name and device name in the clear
// to anyone on the LAN; must stay byte-for-byte in lockstep with
// Android's UdpBeaconEngine.kt, which this mirrors exactly):
//   {"magic":"RIN_BEACON","v":2,"meshTag":<rotating HKDF tag, base64>,
//    "key":<sender's public key, base64>,"port":<tcp_port>,"ts":<millis>,
//    "stunIp":<optional>,"stunPort":<optional>}
//
// meshTag = CryptoEngine::derive_beacon_tag(mesh_key, time_bucket), where
//   time_bucket = unix_seconds / 300 (5-minute windows). Only a device
//   that already holds the real mesh secret can derive the same mesh_key
//   and therefore compute a matching tag -- so a passive LAN observer
//   sees an opaque, rotating blob instead of "mesh 'Family' has a device
//   named 'Ali-Phone'". The tag rotating every 5 minutes also means it
//   isn't a long-lived tracking identifier. This is a coordinated
//   BREAKING wire bump: v1 and v2 peers simply cannot discover each
//   other, by design (see DESIGN_NOTES.md "Discovery hardening").
//
// A meshTag match is a HINT ("probably our mesh"), not trust -- it does
// NOT identify a specific already-known device the way the old raw
// public key alone might suggest. The public key IS still sent in the
// clear here (unlike an earlier draft of this fix), because it's needed
// to know WHO to challenge; what changed is that a match no longer
// grants trust on its own. See MeshEngine::on_peer_discovered and the
// discovery challenge/response handshake (MeshEngine::handle_discovery_challenge
// / handle_discovery_response) for the actual trust boundary: a peer
// must prove it can encrypt/decrypt with the real mesh key, not just
// produce a matching tag guess.

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include <asio.hpp>

#include "rin/protocol.hpp"

namespace rin {

constexpr int kDefaultTcpPort = 45990;
constexpr int kUdpBeaconPort = 45991;
constexpr int kTcpPortScanAttempts = 5;
constexpr int kUdpBeaconIntervalSeconds = 6;
constexpr int kSocketTimeoutMs = 2500;
constexpr int64_t kBeaconTagWindowSeconds = 300;  // must match Android's beaconTagWindowSeconds

// A meshTag match only means "probably our mesh" -- see the wire format
// comment above. public_key is who to potentially challenge, nothing
// more; ip/port/stun_ip/stun_port are just where the beacon came from.
struct DiscoveredPeer {
    std::string mesh_tag;
    std::string public_key;
    std::string ip;             // sender's actual socket address, not wire content
    int port = kDefaultTcpPort;
    std::string stun_ip;        // empty if the sender didn't include one
    int stun_port = 0;          // 0 if the sender didn't include one
    int64_t timestamp_ms = 0;
};

// Callback invoked for every fully-received, signature-verified packet,
// along with the remote IP it arrived from (empty for relay-delivered
// packets, which have no direct socket to reply on -- see RelayClient).
// The remote IP is needed for the discovery challenge/response handshake
// (MeshEngine::handle_discovery_challenge / handle_discovery_response),
// which must open a NEW outbound connection back to the sender rather
// than replying on the same connection. Decryption/interpretation
// happens one layer up (see mesh_engine.hpp) -- this layer's job is
// strictly framing, ACKing, and signature verification, mirroring
// Android's handleIncomingConnection().
using IncomingPacketHandler = std::function<void(const MeshPacket&, const std::string& remote_ip)>;
using PeerDiscoveredHandler = std::function<void(const DiscoveredPeer&)>;

// A single node's TCP listener + outbound send path.
// This is the direct analogue of the TCP server/transmit code inside
// Android's MeshRuntimeEngine (it does not own discovery -- see
// UdpBeacon below).
class TcpTransport {
public:
    explicit TcpTransport(asio::io_context& io);
    ~TcpTransport();

    // Binds starting at kDefaultTcpPort, incrementing on EADDRINUSE up to
    // kTcpPortScanAttempts times -- matches Android's startTcpServer().
    // Returns the port actually bound.
    int start(IncomingPacketHandler on_packet,
              std::function<bool(const MeshPacket&)> verify_signature);
    void stop();

    int listening_port() const { return listening_port_; }

    // Opens a fresh connection, sends one packet, waits for the ACK line,
    // and closes. Returns elapsed round-trip latency in ms, or nullopt on
    // any failure (unreachable, timeout, refused) -- mirrors
    // transmitOverNetwork() returning null on failure rather than throwing.
    std::optional<int64_t> send_packet(const std::string& ip, int port, const MeshPacket& packet);

private:
    void accept_loop();
    void handle_connection(asio::ip::tcp::socket socket);

    asio::io_context& io_;
    asio::ip::tcp::acceptor acceptor_;
    int listening_port_ = kDefaultTcpPort;
    std::atomic<bool> running_{false};
    IncomingPacketHandler on_packet_;
    std::function<bool(const MeshPacket&)> verify_signature_;
    std::thread accept_thread_;
};

// UDP broadcast discovery beacon: listens on kUdpBeaconPort and
// periodically broadcasts this node's presence. Direct analogue of
// UdpBeaconEngine.kt.
class UdpBeacon {
public:
    explicit UdpBeacon(asio::io_context& io);
    ~UdpBeacon();

    // mesh_key is the ALREADY-DERIVED mesh AES key (CryptoEngine::derive_mesh_encryption_key's
    // output), needed to compute this device's own rotating meshTag (see
    // the v2 wire format comment above); it is never put on the wire
    // itself. stun_ip/stun_port are optional (pass empty/0 if this
    // platform has no STUN candidate -- e.g. Windows today).
    void start(const std::array<uint8_t, 32>& mesh_key, const std::string& public_key,
               int tcp_port, const std::string& stun_ip, int stun_port,
               PeerDiscoveredHandler on_peer);
    void stop();

private:
    void listen_loop();
    void broadcast_loop();

    asio::io_context& io_;
    asio::ip::udp::socket socket_;
    std::atomic<bool> running_{false};
    std::array<uint8_t, 32> mesh_key_{};
    std::string public_key_;
    int tcp_port_ = kDefaultTcpPort;
    std::string stun_ip_;
    int stun_port_ = 0;
    PeerDiscoveredHandler on_peer_;
    std::thread listen_thread_;
    std::thread broadcast_thread_;
};

}  // namespace rin
