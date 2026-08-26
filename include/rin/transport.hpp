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
// UDP discovery: broadcast JSON on port 45991 every 6s:
//   {"magic":"RIN_BEACON","mesh":<name>,"key":<pubkey>,"name":<device>,
//    "port":<tcp_port>,"ts":<millis>}

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

struct DiscoveredPeer {
    std::string mesh_name;
    std::string public_key;
    std::string device_name;
    std::string ip;
    int port = kDefaultTcpPort;
};

// Callback invoked for every fully-received, signature-verified packet.
// Decryption/interpretation happens one layer up (see mesh_engine.hpp) --
// this layer's job is strictly framing, ACKing, and signature verification,
// mirroring Android's handleIncomingConnection().
using IncomingPacketHandler = std::function<void(const MeshPacket&)>;
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

    void start(const std::string& mesh_name, const std::string& public_key,
               const std::string& device_name, int tcp_port, PeerDiscoveredHandler on_peer);
    void stop();

private:
    void listen_loop();
    void broadcast_loop();

    asio::io_context& io_;
    asio::ip::udp::socket socket_;
    std::atomic<bool> running_{false};
    std::string mesh_name_;
    std::string public_key_;
    std::string device_name_;
    int tcp_port_ = kDefaultTcpPort;
    PeerDiscoveredHandler on_peer_;
    std::thread listen_thread_;
    std::thread broadcast_thread_;
};

}  // namespace rin
