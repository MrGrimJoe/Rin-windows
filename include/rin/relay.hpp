#pragma once
// Optional relay fallback transport.
//
// NEW in this pass. Nothing here changes existing LAN/UDP behavior --
// this is purely additive: an opt-in extra tier that MeshEngine tries
// only after a direct TcpTransport::send_packet() attempt has already
// failed (see MeshEngine::send_with_fallback in mesh_engine.cpp).
//
// Why this exists: with no relay, two devices that aren't on the same
// LAN/subnet (e.g. different home networks, one on cellular) have no
// path to each other at all on the Windows side today. A relay is the
// same "fallback of last resort" role Apple's iCloud/APNs relay plays
// for Continuity/AirDrop when direct P2P isn't possible -- except this
// one is self-hostable: point RIN_RELAY_HOST/RIN_RELAY_PORT (or the
// console's `relay <host> <port>` command) at any machine running
// rin_relay, including one you run yourself. There is no default/
// built-in relay server and none is required -- if never configured,
// this code path is simply never exercised and behavior is identical
// to before.
//
// Trust model: the relay is a dumb forwarder. It never sees plaintext
// payload (that's still AES-256-GCM ciphertext end-to-end, unchanged),
// only the same metadata (sender_key, sender_name, target_key, rail,
// timestamps) that was already visible to anyone on the LAN via the
// existing UDP beacon/TCP envelope. Running your own relay means you
// don't have to trust anyone else's server with even that much.
//
// Wire format (relay <-> client only; never touches the Android/Windows
// MeshPacket wire format, which travels unmodified as the payload of a
// forward request):
//   Register (long-lived, lets others reach you):
//     {"op":"register","key":"<base64 public key>"}\n
//   Forward (one-shot, asks the relay to deliver one packet):
//     {"op":"forward","target":"<base64 public key>"}\n
//     <packet_to_wire_json(...) line>\n
//   Relay's reply to a forward request:
//     "OK\n"                    -- delivered to a registered target
//     "ERR <reason>\n"          -- target not registered / write failed

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#include <asio.hpp>

#include "rin/protocol.hpp"
#include "rin/transport.hpp"  // for IncomingPacketHandler

namespace rin {

class RelayClient {
public:
    explicit RelayClient(asio::io_context& io);
    ~RelayClient();

    // Configures and starts the persistent registration connection that
    // lets OTHER peers reach us through this relay. A no-op (and
    // is_configured() stays false) if host is empty -- this is how the
    // relay tier stays fully opt-in.
    void start(const std::string& host, int port, const std::string& own_public_key,
               IncomingPacketHandler on_packet,
               std::function<bool(const MeshPacket&)> verify_signature);
    void stop();

    bool is_configured() const { return !host_.empty(); }
    const std::string& host() const { return host_; }
    int port() const { return port_; }

    // One-shot: opens a short connection to the relay and asks it to
    // forward `packet` to `target_public_key`. Returns elapsed
    // round-trip ms on a confirmed delivery ("OK"), or nullopt on any
    // failure -- same contract as TcpTransport::send_packet, so callers
    // can treat both tiers identically.
    std::optional<int64_t> send_via_relay(const std::string& target_public_key,
                                           const MeshPacket& packet);

private:
    void registration_loop(std::string own_public_key);

    asio::io_context& io_;
    std::string host_;
    int port_ = 0;
    std::atomic<bool> running_{false};
    std::thread reg_thread_;
    IncomingPacketHandler on_packet_;
    std::function<bool(const MeshPacket&)> verify_signature_;

    // The registration_loop's socket, so stop() can force-close it to
    // unblock a thread that's sitting in a blocking read_line() call --
    // without this, stop() would join a thread that can never wake up
    // on its own (nothing else ever arrives on an idle registration
    // connection). Guarded by socket_mutex_ since it's written from
    // registration_loop's thread and read from stop()'s (the caller's).
    std::mutex socket_mutex_;
    std::shared_ptr<asio::ip::tcp::socket> current_socket_;
};

}  // namespace rin
