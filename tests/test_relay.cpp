// Relay fallback tier tests.
//
// Unlike test_crypto/test_protocol/etc., this test actually spins up a
// real RelayRegistry-equivalent server loop and two RelayClients talking
// to it over real loopback TCP sockets -- it's the one place in this
// suite that behaves like a small integration test rather than a pure
// unit test, because "does a packet actually get from A to B through a
// third process" isn't something a pure logic test can prove.

#include "rin/relay.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>
#include <unordered_map>

#include <asio.hpp>
#include <nlohmann/json.hpp>

#ifndef _WIN32
#include <sys/socket.h>  // for ::shutdown() on the acceptor's native handle
#endif

using namespace rin;
using asio::ip::tcp;
using nlohmann::json;

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

// Minimal standalone re-implementation of rin_relay's forwarding logic,
// scoped to this test so it doesn't depend on linking the relay_server.cpp
// executable's main()/registry as a library. Deliberately mirrors
// src/relay_server.cpp's protocol handling exactly -- if that file's
// wire behavior changes, this test should be updated to match (and would
// then likely fail, which is the point).
std::string read_line(tcp::socket& socket, asio::streambuf& buf) {
    asio::read_until(socket, buf, '\n');
    std::istream is(&buf);
    std::string line;
    std::getline(is, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return line;
}

class TestRelayServer {
public:
    explicit TestRelayServer(asio::io_context& io) : io_(io), acceptor_(io) {}

    int start() {
        acceptor_.open(tcp::v4());
        acceptor_.set_option(asio::socket_base::reuse_address(true));
        acceptor_.bind(tcp::endpoint(tcp::v4(), 0));  // ephemeral port
        acceptor_.listen();
        running_ = true;
        thread_ = std::thread([this] { accept_loop(); });
        return acceptor_.local_endpoint().port();
    }

    void stop() {
        if (!running_.exchange(false)) return;
        asio::error_code ec;
        // Same cross-thread close()-vs-blocked-syscall problem as
        // RelayClient::stop() (see relay.cpp), but for accept() instead
        // of recv(): closing the listening socket from this thread does
        // not reliably unblock accept_loop()'s thread sitting in a
        // blocking accept() on it. shutdown() on the listening socket's
        // native handle does reliably force that accept() to return.
        // asio's basic_socket_acceptor has no shutdown() of its own
        // (only stream sockets do), so this drops to the raw syscall.
#ifndef _WIN32
        ::shutdown(acceptor_.native_handle(), SHUT_RDWR);
#endif
        acceptor_.close(ec);
        if (thread_.joinable()) thread_.join();
    }

private:
    void accept_loop() {
        while (running_) {
            try {
                auto socket = std::make_shared<tcp::socket>(io_);
                asio::error_code ec;
                acceptor_.accept(*socket, ec);
                if (ec) {
                    if (running_) continue;
                    break;
                }
                std::thread(&TestRelayServer::handle_connection, this, socket).detach();
            } catch (const std::exception&) {
                if (!running_) break;
            }
        }
    }

    void handle_connection(std::shared_ptr<tcp::socket> socket) {
        std::string registered_key;
        asio::streambuf buf;  // reused across every read_line() on this connection
        try {
            std::string control_line = read_line(*socket, buf);
            json control = json::parse(control_line, nullptr, false);
            if (control.is_discarded()) return;

            std::string op = control.value("op", "");
            if (op == "register") {
                registered_key = control.value("key", "");
                if (registered_key.empty()) return;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    peers_[registered_key] = socket;
                }
                while (true) {
                    asio::streambuf discard;
                    asio::error_code ec;
                    asio::read(*socket, discard, asio::transfer_at_least(1), ec);
                    if (ec) break;
                }
            } else if (op == "forward") {
                std::string target = control.value("target", "");
                std::string packet_line = read_line(*socket, buf);
                std::shared_ptr<tcp::socket> target_socket;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    auto it = peers_.find(target);
                    if (it != peers_.end()) target_socket = it->second;
                }
                if (!target_socket) {
                    asio::write(*socket, asio::buffer(std::string("ERR no such peer\n")));
                    return;
                }
                asio::write(*target_socket, asio::buffer(packet_line + "\n"));
                asio::write(*socket, asio::buffer(std::string("OK\n")));
            }
        } catch (const std::exception&) {
            // connection dropped -- fine, same as production relay_server.cpp
        }
        if (!registered_key.empty()) {
            std::lock_guard<std::mutex> lock(mutex_);
            peers_.erase(registered_key);
        }
    }

    asio::io_context& io_;
    tcp::acceptor acceptor_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<tcp::socket>> peers_;
};

MeshPacket make_test_packet(const std::string& sender_key, const std::string& target_key) {
    MeshPacket p;
    p.session_id = "relay_test_session";
    p.sequence = 1;
    p.type = PacketType::Heartbeat;
    p.sender_key = sender_key;
    p.sender_name = "Relay Test Sender";
    p.target_key = target_key;
    p.payload = "test_payload_ciphertext_placeholder";
    p.signature = "ecdsa:test_signature_placeholder";
    p.rail = TransportRail::Lan;
    p.timestamp_ms = 1234567890;
    return p;
}
}  // namespace

void run_relay_tests() {
    std::cout << "\n== Relay fallback tests ==\n";

    asio::io_context io;
    TestRelayServer server(io);
    int relay_port = server.start();

    asio::io_context client_io_a;
    asio::io_context client_io_b;

    // Peer B registers with the relay so it can receive forwarded packets.
    std::mutex received_mutex;
    std::condition_variable received_cv;
    std::optional<MeshPacket> received_packet;

    RelayClient client_b(client_io_b);
    client_b.start(
        "127.0.0.1", relay_port, "peerB_public_key_placeholder",
        [&](const MeshPacket& packet, const std::string& /*remote_ip*/) {
            std::lock_guard<std::mutex> lock(received_mutex);
            received_packet = packet;
            received_cv.notify_one();
        },
        [](const MeshPacket&) { return true; });  // signature check stubbed for this test

    // Give the registration connection a moment to land server-side.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    RelayClient client_a(client_io_a);
    // client_a never registers -- it only needs send_via_relay(), matching
    // how a device with a direct route to everyone it talks to (but no
    // inbound route of its own) could still use the relay purely to send.
    check(!client_a.is_configured(), "an unconfigured RelayClient reports is_configured() == false");

    client_a.start("127.0.0.1", relay_port, "peerA_public_key_placeholder", nullptr, nullptr);
    check(client_a.is_configured(), "start() with a non-empty host makes is_configured() true");

    MeshPacket packet = make_test_packet("peerA_public_key_placeholder", "peerB_public_key_placeholder");
    auto latency = client_a.send_via_relay("peerB_public_key_placeholder", packet);
    check(latency.has_value(), "send_via_relay() to a registered peer succeeds");

    {
        std::unique_lock<std::mutex> lock(received_mutex);
        bool got_it = received_cv.wait_for(lock, std::chrono::seconds(3),
                                             [&] { return received_packet.has_value(); });
        check(got_it, "the registered peer's on_packet callback fires within 3s");
        if (got_it) {
            check(received_packet->session_id == packet.session_id,
                  "forwarded packet's session_id matches what was sent");
            check(received_packet->sender_key == packet.sender_key,
                  "forwarded packet's sender_key matches what was sent");
            check(received_packet->payload == packet.payload,
                  "forwarded packet's payload survives the relay hop unchanged "
                  "(relay never touches ciphertext)");
        }
    }

    // Forwarding to a public key that never registered must fail cleanly,
    // not hang or crash -- this is the "peer is offline / never joined
    // via this relay" case, which will be common in practice.
    MeshPacket orphan_packet = make_test_packet("peerA_public_key_placeholder", "nobody_registered_this_key");
    auto orphan_latency = client_a.send_via_relay("nobody_registered_this_key", orphan_packet);
    check(!orphan_latency.has_value(),
          "send_via_relay() to an unregistered target returns nullopt instead of hanging/crashing");

    client_a.stop();
    client_b.stop();
    server.stop();

    std::cout << (g_failures == 0 ? "All relay tests passed.\n" : "SOME RELAY TESTS FAILED.\n");
}

int g_relay_test_failures() { return g_failures; }
