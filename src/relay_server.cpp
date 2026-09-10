// rin_relay: minimal reference relay server for Rin's opt-in relay
// fallback tier (see include/rin/relay.hpp for the client side and the
// full rationale).
//
// This is a dumb forwarder, on purpose: it never touches the encrypted
// packet payload, only reads two small control lines to decide where to
// forward the (already end-to-end encrypted) packet line that follows.
// It is a REFERENCE implementation for anyone who wants to self-host a
// relay -- it has no TLS, no authentication beyond "you know a public
// key", and no rate limiting. Treat it the way you'd treat any small
// personal server: fine on a LAN or a box you control, not something to
// expose to the open internet without hardening first (see the loud
// comment block below).
//
// Protocol (newline-delimited JSON control lines, see relay.hpp):
//   {"op":"register","key":"<b64 pubkey>"}         -- long-lived
//   {"op":"forward","target":"<b64 pubkey>"}        -- one-shot,
//     followed by exactly one more line: the packet to deliver.
//
// Usage: rin_relay [port]   (default port 45992)

#include <atomic>
#include <csignal>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include <asio.hpp>
#include <nlohmann/json.hpp>

using asio::ip::tcp;
using nlohmann::json;

namespace {

constexpr int kDefaultRelayPort = 45992;

std::string read_line(tcp::socket& socket, asio::streambuf& buf) {
    asio::read_until(socket, buf, '\n');
    std::istream is(&buf);
    std::string line;
    std::getline(is, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return line;
}

// SECURITY NOTE: this map trusts whatever public key a client claims in
// its "register" line -- there is no proof-of-possession challenge here
// (that lives one layer up, in the ECDSA-signed MeshPacket itself, which
// this relay never inspects). A malicious client could register someone
// else's public key and receive traffic meant for them. That's an
// acceptable posture for "a relay you run yourself for your own mesh",
// same trust boundary as a Wi-Fi router forwarding your packets -- it is
// NOT acceptable for a relay shared across untrusted parties without
// adding real client authentication first. Documented here rather than
// silently shipped as if it were a solved problem.
class RelayRegistry {
public:
    void register_peer(const std::string& key, std::shared_ptr<tcp::socket> socket) {
        std::lock_guard<std::mutex> lock(mutex_);
        peers_[key] = std::move(socket);
    }

    void unregister_peer(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        peers_.erase(key);
    }

    // Returns true if the write to the target's registered socket
    // succeeded (i.e. the target is currently registered and reachable).
    bool forward_to(const std::string& target_key, const std::string& packet_line) {
        std::shared_ptr<tcp::socket> target_socket;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = peers_.find(target_key);
            if (it == peers_.end()) return false;
            target_socket = it->second;
        }
        try {
            asio::write(*target_socket, asio::buffer(packet_line));
            return true;
        } catch (const std::exception&) {
            unregister_peer(target_key);
            return false;
        }
    }

private:
    std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<tcp::socket>> peers_;
};

void handle_connection(std::shared_ptr<tcp::socket> socket, RelayRegistry& registry) {
    std::string registered_key;
    // ONE streambuf per connection, reused across every read_line() call
    // on it -- required whenever more than one line is read off the same
    // socket (the forward path reads control-line-then-packet-line). See
    // relay.cpp's read_line comment for the full "why" -- a fresh
    // streambuf per call silently drops already-received bytes and hangs
    // the next read.
    asio::streambuf buf;
    try {
        socket->set_option(asio::ip::tcp::no_delay(true));
        std::string control_line = read_line(*socket, buf);
        if (control_line.empty()) return;

        json control = json::parse(control_line, /*cb=*/nullptr, /*allow_exceptions=*/false);
        if (control.is_discarded()) return;

        std::string op = control.value("op", "");
        if (op == "register") {
            registered_key = control.value("key", "");
            if (registered_key.empty()) return;
            registry.register_peer(registered_key, socket);
            std::cout << "[rin_relay] registered " << registered_key.substr(0, 12) << "...\n";

            // Keep this connection open and idle so the registry entry
            // stays valid; detect disconnect via a blocking read that
            // will throw/return-empty once the peer goes away.
            while (true) {
                asio::streambuf discard;
                asio::error_code ec;
                asio::read(*socket, discard, asio::transfer_at_least(1), ec);
                if (ec) break;
            }
        } else if (op == "forward") {
            std::string target = control.value("target", "");
            std::string packet_line = read_line(*socket, buf);
            if (target.empty() || packet_line.empty()) {
                asio::write(*socket, asio::buffer(std::string("ERR malformed forward request\n")));
                return;
            }
            bool delivered = registry.forward_to(target, packet_line + "\n");
            std::string reply = delivered ? "OK\n" : "ERR no such peer\n";
            asio::write(*socket, asio::buffer(reply));
        } else {
            asio::write(*socket, asio::buffer(std::string("ERR unknown op\n")));
        }
    } catch (const std::exception& e) {
        std::cerr << "[rin_relay] connection error: " << e.what() << "\n";
    }

    if (!registered_key.empty()) {
        registry.unregister_peer(registered_key);
        std::cout << "[rin_relay] unregistered " << registered_key.substr(0, 12) << "...\n";
    }
}

}  // namespace

int main(int argc, char** argv) {
    int port = kDefaultRelayPort;
    if (argc > 1) {
        try {
            port = std::stoi(argv[1]);
        } catch (const std::exception&) {
            std::cerr << "Usage: rin_relay [port]\n";
            return 1;
        }
    }

    RelayRegistry registry;

    try {
        asio::io_context io;
        tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), static_cast<unsigned short>(port)));
        std::cout << "[rin_relay] listening on port " << port
                   << " -- reference relay, self-host only, see relay_server.cpp for the trust\n"
                   << "[rin_relay] model before exposing this to anything but your own devices.\n";

        while (true) {
            auto socket = std::make_shared<tcp::socket>(io);
            acceptor.accept(*socket);
            std::thread(handle_connection, socket, std::ref(registry)).detach();
        }
    } catch (const std::exception& e) {
        std::cerr << "[rin_relay] fatal: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
