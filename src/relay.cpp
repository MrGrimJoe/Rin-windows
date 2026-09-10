#include "rin/relay.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <iostream>

#include "rin/audit_logger.hpp"

using nlohmann::json;
using asio::ip::tcp;

namespace rin {

namespace {
int64_t now_millis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Same semantics as transport.cpp's read_line, EXCEPT this overload
// takes the streambuf explicitly and expects the caller to keep reusing
// the SAME buf across every read on a given socket. That matters here in
// a way it never did for TcpTransport: TcpTransport's connections read
// exactly one line then close, so a fresh per-call streambuf was
// harmless. Every relay connection reads MORE than one line off the same
// socket (control line + packet line for a forward; an unbounded stream
// of packet lines for a registration connection) -- asio::read_until can
// and does read past the delimiter into its buffer in a single recv(),
// and a fresh streambuf per call throws that already-received data away
// the moment it goes out of scope, causing the next read_line() to block
// forever on bytes that already arrived. (This was a real bug caught by
// this file's own test hanging -- see tests/test_relay.cpp.)
std::string read_line(tcp::socket& socket, asio::streambuf& buf) {
    asio::read_until(socket, buf, '\n');
    std::istream is(&buf);
    std::string line;
    std::getline(is, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return line;
}
}  // namespace

RelayClient::RelayClient(asio::io_context& io) : io_(io) {}

RelayClient::~RelayClient() { stop(); }

void RelayClient::start(const std::string& host, int port, const std::string& own_public_key,
                         IncomingPacketHandler on_packet,
                         std::function<bool(const MeshPacket&)> verify_signature) {
    if (host.empty()) return;  // relay tier stays disabled -- nothing to do

    host_ = host;
    port_ = port;
    on_packet_ = std::move(on_packet);
    verify_signature_ = std::move(verify_signature);
    running_ = true;
    reg_thread_ = std::thread(&RelayClient::registration_loop, this, own_public_key);
}

void RelayClient::stop() {
    if (!running_.exchange(false)) return;
    {
        std::lock_guard<std::mutex> lock(socket_mutex_);
        if (current_socket_) {
            asio::error_code ec;
            // shutdown() BEFORE close(): on Linux, closing a socket fd
            // from a different thread than the one blocked in recv() on
            // it does NOT reliably unblock that recv() -- the fd number
            // can even be silently reused elsewhere, leaving the read
            // thread stuck forever (confirmed by hitting exactly this
            // hang while writing this test). shutdown(both) forces the
            // blocked read to return immediately with EOF/error, which
            // close() alone does not reliably guarantee cross-thread.
            current_socket_->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            current_socket_->close(ec);
        }
    }
    if (reg_thread_.joinable()) reg_thread_.join();
}

void RelayClient::registration_loop(std::string own_public_key) {
    // Reconnect-with-backoff: a relay is an optional convenience path,
    // not something that should spin hot or crash the app if it's
    // temporarily unreachable. Mirrors the "log and keep going" posture
    // the rest of this codebase takes toward transient network failure
    // (see StunHolePunchEngine's Android analogue / UdpBeacon's ignore-
    // malformed-packet behavior).
    while (running_) {
        try {
            auto socket = std::make_shared<tcp::socket>(io_);
            {
                std::lock_guard<std::mutex> lock(socket_mutex_);
                current_socket_ = socket;
            }
            asio::ip::tcp::resolver resolver(io_);
            asio::connect(*socket, resolver.resolve(host_, std::to_string(port_)));
            socket->set_option(asio::ip::tcp::no_delay(true));

            json reg;
            reg["op"] = "register";
            reg["key"] = own_public_key;
            std::string reg_line = reg.dump() + "\n";
            asio::write(*socket, asio::buffer(reg_line));

            MeshAuditLogger::instance().log(AuditLevel::Info, AuditCategory::Connection,
                                              "Registered with relay " + host_ + ":" +
                                                  std::to_string(port_));

            // Idle-read loop: the relay pushes forwarded packet lines to
            // this same connection whenever another peer sends `us` a
            // message via forward. Each line is a complete MeshPacket,
            // verified exactly like a direct incoming TCP connection
            // before being handed to on_packet_. stop() closing the
            // socket out from under this blocking read is what lets
            // shutdown actually terminate this thread. ONE streambuf is
            // reused across every iteration -- see read_line's comment
            // above for why a fresh one per call would drop data.
            asio::streambuf buf;
            while (running_) {
                std::string line = read_line(*socket, buf);
                if (line.empty()) continue;

                auto packet_opt = packet_from_wire_json(line);
                if (!packet_opt.has_value()) continue;  // malformed -- drop, mirrors TcpTransport

                const MeshPacket& packet = *packet_opt;
                if (verify_signature_ && !verify_signature_(packet)) {
                    std::cerr << "[RelayClient] signature verification FAILED for sender: "
                              << packet.sender_name << "\n";
                    continue;
                }
                // Relay-delivered packets have no direct remote address
                // to reply on (they arrived via the relay server, not a
                // direct connection) -- pass an empty remote_ip, matching
                // Android's relay path. This matters for the discovery
                // challenge/response handshake, which needs a real
                // address to open a reply connection on; see
                // MeshEngine::handle_discovery_challenge.
                if (on_packet_) on_packet_(packet, "");
            }
        } catch (const std::exception& e) {
            if (!running_) break;
            std::cerr << "[RelayClient] registration connection lost/failed: " << e.what()
                       << " -- retrying in 5s\n";
            for (int i = 0; i < 50 && running_; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }
    std::lock_guard<std::mutex> lock(socket_mutex_);
    current_socket_.reset();
}

std::optional<int64_t> RelayClient::send_via_relay(const std::string& target_public_key,
                                                     const MeshPacket& packet) {
    if (!is_configured()) return std::nullopt;

    const int64_t start = now_millis();
    try {
        tcp::socket socket(io_);
        asio::ip::tcp::resolver resolver(io_);
        asio::connect(socket, resolver.resolve(host_, std::to_string(port_)));
        socket.set_option(asio::ip::tcp::no_delay(true));

        json fwd;
        fwd["op"] = "forward";
        fwd["target"] = target_public_key;
        std::string fwd_line = fwd.dump() + "\n";
        asio::write(socket, asio::buffer(fwd_line));

        std::string packet_line = packet_to_wire_json(packet) + "\n";
        asio::write(socket, asio::buffer(packet_line));

        asio::streambuf reply_buf;
        std::string reply = read_line(socket, reply_buf);
        if (reply == "OK") {
            const int64_t elapsed = now_millis() - start;
            return elapsed < 1 ? 1 : elapsed;
        }
        std::cerr << "[RelayClient] relay declined forward to " << target_public_key.substr(0, 12)
                   << "...: " << reply << "\n";
        return std::nullopt;
    } catch (const std::exception& e) {
        std::cerr << "[RelayClient] send_via_relay to " << host_ << ":" << port_
                   << " failed: " << e.what() << "\n";
        return std::nullopt;
    }
}

}  // namespace rin
