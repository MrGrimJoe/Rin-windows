#include "rin/transport.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <iostream>

using nlohmann::json;
using asio::ip::tcp;
using asio::ip::udp;

namespace rin {

namespace {
int64_t now_millis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Reads one newline-terminated line from a socket, matching Java's
// BufferedReader.readLine() semantics (strips the trailing \n, tolerates
// missing trailing \r). Throws asio::system_error on disconnect/timeout.
std::string read_line(tcp::socket& socket) {
    asio::streambuf buf;
    asio::read_until(socket, buf, '\n');
    std::istream is(&buf);
    std::string line;
    std::getline(is, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return line;
}
}  // namespace

// =======================================================================
// TcpTransport
// =======================================================================

TcpTransport::TcpTransport(asio::io_context& io)
    : io_(io), acceptor_(io) {}

TcpTransport::~TcpTransport() { stop(); }

int TcpTransport::start(IncomingPacketHandler on_packet,
                         std::function<bool(const MeshPacket&)> verify_signature) {
    on_packet_ = std::move(on_packet);
    verify_signature_ = std::move(verify_signature);
    running_ = true;

    // Port scan, matching Android's startTcpServer(): try kDefaultTcpPort,
    // then +1 up to kTcpPortScanAttempts times on bind failure.
    int port = kDefaultTcpPort;
    bool bound = false;
    for (int attempt = 0; attempt < kTcpPortScanAttempts; ++attempt) {
        try {
            tcp::endpoint endpoint(tcp::v4(), static_cast<unsigned short>(port));
            acceptor_.open(endpoint.protocol());
            acceptor_.set_option(asio::socket_base::reuse_address(true));
            acceptor_.bind(endpoint);
            acceptor_.listen();
            bound = true;
            break;
        } catch (const asio::system_error&) {
            acceptor_.close();
            port++;
        }
    }

    if (!bound) {
        throw std::runtime_error("TcpTransport::start: could not bind any port in range " +
                                  std::to_string(kDefaultTcpPort) + "-" +
                                  std::to_string(kDefaultTcpPort + kTcpPortScanAttempts - 1));
    }

    listening_port_ = port;
    accept_thread_ = std::thread([this] { accept_loop(); });
    return listening_port_;
}

void TcpTransport::stop() {
    if (!running_.exchange(false)) return;
    asio::error_code ec;
    acceptor_.close(ec);
    if (accept_thread_.joinable()) accept_thread_.join();
}

void TcpTransport::accept_loop() {
    while (running_) {
        try {
            tcp::socket socket(io_);
            asio::error_code ec;
            acceptor_.accept(socket, ec);
            if (ec) {
                if (running_) continue;  // transient; keep looping until stop() closes acceptor_
                break;
            }
            // One thread per connection, matching Android's
            // launch(Dispatchers.IO) per accepted client -- connections
            // are short-lived (one packet + one ACK) so this is fine.
            std::thread(&TcpTransport::handle_connection, this, std::move(socket)).detach();
        } catch (const std::exception& e) {
            if (running_) {
                std::cerr << "[TcpTransport] accept_loop error: " << e.what() << "\n";
            }
        }
    }
}

void TcpTransport::handle_connection(tcp::socket socket) {
    try {
        socket.set_option(asio::ip::tcp::no_delay(true));

        std::string line = read_line(socket);
        if (line.empty()) return;

        auto packet_opt = packet_from_wire_json(line);
        if (!packet_opt.has_value()) return;  // malformed -- silently drop, mirrors Android

        const MeshPacket& packet = *packet_opt;

        // Signature verification happens BEFORE anything else, exactly
        // like Android's handleIncomingConnection -- an unsigned or
        // forged packet gets zero further processing.
        if (!verify_signature_(packet)) {
            std::cerr << "[TcpTransport] signature verification FAILED for sender: "
                      << packet.sender_name << "\n";
            return;
        }

        // Send ACK immediately after verification, before decrypt/dispatch --
        // matches Android sending the ACK before processIncomingPacket().
        json ack;
        ack["type"] = "ACK";
        ack["seq"] = packet.sequence;
        ack["ts"] = now_millis();
        std::string ack_line = ack.dump() + "\n";
        asio::write(socket, asio::buffer(ack_line));

        if (on_packet_) on_packet_(packet);
    } catch (const std::exception& e) {
        std::cerr << "[TcpTransport] failed to handle incoming packet: " << e.what() << "\n";
    }
}

std::optional<int64_t> TcpTransport::send_packet(const std::string& ip, int port,
                                                   const MeshPacket& packet) {
    if (ip.empty() || ip == "127.0.0.1") return std::nullopt;

    // Uses a private, single-use io_context rather than the shared io_ --
    // io_ is being run concurrently by accept_loop()/UdpBeacon on other
    // threads, and driving the same io_context's run_for() from multiple
    // threads for unrelated operations is a recipe for one call silently
    // completing another's work (or racing shutdown). One-shot local
    // context per outgoing send keeps this call fully self-contained,
    // matching the "new Socket per send" model Android already uses.
    auto start = std::chrono::steady_clock::now();
    try {
        asio::io_context local_io;
        tcp::socket socket(local_io);
        asio::ip::address addr = asio::ip::make_address(ip);
        tcp::endpoint endpoint(addr, static_cast<unsigned short>(port));

        // Connect with a manual timeout since plain asio::connect blocks
        // indefinitely -- matches Android's Socket().connect(addr, 2500).
        asio::error_code connect_ec = asio::error::would_block;
        socket.async_connect(endpoint, [&](const asio::error_code& ec) { connect_ec = ec; });
        local_io.run_for(std::chrono::milliseconds(kSocketTimeoutMs));

        if (connect_ec == asio::error::would_block || connect_ec) {
            return std::nullopt;  // timed out or refused
        }

        std::string line = packet_to_wire_json(packet) + "\n";
        asio::write(socket, asio::buffer(line));

        // Await ACK with the same timeout budget, on the same local context.
        asio::streambuf buf;
        asio::error_code read_ec;
        std::size_t bytes = 0;

        local_io.restart();
        asio::async_read_until(socket, buf, '\n',
                                [&](const asio::error_code& ec, std::size_t n) {
                                    read_ec = ec;
                                    bytes = n;
                                });
        local_io.run_for(std::chrono::milliseconds(kSocketTimeoutMs));

        asio::error_code close_ec;
        socket.close(close_ec);

        if (read_ec || bytes == 0) return std::nullopt;

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();
        return std::max<int64_t>(1, elapsed);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// =======================================================================
// UdpBeacon
// =======================================================================

UdpBeacon::UdpBeacon(asio::io_context& io) : io_(io), socket_(io) {}

UdpBeacon::~UdpBeacon() { stop(); }

void UdpBeacon::start(const std::string& mesh_name, const std::string& public_key,
                       const std::string& device_name, int tcp_port,
                       PeerDiscoveredHandler on_peer) {
    mesh_name_ = mesh_name;
    public_key_ = public_key;
    device_name_ = device_name;
    tcp_port_ = tcp_port;
    on_peer_ = std::move(on_peer);
    running_ = true;

    asio::error_code ec;
    socket_.open(udp::v4(), ec);
    socket_.set_option(asio::socket_base::reuse_address(true), ec);
    socket_.set_option(asio::socket_base::broadcast(true), ec);
    socket_.bind(udp::endpoint(udp::v4(), static_cast<unsigned short>(kUdpBeaconPort)), ec);
    if (ec) {
        throw std::runtime_error("UdpBeacon::start: bind failed on port " +
                                  std::to_string(kUdpBeaconPort) + ": " + ec.message());
    }

    listen_thread_ = std::thread([this] { listen_loop(); });
    broadcast_thread_ = std::thread([this] { broadcast_loop(); });
}

void UdpBeacon::stop() {
    if (!running_.exchange(false)) return;
    asio::error_code ec;
    socket_.close(ec);
    if (listen_thread_.joinable()) listen_thread_.join();
    if (broadcast_thread_.joinable()) broadcast_thread_.join();
}

void UdpBeacon::listen_loop() {
    std::array<char, 2048> buffer{};
    while (running_) {
        try {
            udp::endpoint sender;
            asio::error_code ec;
            size_t len = socket_.receive_from(asio::buffer(buffer), sender, 0, ec);
            if (ec || len == 0) {
                if (running_) continue;
                break;
            }

            std::string message(buffer.data(), len);
            try {
                json j = json::parse(message);
                if (j.value("magic", "") != "RIN_BEACON") continue;

                std::string mesh = j.value("mesh", "");
                std::string key = j.value("key", "");
                std::string name = j.value("name", "");
                int port = j.value("port", kDefaultTcpPort);

                // Disregard our own broadcasts, matching Android.
                if (!key.empty() && key != public_key_ && on_peer_) {
                    DiscoveredPeer peer;
                    peer.mesh_name = mesh;
                    peer.public_key = key;
                    peer.device_name = name;
                    peer.ip = sender.address().to_string();
                    peer.port = port;
                    on_peer_(peer);
                }
            } catch (const json::exception&) {
                // malformed beacon -- ignore, matches Android
            }
        } catch (const std::exception&) {
            if (!running_) break;
        }
    }
}

void UdpBeacon::broadcast_loop() {
    while (running_) {
        try {
            json j;
            j["magic"] = "RIN_BEACON";
            j["mesh"] = mesh_name_;
            j["key"] = public_key_;
            j["name"] = device_name_;
            j["port"] = tcp_port_;
            j["ts"] = now_millis();

            std::string payload = j.dump();
            udp::endpoint broadcast_endpoint(asio::ip::address_v4::broadcast(), kUdpBeaconPort);
            asio::error_code ec;
            socket_.send_to(asio::buffer(payload), broadcast_endpoint, 0, ec);
            // Ignore transient send errors, matching Android's catch-and-continue.
        } catch (const std::exception&) {
            // ignore
        }

        for (int i = 0; i < kUdpBeaconIntervalSeconds * 10 && running_; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

}  // namespace rin
