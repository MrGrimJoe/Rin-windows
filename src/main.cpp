// Rin Windows core -- console milestone.
//
// Scope: prove the core can (a) create a mesh identity, (b) discover
// peers via UDP beacon, (c) accept + verify + decrypt incoming TCP
// packets, and (d) complete a QR-based join handshake -- all wire
// compatible with the Android app. No Win32 UI yet; that's the next
// milestone once this is validated against a real phone.

#include <asio.hpp>

#include <cstdlib>
#include <iostream>
#include <sstream>
#include <thread>

#include "rin/mesh_engine.hpp"

namespace {

void print_help() {
    std::cout << "\nCommands:\n"
              << "  token              Print this device's join token JSON (includes this\n"
              << "                     PC's LAN IP; set RIN_ADVERTISE_IP to override it).\n"
              << "                     The Rin GUI shows the same token as a QR for phones.\n"
              << "  join <json>        Complete a join handshake using another device's token\n"
              << "                     JSON (this PC joins THAT device's mesh and adopts its\n"
              << "                     name and secret). Windows never scans QR codes.\n"
              << "  devices            List currently known devices\n"
              << "  events             Show recent mesh events\n"
              << "  clipboard <text>   Broadcast text to the mesh as a clipboard sync\n"
              << "  sendfile <key> <path>  Send a file to a specific device (use devices to get key)\n"
              << "  quit               Stop and exit\n\n"
              << "Relay fallback (NEW, opt-in, off by default): set RIN_RELAY_HOST (and\n"
              << "optionally RIN_RELAY_PORT, default 45992) before launching to register\n"
              << "with a relay -- e.g. one you run yourself via the rin_relay binary --\n"
              << "so devices with no direct LAN path to each other still have one. Safe\n"
              << "to leave unset: behavior is identical to before when it's not set.\n\n";
}

const char* platform_name(rin::PlatformType p) {
    switch (p) {
        case rin::PlatformType::Android: return "Android";
        case rin::PlatformType::Windows: return "Windows";
        case rin::PlatformType::Linux: return "Linux";
        case rin::PlatformType::MacOS: return "macOS";
        case rin::PlatformType::Tablet: return "Tablet";
    }
    return "Unknown";
}

const char* state_name(rin::ConnectionState s) {
    switch (s) {
        case rin::ConnectionState::Connected: return "CONNECTED";
        case rin::ConnectionState::Active: return "ACTIVE";
        case rin::ConnectionState::Reconnecting: return "RECONNECTING";
        case rin::ConnectionState::Idle: return "IDLE";
        case rin::ConnectionState::Offline: return "OFFLINE";
        case rin::ConnectionState::Lost: return "LOST";
        case rin::ConnectionState::Discovered: return "DISCOVERED";
        case rin::ConnectionState::Authenticating: return "AUTHENTICATING";
    }
    return "?";
}

}  // namespace

int main() {
    std::cout << "Rin -- Windows core (console milestone)\n";
    std::cout << "========================================\n";

    asio::io_context io;
    rin::MeshEngine engine(io);

    bool loaded = engine.try_load_persisted();
    if (loaded) {
        std::cout << "Loaded saved mesh \"" << engine.identity().mesh_name << "\" ("
                  << engine.trusted_devices().size() << " known device(s)).\n";
    } else {
        std::string mesh_name, device_name;
        std::cout << "No saved mesh found -- let's set one up.\n";
        std::cout << "Mesh name (blank = \"My Mesh\"): ";
        std::getline(std::cin, mesh_name);
        std::cout << "This device's name (blank = \"Windows PC\"): ";
        std::getline(std::cin, device_name);
        if (device_name.empty()) device_name = "Windows PC";

        try {
            engine.create_initial_mesh(mesh_name, device_name);
        } catch (const std::exception& e) {
            std::cerr << "Fatal: failed to create mesh: " << e.what() << "\n";
            return 1;
        }
    }

    if (const char* relay_host_env = std::getenv("RIN_RELAY_HOST")) {
        if (*relay_host_env) {
            int relay_port = 45992;
            if (const char* relay_port_env = std::getenv("RIN_RELAY_PORT")) {
                try {
                    relay_port = std::stoi(relay_port_env);
                } catch (const std::exception&) {
                    std::cerr << "Warning: RIN_RELAY_PORT is not a valid number, using default "
                              << relay_port << "\n";
                }
            }
            engine.configure_relay(relay_host_env, relay_port);
            std::cout << "Relay fallback configured: " << relay_host_env << ":" << relay_port << "\n";
        }
    }

    try {
        engine.start();
    } catch (const std::exception& e) {
        std::cerr << "Fatal: failed to start mesh engine: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nFingerprint: " << engine.identity().local_fingerprint << "\n";
    print_help();

    std::string line;
    while (true) {
        std::cout << "rin> ";
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "quit" || cmd == "exit") {
            break;
        } else if (cmd == "token") {
            std::cout << engine.build_join_token_json() << "\n";
        } else if (cmd == "join") {
            std::string rest;
            std::getline(iss, rest);
            if (!rest.empty() && rest[0] == ' ') rest.erase(0, 1);
            auto token = rin::QrJoinToken::from_json(rest);
            if (!token.has_value()) {
                std::cout << "Could not parse token JSON.\n";
                continue;
            }
            if (!token->host_ip.has_value()) {
                std::cout << "Token has no hostIp, so there is no address to send the join to.\n"
                          << "Ask the other device to re-generate its token on a network (a Windows\n"
                          << "host can set RIN_ADVERTISE_IP), or add \"hostIp\":\"<its LAN IP>\" to the\n"
                          << "token JSON by hand and retry.\n";
                continue;
            }
            bool ok = engine.complete_join_handshake(*token);
            std::cout << (ok ? "Join handshake sent.\n" : "Join handshake failed.\n");
        } else if (cmd == "devices") {
            auto devices = engine.trusted_devices();
            if (devices.empty()) {
                std::cout << "(no devices)\n";
            }
            for (const auto& d : devices) {
                std::cout << "  " << d.name << "  [" << platform_name(d.platform) << "]  "
                          << state_name(d.connection_state) << "  "
                          << (d.ip_address.has_value() ? *d.ip_address : std::string("-")) << ":"
                          << d.port << (d.is_self ? "  (self)" : "") << "\n";
            }
        } else if (cmd == "events") {
            for (const auto& e : engine.recent_events()) {
                std::cout << "  " << e.message << "\n";
            }
        } else if (cmd == "clipboard") {
            std::string text;
            std::getline(iss, text);
            if (!text.empty() && text[0] == ' ') text.erase(0, 1);
            engine.broadcast_clipboard(text);
        } else if (cmd == "sendfile") {
            std::string target_key, file_path;
            iss >> target_key;
            std::getline(iss, file_path);
            if (!file_path.empty() && file_path[0] == ' ') file_path.erase(0, 1);
            if (target_key.empty() || file_path.empty()) { std::cout << "Usage: sendfile <device_key_prefix> <file_path>\n"; }
            else { engine.send_file(file_path, target_key); }
        } else if (cmd == "help") {
            print_help();
        } else {
            std::cout << "Unknown command. Type 'help' for a list.\n";
        }
    }

    engine.stop();
    std::cout << "Stopped.\n";
    return 0;
}
