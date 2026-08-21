// Rin Windows core -- console milestone.
//
// Scope: prove the core can (a) create a mesh identity, (b) discover
// peers via UDP beacon, (c) accept + verify + decrypt incoming TCP
// packets, and (d) complete a QR-based join handshake -- all wire
// compatible with the Android app. No Win32 UI yet; that's the next
// milestone once this is validated against a real phone.

#include <asio.hpp>

#include <iostream>
#include <sstream>
#include <thread>

#include "rin/mesh_engine.hpp"

namespace {

void print_help() {
    std::cout << "\nCommands:\n"
              << "  token              Print this device's QR join token JSON\n"
              << "                     (paste this as text on the phone's join screen,\n"
              << "                     or generate a QR from it, until the real QR UI exists)\n"
              << "  join <json>        Complete a join handshake using a token JSON string\n"
              << "                     (paste what the phone's \"Add Device\" screen shows)\n"
              << "  devices            List currently known devices\n"
              << "  events             Show recent mesh events\n"
              << "  clipboard <text>   Broadcast text to the mesh as a clipboard sync\n"
              << "  quit               Stop and exit\n\n";
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

    std::string mesh_name, device_name;
    std::cout << "Mesh name (blank = \"My Mesh\"): ";
    std::getline(std::cin, mesh_name);
    std::cout << "This device's name (blank = \"Windows PC\"): ";
    std::getline(std::cin, device_name);
    if (device_name.empty()) device_name = "Windows PC";

    asio::io_context io;
    rin::MeshEngine engine(io);

    try {
        engine.create_initial_mesh(mesh_name, device_name);
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
                std::cout << "Warning: token has no hostIp. This build requires a hostIp until\n"
                          << "the QR camera/scan UI and address-resolution-via-beacon path exist.\n"
                          << "Add \"hostIp\":\"<phone's LAN IP>\" to the token JSON and retry.\n";
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
