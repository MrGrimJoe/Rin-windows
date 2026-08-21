#pragma once
// Mesh orchestration: identity, trust list, join handshake, and the
// packet decrypt/dispatch logic that sits on top of TcpTransport/UdpBeacon.
//
// MUST stay in sync with:
//   app/src/main/java/com/example/core/transport/MeshRuntimeEngine.kt
//   (processIncomingPacket, completeJoinHandshake, createInitialMesh)
//
// Milestone scope for this pass: identity, discovery, join handshake,
// and correctly verifying + decrypting inbound packets. Feature-level
// reactions (updating a system clipboard, saving a received file, etc.)
// are stubbed as logged events for now -- Windows has no single
// "system clipboard" analogue to Android's ClipboardManager yet, and
// wiring that up is a follow-up step once the core handshake is proven
// against a real phone.

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <asio.hpp>

#include "rin/crypto.hpp"
#include "rin/protocol.hpp"
#include "rin/transport.hpp"

namespace rin {

// Local device + mesh identity. Analogue of Android's MeshEntity.
struct MeshIdentity {
    std::string mesh_name;
    std::string local_device_name;
    std::string local_public_key;
    std::string local_private_key;
    std::string local_fingerprint;
    std::string mesh_secret;
    int port = kDefaultTcpPort;
};

// A device we trust (or that has trusted us). Analogue of TrustedDeviceEntity.
struct TrustedDevice {
    std::string public_key;
    std::string name;
    PlatformType platform = PlatformType::Windows;
    ConnectionState connection_state = ConnectionState::Discovered;
    TransportRail active_rail = TransportRail::Lan;
    std::optional<std::string> ip_address;
    int port = kDefaultTcpPort;
    int64_t latency_ms = 2;
    bool is_self = false;
};

// Simple in-memory event log for what would otherwise be Room-persisted
// packet history / notifications on Android. Swap for real persistence
// once this proves out against a live phone.
struct MeshEvent {
    int64_t timestamp_ms;
    std::string message;
};

class MeshEngine {
public:
    explicit MeshEngine(asio::io_context& io);

    // Creates a brand-new mesh: generates identity keys + a real random
    // meshSecret. Analogue of createInitialMesh().
    void create_initial_mesh(const std::string& mesh_name, const std::string& device_name);

    // Starts the TCP listener + UDP beacon and begins accepting/discovering.
    void start();
    void stop();

    // Produces this device's QR join token JSON, to be rendered as a QR
    // code by the UI layer (or shown as text for the console milestone).
    std::string build_join_token_json() const;

    // Consumes a token scanned from another device's QR and completes the
    // handshake against it (sends a signed+encrypted JOIN_ACCEPT). Analogue
    // of completeJoinHandshake(). Returns true on successful send.
    bool complete_join_handshake(const QrJoinToken& token);

    // -- Outbound feature actions (mirroring MeshRuntimeEngine) ---------
    void broadcast_clipboard(const std::string& text);
    void send_browser_handoff(const std::string& url, const std::optional<std::string>& target_device_key);
    void revoke_device(const std::string& public_key);

    // -- Introspection for the console/UI shell --------------------------
    const MeshIdentity& identity() const { return identity_; }
    std::vector<TrustedDevice> trusted_devices() const;
    std::vector<MeshEvent> recent_events(size_t max = 20) const;

private:
    void on_packet_received(const MeshPacket& packet);
    bool verify_packet_signature(const MeshPacket& packet) const;
    std::string decrypt_packet_payload(const MeshPacket& packet) const;
    void on_peer_discovered(const DiscoveredPeer& peer);
    void log_event(const std::string& message);
    int64_t next_sequence();

    asio::io_context& io_;
    TcpTransport tcp_;
    UdpBeacon udp_;

    MeshIdentity identity_;
    mutable std::mutex devices_mutex_;
    std::unordered_map<std::string, TrustedDevice> devices_;  // keyed by public_key

    mutable std::mutex events_mutex_;
    std::vector<MeshEvent> events_;

    std::atomic<int64_t> sequence_{1};
};

}  // namespace rin
