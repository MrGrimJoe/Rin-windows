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
#include "rin/file_transfer.hpp"
#include "rin/persistence.hpp"
#include "rin/protocol.hpp"
#include "rin/relay.hpp"
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
    // meshSecret. Analogue of createInitialMesh(). Persists immediately
    // via PersistenceStore so a subsequent restart sees try_load_persisted()
    // succeed instead of hitting the first-launch chooser again.
    void create_initial_mesh(const std::string& mesh_name, const std::string& device_name);

    // Attempts to load a previously-created identity + trusted device list
    // from db_path (PersistenceStore::default_db_path() if empty). Returns
    // true if a saved identity was found and loaded (skip the first-launch
    // chooser), false if this is a fresh install (no saved identity --
    // caller should fall through to create_initial_mesh or a join flow).
    // A persistence-layer failure (corrupt file, permissions) is logged
    // and treated the same as "no saved identity" -- this never throws,
    // since failing to load history should degrade to first-launch, not
    // crash the app.
    bool try_load_persisted(const std::string& db_path = "");

    // Starts the TCP listener + UDP beacon and begins accepting/discovering.
    void start();
    void stop();

    // Opt-in relay fallback tier (NEW). Disabled by default -- call this
    // before start() to have this device register with a relay server
    // (see rin/relay.hpp) so devices with no direct LAN/IP path to each
    // other still have a route. Never required for LAN-only meshes.
    void configure_relay(const std::string& host, int port);
    bool relay_configured() const { return relay_.is_configured(); }

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
    void send_file(const std::string& local_path, const std::string& target_device_key,
                   std::function<void(float, int64_t, int64_t)> on_progress = nullptr);
    void revoke_device(const std::string& public_key);

    // -- Introspection for the console/UI shell --------------------------
    const MeshIdentity& identity() const { return identity_; }
    std::vector<TrustedDevice> trusted_devices() const;
    std::vector<MeshEvent> recent_events(size_t max = 20) const;

    // Handles one received discovery beacon (UDP today; any future
    // discovery transport should funnel through this same entry point).
    // A meshTag match is only a HINT that a beacon is probably from our
    // mesh -- it does NOT grant trust on its own. If the sender's public
    // key is already in the trust store, this just refreshes its IP/
    // port/rail. If not, this kicks off (or waits for, per the tie-
    // break) a discovery challenge/response handshake -- see
    // handle_discovery_challenge/handle_discovery_response below. Public
    // specifically so this security-critical logic can be exercised
    // directly by tests without standing up real sockets. See the
    // implementation's doc comment for the full trust-model rationale.
    void on_peer_discovered(const DiscoveredPeer& peer);

    // We are the CHALLENGED side here: someone (who matched our beacon's
    // meshTag, or is guessing) sent us a nonce encrypted with what they
    // claim is the mesh key. Decrypting it proves WE hold the real
    // secret; encrypting the echo proves it again on the way back. If we
    // can't decrypt, we simply don't reply -- no error packet, no
    // information leak about why it failed. remote_ip is required to
    // open the reply connection (empty if this arrived via relay, which
    // has no direct address to reply on -- the reply is simply skipped
    // in that case; peers reached only via relay get trust through the
    // QR join handshake instead). Public for the same testability reason
    // as on_peer_discovered.
    void handle_discovery_challenge(const MeshPacket& packet, const std::string& remote_ip);

    // We are the CHALLENGER here, checking the echo. Public for the same
    // testability reason as on_peer_discovered.
    void handle_discovery_response(const MeshPacket& packet, const std::string& remote_ip);

private:
    void on_packet_received(const MeshPacket& packet, const std::string& remote_ip);
    bool verify_packet_signature(const MeshPacket& packet) const;
    std::string decrypt_packet_payload(const MeshPacket& packet) const;
    void log_event(const std::string& message);
    int64_t next_sequence();
    void send_discovery_challenge(const std::string& ip, int port, const std::string& peer_public_key,
                                   const std::string& nonce);
    void promote_to_trusted(const std::string& public_key, const std::string& device_name,
                             const std::string& ip, int port);

    // Tries a direct send first (LAN or Wi-Fi-Direct-range IP, exactly as
    // before); only falls back to the relay tier if that fails AND a
    // relay is configured. Every existing call site that used to call
    // tcp_.send_packet(*device.ip_address, device.port, packet) directly
    // now goes through this instead -- same return contract (nullopt on
    // total failure), so nothing about the LAN-only path changes when no
    // relay is configured.
    std::optional<int64_t> send_with_fallback(const TrustedDevice& device, const MeshPacket& packet);

    asio::io_context& io_;
    TcpTransport tcp_;
    UdpBeacon udp_;
    RelayClient relay_;
    std::string relay_host_;
    int relay_port_ = 0;
    std::unique_ptr<PersistenceStore> store_;
    std::unique_ptr<FileTransferEngine> file_transfer_;

    MeshIdentity identity_;
    mutable std::mutex devices_mutex_;
    std::unordered_map<std::string, TrustedDevice> devices_;  // keyed by public_key

    // Discovery challenge/response state: one outstanding challenge per
    // peer public key we've challenged but not yet heard back from.
    // Deliberately NOT erased on a failed/mismatched response (see
    // handle_discovery_response's doc comment) -- only on success, or
    // implicitly by never being erased if the peer never replies (no
    // expiry logic yet; a stale entry just means a future legitimate
    // beacon match from the same peer won't re-challenge until the
    // process restarts -- acceptable for this milestone, flagged as a
    // follow-up alongside Android's identical gap).
    struct PendingChallenge {
        std::string nonce;
        std::string ip;
        int port = kDefaultTcpPort;
        int64_t sent_at_ms = 0;
    };
    mutable std::mutex pending_challenges_mutex_;
    std::unordered_map<std::string, PendingChallenge> pending_challenges_;  // keyed by peer public_key

    mutable std::mutex events_mutex_;
    std::vector<MeshEvent> events_;

    std::atomic<int64_t> sequence_{1};
};

}  // namespace rin
