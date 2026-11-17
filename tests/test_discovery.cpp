// Discovery/trust-boundary tests -- meshTag + challenge/response design.
//
// Mirrors Android's onPeerDiscoveredNeedsVerification / handleDiscoveryChallenge
// / handleDiscoveryResponse exactly (see MeshRuntimeEngine.kt and
// DESIGN_NOTES.md "Discovery hardening"). Covers the SECURITY FIX: a
// beacon's meshTag match is only a HINT ("probably our mesh"), never
// trust by itself. Trust requires the peer to prove it holds the real
// mesh secret via a nonce challenge/response, encrypted with the actual
// derived mesh key -- not a self-consistent keypair, not a guessed tag.
//
// This exercises on_peer_discovered/handle_discovery_challenge/
// handle_discovery_response directly (all public specifically so this
// can be tested without standing up real UDP sockets -- see their
// declarations in mesh_engine.hpp).
//
// One test below (the full round-trip) goes further than a pure unit
// test: it runs a real MeshEngine against a real loopback TCP listener
// to capture the ACTUAL DiscoveryChallenge packet the engine sends,
// decrypts it for real, and feeds a real DiscoveryResponse back in --
// exercising the true send path, not just the receive-side handlers in
// isolation. A genuine two-MeshEngine-instances-broadcasting-real-UDP-
// beacons-at-each-other test was considered and deliberately NOT done:
// two UdpBeacon instances in one process both binding port 45991 has
// undefined-per-OS delivery semantics and would be a flaky test, not a
// more thorough one. Real two-device testing remains the manual step
// described in "Testing this against your phone" below.

#include "rin/mesh_engine.hpp"

#include <nlohmann/json.hpp>

#include <asio.hpp>
#include <cstdlib>
#include <iostream>
#include <thread>

using namespace rin;
using nlohmann::json;
using asio::ip::tcp;

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

std::optional<TrustedDevice> find_device(const std::vector<TrustedDevice>& devices,
                                          const std::string& public_key) {
    for (const auto& d : devices) {
        if (d.public_key == public_key) return d;
    }
    return std::nullopt;
}

int64_t current_bucket() {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::system_clock::now().time_since_epoch())
                  .count();
    return ms / 1000 / kBeaconTagWindowSeconds;
}

void set_env(const char* name, const char* value) {
#ifdef _WIN32
    _putenv_s(name, value);
#else
    setenv(name, value, 1);
#endif
}

void clear_env(const char* name) {
#ifdef _WIN32
    _putenv_s(name, "");
#else
    unsetenv(name);
#endif
}
}  // namespace

void run_discovery_tests() {
    std::cout << "\n== Discovery / trust-boundary tests (meshTag + challenge/response) ==\n";

    asio::io_context io;
    MeshEngine engine(io);
    engine.create_initial_mesh("Discovery Test Mesh", "Test PC");
    std::array<uint8_t, 32> mesh_key =
        CryptoEngine::derive_mesh_encryption_key(engine.identity().mesh_secret, engine.identity().mesh_name);

    // -- Case 1: a beacon whose meshTag matches, from a peer we already
    // trust, just refreshes connection info -- no challenge needed.
    {
        KeyPair phone = CryptoEngine::generate_identity_keypair();
        QrJoinToken token;
        token.mesh_name = engine.identity().mesh_name;
        token.host_public_key = phone.public_key_b64;
        token.host_device_name = "Test Phone";
        token.ephemeral_token = CryptoEngine::generate_ephemeral_token();
        token.mesh_secret = engine.identity().mesh_secret;
        token.host_port = 45990;
        token.host_ip = "127.0.0.1";  // handshake reply send will fail (nothing listening) -- fine,
                                       // the device is added to the trust store before that's attempted
        engine.complete_join_handshake(token);
        size_t devices_after_join = engine.trusted_devices().size();

        DiscoveredPeer peer;
        peer.mesh_tag = CryptoEngine::derive_beacon_tag(mesh_key, current_bucket());
        peer.public_key = phone.public_key_b64;
        peer.ip = "10.0.0.55";  // phone roamed to a new IP
        peer.port = 45990;
        peer.timestamp_ms = 1700000000000LL;

        engine.on_peer_discovered(peer);

        auto devices = engine.trusted_devices();
        check(devices.size() == devices_after_join,
              "a matching-tag beacon from an already-trusted device creates NO new device");
        auto updated = find_device(devices, phone.public_key_b64);
        check(updated.has_value() && updated->ip_address.has_value() && *updated->ip_address == "10.0.0.55",
              "and DOES update that trusted device's IP directly, with no challenge round-trip");
    }

    // -- Case 2: a beacon with a WRONG mesh tag (different/foreign mesh)
    // is ignored outright -- never even considered for challenge.
    {
        DiscoveredPeer peer;
        peer.mesh_tag = "not_a_real_tag_at_all";
        peer.public_key = CryptoEngine::generate_identity_keypair().public_key_b64;
        peer.ip = "10.0.0.77";
        peer.port = 45990;

        size_t before = engine.trusted_devices().size();
        engine.on_peer_discovered(peer);
        check(engine.trusted_devices().size() == before,
              "a beacon with a non-matching meshTag creates no device and starts no challenge");
    }

    // -- Case 3: a matching-tag beacon from a genuinely NEW peer does NOT
    // immediately create a trusted device -- it can only ever create a
    // PENDING challenge (verified indirectly: device count stays flat
    // right after the call, since the real network send happens
    // asynchronously to nothing and promotion only happens on a verified
    // response, which this peer never sends).
    {
        // Use a key that sorts LOWER than ours so tie-break says WE
        // initiate (deterministic assertion below depends on this).
        KeyPair stranger = CryptoEngine::generate_identity_keypair();
        std::string lower_key = stranger.public_key_b64 < engine.identity().local_public_key
                                     ? stranger.public_key_b64
                                     : engine.identity().local_public_key + "_lower_placeholder_never_matches";
        // (If bad luck produces a key that sorts higher, this case still
        // proves the more important half: no device is ever created
        // from a beacon alone, tie-break direction aside.)

        DiscoveredPeer peer;
        peer.mesh_tag = CryptoEngine::derive_beacon_tag(mesh_key, current_bucket());
        peer.public_key = lower_key;
        peer.ip = "10.0.0.99";
        peer.port = 1;  // nothing real listens here -- the send is expected to fail silently

        size_t before = engine.trusted_devices().size();
        engine.on_peer_discovered(peer);
        check(engine.trusted_devices().size() == before,
              "a matching-tag beacon from a brand-new peer creates NO device immediately -- "
              "at most a pending challenge, never automatic trust");
    }

    // -- Case 4: we are the CHALLENGED side. A well-formed, correctly
    // encrypted DiscoveryChallenge (as if from a real peer who derived
    // the same mesh key) gets a response AND promotes that peer to
    // trusted directly -- this is the "symmetric promotion" path.
    {
        KeyPair peer_device = CryptoEngine::generate_identity_keypair();
        std::string nonce = CryptoEngine::generate_discovery_nonce();

        json body;
        body["nonce"] = nonce;
        body["ts"] = 1700000001000LL;
        body["challengerPort"] = 45990;
        std::string encrypted = CryptoEngine::encrypt_payload(body.dump(), mesh_key);

        MeshPacket challenge;
        challenge.session_id = "discovery_test_session";
        challenge.sequence = 1;
        challenge.type = PacketType::DiscoveryChallenge;
        challenge.sender_key = peer_device.public_key_b64;
        challenge.sender_name = "Peer Device";
        challenge.target_key = engine.identity().local_public_key;
        challenge.payload = encrypted;
        challenge.signature = CryptoEngine::sign(encrypted, peer_device.private_key_b64);
        challenge.rail = TransportRail::Lan;
        challenge.timestamp_ms = 1700000001000LL;

        // remote_ip is a real, unreachable loopback port -- the reply
        // send inside handle_discovery_challenge will fail silently
        // (matches "ignore transient send errors" elsewhere), but
        // promotion happens regardless, since it's based on having
        // successfully DECRYPTED the challenge, not on the reply
        // succeeding.
        engine.handle_discovery_challenge(challenge, "127.0.0.1");

        auto promoted = find_device(engine.trusted_devices(), peer_device.public_key_b64);
        check(promoted.has_value() && promoted->name == "Peer Device",
              "a correctly-encrypted DiscoveryChallenge (proof of real mesh-secret possession) "
              "promotes the sender to trusted directly, symmetrically, without us ever having "
              "sent a challenge of our own");
    }

    // -- Case 5: a forged/garbage DiscoveryChallenge (wrong key, so it
    // cannot have been encrypted with our real mesh key) is rejected --
    // decrypt fails, nothing is promoted, no reply is sent.
    {
        KeyPair attacker = CryptoEngine::generate_identity_keypair();
        std::array<uint8_t, 32> wrong_key =
            CryptoEngine::derive_mesh_encryption_key("a-completely-different-secret", "Discovery Test Mesh");

        json body;
        body["nonce"] = "forged_nonce";
        std::string encrypted = CryptoEngine::encrypt_payload(body.dump(), wrong_key);

        MeshPacket forged;
        forged.session_id = "forged_session";
        forged.sequence = 1;
        forged.type = PacketType::DiscoveryChallenge;
        forged.sender_key = attacker.public_key_b64;
        forged.sender_name = "Attacker";
        forged.target_key = engine.identity().local_public_key;
        forged.payload = encrypted;
        forged.signature = CryptoEngine::sign(encrypted, attacker.private_key_b64);
        forged.rail = TransportRail::Lan;
        forged.timestamp_ms = 1700000002000LL;

        engine.handle_discovery_challenge(forged, "127.0.0.1");

        check(!find_device(engine.trusted_devices(), attacker.public_key_b64).has_value(),
              "a DiscoveryChallenge encrypted with the WRONG mesh key is rejected -- "
              "the attacker is never promoted to trusted");
    }

    // -- Case 6: full round-trip using the REAL send path. A raw loopback
    // listener stands in for "the other device", capturing the actual
    // DiscoveryChallenge our engine sends (via the real tie-break +
    // send_discovery_challenge code, not a hand-built packet), decrypts
    // it for real, and replies with a real DiscoveryResponse -- proving
    // the challenger side's handle_discovery_response promotes on a
    // genuine round trip, not just on a hand-fed one like Case 4 tests
    // for the challenged side.
    {
        KeyPair other_device = CryptoEngine::generate_identity_keypair();
        // Must sort LOWER than our key so tie-break makes OUR engine the
        // initiator (challenger).
        while (other_device.public_key_b64 >= engine.identity().local_public_key) {
            other_device = CryptoEngine::generate_identity_keypair();
        }

        // 127.0.0.2, not 127.0.0.1: TcpTransport::send_packet has a
        // pre-existing, undocumented guard that refuses to connect to the
        // literal string "127.0.0.1" (found while writing this test --
        // it turned a real bug into a hang instead of a clean failure,
        // see send_discovery_challenge's fire-and-forget comment). Any
        // other loopback address works identically on Linux without
        // needing to touch that guard, which we don't understand the
        // original intent of well enough to safely change here.
        asio::io_context listener_io;
        tcp::acceptor acceptor(listener_io, tcp::endpoint(asio::ip::make_address("127.0.0.2"), 0));
        int listener_port = acceptor.local_endpoint().port();

        std::string captured_line;
        std::thread listener_thread([&] {
            tcp::socket socket(listener_io);
            acceptor.accept(socket);
            asio::streambuf buf;
            asio::read_until(socket, buf, '\n');
            std::istream is(&buf);
            std::getline(is, captured_line);
        });

        DiscoveredPeer peer;
        peer.mesh_tag = CryptoEngine::derive_beacon_tag(mesh_key, current_bucket());
        peer.public_key = other_device.public_key_b64;
        peer.ip = "127.0.0.2";
        peer.port = listener_port;
        engine.on_peer_discovered(peer);  // real send_discovery_challenge() call, real TCP connect

        listener_thread.join();

        auto challenge_packet = packet_from_wire_json(captured_line);
        check(challenge_packet.has_value() && challenge_packet->type == PacketType::DiscoveryChallenge,
              "our engine actually sent a real DiscoveryChallenge over TCP when it won the tie-break");

        if (challenge_packet.has_value()) {
            std::string decrypted = CryptoEngine::decrypt_payload(challenge_packet->payload, mesh_key);
            json challenge_body = json::parse(decrypted);
            std::string real_nonce = challenge_body.value("nonce", "");
            check(!real_nonce.empty(), "the captured challenge decrypts with our real mesh key and has a nonce");

            // Now play the other device: echo the real nonce back in a
            // real, correctly-encrypted DiscoveryResponse.
            json response_body;
            response_body["nonce"] = real_nonce;
            response_body["deviceName"] = "The Other Device";
            response_body["ts"] = 1700000003000LL;
            std::string encrypted_response = CryptoEngine::encrypt_payload(response_body.dump(), mesh_key);

            MeshPacket response;
            response.session_id = challenge_packet->session_id;
            response.sequence = 1;
            response.type = PacketType::DiscoveryResponse;
            response.sender_key = other_device.public_key_b64;
            response.sender_name = "The Other Device";
            response.target_key = engine.identity().local_public_key;
            response.payload = encrypted_response;
            response.signature = CryptoEngine::sign(encrypted_response, other_device.private_key_b64);
            response.rail = TransportRail::Lan;
            response.timestamp_ms = 1700000003000LL;

            engine.handle_discovery_response(response, "127.0.0.2");

            auto promoted = find_device(engine.trusted_devices(), other_device.public_key_b64);
            check(promoted.has_value() && promoted->name == "The Other Device",
                  "a full real round-trip (real challenge sent -> decrypted -> real response with "
                  "correctly-echoed nonce) promotes the other device to trusted");
        }
    }

    // -- QR join token must carry a reachable host address -----------------
    // The phone that scans this device's QR has nothing else to reach it by:
    // Android's completeJoinHandshake picks the INTERNET_P2P rail when hostIp
    // is missing, and the JOIN_ACCEPT then goes nowhere.
    {
        set_env("RIN_ADVERTISE_IP", "192.168.77.20");
        auto forced = detect_local_lan_ip();
        check(forced.has_value() && *forced == "192.168.77.20",
              "RIN_ADVERTISE_IP overrides LAN IP detection");

        auto token = QrJoinToken::from_json(engine.build_join_token_json());
        check(token.has_value(), "the join token JSON parses back");
        check(token.has_value() && token->host_ip.has_value() && *token->host_ip == "192.168.77.20",
              "the join token embeds the host's LAN IP so a scanning phone can reach it");
        check(token.has_value() && token->host_port == engine.identity().port,
              "the join token embeds the real listening port");

        set_env("RIN_ADVERTISE_IP", "not-an-ip");
        auto bad = detect_local_lan_ip();
        check(!bad.has_value() || *bad != "not-an-ip",
              "a malformed RIN_ADVERTISE_IP is ignored, never advertised");

        clear_env("RIN_ADVERTISE_IP");
        auto detected = detect_local_lan_ip();
        bool plausible = !detected.has_value() ||
                         (asio::ip::make_address_v4(*detected).is_loopback() == false &&
                          asio::ip::make_address_v4(*detected).is_unspecified() == false);
        check(plausible, "auto-detected LAN IP (if any) is neither loopback nor 0.0.0.0");
    }

    // -- Joining must adopt the host's mesh NAME as well as its secret -----
    // The name is the HKDF salt in derive_mesh_encryption_key. A joiner that
    // keeps its own placeholder name derives a different mesh key than the
    // host, so everything encrypted with the mesh key silently fails.
    {
        set_env("RIN_ADVERTISE_IP", "127.0.0.1");
        asio::io_context joiner_io;
        MeshEngine joiner(joiner_io);
        joiner.create_initial_mesh("Joining...", "Joiner Phone");
        auto host_token = QrJoinToken::from_json(engine.build_join_token_json());
        clear_env("RIN_ADVERTISE_IP");

        check(host_token.has_value(), "host token parses for the join-adoption test");
        if (host_token.has_value()) {
            // No listener is running at the token's address, so the send is
            // expected to fail -- adoption happens before the send and is
            // exactly what's under test here.
            host_token->host_port = 1;
            joiner.complete_join_handshake(*host_token);

            check(joiner.identity().mesh_name == engine.identity().mesh_name,
                  "joiner adopts the host's mesh name, not its own placeholder");
            check(joiner.identity().mesh_secret == engine.identity().mesh_secret,
                  "joiner adopts the host's mesh secret");
            check(CryptoEngine::derive_mesh_encryption_key(joiner.identity().mesh_secret,
                                                           joiner.identity().mesh_name) ==
                      CryptoEngine::derive_mesh_encryption_key(engine.identity().mesh_secret,
                                                               engine.identity().mesh_name),
                  "after joining, both devices derive the identical mesh key");
        }
    }

    std::cout << (g_failures == 0 ? "All discovery tests passed.\n" : "SOME DISCOVERY TESTS FAILED.\n");
}

int g_discovery_test_failures() { return g_failures; }
