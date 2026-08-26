// Protocol wire-format tests.
//
// These check the JSON produced/parsed matches the EXACT shape Android's
// MeshRuntimeEngine.transmitOverNetwork() / handleIncomingConnection()
// use -- field names, enum spellings, and the fact that everything rides
// as one JSON object per line. A mismatch here means "the phone and PC
// can't talk to each other," which is the single most important thing
// to catch before testing against a real device.

#include "rin/protocol.hpp"

#include <iostream>

using namespace rin;

extern int g_crypto_test_failures();

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

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}
}  // namespace

void run_protocol_tests() {
    std::cout << "\n== Protocol tests ==\n";

    // -- PacketType wire strings match Kotlin enum .name exactly ---------
    check(std::string(to_wire_string(PacketType::ClipboardSync)) == "CLIPBOARD_SYNC",
          "ClipboardSync serializes to CLIPBOARD_SYNC");
    check(std::string(to_wire_string(PacketType::JoinAccept)) == "JOIN_ACCEPT",
          "JoinAccept serializes to JOIN_ACCEPT");
    check(std::string(to_wire_string(PacketType::BrowserHandoff)) == "BROWSER_HANDOFF",
          "BrowserHandoff serializes to BROWSER_HANDOFF");
    check(packet_type_from_wire_string("HEARTBEAT") == PacketType::Heartbeat, "HEARTBEAT round-trips");
    check(!packet_type_from_wire_string("NOT_A_REAL_TYPE").has_value(),
          "unknown packet type string is rejected, not defaulted silently");

    // -- MeshPacket JSON has the exact abbreviated field names Android uses --
    {
        MeshPacket p;
        p.version = 1;
        p.session_id = "sess_abc123";
        p.sequence = 42;
        p.type = PacketType::ClipboardSync;
        p.sender_key = "MFkwEwYHKoZI...";
        p.sender_name = "Windows PC";
        p.target_key = "MFkwEwYHKoZI-target";
        p.payload = "base64ciphertext==";
        p.signature = "ecdsa:base64sig==";
        p.rail = TransportRail::Lan;
        p.timestamp_ms = 1771583429000;

        std::string json_line = packet_to_wire_json(p);

        // These are the exact keys Android's transmitOverNetwork() builds --
        // NOT "version"/"sessionId"/"sequence" as the README implies.
        check(contains(json_line, "\"v\":1"), "wire JSON uses abbreviated key 'v' for version");
        check(contains(json_line, "\"sess\":\"sess_abc123\""), "wire JSON uses 'sess' for session_id");
        check(contains(json_line, "\"seq\":42"), "wire JSON uses 'seq' for sequence");
        check(contains(json_line, "\"type\":\"CLIPBOARD_SYNC\""), "wire JSON uses 'type' with enum name");
        check(contains(json_line, "\"senderKey\":"), "wire JSON uses 'senderKey'");
        check(contains(json_line, "\"senderName\":\"Windows PC\""), "wire JSON uses 'senderName'");
        check(contains(json_line, "\"targetKey\":"), "wire JSON includes 'targetKey' when present");
        check(contains(json_line, "\"payload\":"), "wire JSON uses 'payload'");
        check(contains(json_line, "\"sig\":"), "wire JSON uses 'sig' (not 'signature')");
        check(contains(json_line, "\"rail\":\"LAN\""), "wire JSON uses 'rail' with enum name");
        check(contains(json_line, "\"ts\":1771583429000"), "wire JSON uses 'ts' for timestamp");

        // Round-trip.
        auto parsed = packet_from_wire_json(json_line);
        check(parsed.has_value(), "packet JSON parses back successfully");
        if (parsed.has_value()) {
            check(parsed->session_id == p.session_id, "round-trip preserves session_id");
            check(parsed->sequence == p.sequence, "round-trip preserves sequence");
            check(parsed->type == p.type, "round-trip preserves type");
            check(parsed->sender_key == p.sender_key, "round-trip preserves sender_key");
            check(parsed->target_key.has_value() && *parsed->target_key == *p.target_key,
                  "round-trip preserves target_key");
            check(parsed->signature == p.signature, "round-trip preserves signature");
            check(parsed->rail == p.rail, "round-trip preserves rail");
        }
    }

    // -- targetKey omitted when absent (matches Android's targetKey?.let{}) --
    {
        MeshPacket p;
        p.session_id = "s";
        p.sender_key = "k";
        p.sender_name = "n";
        p.payload = "p";
        p.signature = "ecdsa:x";
        p.target_key = std::nullopt;
        std::string json_line = packet_to_wire_json(p);
        check(!contains(json_line, "targetKey"), "targetKey key is omitted entirely when absent, not null");
    }

    // -- Malformed input is dropped, not defaulted into a fake packet -----
    {
        auto parsed = packet_from_wire_json("this is not json");
        check(!parsed.has_value(), "malformed JSON line yields nullopt, matching Android's parse-and-continue");

        auto parsed2 = packet_from_wire_json("{\"type\":\"BOGUS_TYPE\",\"payload\":\"x\"}");
        check(!parsed2.has_value(), "unknown packet type in JSON yields nullopt rather than a garbage default");
    }

    // -- QrJoinToken round-trip, matching QrJoinToken.kt field names -------
    {
        QrJoinToken token;
        token.mesh_name = "Ali's Devices";
        token.host_public_key = "pubkey123";
        token.host_device_name = "Pixel 8 Pro";
        token.ephemeral_token = "rin_join_deadbeef";
        token.mesh_secret = "supersecret";
        token.host_port = 45990;
        token.host_ip = "192.168.1.42";
        token.timestamp_ms = 1771583429000;

        std::string json = token.to_json();
        check(contains(json, "\"meshName\":\"Ali's Devices\""), "QR token uses 'meshName'");
        check(contains(json, "\"hostPublicKey\":"), "QR token uses 'hostPublicKey'");
        check(contains(json, "\"ephemeralToken\":"), "QR token uses 'ephemeralToken'");
        check(contains(json, "\"meshSecret\":\"supersecret\""), "QR token includes meshSecret when present");
        check(contains(json, "\"hostIp\":\"192.168.1.42\""), "QR token includes hostIp when present");

        auto parsed = QrJoinToken::from_json(json);
        check(parsed.has_value(), "QR token JSON parses back");
        if (parsed.has_value()) {
            check(parsed->mesh_name == token.mesh_name, "QR token round-trip preserves mesh_name");
            check(parsed->mesh_secret.has_value() && *parsed->mesh_secret == "supersecret",
                  "QR token round-trip preserves mesh_secret");
            check(parsed->host_ip.has_value() && *parsed->host_ip == "192.168.1.42",
                  "QR token round-trip preserves host_ip");
        }
    }

    // -- QrJoinToken without optional fields (legacy / no-secret case) ----
    {
        std::string minimal_json =
            R"({"meshName":"M","hostPublicKey":"k","hostDeviceName":"d","ephemeralToken":"t","hostPort":45990,"timestamp":123})";
        auto parsed = QrJoinToken::from_json(minimal_json);
        check(parsed.has_value(), "QR token without meshSecret/hostIp still parses");
        if (parsed.has_value()) {
            check(!parsed->mesh_secret.has_value(), "missing meshSecret parses as nullopt, not empty string");
            check(!parsed->host_ip.has_value(), "missing hostIp parses as nullopt");
        }
    }

    std::cout << (g_failures == 0 ? "All protocol tests passed.\n" : "SOME PROTOCOL TESTS FAILED.\n");
}

int g_protocol_test_failures() { return g_failures; }

void run_crypto_tests();
void run_qr_tests();
void run_audit_logger_tests();
void run_persistence_tests();
void run_file_transfer_tests();
int g_qr_test_failures();
int g_audit_test_failures();
int g_persistence_test_failures();
int g_file_transfer_test_failures();

int main() {
    run_crypto_tests();
    run_protocol_tests();
    run_qr_tests();
    run_audit_logger_tests();
    run_persistence_tests();
    run_file_transfer_tests();

    int total_failures = g_crypto_test_failures() + g_protocol_test_failures() +
                          g_qr_test_failures() + g_audit_test_failures() +
                          g_persistence_test_failures() + g_file_transfer_test_failures();
    std::cout << "\n========================================\n";
    if (total_failures == 0) {
        std::cout << "ALL TESTS PASSED.\n";
        return 0;
    } else {
        std::cout << total_failures << " TEST(S) FAILED.\n";
        return 1;
    }
}
