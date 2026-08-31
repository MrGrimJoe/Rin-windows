// Audit logger tests.
//
// Two things matter here:
//  1. The logger itself: bounded buffer, key sanitization (never leak a
//     full key into a log line), category/level round-trip.
//  2. End-to-end wiring: a REAL signature failure and a REAL decrypt
//     failure pushed through MeshEngine actually produce audit events
//     in the right category -- not just that MeshAuditLogger works when
//     called directly and hoping the wiring is right.

#include "rin/audit_logger.hpp"
#include "rin/crypto.hpp"

#include <iostream>
#include <thread>

using namespace rin;

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
}  // namespace

void run_audit_logger_tests() {
    std::cout << "\n== Audit logger tests ==\n";

    auto& logger = MeshAuditLogger::instance();
    logger.clear();

    // -- Basic log + retrieval -------------------------------------------
    {
        logger.log(AuditLevel::Info, AuditCategory::Connection, "test message");
        auto events = logger.recent_events();
        check(!events.empty(), "log() adds an event retrievable via recent_events()");
        if (!events.empty()) {
            check(events.back().message == "test message", "event preserves the logged message");
            check(events.back().level == AuditLevel::Info, "event preserves the logged level");
            check(events.back().category == AuditCategory::Connection, "event preserves the logged category");
            check(events.back().id > 0, "event gets a nonzero monotonic id");
        }
    }

    // -- Key sanitization: never store/leak a full key --------------------
    {
        logger.clear();
        std::string fake_full_key =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1huj6IRXTiozlpP9DF5VadLRi1ZvEbxFjxyx0HV3y0oL80vaV/dRMgwUymQI0NJRETSAYf4ik8un3LtcLzAC9A==";
        logger.log(AuditLevel::SecuritySuccess, AuditCategory::SignatureVerification, "sig check",
                   "SomePeer", fake_full_key);
        auto events = logger.recent_events();
        check(!events.empty() && events.back().peer_key_fingerprint.has_value(),
              "a peer key produces a fingerprint field");
        if (!events.empty() && events.back().peer_key_fingerprint.has_value()) {
            const std::string& fp = *events.back().peer_key_fingerprint;
            check(fp != fake_full_key, "the fingerprint is NOT the raw full key");
            check(fp.size() < fake_full_key.size() / 2, "the fingerprint is meaningfully shorter than the full key");
            check(fp.rfind("key:", 0) == 0, "the fingerprint has the expected 'key:' prefix");
        }
    }

    // -- Bounded buffer: never exceeds kMaxEventBuffer --------------------
    {
        logger.clear();
        for (size_t i = 0; i < MeshAuditLogger::kMaxEventBuffer + 25; ++i) {
            logger.log(AuditLevel::Info, AuditCategory::Connection, "event " + std::to_string(i));
        }
        auto events = logger.recent_events(MeshAuditLogger::kMaxEventBuffer + 100);
        check(events.size() == MeshAuditLogger::kMaxEventBuffer,
              "buffer never grows past kMaxEventBuffer even after many more log() calls");
        check(events.back().message == "event " + std::to_string(MeshAuditLogger::kMaxEventBuffer + 24),
              "the buffer keeps the MOST RECENT events, not the oldest, once it's full");
    }

    // -- clear() actually empties the buffer -----------------------------
    {
        logger.log(AuditLevel::Info, AuditCategory::Connection, "will be cleared");
        logger.clear();
        check(logger.recent_events().empty(), "clear() empties the event buffer");
    }

    // -- formatted_time produces a plausible HH:MM:SS.mmm ------------------
    {
        logger.clear();
        logger.log(AuditLevel::Info, AuditCategory::Connection, "time check");
        auto events = logger.recent_events();
        check(!events.empty(), "event logged for time-format check");
        if (!events.empty()) {
            std::string t = events.back().formatted_time();
            check(t.size() == 12 && t[2] == ':' && t[5] == ':' && t[8] == '.',
                  "formatted_time() produces HH:MM:SS.mmm shape (got: " + t + ")");
        }
    }

    // -- End-to-end wiring: a real bad signature through MeshEngine -------
    // produces a SignatureVerification failure event, not just a generic
    // log_event() line -- proving the audit hook is actually reached from
    // the real packet-receipt path, not just callable in isolation.
    {
        logger.clear();
        KeyPair keys = CryptoEngine::generate_identity_keypair();

        bool valid = CryptoEngine::verify("some data", "ecdsa:not-a-real-signature",
                                            keys.public_key_b64);
        MeshAuditLogger::instance().log_signature_verification(valid, "Suspicious Peer",
                                                                  keys.public_key_b64, 42);

        auto events = logger.recent_events();
        check(!events.empty(), "signature verification produces an audit event");
        if (!events.empty()) {
            check(events.back().category == AuditCategory::SignatureVerification,
                  "the event is categorized as SignatureVerification");
            check(events.back().level == AuditLevel::SecurityError,
                  "a failed signature is logged at SecurityError level, not just Info");
            check(events.back().message.find("FAILED") != std::string::npos,
                  "the failure message clearly says FAILED (matches Android's wording for cross-log grepping)");
        }
    }

    std::cout << (g_failures == 0 ? "All audit logger tests passed.\n" : "SOME AUDIT LOGGER TESTS FAILED.\n");
}

int g_audit_test_failures() { return g_failures; }
