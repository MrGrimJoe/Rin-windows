// Crypto engine tests.
//
// Two jobs here:
//  1. Prove round-trip correctness (sign/verify, encrypt/decrypt, ECDH
//     agreement, HKDF) in isolation.
//  2. Prove the fail-closed guarantees actually hold: tampered
//     ciphertext, wrong keys, and malformed signatures must be REJECTED,
//     not silently accepted or degraded. This is the whole reason the
//     Android side was rewritten, so it's the most important thing to
//     verify here.
//
// This intentionally does not (and cannot, without a JVM) test byte-for-
// byte interop against the real Android CryptoEngine.kt. What it proves
// instead: given a keypair generated on ONE side, standard JCA-compatible
// EC P-256 / ECDSA / ECDH / AES-GCM primitives interoperate -- because
// both sides use the same standards (X.509 SPKI, PKCS8, SHA256withECDSA,
// AES/GCM/NoPadding with a 12-byte IV + 16-byte tag), not a custom format.
// See DESIGN_NOTES.md for the cross-language verification plan.

#include "rin/crypto.hpp"

#include <cassert>
#include <functional>
#include <iostream>

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

void expect_throws(const std::function<void()>& fn, const std::string& name) {
    try {
        fn();
        std::cout << "  [FAIL] " << name << " (expected CryptoException, none thrown)\n";
        g_failures++;
    } catch (const CryptoException&) {
        std::cout << "  [PASS] " << name << "\n";
    } catch (const std::exception& e) {
        std::cout << "  [FAIL] " << name << " (wrong exception type: " << e.what() << ")\n";
        g_failures++;
    }
}
}  // namespace

void run_crypto_tests() {
    std::cout << "\n== Crypto tests ==\n";

    // -- Identity generation --------------------------------------------
    KeyPair alice = CryptoEngine::generate_identity_keypair();
    KeyPair bob = CryptoEngine::generate_identity_keypair();
    check(!alice.public_key_b64.empty() && !alice.private_key_b64.empty(), "keypair generation produces keys");
    check(alice.public_key_b64 != bob.public_key_b64, "two keypairs are distinct");
    check(alice.fingerprint.rfind("key:", 0) == 0, "fingerprint has expected prefix");

    // -- base64 round-trip -----------------------------------------------
    {
        std::vector<uint8_t> data = {0, 1, 2, 3, 250, 251, 252, 253, 254, 255};
        std::string encoded = base64_encode(data);
        std::vector<uint8_t> decoded = base64_decode(encoded);
        check(decoded == data, "base64 round-trip preserves arbitrary bytes");
    }

    // -- Signatures: strict ECDSA, fail-closed ---------------------------
    {
        std::string data = "hello mesh";
        std::string sig = CryptoEngine::sign(data, alice.private_key_b64);
        check(sig.rfind("ecdsa:", 0) == 0, "signature has ecdsa: prefix");
        check(CryptoEngine::verify(data, sig, alice.public_key_b64), "valid signature verifies");
        check(!CryptoEngine::verify(data, sig, bob.public_key_b64), "signature rejected under wrong public key");
        check(!CryptoEngine::verify("tampered data", sig, alice.public_key_b64),
              "signature rejected when data is tampered");
        check(!CryptoEngine::verify(data, "hmac:deadbeef", alice.public_key_b64),
              "non-ecdsa-prefixed signature is rejected outright (no fallback)");
        check(!CryptoEngine::verify(data, "", alice.public_key_b64), "empty signature rejected");
        check(!CryptoEngine::verify(data, sig, ""), "empty public key rejected");
        check(!CryptoEngine::verify(data, "ecdsa:not-valid-base64!!!", alice.public_key_b64),
              "malformed base64 in signature does not throw, just fails");
    }

    expect_throws([&] { CryptoEngine::sign("data", "not a valid private key"); },
                  "sign() throws CryptoException on invalid private key (fail closed, no fallback)");

    // -- AES-256-GCM: strict, fail-closed ----------------------------------
    {
        auto key = CryptoEngine::hkdf_derive_key({1, 2, 3, 4}, {5, 6, 7, 8}, "test-info");
        std::string plaintext = "the quick brown fox jumps over the lazy dog";
        std::string ct = CryptoEngine::encrypt_payload(plaintext, key);
        std::string pt = CryptoEngine::decrypt_payload(ct, key);
        check(pt == plaintext, "AES-GCM round-trip preserves plaintext");

        std::array<uint8_t, 32> wrong_key = key;
        wrong_key[0] ^= 0xFF;
        bool threw = false;
        try {
            CryptoEngine::decrypt_payload(ct, wrong_key);
        } catch (const CryptoException&) {
            threw = true;
        }
        check(threw, "decrypt throws (not silently wrong-plaintext) under wrong key");

        // Tamper with one byte of the base64 ciphertext body.
        std::string tampered = ct;
        size_t mid = tampered.size() / 2;
        tampered[mid] = (tampered[mid] == 'A') ? 'B' : 'A';
        bool tamper_threw = false;
        try {
            CryptoEngine::decrypt_payload(tampered, key);
        } catch (const CryptoException&) {
            tamper_threw = true;
        }
        check(tamper_threw, "decrypt throws on tampered ciphertext (GCM auth tag catches it)");

        expect_throws([&] { CryptoEngine::decrypt_payload("dG9vc2hvcnQ=", key); },
                      "decrypt throws on too-short ciphertext rather than returning garbage");

        expect_throws([&] { CryptoEngine::decrypt_payload("not valid base64 at all!!", key); },
                      "decrypt throws on malformed base64 rather than returning input verbatim");
    }

    // -- ECDH + HKDF session keys -------------------------------------------
    {
        auto alice_shared = CryptoEngine::compute_ecdh_shared_secret(alice.private_key_b64, bob.public_key_b64);
        auto bob_shared = CryptoEngine::compute_ecdh_shared_secret(bob.private_key_b64, alice.public_key_b64);
        check(alice_shared == bob_shared, "ECDH shared secret matches from both sides");

        auto alice_session = CryptoEngine::derive_peer_session_key(alice.private_key_b64, bob.public_key_b64, "sess_1");
        auto bob_session = CryptoEngine::derive_peer_session_key(bob.private_key_b64, alice.public_key_b64, "sess_1");
        check(alice_session == bob_session, "derived peer session key matches from both sides");

        auto different_session =
            CryptoEngine::derive_peer_session_key(alice.private_key_b64, bob.public_key_b64, "sess_2");
        check(alice_session != different_session, "different session_id salts produce different keys (forward secrecy)");

        // Use one side's session key to actually encrypt/decrypt cross-party.
        std::string msg = "cross-party ECDH session test";
        std::string ct = CryptoEngine::encrypt_payload(msg, alice_session);
        std::string pt = CryptoEngine::decrypt_payload(ct, bob_session);
        check(pt == msg, "message encrypted with Alice's derived key decrypts with Bob's derived key");
    }

    expect_throws(
        [&] { CryptoEngine::compute_ecdh_shared_secret(alice.private_key_b64, "garbage-not-a-key"); },
        "ECDH throws CryptoException on malformed peer public key");

    // -- Mesh group key ------------------------------------------------
    {
        std::string secret = CryptoEngine::generate_ephemeral_secret();
        auto key1 = CryptoEngine::derive_mesh_encryption_key(secret, "Ali's Devices");
        auto key2 = CryptoEngine::derive_mesh_encryption_key(secret, "Ali's Devices");
        check(key1 == key2, "mesh key derivation is deterministic given the same secret+name");

        auto key_other_mesh = CryptoEngine::derive_mesh_encryption_key(secret, "Different Mesh");
        check(key1 != key_other_mesh, "different mesh names produce different keys even with same secret");

        auto key_no_secret_a = CryptoEngine::derive_mesh_encryption_key("", "Legacy Mesh");
        auto key_no_secret_b = CryptoEngine::derive_mesh_encryption_key("", "Legacy Mesh");
        check(key_no_secret_a == key_no_secret_b,
              "legacy empty-secret fallback is at least deterministic (still NOT a real secret -- see docs)");
    }

    // -- Ephemeral token/session ID formats ------------------------------
    {
        std::string token = CryptoEngine::generate_ephemeral_token();
        check(token.rfind("rin_join_", 0) == 0, "ephemeral token has expected prefix");
        std::string session = CryptoEngine::generate_session_id();
        check(session.rfind("sess_", 0) == 0, "session ID has expected prefix");
        check(CryptoEngine::generate_session_id() != session, "session IDs are not repeated");
    }

    std::cout << (g_failures == 0 ? "All crypto tests passed.\n" : "SOME CRYPTO TESTS FAILED.\n");
}

int g_crypto_test_failures() { return g_failures; }
