#pragma once
// Cryptographic engine.
//
// MUST stay in exact behavioral sync with the Android side:
//   app/src/main/java/com/example/core/crypto/CryptoEngine.kt (post-fix version)
//
// Design principles carried over from Android, non-negotiable:
//  - Device identity: NIST P-256 (secp256r1) EC keypairs.
//  - Signatures: SHA256withECDSA only. No HMAC fallback, no hash fallback.
//    A signature that doesn't verify is REJECTED, full stop.
//  - Encryption: AES-256-GCM only. No plaintext fallback on failure.
//    Any encrypt/decrypt failure throws/returns an error -- never silently
//    degrades to something weaker or unauthenticated.
//  - Session keys: ECDH (P-256) + HKDF-SHA256 (RFC 5869), per-peer, salted
//    with the session ID for forward secrecy.
//  - Mesh group key: HKDF over a real random per-mesh secret (meshSecret),
//    NOT derived from the public mesh name alone.
//
// This project uses OpenSSL (EVP_PKEY / EC / HKDF) rather than libsodium,
// since Android's implementation is JCA/BouncyCastle-backed EC + AES-GCM,
// not libsodium's Ed25519/X25519 -- OpenSSL's EC P-256 primitives are the
// natural match for wire compatibility. See DESIGN_NOTES.md.

#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace rin {

// Thrown by every crypto operation on failure. There is deliberately no
// error code / bool-return path for signing, verification failure, or
// decryption -- callers must handle this exception. This mirrors
// CryptoEngine.kt's CryptoException fail-closed contract.
class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& message) : std::runtime_error(message) {}
};

struct KeyPair {
    std::string public_key_b64;   // X.509 SubjectPublicKeyInfo, base64
    std::string private_key_b64;  // PKCS8, base64
    std::string fingerprint;      // "key:xxxxxx...yyyy"
};

class CryptoEngine {
public:
    // -- Identity -----------------------------------------------------
    static KeyPair generate_identity_keypair();

    // 256-bit random secret, hex-encoded. Used as a mesh's real secret
    // (MeshEntity.meshSecret on Android), transmitted only inside the
    // QR join token, never derived from public info.
    static std::string generate_ephemeral_secret();

    static std::string generate_ephemeral_token();  // "rin_join_<32 hex chars>"
    static std::string generate_session_id();       // "sess_<16 hex chars>"

    // -- HKDF (RFC 5869) ------------------------------------------------
    static std::vector<uint8_t> hkdf_extract(const std::vector<uint8_t>& salt,
                                              const std::vector<uint8_t>& ikm);
    static std::vector<uint8_t> hkdf_expand(const std::vector<uint8_t>& prk,
                                             const std::vector<uint8_t>& info,
                                             size_t length = 32);
    static std::array<uint8_t, 32> hkdf_derive_key(const std::vector<uint8_t>& ikm,
                                                    const std::vector<uint8_t>& salt,
                                                    const std::string& info);

    // -- ECDH + session keys -------------------------------------------
    // Throws CryptoException on any failure (malformed keys, curve mismatch).
    static std::vector<uint8_t> compute_ecdh_shared_secret(const std::string& local_private_key_b64,
                                                             const std::string& remote_public_key_b64);

    // Per-peer AES-256 session key. session_id (if present) salts the HKDF,
    // exactly like Android's derivePeerSessionKey.
    static std::array<uint8_t, 32> derive_peer_session_key(
        const std::string& local_private_key_b64,
        const std::string& remote_public_key_b64,
        const std::optional<std::string>& session_id = std::nullopt);

    // Mesh-wide broadcast key. mesh_secret should be the mesh's real
    // random secret; an empty mesh_secret falls back to SHA-256(mesh_name)
    // for legacy-mesh compatibility only -- this fallback is NOT a secret
    // (mesh_name is shown on screen / in the QR payload) and should not be
    // relied on for anything beyond talking to old Android installs.
    static std::array<uint8_t, 32> derive_mesh_encryption_key(const std::string& mesh_secret,
                                                                const std::string& mesh_name);

    // -- Signatures (strict, fail-closed) --------------------------------
    // Returns "ecdsa:<base64 DER signature>". Throws CryptoException on failure.
    static std::string sign(const std::string& data, const std::string& private_key_b64);

    // Returns false on ANY problem: missing "ecdsa:" prefix, malformed key,
    // malformed signature, or mathematically invalid signature. Never throws --
    // this is the one operation that must be a safe bool for callers on the
    // hot path (every incoming packet gets verified before anything else runs).
    static bool verify(const std::string& data, const std::string& signature,
                        const std::string& public_key_b64);

    // -- AES-256-GCM (strict, fail-closed) -------------------------------
    // Wire format: base64( IV[12 bytes] || ciphertext || GCM tag[16 bytes] ).
    // Throws CryptoException on any failure. No AAD is used by the current
    // Android implementation (aad param kept for future compatibility).
    static std::string encrypt_payload(const std::string& plaintext,
                                        const std::array<uint8_t, 32>& key,
                                        const std::vector<uint8_t>* aad = nullptr);

    static std::string decrypt_payload(const std::string& ciphertext_b64,
                                        const std::array<uint8_t, 32>& key,
                                        const std::vector<uint8_t>* aad = nullptr);

private:
    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
};

// -- base64 helpers (standard alphabet, matches java.util.Base64) --------
std::string base64_encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> base64_decode(const std::string& encoded);

}  // namespace rin
