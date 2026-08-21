#include "rin/crypto.hpp"

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <cstring>
#include <memory>
#include <sstream>

namespace rin {

namespace {

// RAII wrappers so every OpenSSL error path (which we hit a LOT of, since
// everything here is fail-closed) can't leak a key/context/cipher handle.
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

EvpPkeyPtr make_pkey() { return EvpPkeyPtr(EVP_PKEY_new(), EVP_PKEY_free); }

[[noreturn]] void throw_openssl_error(const std::string& context) {
    unsigned long err = ERR_get_error();
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    throw CryptoException(context + ": " + buf);
}

// Loads a PKCS8 DER-encoded EC private key (what Java's
// PKCS8EncodedKeySpec + Base64 produces).
EvpPkeyPtr load_private_key(const std::string& private_key_b64) {
    std::vector<uint8_t> der = base64_decode(private_key_b64);
    const uint8_t* p = der.data();
    EVP_PKEY* raw = d2i_AutoPrivateKey(nullptr, &p, static_cast<long>(der.size()));
    if (!raw) throw_openssl_error("load_private_key: invalid PKCS8 EC key");
    return EvpPkeyPtr(raw, EVP_PKEY_free);
}

// Loads an X.509 SubjectPublicKeyInfo DER-encoded EC public key (what
// Java's X509EncodedKeySpec + Base64 produces).
EvpPkeyPtr load_public_key(const std::string& public_key_b64) {
    std::vector<uint8_t> der = base64_decode(public_key_b64);
    const uint8_t* p = der.data();
    EVP_PKEY* raw = d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size()));
    if (!raw) throw_openssl_error("load_public_key: invalid X.509 EC key");
    return EvpPkeyPtr(raw, EVP_PKEY_free);
}

}  // namespace

// ---------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------

KeyPair CryptoEngine::generate_identity_keypair() {
    EvpPkeyCtxPtr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
    if (!pctx) throw_openssl_error("generate_identity_keypair: ctx");

    if (EVP_PKEY_keygen_init(pctx.get()) <= 0)
        throw_openssl_error("generate_identity_keypair: keygen_init");

    // NIST P-256 == secp256r1 -- the exact curve Android requests via
    // ECGenParameterSpec("secp256r1").
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1) <= 0)
        throw_openssl_error("generate_identity_keypair: set curve");

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &raw) <= 0)
        throw_openssl_error("generate_identity_keypair: keygen");
    EvpPkeyPtr pkey(raw, EVP_PKEY_free);

    // Serialize private key as PKCS8 DER (matches Java's getEncoded() on
    // an EC PrivateKey, which is PKCS8 by JCA convention).
    uint8_t* priv_der = nullptr;
    int priv_len = 0;
    {
        BioPtr mem(BIO_new(BIO_s_mem()), BIO_free);
        if (!i2d_PKCS8PrivateKeyInfo_bio(mem.get(), pkey.get()))
            throw_openssl_error("generate_identity_keypair: serialize private key");
        BUF_MEM* bptr = nullptr;
        BIO_get_mem_ptr(mem.get(), &bptr);
        priv_len = static_cast<int>(bptr->length);
        priv_der = static_cast<uint8_t*>(OPENSSL_malloc(priv_len));
        std::memcpy(priv_der, bptr->data, priv_len);
    }

    // Serialize public key as X.509 SubjectPublicKeyInfo DER (matches
    // Java's getEncoded() on an EC PublicKey).
    int pub_len = i2d_PUBKEY(pkey.get(), nullptr);
    if (pub_len <= 0) throw_openssl_error("generate_identity_keypair: pub size");
    std::vector<uint8_t> pub_der(pub_len);
    uint8_t* pub_p = pub_der.data();
    if (i2d_PUBKEY(pkey.get(), &pub_p) <= 0) {
        throw_openssl_error("generate_identity_keypair: serialize public key");
    }

    std::vector<uint8_t> priv_vec(priv_der, priv_der + priv_len);
    OPENSSL_free(priv_der);

    KeyPair kp;
    kp.public_key_b64 = base64_encode(pub_der);
    kp.private_key_b64 = base64_encode(priv_vec);

    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(pub_der.data(), pub_der.size(), digest);
    std::string hex = bytes_to_hex(std::vector<uint8_t>(digest, digest + SHA256_DIGEST_LENGTH));
    kp.fingerprint = "key:" + hex.substr(0, 6) + "..." + hex.substr(hex.size() - 4);

    return kp;
}

std::string CryptoEngine::generate_ephemeral_secret() {
    uint8_t buf[32];
    if (RAND_bytes(buf, sizeof(buf)) != 1) throw_openssl_error("generate_ephemeral_secret");
    return bytes_to_hex(std::vector<uint8_t>(buf, buf + sizeof(buf)));
}

std::string CryptoEngine::generate_ephemeral_token() {
    uint8_t buf[16];
    if (RAND_bytes(buf, sizeof(buf)) != 1) throw_openssl_error("generate_ephemeral_token");
    return "rin_join_" + bytes_to_hex(std::vector<uint8_t>(buf, buf + sizeof(buf)));
}

std::string CryptoEngine::generate_session_id() {
    uint8_t buf[8];
    if (RAND_bytes(buf, sizeof(buf)) != 1) throw_openssl_error("generate_session_id");
    return "sess_" + bytes_to_hex(std::vector<uint8_t>(buf, buf + sizeof(buf)));
}

// ---------------------------------------------------------------------
// HKDF (RFC 5869) -- hand-rolled to match CryptoEngine.kt's own manual
// HMAC-based implementation exactly (same salt-empty behavior, same
// counter-based expand loop), rather than relying on OpenSSL's HKDF EVP_KDF
// (whose empty-salt handling differs across OpenSSL versions).
// ---------------------------------------------------------------------

namespace {
std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
    unsigned int len = 0;
    uint8_t out[EVP_MAX_MD_SIZE];
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out,
              &len)) {
        throw_openssl_error("hmac_sha256");
    }
    return std::vector<uint8_t>(out, out + len);
}
}  // namespace

std::vector<uint8_t> CryptoEngine::hkdf_extract(const std::vector<uint8_t>& salt,
                                                 const std::vector<uint8_t>& ikm) {
    // Kotlin: effectiveSalt = 32 zero bytes if salt is null/empty.
    std::vector<uint8_t> effective_salt = salt;
    if (effective_salt.empty()) effective_salt.assign(32, 0);
    return hmac_sha256(effective_salt, ikm);
}

std::vector<uint8_t> CryptoEngine::hkdf_expand(const std::vector<uint8_t>& prk,
                                                const std::vector<uint8_t>& info, size_t length) {
    std::vector<uint8_t> result;
    result.reserve(length);
    std::vector<uint8_t> t;
    uint8_t counter = 1;

    while (result.size() < length) {
        std::vector<uint8_t> input;
        input.insert(input.end(), t.begin(), t.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);
        t = hmac_sha256(prk, input);
        size_t to_copy = std::min(t.size(), length - result.size());
        result.insert(result.end(), t.begin(), t.begin() + static_cast<long>(to_copy));
        counter++;
    }
    return result;
}

std::array<uint8_t, 32> CryptoEngine::hkdf_derive_key(const std::vector<uint8_t>& ikm,
                                                       const std::vector<uint8_t>& salt,
                                                       const std::string& info) {
    std::vector<uint8_t> prk = hkdf_extract(salt, ikm);
    std::vector<uint8_t> okm =
        hkdf_expand(prk, std::vector<uint8_t>(info.begin(), info.end()), 32);
    std::array<uint8_t, 32> key{};
    std::copy(okm.begin(), okm.end(), key.begin());
    return key;
}

// ---------------------------------------------------------------------
// ECDH
// ---------------------------------------------------------------------

std::vector<uint8_t> CryptoEngine::compute_ecdh_shared_secret(const std::string& local_private_key_b64,
                                                                const std::string& remote_public_key_b64) {
    try {
        EvpPkeyPtr priv = load_private_key(local_private_key_b64);
        EvpPkeyPtr pub = load_public_key(remote_public_key_b64);

        EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(priv.get(), nullptr), EVP_PKEY_CTX_free);
        if (!ctx) throw_openssl_error("compute_ecdh_shared_secret: ctx");
        if (EVP_PKEY_derive_init(ctx.get()) <= 0) throw_openssl_error("compute_ecdh_shared_secret: derive_init");
        if (EVP_PKEY_derive_set_peer(ctx.get(), pub.get()) <= 0)
            throw_openssl_error("compute_ecdh_shared_secret: set_peer");

        size_t secret_len = 0;
        if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) <= 0)
            throw_openssl_error("compute_ecdh_shared_secret: derive size");
        std::vector<uint8_t> secret(secret_len);
        if (EVP_PKEY_derive(ctx.get(), secret.data(), &secret_len) <= 0)
            throw_openssl_error("compute_ecdh_shared_secret: derive");
        secret.resize(secret_len);
        return secret;
    } catch (const CryptoException&) {
        throw;
    } catch (const std::exception& e) {
        throw CryptoException(std::string("compute_ecdh_shared_secret failed: ") + e.what());
    }
}

std::array<uint8_t, 32> CryptoEngine::derive_peer_session_key(
    const std::string& local_private_key_b64, const std::string& remote_public_key_b64,
    const std::optional<std::string>& session_id) {
    std::vector<uint8_t> shared_secret =
        compute_ecdh_shared_secret(local_private_key_b64, remote_public_key_b64);
    std::vector<uint8_t> salt;
    if (session_id.has_value()) {
        salt.assign(session_id->begin(), session_id->end());
    }
    static const std::string kInfo = "rin-p2p-session-key-v1";
    return hkdf_derive_key(shared_secret, salt, kInfo);
}

std::array<uint8_t, 32> CryptoEngine::derive_mesh_encryption_key(const std::string& mesh_secret,
                                                                   const std::string& mesh_name) {
    std::vector<uint8_t> ikm;
    if (!mesh_secret.empty()) {
        ikm.assign(mesh_secret.begin(), mesh_secret.end());
    } else {
        // Legacy-mesh fallback ONLY -- see header doc comment. Not a real
        // secret; anyone who can see the mesh name can derive this.
        uint8_t digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const uint8_t*>(mesh_name.data()), mesh_name.size(), digest);
        std::string seed =
            "rin_seed_" + bytes_to_hex(std::vector<uint8_t>(digest, digest + SHA256_DIGEST_LENGTH));
        ikm.assign(seed.begin(), seed.end());
    }
    std::vector<uint8_t> salt(mesh_name.begin(), mesh_name.end());
    static const std::string kInfo = "rin-mesh-broadcast-v1";
    return hkdf_derive_key(ikm, salt, kInfo);
}

// ---------------------------------------------------------------------
// Signatures -- strict ECDSA, fail closed
// ---------------------------------------------------------------------

std::string CryptoEngine::sign(const std::string& data, const std::string& private_key_b64) {
    try {
        EvpPkeyPtr priv = load_private_key(private_key_b64);

        EvpMdCtxPtr mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!mdctx) throw_openssl_error("sign: mdctx");
        if (EVP_DigestSignInit(mdctx.get(), nullptr, EVP_sha256(), nullptr, priv.get()) <= 0)
            throw_openssl_error("sign: DigestSignInit");
        if (EVP_DigestSignUpdate(mdctx.get(), data.data(), data.size()) <= 0)
            throw_openssl_error("sign: DigestSignUpdate");

        size_t sig_len = 0;
        if (EVP_DigestSignFinal(mdctx.get(), nullptr, &sig_len) <= 0)
            throw_openssl_error("sign: size query");
        std::vector<uint8_t> sig(sig_len);
        if (EVP_DigestSignFinal(mdctx.get(), sig.data(), &sig_len) <= 0)
            throw_openssl_error("sign: DigestSignFinal");
        sig.resize(sig_len);

        return "ecdsa:" + base64_encode(sig);
    } catch (const CryptoException&) {
        throw;
    } catch (const std::exception& e) {
        throw CryptoException(std::string("ECDSA signing failed: ") + e.what());
    }
}

bool CryptoEngine::verify(const std::string& data, const std::string& signature,
                           const std::string& public_key_b64) {
    if (signature.empty() || public_key_b64.empty()) return false;
    static const std::string kPrefix = "ecdsa:";
    if (signature.rfind(kPrefix, 0) != 0) return false;  // reject anything non-ECDSA outright

    try {
        std::string raw_sig_b64 = signature.substr(kPrefix.size());
        std::vector<uint8_t> sig_bytes = base64_decode(raw_sig_b64);
        EvpPkeyPtr pub = load_public_key(public_key_b64);

        EvpMdCtxPtr mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!mdctx) return false;
        if (EVP_DigestVerifyInit(mdctx.get(), nullptr, EVP_sha256(), nullptr, pub.get()) <= 0)
            return false;
        if (EVP_DigestVerifyUpdate(mdctx.get(), data.data(), data.size()) <= 0) return false;

        int rc = EVP_DigestVerifyFinal(mdctx.get(), sig_bytes.data(), sig_bytes.size());
        return rc == 1;
    } catch (...) {
        return false;  // any parse/format problem == not verified, never throw
    }
}

// ---------------------------------------------------------------------
// AES-256-GCM -- strict, fail closed
// ---------------------------------------------------------------------

namespace {
constexpr int kGcmIvBytes = 12;
constexpr int kGcmTagBytes = 16;
constexpr int kMinCiphertextBytes = kGcmIvBytes + kGcmTagBytes;
}  // namespace

std::string CryptoEngine::encrypt_payload(const std::string& plaintext,
                                           const std::array<uint8_t, 32>& key,
                                           const std::vector<uint8_t>* aad) {
    try {
        uint8_t iv[kGcmIvBytes];
        if (RAND_bytes(iv, sizeof(iv)) != 1) throw_openssl_error("encrypt_payload: IV gen");

        EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) throw_openssl_error("encrypt_payload: ctx");
        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0)
            throw_openssl_error("encrypt_payload: init algo");
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, kGcmIvBytes, nullptr) <= 0)
            throw_openssl_error("encrypt_payload: set IV len");
        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv) <= 0)
            throw_openssl_error("encrypt_payload: init key/iv");

        int len = 0;
        if (aad && !aad->empty()) {
            if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad->data(), static_cast<int>(aad->size())) <= 0)
                throw_openssl_error("encrypt_payload: AAD");
        }

        std::vector<uint8_t> ciphertext(plaintext.size());
        int out_len = 0;
        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len,
                               reinterpret_cast<const uint8_t*>(plaintext.data()),
                               static_cast<int>(plaintext.size())) <= 0)
            throw_openssl_error("encrypt_payload: EncryptUpdate");
        int total_len = out_len;

        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + total_len, &out_len) <= 0)
            throw_openssl_error("encrypt_payload: EncryptFinal");
        total_len += out_len;
        ciphertext.resize(total_len);

        uint8_t tag[kGcmTagBytes];
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kGcmTagBytes, tag) <= 0)
            throw_openssl_error("encrypt_payload: get tag");

        // Wire format: IV || ciphertext || tag (matches Android's
        // iv + encrypted, where Java's Cipher already appends the GCM tag
        // to the ciphertext internally).
        std::vector<uint8_t> combined;
        combined.reserve(kGcmIvBytes + ciphertext.size() + kGcmTagBytes);
        combined.insert(combined.end(), iv, iv + kGcmIvBytes);
        combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());
        combined.insert(combined.end(), tag, tag + kGcmTagBytes);

        return base64_encode(combined);
    } catch (const CryptoException&) {
        throw;
    } catch (const std::exception& e) {
        throw CryptoException(std::string("AES-256-GCM encryption failed: ") + e.what());
    }
}

std::string CryptoEngine::decrypt_payload(const std::string& ciphertext_b64,
                                           const std::array<uint8_t, 32>& key,
                                           const std::vector<uint8_t>* aad) {
    std::vector<uint8_t> decoded;
    try {
        decoded = base64_decode(ciphertext_b64);
    } catch (const std::exception& e) {
        throw CryptoException(std::string("decrypt_payload: malformed base64: ") + e.what());
    }

    if (decoded.size() < static_cast<size_t>(kMinCiphertextBytes)) {
        throw CryptoException("decrypt_payload: ciphertext too short (" +
                               std::to_string(decoded.size()) + " < " +
                               std::to_string(kMinCiphertextBytes) + " bytes)");
    }

    try {
        const uint8_t* iv = decoded.data();
        const uint8_t* body = decoded.data() + kGcmIvBytes;
        size_t body_len = decoded.size() - kGcmIvBytes;
        size_t ct_len = body_len - kGcmTagBytes;
        const uint8_t* tag = body + ct_len;

        EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) throw_openssl_error("decrypt_payload: ctx");
        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0)
            throw_openssl_error("decrypt_payload: init algo");
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, kGcmIvBytes, nullptr) <= 0)
            throw_openssl_error("decrypt_payload: set IV len");
        if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv) <= 0)
            throw_openssl_error("decrypt_payload: init key/iv");

        int out_len = 0;
        std::vector<uint8_t> plaintext(ct_len);
        if (ct_len > 0) {
            if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len, body,
                                   static_cast<int>(ct_len)) <= 0)
                throw_openssl_error("decrypt_payload: DecryptUpdate");
        }
        int total_len = out_len;

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kGcmTagBytes,
                                 const_cast<uint8_t*>(tag)) <= 0)
            throw_openssl_error("decrypt_payload: set tag");

        // Note: EVP_DecryptFinal_ex return value IS the authentication check.
        // A tampered ciphertext or wrong key causes this to return <= 0,
        // which we turn into a thrown CryptoException -- fail closed.
        int final_rc = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + total_len, &out_len);
        if (final_rc <= 0) {
            throw CryptoException("AES-256-GCM authentication failed (tampered ciphertext or wrong key)");
        }
        total_len += out_len;
        plaintext.resize(total_len);

        return std::string(plaintext.begin(), plaintext.end());
    } catch (const CryptoException&) {
        throw;
    } catch (const std::exception& e) {
        throw CryptoException(std::string("AES-256-GCM decryption failed: ") + e.what());
    }
}

std::string CryptoEngine::bytes_to_hex(const std::vector<uint8_t>& bytes) {
    static const char* hex_chars = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        result.push_back(hex_chars[b >> 4]);
        result.push_back(hex_chars[b & 0x0F]);
    }
    return result;
}

}  // namespace rin
