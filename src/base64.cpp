#include "rin/crypto.hpp"

#include <openssl/evp.h>

namespace rin {

// Matches java.util.Base64.getEncoder()/getDecoder() -- standard alphabet,
// with padding. OpenSSL's EVP_Encode/DecodeBlock use the same alphabet.
std::string base64_encode(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";
    // EVP_EncodeBlock output size: ((n + 2) / 3) * 4, plus room for the
    // implicit null terminator it writes.
    std::vector<uint8_t> out(4 * ((data.size() + 2) / 3) + 1);
    int len = EVP_EncodeBlock(out.data(), data.data(), static_cast<int>(data.size()));
    return std::string(reinterpret_cast<char*>(out.data()), len);
}

namespace {
// EVP_DecodeBlock's handling of characters outside the base64 alphabet is
// NOT consistently specified/validated across OpenSSL versions and builds
// (some versions/table configurations reject them via a negative return,
// others silently decode them as if they were 'A'). Relying on its return
// code alone to detect malformed input is therefore not portable -- do the
// alphabet check ourselves so behavior can't drift out from under us
// depending on which OpenSSL we're linked against.
bool is_base64_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
}
}  // namespace

std::vector<uint8_t> base64_decode(const std::string& encoded) {
    if (encoded.empty()) return {};
    // Strip any whitespace defensively; EVP_DecodeBlock does not tolerate it.
    std::string clean;
    clean.reserve(encoded.size());
    for (char c : encoded) {
        if (c != '\n' && c != '\r' && c != ' ') clean.push_back(c);
    }

    if (clean.empty() || clean.size() % 4 != 0) {
        throw CryptoException("base64_decode: malformed input (bad length)");
    }

    // Padding ('=') is only ever valid in the last two positions. Validate
    // every other character strictly against the base64 alphabet ourselves
    // -- do not trust EVP_DecodeBlock to reject bad characters, since that
    // behavior isn't guaranteed portable across OpenSSL versions/builds.
    size_t padding = 0;
    if (clean[clean.size() - 1] == '=') padding++;
    if (clean.size() >= 2 && clean[clean.size() - 2] == '=') padding++;
    for (size_t i = 0; i < clean.size() - padding; ++i) {
        if (!is_base64_char(clean[i])) {
            throw CryptoException("base64_decode: malformed input (invalid character)");
        }
    }

    std::vector<uint8_t> out(3 * (clean.size() / 4) + 3);
    int len = EVP_DecodeBlock(out.data(), reinterpret_cast<const uint8_t*>(clean.data()),
                               static_cast<int>(clean.size()));
    if (len < 0 || static_cast<size_t>(len) < padding) {
        throw CryptoException("base64_decode: malformed input");
    }

    // EVP_DecodeBlock does not account for '=' padding -- trim manually.
    out.resize(static_cast<size_t>(len) - padding);
    return out;
}

}  // namespace rin
