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

std::vector<uint8_t> base64_decode(const std::string& encoded) {
    if (encoded.empty()) return {};
    // Strip any whitespace defensively; EVP_DecodeBlock does not tolerate it.
    std::string clean;
    clean.reserve(encoded.size());
    for (char c : encoded) {
        if (c != '\n' && c != '\r' && c != ' ') clean.push_back(c);
    }

    std::vector<uint8_t> out(3 * (clean.size() / 4) + 3);
    int len = EVP_DecodeBlock(out.data(), reinterpret_cast<const uint8_t*>(clean.data()),
                               static_cast<int>(clean.size()));
    if (len < 0) {
        throw CryptoException("base64_decode: malformed input");
    }

    // EVP_DecodeBlock does not account for '=' padding -- trim manually.
    size_t padding = 0;
    if (clean.size() >= 1 && clean[clean.size() - 1] == '=') padding++;
    if (clean.size() >= 2 && clean[clean.size() - 2] == '=') padding++;
    out.resize(static_cast<size_t>(len) - padding);
    return out;
}

}  // namespace rin
