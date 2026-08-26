#include "rin/qr_code.hpp"

#include <qrencode.h>

#include <cstring>
#include <fstream>

namespace rin {

QrImage QrCode::encode(const std::string& data) {
    // QRcode_encodeData (not encodeString) so arbitrary bytes -- including
    // JSON's quotes, braces, colons -- go through 8-bit mode untouched
    // rather than being run through the alphanumeric-mode character
    // filter (which only supports a restricted character set and would
    // silently corrupt or reject our token JSON).
    QRcode* qr = QRcode_encodeData(static_cast<int>(data.size()),
                                    reinterpret_cast<const unsigned char*>(data.data()),
                                    0,  // version 0 = auto-select smallest that fits
                                    QR_ECLEVEL_M);  // M: reasonable balance for a screen-to-camera scan
    if (!qr) {
        throw QrCodeException(
            "QR encoding failed -- join token is likely too large for a single QR symbol "
            "(size was " + std::to_string(data.size()) + " bytes)");
    }

    QrImage image;
    image.module_count = qr->width;
    image.modules.resize(static_cast<size_t>(qr->width) * qr->width);
    for (int i = 0; i < qr->width * qr->width; ++i) {
        // Per qrencode.h's bitfield doc: bit 0 of each byte is the actual
        // dark/light value; the other bits are debug/structural info we
        // don't care about here.
        image.modules[static_cast<size_t>(i)] = qr->data[i] & 0x01;
    }

    QRcode_free(qr);
    return image;
}

std::vector<uint8_t> QrCode::render_grayscale(const QrImage& qr, int scale, int quiet_zone_modules,
                                                int* out_width, int* out_height) {
    if (qr.module_count <= 0) throw QrCodeException("render_grayscale: empty QR image");
    if (scale < 1) scale = 1;
    if (quiet_zone_modules < 0) quiet_zone_modules = 0;

    int total_modules = qr.module_count + 2 * quiet_zone_modules;
    int pixel_size = total_modules * scale;

    std::vector<uint8_t> pixels(static_cast<size_t>(pixel_size) * pixel_size, 255);  // start all-white

    for (int y = 0; y < qr.module_count; ++y) {
        for (int x = 0; x < qr.module_count; ++x) {
            if (qr.modules[static_cast<size_t>(y) * qr.module_count + x] == 0) continue;  // white module, already filled

            int px0 = (x + quiet_zone_modules) * scale;
            int py0 = (y + quiet_zone_modules) * scale;
            for (int dy = 0; dy < scale; ++dy) {
                uint8_t* row = &pixels[static_cast<size_t>(py0 + dy) * pixel_size + px0];
                std::memset(row, 0, static_cast<size_t>(scale));  // black
            }
        }
    }

    if (out_width) *out_width = pixel_size;
    if (out_height) *out_height = pixel_size;
    return pixels;
}

void QrCode::save_as_bmp(const std::string& data, const std::string& file_path, int scale) {
    QrImage qr = encode(data);
    int width = 0, height = 0;
    std::vector<uint8_t> gray = render_grayscale(qr, scale, 4, &width, &height);

    // Minimal 8-bit grayscale BMP writer (BITMAPFILEHEADER + BITMAPINFOHEADER
    // + a 256-entry grayscale palette + row data). BMP rows are padded to a
    // 4-byte boundary and stored bottom-to-top -- both handled below.
    int row_padded = (width + 3) & ~3;
    uint32_t palette_bytes = 256 * 4;
    uint32_t pixel_data_offset = 14 + 40 + palette_bytes;
    uint32_t file_size = pixel_data_offset + static_cast<uint32_t>(row_padded) * height;

    std::ofstream out(file_path, std::ios::binary);
    if (!out) throw QrCodeException("save_as_bmp: could not open '" + file_path + "' for writing");

    auto write_u16 = [&](uint16_t v) { out.write(reinterpret_cast<char*>(&v), 2); };
    auto write_u32 = [&](uint32_t v) { out.write(reinterpret_cast<char*>(&v), 4); };
    auto write_i32 = [&](int32_t v) { out.write(reinterpret_cast<char*>(&v), 4); };

    // BITMAPFILEHEADER
    out.write("BM", 2);
    write_u32(file_size);
    write_u32(0);  // reserved
    write_u32(pixel_data_offset);

    // BITMAPINFOHEADER
    write_u32(40);            // header size
    write_i32(width);
    write_i32(height);
    write_u16(1);              // planes
    write_u16(8);              // bits per pixel
    write_u32(0);              // no compression
    write_u32(static_cast<uint32_t>(row_padded) * height);
    write_i32(2835);           // ~72 DPI
    write_i32(2835);
    write_u32(256);            // palette entries used
    write_u32(0);              // all colors important

    // Grayscale palette: index i -> (i, i, i, 0)
    for (int i = 0; i < 256; ++i) {
        char entry[4] = {static_cast<char>(i), static_cast<char>(i), static_cast<char>(i), 0};
        out.write(entry, 4);
    }

    // Pixel data, bottom-to-top, each row padded to 4 bytes.
    std::vector<uint8_t> pad_row(static_cast<size_t>(row_padded), 255);
    for (int y = height - 1; y >= 0; --y) {
        std::vector<uint8_t> row(pad_row);
        std::memcpy(row.data(), &gray[static_cast<size_t>(y) * width], static_cast<size_t>(width));
        out.write(reinterpret_cast<char*>(row.data()), row_padded);
    }
}

}  // namespace rin
