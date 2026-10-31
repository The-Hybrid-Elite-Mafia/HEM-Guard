// HEM Guard - SHA-256 (our own small, tested implementation; no outside library).
#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace hem::guard {

class Sha256 {
public:
    Sha256();
    void update(const void* data, std::size_t len);
    std::array<std::uint8_t, 32> finish();  // call once
    std::string finish_hex();

private:
    void block(const std::uint8_t* p);
    std::uint32_t h_[8];
    std::uint8_t buf_[64];
    std::size_t buf_len_ = 0;
    std::uint64_t total_ = 0;
};

std::string sha256_hex(std::string_view data);
// Returns false if the file cannot be read. size_out is set to the bytes hashed.
bool sha256_file(const std::filesystem::path& p, std::string& hex_out, std::uint64_t* size_out = nullptr);

}  // namespace hem::guard
