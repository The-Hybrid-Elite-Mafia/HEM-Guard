// HEM Guard - small shared helpers (text, paths, time, safe file moves).
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace hem::guard {

namespace fs = std::filesystem;

// Paths <-> UTF-8 text. Always use these, never path::string() (lossy on Windows).
std::string to_u8(const fs::path& p);
fs::path from_u8(std::string_view s);

std::string to_lower_ascii(std::string_view s);
std::string trim(std::string_view s);
std::vector<std::string> split(std::string_view s, char sep);
bool ends_with_icase(std::string_view s, std::string_view suffix);

std::string hex_encode(const std::uint8_t* data, std::size_t n);
// Accepts upper/lower case and spaces. Returns false on odd length or non-hex.
bool hex_decode(std::string_view text, std::vector<std::uint8_t>& out);

// Tab-separated manifest fields: escapes \\ \t \n \r.
std::string tsv_escape(std::string_view s);
std::string tsv_unescape(std::string_view s);

std::int64_t unix_now();
std::string format_time_utc(std::int64_t unix_seconds);  // "2026-10-31 13:09:00Z"
std::string format_bytes(std::uint64_t n);               // "12.3 MB"

// Lexical, case-insensitive on Windows. child == parent counts as "within".
bool path_is_within(const fs::path& child, const fs::path& parent);
// Absolute + canonical where possible. Never throws.
fs::path normalize_path(const fs::path& p);
bool is_filesystem_root(const fs::path& p);

// Whole-file text helpers for small files. Never throw.
bool read_text_file(const fs::path& p, std::string& out, std::uint64_t max_bytes = 64ull * 1024 * 1024);
bool write_text_file(const fs::path& p, std::string_view data);
bool append_text_file(const fs::path& p, std::string_view data);

// Moves a file. Tries a plain rename first; if that fails (other drive) it copies,
// checks the size, then removes the source. If removing the source fails, the copy
// is removed again so you never end up with two. Never overwrites an existing target.
bool move_file_safe(const fs::path& from, const fs::path& to, std::string& error);

// '*' and '?' wildcard match, case-insensitive.
bool glob_match(std::string_view pattern, std::string_view text);

// Quotes one argument the way Windows programs read their command line.
std::string quote_windows_arg(std::string_view arg);

// Random lower-case hex of n characters.
std::string random_hex(std::size_t n);

}  // namespace hem::guard
