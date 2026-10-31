#include "hem_guard/util.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <random>
#include <system_error>

namespace hem::guard {

std::string to_u8(const fs::path& p) {
    const auto u = p.u8string();
    return std::string(reinterpret_cast<const char*>(u.data()), u.size());
}

fs::path from_u8(std::string_view s) {
    std::u8string u(reinterpret_cast<const char8_t*>(s.data()), s.size());
    return fs::path(u);
}

std::string to_lower_ascii(std::string_view s) {
    std::string r(s);
    for (auto& c : r) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return r;
}

std::string trim(std::string_view s) {
    std::size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return std::string(s.substr(a, b - a));
}

std::vector<std::string> split(std::string_view s, char sep) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (true) {
        const auto pos = s.find(sep, start);
        if (pos == std::string_view::npos) {
            out.emplace_back(s.substr(start));
            break;
        }
        out.emplace_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return out;
}

bool ends_with_icase(std::string_view s, std::string_view suffix) {
    if (suffix.size() > s.size()) return false;
    return to_lower_ascii(s.substr(s.size() - suffix.size())) == to_lower_ascii(suffix);
}

std::string hex_encode(const std::uint8_t* data, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string r;
    r.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        r.push_back(d[data[i] >> 4]);
        r.push_back(d[data[i] & 15]);
    }
    return r;
}

bool hex_decode(std::string_view text, std::vector<std::uint8_t>& out) {
    out.clear();
    int hi = -1;
    for (char c : text) {
        if (c == ' ' || c == '\t') continue;
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return false;
        if (hi < 0) hi = v;
        else {
            out.push_back(static_cast<std::uint8_t>(hi * 16 + v));
            hi = -1;
        }
    }
    return hi < 0 && !out.empty();
}

std::string tsv_escape(std::string_view s) {
    std::string r;
    for (char c : s) {
        switch (c) {
            case '\\': r += "\\\\"; break;
            case '\t': r += "\\t"; break;
            case '\n': r += "\\n"; break;
            case '\r': r += "\\r"; break;
            default: r.push_back(c);
        }
    }
    return r;
}

std::string tsv_unescape(std::string_view s) {
    std::string r;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            ++i;
            switch (s[i]) {
                case 't': r.push_back('\t'); break;
                case 'n': r.push_back('\n'); break;
                case 'r': r.push_back('\r'); break;
                default: r.push_back(s[i]);
            }
        } else {
            r.push_back(s[i]);
        }
    }
    return r;
}

std::int64_t unix_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string format_time_utc(std::int64_t t) {
    std::time_t tt = static_cast<std::time_t>(t);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    char buf[40];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02d %02d:%02d:%02dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

std::string format_bytes(std::uint64_t n) {
    const char* unit[] = {"B", "KB", "MB", "GB", "TB"};
    double v = static_cast<double>(n);
    int u = 0;
    while (v >= 1024.0 && u < 4) {
        v /= 1024.0;
        ++u;
    }
    char buf[40];
    if (u == 0) std::snprintf(buf, sizeof buf, "%llu B", static_cast<unsigned long long>(n));
    else std::snprintf(buf, sizeof buf, "%.1f %s", v, unit[u]);
    return buf;
}

namespace {
std::string fold_component(const fs::path& c) {
    std::string s = to_u8(c);
#ifdef _WIN32
    // Windows paths are case-insensitive. ASCII fold is enough for our own comparisons.
    s = to_lower_ascii(s);
#endif
    return s;
}
std::vector<std::string> components(const fs::path& p) {
    std::vector<std::string> v;
    for (const auto& c : p) {
        auto s = fold_component(c);
        if (s.empty() || s == ".") continue;
        // Treat both slash styles as separators inside a root name like "C:\\".
        while (s.size() > 1 && (s.back() == '/' || s.back() == '\\')) s.pop_back();
        v.push_back(std::move(s));
    }
    return v;
}
}  // namespace

bool path_is_within(const fs::path& child, const fs::path& parent) {
    const auto c = components(child.lexically_normal());
    const auto p = components(parent.lexically_normal());
    if (p.empty() || c.size() < p.size()) return false;
    for (std::size_t i = 0; i < p.size(); ++i) {
        if (c[i] != p[i]) return false;
    }
    return true;
}

fs::path normalize_path(const fs::path& p) {
    std::error_code ec;
    fs::path r = fs::weakly_canonical(p, ec);
    if (ec || r.empty()) {
        ec.clear();
        r = fs::absolute(p, ec);
        if (ec) return p.lexically_normal();
        return r.lexically_normal();
    }
    return r.lexically_normal();
}

bool is_filesystem_root(const fs::path& p) {
    const auto n = p.lexically_normal();
    return n.has_root_path() && n == n.root_path();
}

bool read_text_file(const fs::path& p, std::string& out, std::uint64_t max_bytes) {
    out.clear();
    std::error_code ec;
    const auto sz = fs::file_size(p, ec);
    if (ec || sz > max_bytes) return false;
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;
    out.resize(static_cast<std::size_t>(sz));
    if (sz > 0) f.read(out.data(), static_cast<std::streamsize>(sz));
    out.resize(static_cast<std::size_t>(f.gcount()));
    return true;
}

bool write_text_file(const fs::path& p, std::string_view data) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
    f.flush();
    return static_cast<bool>(f);
}

bool append_text_file(const fs::path& p, std::string_view data) {
    std::ofstream f(p, std::ios::binary | std::ios::app);
    if (!f) return false;
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
    f.flush();
    return static_cast<bool>(f);
}

bool move_file_safe(const fs::path& from, const fs::path& to, std::string& error) {
    std::error_code ec;
    if (fs::exists(fs::symlink_status(to, ec))) {
        error = "target already exists";
        return false;
    }
    ec.clear();
    fs::rename(from, to, ec);
    if (!ec) return true;

    // Probably another drive. Copy, check, then remove the source.
    ec.clear();
    const auto src_size = fs::file_size(from, ec);
    if (ec) {
        error = "cannot read source size: " + ec.message();
        return false;
    }
    ec.clear();
    if (!fs::copy_file(from, to, fs::copy_options::none, ec) || ec) {
        error = "copy failed: " + ec.message();
        std::error_code ignore;
        fs::remove(to, ignore);
        return false;
    }
    ec.clear();
    const auto dst_size = fs::file_size(to, ec);
    if (ec || dst_size != src_size) {
        error = "copy check failed (size mismatch)";
        std::error_code ignore;
        fs::remove(to, ignore);
        return false;
    }
    ec.clear();
    fs::remove(from, ec);
    if (ec) {
        // Source is locked / in use. Roll back the copy so there are not two files.
        error = "file is in use or locked: " + ec.message();
        std::error_code ignore;
        fs::remove(to, ignore);
        return false;
    }
    return true;
}

bool glob_match(std::string_view pat, std::string_view txt) {
    const std::string p = to_lower_ascii(pat), t = to_lower_ascii(txt);
    std::size_t pi = 0, ti = 0, star = std::string::npos, mark = 0;
    while (ti < t.size()) {
        if (pi < p.size() && (p[pi] == '?' || p[pi] == t[ti])) {
            ++pi;
            ++ti;
        } else if (pi < p.size() && p[pi] == '*') {
            star = pi++;
            mark = ti;
        } else if (star != std::string::npos) {
            pi = star + 1;
            ti = ++mark;
        } else {
            return false;
        }
    }
    while (pi < p.size() && p[pi] == '*') ++pi;
    return pi == p.size();
}

std::string quote_windows_arg(std::string_view arg) {
    if (!arg.empty() && arg.find_first_of(" \t\n\v\"") == std::string_view::npos) return std::string(arg);
    std::string r = "\"";
    std::size_t backslashes = 0;
    for (char c : arg) {
        if (c == '\\') {
            ++backslashes;
        } else if (c == '"') {
            r.append(backslashes * 2 + 1, '\\');
            r.push_back('"');
            backslashes = 0;
        } else {
            r.append(backslashes, '\\');
            r.push_back(c);
            backslashes = 0;
        }
    }
    r.append(backslashes * 2, '\\');
    r.push_back('"');
    return r;
}

std::string random_hex(std::size_t n) {
    static thread_local std::mt19937_64 gen{std::random_device{}() ^
                                            static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count())};
    static const char* d = "0123456789abcdef";
    std::string r;
    for (std::size_t i = 0; i < n; ++i) r.push_back(d[gen() & 15]);
    return r;
}

}  // namespace hem::guard
