#include "hem_guard/quarantine.hpp"

#include <cstring>
#include <fstream>

#include "hem_guard/config.hpp"
#include "hem_guard/sha256.hpp"

namespace hem::guard {

namespace {

constexpr std::size_t kHeaderBytes = 16;  // magic(4) + zero(4) + original size(8)

void put_header(std::uint8_t* h, std::uint64_t size) {
    std::memset(h, 0, kHeaderBytes);
    std::memcpy(h, cfg::kQuarantineMagic.data(), 4);
    for (int i = 0; i < 8; ++i) h[8 + i] = static_cast<std::uint8_t>(size >> (8 * i));
}

bool read_header(const std::uint8_t* h, std::uint64_t& size) {
    if (std::memcmp(h, cfg::kQuarantineMagic.data(), 4) != 0) return false;
    size = 0;
    for (int i = 0; i < 8; ++i) size |= std::uint64_t(h[8 + i]) << (8 * i);
    return true;
}

// Scramble / unscramble (same operation). `offset` is the byte position inside the original file.
void xor_block(std::uint8_t* data, std::size_t n, std::uint64_t offset) {
    const auto key = cfg::kQuarantineXorKey;
    for (std::size_t i = 0; i < n; ++i) {
        data[i] ^= static_cast<std::uint8_t>(key[(offset + i) % key.size()]) ^ 0x5A;
    }
}

bool valid_id(const std::string& id) {
    return id.size() == 12 && id.find_first_not_of("0123456789abcdef") == std::string::npos;
}

std::string entry_line(const QuarantineEntry& e) {
    return e.id + "\t" + (e.active ? "Q" : "R") + "\t" + std::to_string(e.size) + "\t" + e.sha256 + "\t" +
           std::to_string(e.time) + "\t" + tsv_escape(to_u8(e.original)) + "\t" + tsv_escape(e.reason) + "\n";
}

}  // namespace

Quarantine::Quarantine(fs::path root) : root_(std::move(root)) {}

fs::path Quarantine::payload_path(const std::string& id) const { return root_ / (id + std::string(cfg::kQuarantineExt)); }

bool Quarantine::quarantine_file(const fs::path& file, const std::string& reason, std::string& id_out, std::string& error) {
    error.clear();
    std::error_code ec;
    const auto st = fs::symlink_status(file, ec);
    if (ec || !fs::is_regular_file(st)) {
        error = "not a regular file (links and folders are never quarantined)";
        return false;
    }
    if (path_is_within(normalize_path(file), normalize_path(root_))) {
        error = "file is already inside the quarantine folder";
        return false;
    }
    fs::create_directories(root_, ec);
    if (ec) {
        error = "cannot create quarantine folder: " + ec.message();
        return false;
    }

    const std::string id = random_hex(12);
    const fs::path payload = payload_path(id);

    std::ifstream in(file, std::ios::binary);
    if (!in) {
        error = "cannot open the file (in use or no permission)";
        return false;
    }
    std::ofstream out(payload, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "cannot create quarantine file";
        return false;
    }

    const std::uint64_t original_size = fs::file_size(file, ec);
    if (ec) {
        error = "cannot read file size";
        return false;
    }
    ec.clear();
    const auto mtime_before = fs::last_write_time(file, ec);
    const bool have_mtime = !ec;
    std::uint8_t header[kHeaderBytes];
    put_header(header, original_size);
    out.write(reinterpret_cast<const char*>(header), kHeaderBytes);

    Sha256 hasher;
    std::vector<std::uint8_t> buf(1 << 20);
    std::uint64_t offset = 0;
    while (in) {
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        const auto got = static_cast<std::size_t>(in.gcount());
        if (got == 0) break;
        hasher.update(buf.data(), got);
        xor_block(buf.data(), got, offset);
        out.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(got));
        offset += got;
    }
    out.flush();
    const bool write_ok = static_cast<bool>(out);
    out.close();
    in.close();

    if (in.bad() || !write_ok || offset != original_size) {
        std::error_code ignore;
        fs::remove(payload, ignore);
        error = "copy into quarantine failed";
        return false;
    }
    ec.clear();
    if (fs::file_size(payload, ec) != original_size + kHeaderBytes || ec) {
        std::error_code ignore;
        fs::remove(payload, ignore);
        error = "quarantine copy check failed";
        return false;
    }

    // The file must not have changed while we were copying it.
    ec.clear();
    if (fs::file_size(file, ec) != original_size || ec || (have_mtime && fs::last_write_time(file, ec) != mtime_before)) {
        std::error_code ignore;
        fs::remove(payload, ignore);
        error = "the file changed while it was being copied, so it was left where it is";
        return false;
    }

    QuarantineEntry e;
    e.id = id;
    e.original = normalize_path(file);
    e.size = original_size;
    e.sha256 = hasher.finish_hex();
    e.time = unix_now();
    e.reason = reason;
    // Write the log line BEFORE touching the original. If this fails, nothing has been removed yet.
    if (!append_text_file(manifest_path(), entry_line(e))) {
        std::error_code ignore;
        fs::remove(payload, ignore);
        error = "could not write the quarantine log, so the file was left where it is";
        return false;
    }

    // Only now take the original out of its place.
    ec.clear();
    fs::remove(file, ec);
    if (ec) {
        // Could not remove it (in use). Mark the log line as not active and drop the copy.
        auto all = list();
        for (auto& x : all) {
            if (x.id == id) x.active = false;
        }
        rewrite_manifest(all);
        std::error_code ignore;
        fs::remove(payload, ignore);
        error = "file is in use or locked, so it was left where it is";
        return false;
    }
    id_out = id;
    return true;
}

std::vector<QuarantineEntry> Quarantine::list() const {
    std::vector<QuarantineEntry> v;
    std::string text;
    if (!read_text_file(manifest_path(), text)) return v;
    for (const auto& line : split(text, '\n')) {
        if (line.empty()) continue;
        const auto f = split(line, '\t');
        if (f.size() < 7) continue;
        if (!valid_id(f[0])) continue;  // a tampered id could point at some other file
        QuarantineEntry e;
        e.id = f[0];
        e.active = (f[1] == "Q");
        try {
            e.size = std::stoull(f[2]);
            e.time = std::stoll(f[4]);
        } catch (...) {
            continue;
        }
        e.sha256 = f[3];
        e.original = from_u8(tsv_unescape(f[5]));
        e.reason = tsv_unescape(f[6]);
        v.push_back(std::move(e));
    }
    return v;
}

bool Quarantine::rewrite_manifest(const std::vector<QuarantineEntry>& all) const {
    std::string text;
    for (const auto& e : all) text += entry_line(e);
    const fs::path tmp = root_ / "manifest.tsv.tmp";
    if (!write_text_file(tmp, text)) return false;
    std::error_code ec;
    fs::rename(tmp, manifest_path(), ec);  // replaces the old file
    if (ec) {
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

bool Quarantine::restore(const std::string& id, std::string& error, const fs::path* to) {
    error.clear();
    auto all = list();
    QuarantineEntry* hit = nullptr;
    for (auto& e : all) {
        if (e.id == id && e.active) hit = &e;
    }
    if (!hit) {
        error = "no active quarantine entry with that id";
        return false;
    }
    const fs::path dest = to ? *to : hit->original;
    std::error_code ec;
    if (!dest.is_absolute() || path_is_within(normalize_path(dest), normalize_path(root_))) {
        error = "the saved original path looks wrong, so nothing was restored";
        return false;
    }
    if (fs::exists(fs::symlink_status(dest, ec))) {
        error = "something already exists at " + to_u8(dest) + " (restore never overwrites)";
        return false;
    }
    const fs::path payload = payload_path(id);
    std::ifstream in(payload, std::ios::binary);
    if (!in) {
        error = "quarantine file is missing";
        return false;
    }
    std::uint8_t header[kHeaderBytes];
    in.read(reinterpret_cast<char*>(header), kHeaderBytes);
    std::uint64_t size = 0;
    if (in.gcount() != static_cast<std::streamsize>(kHeaderBytes) || !read_header(header, size) || size != hit->size) {
        error = "quarantine file is damaged (header check failed)";
        return false;
    }
    fs::create_directories(dest.parent_path(), ec);
    const fs::path tmp = dest.parent_path() / (to_u8(dest.filename()) + "." + random_hex(4) + ".hgq-restoring");
    {
        std::ofstream out(tmp, std::ios::binary);
        if (!out) {
            error = "cannot create the restored file (no permission?)";
            return false;
        }
        Sha256 hasher;
        std::vector<std::uint8_t> buf(1 << 20);
        std::uint64_t off = 0;
        while (in) {
            in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
            const auto got = static_cast<std::size_t>(in.gcount());
            if (got == 0) break;
            xor_block(buf.data(), got, off);
            hasher.update(buf.data(), got);
            out.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(got));
            off += got;
        }
        out.flush();
        const bool ok = static_cast<bool>(out);
        out.close();
        if (!ok || off != size || hasher.finish_hex() != hit->sha256) {
            std::error_code ignore;
            fs::remove(tmp, ignore);
            error = "restored copy did not match the saved SHA-256; nothing was restored";
            return false;
        }
    }
    ec.clear();
    std::string move_err;
    if (!move_file_safe(tmp, dest, move_err)) {  // never replaces a file that showed up meanwhile
        std::error_code ignore;
        fs::remove(tmp, ignore);
        error = "could not put the file in place: " + move_err;
        return false;
    }
    in.close();
    hit->active = false;
    rewrite_manifest(all);
    std::error_code ignore;
    fs::remove(payload, ignore);
    return true;
}

}  // namespace hem::guard
