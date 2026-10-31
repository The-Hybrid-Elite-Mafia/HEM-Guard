#include "hem_guard/scanner.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>

#include "hem_guard/sha256.hpp"
#include "hem_guard/throttle.hpp"
#include "hem_guard/walk.hpp"

namespace hem::guard {

const char* to_string(FindingKind k) {
    switch (k) {
        case FindingKind::KnownBadHash: return "known-bad file";
        case FindingKind::PatternRule: return "pattern match";
        default: return "warning sign";
    }
}

std::string startup_key(const fs::path& p) { return to_lower_ascii(to_u8(normalize_path(p))); }

namespace {

bool in_list(std::string_view ext, const auto& list) {
    for (auto e : list) {
        if (ext == e) return true;
    }
    return false;
}

std::string ext_of(const fs::path& p) { return to_lower_ascii(to_u8(p.extension())); }

const std::uint8_t* find_bytes(const std::uint8_t* hay, std::size_t hlen, const std::uint8_t* needle, std::size_t nlen) {
    if (nlen == 0 || hlen < nlen) return nullptr;
    const std::uint8_t* end = hay + (hlen - nlen) + 1;
    const std::uint8_t* p = hay;
    while (p < end) {
        p = static_cast<const std::uint8_t*>(std::memchr(p, needle[0], static_cast<std::size_t>(end - p)));
        if (!p) return nullptr;
        if (std::memcmp(p, needle, nlen) == 0) return p;
        ++p;
    }
    return nullptr;
}

bool within_any(const fs::path& p, const std::vector<fs::path>& roots) {
    for (const auto& r : roots) {
        if (path_is_within(p, r)) return true;
    }
    return false;
}

// A real Windows program starts with "MZ" and has "PE\0\0" where the header says (offset stored at 0x3C).
bool looks_like_pe(const std::uint8_t* h, std::size_t n) {
    if (n < 0x40 || h[0] != 'M' || h[1] != 'Z') return false;
    const std::uint32_t lf = std::uint32_t(h[0x3C]) | (std::uint32_t(h[0x3D]) << 8) | (std::uint32_t(h[0x3E]) << 16) |
                             (std::uint32_t(h[0x3F]) << 24);
    if (lf < 0x40 || lf > n - 4) return false;
    return h[lf] == 'P' && h[lf + 1] == 'E' && h[lf + 2] == 0 && h[lf + 3] == 0;
}

Severity level_from_score(int score) {
    if (score >= cfg::kScoreHighFrom) return Severity::High;
    if (score >= cfg::kScoreMediumFrom) return Severity::Medium;
    return Severity::Low;
}

}  // namespace

std::vector<Finding> scan_buffer(const std::uint8_t* data, std::size_t len, const RuleSet& rules) {
    std::vector<Finding> out;
    for (const auto& r : rules.rules()) {
        if (find_bytes(data, len, r.pattern.data(), r.pattern.size())) {
            Finding f;
            f.kind = FindingKind::PatternRule;
            f.severity = r.severity;
            f.rule = r.name;
            f.detail = "matches byte-pattern rule " + r.name;
            out.push_back(std::move(f));
        }
    }
    return out;
}

std::vector<Finding> assess_warnings(const fs::path& file, bool header_is_mz, const ScanOptions& opt) {
    const std::string name = to_lower_ascii(to_u8(file.filename()));
    const std::string ext = ext_of(file);
    const bool exec_ext = in_list(ext, cfg::kExecutableExts);

    int score = 0;
    std::vector<std::string> why;

    if (exec_ext && !opt.risky_dirs.empty() && within_any(file, opt.risky_dirs)) {
        score += cfg::kPointsExecInRiskyDir;
        why.push_back("program sitting in a Temp or Downloads folder");
    }

    // Double extension: "invoice.pdf.exe"
    if (exec_ext) {
        const fs::path stem = fs::path(from_u8(name)).stem();
        const std::string inner = to_lower_ascii(to_u8(stem.extension()));
        if (!inner.empty() && in_list(inner, cfg::kDocLikeExts)) {
            score += cfg::kPointsDoubleExtension;
            why.push_back("double extension (looks like a " + inner + " file but is a program)");
        }
    }

    // Program body hiding behind a document / picture name.
    if (header_is_mz && !exec_ext && in_list(ext, cfg::kDocLikeExts)) {
        score += cfg::kPointsDisguisedExecutable;
        why.push_back("file named " + ext + " but its contents are a Windows program");
    }

    // Unsigned program in a startup spot.
    if (exec_ext) {
        const bool in_startup_dir = within_any(file, opt.startup_dirs);
        const bool in_startup_list = opt.startup_files.count(startup_key(file)) > 0;
        if (in_startup_dir || in_startup_list) {
            const auto sig_fn = opt.signature_fn ? opt.signature_fn : std::function<SignState(const fs::path&)>(check_signature);
            if (sig_fn(file) == SignState::Unsigned) {
                score += cfg::kPointsUnsignedInStartup;
                why.push_back("runs at startup and has no valid digital signature");
            }
        }
    }

    std::vector<Finding> out;
    if (score > 0) {
        Finding f;
        f.path = file;
        f.kind = FindingKind::WarningSign;
        f.severity = level_from_score(score);
        f.score = score;
        f.rule = "warning-signs";
        for (std::size_t i = 0; i < why.size(); ++i) f.detail += (i ? "; " : "") + why[i];
        out.push_back(std::move(f));
    }
    return out;
}

ScanReport scan_path(const fs::path& root, const ScanOptions& opt_in) {
    ScanReport rep;
    ScanOptions opt = opt_in;
    for (auto& p : opt.skip_roots) p = normalize_path(p);
    for (auto& p : opt.risky_dirs) p = normalize_path(p);
    for (auto& p : opt.startup_dirs) p = normalize_path(p);

    const bool need_read = (opt.rules && !opt.rules->rules().empty()) || (opt.hashes && opt.hashes->size() > 0);
    const std::size_t overlap = opt.rules ? opt.rules->max_pattern_len() : 0;
    const std::size_t chunk = std::max<std::size_t>(opt.chunk_bytes, 64);

    CpuThrottle throttle(opt.cpu_share);
    const auto wall0 = std::chrono::steady_clock::now();
    const double cpu0 = process_cpu_seconds();

    WalkOptions wo;
    wo.stop = opt.stop;
    wo.enter_dir = [&](const fs::path& d, std::size_t) { return !within_any(normalize_path(d), opt.skip_roots); };

    std::vector<std::uint8_t> buf;
    std::vector<std::uint8_t> carry;

    walk_files(root, wo, [&](const FileInfo& fi) {
        ++rep.files_seen;
        if (!opt.skip_roots.empty() && within_any(normalize_path(fi.path), opt.skip_roots)) return;
        if (opt.on_file) opt.on_file(fi.path);

        bool header_mz = false;
        std::string sha;
        std::vector<char> matched_rules;  // one flag per rule
        std::vector<Finding> found;

        if (fi.size > opt.max_file_bytes) {
            ++rep.files_too_big;
        } else {
            std::ifstream f(fi.path, std::ios::binary);
            if (!f) {
                ++rep.files_unreadable;
            } else {
                ++rep.files_scanned;
                Sha256 hasher;
                const bool want_hash = opt.hashes && opt.hashes->size() > 0;
                static const std::vector<Rule> kNoRules;
                const auto& rules = opt.rules ? opt.rules->rules() : kNoRules;
                matched_rules.assign(rules.size(), 0);
                carry.clear();
                buf.resize(chunk);
                {
                    // Peek at the first 1 KB to see whether this is really a Windows program, then start over.
                    std::uint8_t hdr[1024] = {};
                    f.read(reinterpret_cast<char*>(hdr), sizeof hdr);
                    header_mz = looks_like_pe(hdr, static_cast<std::size_t>(f.gcount()));
                    f.clear();
                    f.seekg(0);
                }
                while (need_read && f) {
                    f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(chunk));
                    const auto got = static_cast<std::size_t>(f.gcount());
                    if (got == 0) break;
                    rep.bytes_read += got;
                    if (want_hash) hasher.update(buf.data(), got);
                    if (!rules.empty()) {
                        // Search carry + chunk so a pattern split across two reads is still found.
                        std::vector<std::uint8_t> window;
                        window.reserve(carry.size() + got);
                        window.insert(window.end(), carry.begin(), carry.end());
                        window.insert(window.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(got));
                        for (std::size_t i = 0; i < rules.size(); ++i) {
                            if (matched_rules[i]) continue;
                            if (find_bytes(window.data(), window.size(), rules[i].pattern.data(), rules[i].pattern.size())) {
                                matched_rules[i] = 1;
                                Finding fd;
                                fd.path = fi.path;
                                fd.kind = FindingKind::PatternRule;
                                fd.severity = rules[i].severity;
                                fd.rule = rules[i].name;
                                fd.detail = "matches byte-pattern rule " + rules[i].name;
                                found.push_back(std::move(fd));
                            }
                        }
                        const std::size_t keep = overlap > 0 ? std::min(overlap - 1, window.size()) : 0;
                        carry.assign(window.end() - static_cast<std::ptrdiff_t>(keep), window.end());
                    }
                    throttle.tick();
                }
                if (f.bad()) ++rep.files_unreadable;
                if (want_hash) {
                    sha = hasher.finish_hex();
                    if (const std::string* nm = opt.hashes->find(sha)) {
                        Finding fd;
                        fd.path = fi.path;
                        fd.kind = FindingKind::KnownBadHash;
                        fd.severity = Severity::High;
                        fd.rule = *nm;
                        fd.detail = "SHA-256 is on the known-bad list as " + *nm;
                        found.insert(found.begin(), std::move(fd));
                    }
                }
            }
        }

        for (auto& w : assess_warnings(fi.path, header_mz, opt)) found.push_back(std::move(w));
        for (auto& fd : found) {
            fd.sha256 = sha;
            rep.findings.push_back(std::move(fd));
        }
        throttle.tick();
    });

    rep.wall_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - wall0).count();
    rep.cpu_seconds = process_cpu_seconds() - cpu0;
    rep.cpu_share_used = rep.wall_seconds > 0 ? rep.cpu_seconds / rep.wall_seconds : 0.0;
    rep.busy_share = rep.wall_seconds > 0 ? std::max(0.0, 1.0 - throttle.total_slept_seconds() / rep.wall_seconds) : 0.0;
    return rep;
}

}  // namespace hem::guard
