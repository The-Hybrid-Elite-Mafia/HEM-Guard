// HEM Guard - on-demand scanner. It only READS. It never deletes, moves or changes a file.
// (Moving a found file to quarantine is a separate, explicit step: see quarantine.hpp.)
#pragma once

#include <atomic>
#include <functional>
#include <set>
#include <string>
#include <vector>

#include "hem_guard/config.hpp"
#include "hem_guard/platform.hpp"
#include "hem_guard/rules.hpp"
#include "hem_guard/util.hpp"

namespace hem::guard {

enum class FindingKind { KnownBadHash, PatternRule, WarningSign };
const char* to_string(FindingKind k);

struct Finding {
    fs::path path;
    FindingKind kind = FindingKind::WarningSign;
    Severity severity = Severity::Low;
    std::string rule;      // rule or hash-list name, or a short warning label
    std::string detail;    // plain-words explanation
    std::string sha256;    // filled when the file was hashed
    int score = 0;         // warning signs only
};

struct ScanOptions {
    const RuleSet* rules = nullptr;
    const HashList* hashes = nullptr;
    double cpu_share = cfg::kScanCpuShareMax;
    std::uint64_t max_file_bytes = cfg::kScanMaxFileBytes;
    std::size_t chunk_bytes = cfg::kReadChunkBytes;

    std::vector<fs::path> skip_roots;      // never scanned (e.g. the quarantine folder)
    std::vector<fs::path> risky_dirs;      // Temp, Downloads ...
    std::vector<fs::path> startup_dirs;    // Startup folders
    std::set<std::string> startup_files;   // exact program paths used by startup entries (normalised, see startup_key)

    // How to check a signature. Default is the real Windows check. Tests replace it.
    std::function<SignState(const fs::path&)> signature_fn;

    const std::atomic<bool>* stop = nullptr;
    std::function<void(const fs::path&)> on_file;  // progress
};

struct ScanReport {
    std::uint64_t files_seen = 0;
    std::uint64_t files_scanned = 0;      // opened and read
    std::uint64_t files_too_big = 0;
    std::uint64_t files_unreadable = 0;
    std::uint64_t bytes_read = 0;
    double wall_seconds = 0;
    double cpu_seconds = 0;
    double busy_share = 0;                // share of the wall time spent working (not paused by the limiter); measured with a precise clock
    double cpu_share_used = 0;            // cpu_seconds / wall_seconds (this whole process)
    std::vector<Finding> findings;
};

// Key used to compare program paths (lower-cased, normalised). Used for startup_files.
std::string startup_key(const fs::path& p);

// Scan one buffer in memory against the rules (used by tests and by "scan this text").
std::vector<Finding> scan_buffer(const std::uint8_t* data, std::size_t len, const RuleSet& rules);

// Path-and-header warning signs only (no file reading except the 2-byte header the caller supplies).
// Returns zero or one Finding.
std::vector<Finding> assess_warnings(const fs::path& file, bool header_is_mz, const ScanOptions& opt);

ScanReport scan_path(const fs::path& root, const ScanOptions& opt);

}  // namespace hem::guard
