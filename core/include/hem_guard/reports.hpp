// HEM Guard - report-only tools: duplicate finder and storage report.
// These only READ. They never delete, move or change anything.
#pragma once

#include <map>
#include <string>
#include <vector>

#include "hem_guard/config.hpp"
#include "hem_guard/util.hpp"

namespace hem::guard {

struct DuplicateGroup {
    std::uint64_t size = 0;
    std::string sha256;
    std::vector<fs::path> paths;
    std::uint64_t wasted_bytes() const { return size * (paths.size() - 1); }
};

struct DuplicateReport {
    std::vector<DuplicateGroup> groups;  // biggest waste first
    std::uint64_t files_seen = 0;
    std::uint64_t files_hashed = 0;
    std::uint64_t total_wasted = 0;
};

// Matches by size first, then by full SHA-256. Report only.
DuplicateReport find_duplicates(const fs::path& root, std::uint64_t min_bytes = cfg::kDupMinBytes);

struct FolderSize {
    fs::path path;
    std::uint64_t bytes = 0;
    std::uint64_t files = 0;
};
struct TypeSize {
    std::string ext;  // lower-case with dot, or "(none)"
    std::uint64_t bytes = 0;
    std::uint64_t files = 0;
};
struct BigFile {
    fs::path path;
    std::uint64_t bytes = 0;
};

struct StorageReport {
    std::uint64_t total_bytes = 0;
    std::uint64_t total_files = 0;
    std::vector<FolderSize> folders;  // biggest first, down to `folder_depth` levels
    std::vector<TypeSize> types;      // biggest first
    std::vector<BigFile> biggest_files;
};

StorageReport storage_report(const fs::path& root, int folder_depth = cfg::kStorageFolderDepth,
                             std::size_t top_n = cfg::kStorageTopN);

}  // namespace hem::guard
