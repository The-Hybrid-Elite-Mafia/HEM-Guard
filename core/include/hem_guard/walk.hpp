// HEM Guard - one safe folder walker used by the scanner, cleaner, storage report and duplicate finder.
// It never follows symbolic links or junctions, never throws, and keeps going past errors.
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>

#include "hem_guard/config.hpp"
#include "hem_guard/util.hpp"

namespace hem::guard {

struct FileInfo {
    fs::path path;
    std::uint64_t size = 0;
    std::int64_t mtime_unix = 0;
};

struct WalkOptions {
    std::size_t max_depth = cfg::kMaxWalkDepth;
    // Return false to skip a folder (and everything below it). Depth 0 = the start folder's children.
    std::function<bool(const fs::path& dir, std::size_t depth)> enter_dir;
    const std::atomic<bool>* stop = nullptr;
};

struct WalkStats {
    std::uint64_t dirs_visited = 0;
    std::uint64_t files_seen = 0;
    std::uint64_t links_skipped = 0;   // symlinks / junctions we refused to follow
    std::uint64_t errors = 0;          // folders or files we could not read
};

// Calls on_file for each regular file. Return value is false if stopped early.
bool walk_files(const fs::path& root, const WalkOptions& opt, const std::function<void(const FileInfo&)>& on_file,
                WalkStats* stats = nullptr);

}  // namespace hem::guard
