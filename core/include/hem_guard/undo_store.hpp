// HEM Guard - the "HEM Guard Undo" folder.
// Cleaning never deletes straight away. Files are MOVED here, grouped in batches, and kept for a set
// number of days. "Undo" moves a whole batch back. Only an expired batch is really removed.
#pragma once

#include <string>
#include <vector>

#include "hem_guard/config.hpp"
#include "hem_guard/util.hpp"

namespace hem::guard {

struct UndoBatchInfo {
    std::string id;
    std::int64_t created = 0;
    int retention_days = 0;
    std::int64_t expires = 0;
    std::size_t items = 0;
    std::uint64_t bytes = 0;
};

struct RestoreReport {
    std::size_t restored = 0;
    std::size_t conflicts = 0;  // something already sits at the original path; we never overwrite
    std::size_t missing = 0;
    std::size_t failed = 0;
    std::vector<std::string> messages;
};

class UndoStore {
public:
    explicit UndoStore(fs::path root, int retention_days = cfg::kUndoRetentionDays);
    const fs::path& root() const { return root_; }

    // `created` defaults to now (tests pass an older time to check expiry).
    bool begin_batch(std::string& id_out, std::string& error, std::int64_t created = 0);
    // Moves one file into the batch and records where it came from.
    bool store(const std::string& batch_id, const fs::path& original, std::uint64_t size, std::string& error);

    std::vector<UndoBatchInfo> list_batches() const;  // oldest first
    RestoreReport restore_batch(const std::string& id);
    RestoreReport restore_latest();

    // Really removes batches whose time is up. Returns how many batches were removed.
    std::size_t purge_expired(std::int64_t now = 0);

    static bool is_batch_id(const std::string& s);

private:
    fs::path batch_dir(const std::string& id) const { return root_ / id; }
    int retention_days_;
    fs::path root_;
};

}  // namespace hem::guard
