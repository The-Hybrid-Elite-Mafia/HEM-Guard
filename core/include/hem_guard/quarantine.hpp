// HEM Guard - quarantine. A found file is MOVED here, scrambled and renamed so it cannot run.
// Nothing is deleted. Every entry remembers where the file came from, so "restore" puts it back
// exactly as it was (byte for byte; the restore is checked against the saved SHA-256).
#pragma once

#include <string>
#include <vector>

#include "hem_guard/util.hpp"

namespace hem::guard {

struct QuarantineEntry {
    std::string id;
    bool active = true;  // false once restored
    fs::path original;
    std::uint64_t size = 0;
    std::string sha256;
    std::int64_t time = 0;
    std::string reason;
};

class Quarantine {
public:
    explicit Quarantine(fs::path root);
    const fs::path& root() const { return root_; }

    // Moves `file` into quarantine. On success `id_out` is the new entry id.
    bool quarantine_file(const fs::path& file, const std::string& reason, std::string& id_out, std::string& error);

    std::vector<QuarantineEntry> list() const;  // all entries, newest last
    // Restores to the original place (or `to` when given). Never overwrites an existing file.
    bool restore(const std::string& id, std::string& error, const fs::path* to = nullptr);

    fs::path payload_path(const std::string& id) const;

private:
    fs::path manifest_path() const { return root_ / "manifest.tsv"; }
    bool rewrite_manifest(const std::vector<QuarantineEntry>& all) const;
    fs::path root_;
};

}  // namespace hem::guard
