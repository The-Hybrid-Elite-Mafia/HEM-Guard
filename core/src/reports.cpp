#include "hem_guard/reports.hpp"

#include <algorithm>
#include <unordered_map>

#include "hem_guard/sha256.hpp"
#include "hem_guard/walk.hpp"

namespace hem::guard {

DuplicateReport find_duplicates(const fs::path& root, std::uint64_t min_bytes) {
    DuplicateReport rep;
    std::map<std::uint64_t, std::vector<fs::path>> by_size;
    walk_files(root, {}, [&](const FileInfo& fi) {
        ++rep.files_seen;
        if (fi.size >= min_bytes && fi.size > 0) by_size[fi.size].push_back(fi.path);
    });
    for (auto& [size, paths] : by_size) {
        if (paths.size() < 2) continue;  // a lone size cannot be a duplicate
        std::map<std::string, std::vector<fs::path>> by_hash;
        for (const auto& p : paths) {
            std::string h;
            if (sha256_file(p, h)) {
                ++rep.files_hashed;
                by_hash[h].push_back(p);
            }
        }
        for (auto& [h, ps] : by_hash) {
            if (ps.size() < 2) continue;
            DuplicateGroup g;
            g.size = size;
            g.sha256 = h;
            g.paths = std::move(ps);
            std::sort(g.paths.begin(), g.paths.end());
            rep.total_wasted += g.wasted_bytes();
            rep.groups.push_back(std::move(g));
        }
    }
    std::sort(rep.groups.begin(), rep.groups.end(),
              [](const auto& a, const auto& b) { return a.wasted_bytes() > b.wasted_bytes(); });
    if (rep.groups.size() > cfg::kDupMaxGroupsListed) rep.groups.resize(cfg::kDupMaxGroupsListed);
    return rep;
}

StorageReport storage_report(const fs::path& root_in, int folder_depth, std::size_t top_n) {
    StorageReport rep;
    const fs::path root = normalize_path(root_in);
    std::unordered_map<std::string, FolderSize> folders;
    std::unordered_map<std::string, TypeSize> types;

    walk_files(root, {}, [&](const FileInfo& fi) {
        ++rep.total_files;
        rep.total_bytes += fi.size;

        // Add this file's size to each ancestor folder, up to folder_depth levels below the root.
        const fs::path rel = fi.path.lexically_relative(root);
        fs::path cur = root;
        int depth = 0;
        auto it = rel.begin();
        auto last = rel.end();
        if (it != last) --last;  // the last element is the file name itself
        for (; it != last && depth < folder_depth; ++it, ++depth) {
            cur /= *it;
            auto& f = folders[to_u8(cur)];
            if (f.path.empty()) f.path = cur;
            f.bytes += fi.size;
            ++f.files;
        }

        std::string ext = to_lower_ascii(to_u8(fi.path.extension()));
        if (ext.empty()) ext = "(none)";
        auto& t = types[ext];
        if (t.ext.empty()) t.ext = ext;
        t.bytes += fi.size;
        ++t.files;

        // Keep a short list of the biggest files.
        if (rep.biggest_files.size() < top_n || fi.size > rep.biggest_files.back().bytes) {
            rep.biggest_files.push_back({fi.path, fi.size});
            std::sort(rep.biggest_files.begin(), rep.biggest_files.end(),
                      [](const auto& a, const auto& b) { return a.bytes > b.bytes; });
            if (rep.biggest_files.size() > top_n) rep.biggest_files.pop_back();
        }
    });

    for (auto& [k, f] : folders) rep.folders.push_back(std::move(f));
    std::sort(rep.folders.begin(), rep.folders.end(), [](const auto& a, const auto& b) {
        return a.bytes != b.bytes ? a.bytes > b.bytes : a.path < b.path;
    });
    if (rep.folders.size() > top_n) rep.folders.resize(top_n);
    for (auto& [k, t] : types) rep.types.push_back(std::move(t));
    std::sort(rep.types.begin(), rep.types.end(), [](const auto& a, const auto& b) {
        return a.bytes != b.bytes ? a.bytes > b.bytes : a.ext < b.ext;
    });
    if (rep.types.size() > top_n) rep.types.resize(top_n);
    return rep;
}

}  // namespace hem::guard
