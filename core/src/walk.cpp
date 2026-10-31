#include "hem_guard/walk.hpp"

#include <chrono>
#include <system_error>
#include <vector>

#include "hem_guard/platform.hpp"

namespace hem::guard {

namespace {
std::int64_t to_unix(fs::file_time_type ft) {
    try {
        const auto sys = std::chrono::clock_cast<std::chrono::system_clock>(ft);
        return std::chrono::duration_cast<std::chrono::seconds>(sys.time_since_epoch()).count();
    } catch (...) {
        return 0;
    }
}
}  // namespace

bool walk_files(const fs::path& root, const WalkOptions& opt, const std::function<void(const FileInfo&)>& on_file,
                WalkStats* stats) {
    WalkStats local;
    WalkStats& st = stats ? *stats : local;

    struct Item {
        fs::path dir;
        std::size_t depth;
    };
    std::vector<Item> stack;

    std::error_code ec;
    const auto root_status = fs::symlink_status(root, ec);
    if (ec) {
        ++st.errors;
        return true;
    }
    if (fs::is_symlink(root_status) || is_reparse_or_symlink(root)) {
        ++st.links_skipped;
        return true;
    }
    if (fs::is_regular_file(root_status)) {
        FileInfo fi;
        fi.path = root;
        fi.size = fs::file_size(root, ec);
        if (ec) fi.size = 0;
        ec.clear();
        fi.mtime_unix = to_unix(fs::last_write_time(root, ec));
        ++st.files_seen;
        on_file(fi);
        return true;
    }
    if (!fs::is_directory(root_status)) return true;
    stack.push_back({root, 0});

    while (!stack.empty()) {
        if (opt.stop && opt.stop->load()) return false;
        Item cur = std::move(stack.back());
        stack.pop_back();
        ++st.dirs_visited;

        std::error_code dec;
        fs::directory_iterator it(cur.dir, fs::directory_options::skip_permission_denied, dec);
        if (dec) {
            ++st.errors;
            continue;
        }
        const fs::directory_iterator end;
        while (it != end) {
            if (opt.stop && opt.stop->load()) return false;
            const fs::directory_entry entry = *it;
            std::error_code sec;
            const auto status = entry.symlink_status(sec);
            if (sec) {
                ++st.errors;
            } else if (fs::is_symlink(status)) {
                ++st.links_skipped;
            } else if (fs::is_directory(status)) {
                if (is_reparse_or_symlink(entry.path())) {
                    ++st.links_skipped;
                } else if (cur.depth + 1 < opt.max_depth) {
                    if (!opt.enter_dir || opt.enter_dir(entry.path(), cur.depth)) stack.push_back({entry.path(), cur.depth + 1});
                }
            } else if (fs::is_regular_file(status)) {
                FileInfo fi;
                fi.path = entry.path();
                std::error_code fec;
                fi.size = entry.file_size(fec);
                if (fec) {
                    fi.size = 0;
                    ++st.errors;
                }
                fec.clear();
                fi.mtime_unix = to_unix(entry.last_write_time(fec));
                ++st.files_seen;
                on_file(fi);
            }
            it.increment(dec);
            if (dec) {
                ++st.errors;
                break;
            }
        }
    }
    return true;
}

}  // namespace hem::guard
