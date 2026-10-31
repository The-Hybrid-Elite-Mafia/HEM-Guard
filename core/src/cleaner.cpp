#include "hem_guard/cleaner.hpp"

#include <algorithm>
#include <chrono>
#include <system_error>
#include <unordered_map>

#include "hem_guard/platform.hpp"
#include "hem_guard/walk.hpp"

namespace hem::guard {

const char* to_string(Risk r) {
    switch (r) {
        case Risk::Safe: return "SAFE";
        case Risk::Careful: return "CAREFUL";
        default: return "DO NOT TOUCH";
    }
}

namespace {

fs::path norm_or_empty(const fs::path& p) { return p.empty() ? fs::path{} : normalize_path(p); }

bool dir_exists(const fs::path& p) {
    std::error_code ec;
    return !p.empty() && fs::is_directory(p, ec);
}

const std::string* protected_label(const fs::path& normalized, const Environment& env, std::size_t* idx = nullptr) {
    for (std::size_t i = 0; i < env.protected_folders.size(); ++i) {
        if (!env.protected_folders[i].second.empty() && path_is_within(normalized, env.protected_folders[i].second)) {
            if (idx) *idx = i;
            return &env.protected_folders[i].first;
        }
    }
    return nullptr;
}

std::int64_t file_mtime_unix(const fs::path& p) {
    std::error_code ec;
    const auto ft = fs::last_write_time(p, ec);
    if (ec) return 0;
    try {
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::clock_cast<std::chrono::system_clock>(ft).time_since_epoch())
            .count();
    } catch (...) {
        return 0;
    }
}

void add_skip(CleanPlan& plan, const fs::path& p, std::string why) {
    ++plan.skipped_count;
    if (plan.skipped.size() < cfg::kMaxSkippedListed) plan.skipped.push_back({p, std::move(why)});
}

}  // namespace

bool looks_like_project_folder(const fs::path& dir) {
    std::error_code ec;
    for (auto m : cfg::kProjectMarkers) {
        if (fs::exists(dir / std::string(m), ec)) return true;
        ec.clear();
    }
    for (fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end; !ec && it != end;
         it.increment(ec)) {
        const std::string ext = to_lower_ascii(to_u8(it->path().extension()));
        for (auto pe : cfg::kProjectMarkerExts) {
            if (ext == pe) return true;
        }
    }
    return false;
}

Environment Environment::detect() {
    Environment env;
    if (!is_windows()) return env;  // cleaning is Windows only; elsewhere nothing is a target
    if (auto t = env_var("TEMP")) env.user_temp = from_u8(*t);
    else if (auto t2 = env_var("TMP")) env.user_temp = from_u8(*t2);
    if (auto l = env_var("LOCALAPPDATA")) env.local_appdata = from_u8(*l);
    if (auto w = env_var("WINDIR")) env.windir = from_u8(*w);
    else if (auto w2 = env_var("SystemRoot")) env.windir = from_u8(*w2);
    if (!env.windir.empty()) env.windows_temp = env.windir / "Temp";
    if (auto d = env_var("SystemDrive")) env.system_drive_root = from_u8(*d + "\\");

    const auto k = known_folders();
    env.protected_folders = {{"Documents", k.documents}, {"Desktop", k.desktop},   {"Pictures", k.pictures},
                             {"Music", k.music},         {"Videos", k.videos},     {"Downloads", k.downloads}};
    if (auto od = env_var("OneDrive")) env.protected_folders.emplace_back("OneDrive", from_u8(*od));
    if (auto od = env_var("OneDriveConsumer")) env.protected_folders.emplace_back("OneDrive", from_u8(*od));
    if (auto od = env_var("OneDriveCommercial")) env.protected_folders.emplace_back("OneDrive", from_u8(*od));

    for (auto& pf : env.protected_folders) pf.second = norm_or_empty(pf.second);
    env.user_temp = norm_or_empty(env.user_temp);
    env.windows_temp = norm_or_empty(env.windows_temp);
    env.local_appdata = norm_or_empty(env.local_appdata);
    env.windir = norm_or_empty(env.windir);
    env.system_drive_root = norm_or_empty(env.system_drive_root);
    env.user_sid = current_user_sid();
    if (!env.local_appdata.empty()) env.undo_root = env.local_appdata / "HEM Guard" / "Undo";
    return env;
}

bool target_is_sane(const CleanTarget& t, const Environment& env, std::string* why) {
    auto bad = [&](const char* m) {
        if (why) *why = m;
        return false;
    };
    if (t.root.empty()) return bad("empty path");
    const fs::path r = normalize_path(t.root);
    if (is_filesystem_root(r)) return bad("is a whole drive");
    for (const auto& pf : env.protected_folders) {
        if (pf.second.empty()) continue;
        // The target may not BE a protected folder, sit inside one, or contain one.
        if (path_is_within(r, pf.second)) return bad("is inside a protected folder");
        if (path_is_within(pf.second, r)) return bad("contains a protected folder");
    }
    const auto k = known_folders();
    if (!k.profile.empty() && path_is_within(normalize_path(k.profile), r)) return bad("contains your user profile");
    if (!env.undo_root.empty() && (path_is_within(env.undo_root, r) || path_is_within(r, env.undo_root)))
        return bad("overlaps the undo folder");
    return true;
}

std::vector<CleanTarget> default_targets(const Environment& env, std::vector<std::string>* notes) {
    std::vector<CleanTarget> all;
    auto add = [&](std::string id, std::string label, fs::path root, Risk risk, std::string glob, bool recursive, int age) {
        if (!dir_exists(root)) return;
        CleanTarget t;
        t.id = std::move(id);
        t.label = std::move(label);
        t.root = normalize_path(root);
        t.risk = risk;
        t.file_glob = std::move(glob);
        t.recursive = recursive;
        t.min_age_hours = age;
        all.push_back(std::move(t));
    };

    add("user-temp", "Your temp files", env.user_temp, Risk::Safe, "", true, cfg::kTempMinAgeHours);
    add("windows-temp", "Windows temp files (needs administrator)", env.windows_temp, Risk::Safe, "", true, cfg::kTempMinAgeHours);

    // Chromium browsers: only the cache folders of each profile. Never cookies, passwords, history or bookmarks.
    struct Chromium {
        const char* id;
        const char* label;
        fs::path base;
    };
    const std::vector<Chromium> chromes = {{"chrome", "Chrome", env.local_appdata / "Google" / "Chrome" / "User Data"},
                                           {"edge", "Edge", env.local_appdata / "Microsoft" / "Edge" / "User Data"}};
    for (const auto& c : chromes) {
        std::error_code ec;
        if (c.base.empty() || !fs::is_directory(c.base, ec)) continue;
        for (fs::directory_iterator it(c.base, ec), end; !ec && it != end; it.increment(ec)) {
            const std::string name = to_u8(it->path().filename());
            const bool profile = name == "Default" || name.rfind("Profile ", 0) == 0;
            if (!profile || !it->is_directory(ec)) continue;
            for (const char* sub : {"Cache", "Code Cache", "GPUCache"}) {
                add(std::string(c.id) + "-" + name + "-" + sub, std::string(c.label) + " cache (" + name + ", " + sub + ")",
                    it->path() / sub, Risk::Safe, "", true, cfg::kCacheMinAgeHours);
            }
        }
    }
    // Firefox: cache2 inside each profile.
    {
        std::error_code ec;
        const fs::path base = env.local_appdata / "Mozilla" / "Firefox" / "Profiles";
        if (!env.local_appdata.empty() && fs::is_directory(base, ec)) {
            for (fs::directory_iterator it(base, ec), end; !ec && it != end; it.increment(ec)) {
                if (!it->is_directory(ec)) continue;
                add("firefox-" + to_u8(it->path().filename()) + "-cache2",
                    "Firefox cache (" + to_u8(it->path().filename()) + ")", it->path() / "cache2", Risk::Safe, "", true,
                    cfg::kCacheMinAgeHours);
            }
        }
    }
    if (!env.windir.empty()) {
        add("windows-update-cache", "Windows Update download cache (needs administrator)",
            env.windir / "SoftwareDistribution" / "Download", Risk::Careful, "", true, cfg::kCacheMinAgeHours);
    }
    if (!env.local_appdata.empty()) {
        add("thumbnail-cache", "Thumbnail cache", env.local_appdata / "Microsoft" / "Windows" / "Explorer", Risk::Safe,
            "thumbcache_*.db", false, cfg::kCacheMinAgeHours);
    }
    if (!env.system_drive_root.empty()) {
        // Only YOUR Recycle Bin folder (named after your account id), never other people's.
        const std::string sid = env.user_sid;
        if (!sid.empty()) {
            add("recycle-bin", "Recycle Bin (your own)", env.system_drive_root / "$Recycle.Bin" / from_u8(sid), Risk::Careful, "", true,
                cfg::kCacheMinAgeHours);
        } else if (notes) {
            notes->push_back("left out \"Recycle Bin\": could not tell which one is yours");
        }
    }

    std::vector<CleanTarget> ok;
    for (auto& t : all) {
        std::string why;
        // A temp folder must really be called Temp or Tmp. (A TEMP setting that points at a Dropbox or work
        // folder is left alone.)
        if ((t.id == "user-temp" || t.id == "windows-temp") && !t.root.empty()) {
            const std::string leaf = to_lower_ascii(to_u8(t.root.filename()));
            if (leaf != "temp" && leaf != "tmp") {
                if (notes) notes->push_back("left out \"" + t.label + "\": its folder is not called Temp");
                continue;
            }
        }
        if (target_is_sane(t, env, &why)) ok.push_back(std::move(t));
        else if (notes) notes->push_back("left out \"" + t.label + "\": it " + why);
    }
    return ok;
}

namespace {
// Remembers answers about folders so a big clean-up does not re-scan the same folder for every file.
struct JudgeCache {
    std::unordered_map<std::string, bool> project;
    std::unordered_map<std::string, bool> link;
    bool is_project(const fs::path& d) {
        const std::string k = to_u8(d);
        auto it = project.find(k);
        if (it != project.end()) return it->second;
        const bool v = looks_like_project_folder(d);
        project.emplace(k, v);
        return v;
    }
    bool is_link(const fs::path& d) {
        const std::string k = to_u8(d);
        auto it = link.find(k);
        if (it != link.end()) return it->second;
        std::error_code ec;
        const bool v = is_reparse_or_symlink(d) || fs::is_symlink(fs::symlink_status(d, ec));
        link.emplace(k, v);
        return v;
    }
};

Verdict judge_impl(const fs::path& file, const Environment& env, const std::vector<CleanTarget>& targets, JudgeCache& cache) {
    Verdict v;
    if (file.empty()) {
        v.reason = "empty path";
        return v;
    }
    const fs::path n = normalize_path(file);

    if (const std::string* label = protected_label(n, env)) {
        v.reason = "inside protected folder: " + *label;
        return v;
    }
    for (const auto& t : targets) {
        const fs::path root = normalize_path(t.root);
        if (!path_is_within(n, root) || n == root) continue;
        if (!t.recursive && n.parent_path() != root) continue;
        if (!t.file_glob.empty() && !glob_match(t.file_glob, to_u8(n.filename()))) continue;

        // Walk from the target root down to the file: no links, no project folders on the way.
        fs::path cur = root;
        const fs::path rel = n.lexically_relative(root);
        for (const auto& part : rel) {
            cur /= part;
            if (cache.is_link(cur)) {
                v.reason = "path goes through a link (links are never followed)";
                return v;
            }
            if (cur != n && cache.is_project(cur)) {
                v.reason = "inside a project folder";
                return v;
            }
        }
        v.risk = t.risk;
        v.target = &t;
        v.reason = "inside cleanup target: " + t.label;
        return v;
    }
    v.reason = "not on the cleanup list (default is: do not touch)";
    return v;
}
}  // namespace

Verdict judge_path(const fs::path& file, const Environment& env, const std::vector<CleanTarget>& targets) {
    JudgeCache cache;
    return judge_impl(file, env, targets, cache);
}

CleanPlan make_plan(const Environment& env, const std::vector<CleanTarget>& targets, const PlanOptions& opt) {
    CleanPlan plan;
    plan.include_careful = opt.include_careful;
    const std::int64_t now = opt.now ? opt.now : unix_now();

    for (const auto& t : targets) {
        if (t.risk == Risk::DoNotTouch) continue;
        const fs::path root = normalize_path(t.root);
        const bool include = (t.risk == Risk::Safe) || opt.include_careful;
        TargetSummary& sum = plan.by_target[t.id];
        sum.label = t.label;
        sum.risk = t.risk;
        sum.included = include;

        WalkOptions wo;
        if (t.recursive) {
            wo.enter_dir = [&](const fs::path& d, std::size_t) {
                if (const std::string* label = protected_label(d, env)) {
                    add_skip(plan, d, "protected folder: " + *label);
                    return false;
                }
                if (looks_like_project_folder(d)) {
                    add_skip(plan, d, "looks like a project folder");
                    return false;
                }
                return true;
            };
        } else {
            wo.enter_dir = [](const fs::path&, std::size_t) { return false; };
        }

        walk_files(root, wo, [&](const FileInfo& fi) {
            const std::string name = to_u8(fi.path.filename());
            if (to_lower_ascii(name) == "desktop.ini") return;
            if (!t.file_glob.empty() && !glob_match(t.file_glob, name)) return;
            if (const std::string* label = protected_label(fi.path, env)) {
                add_skip(plan, fi.path, "protected folder: " + *label);
                return;
            }
            if (t.min_age_hours > 0) {
                const std::int64_t age = now - fi.mtime_unix;
                if (age < static_cast<std::int64_t>(t.min_age_hours) * 3600) {
                    add_skip(plan, fi.path, "changed in the last " + std::to_string(t.min_age_hours) + " hours");
                    return;
                }
            }
            ++sum.files;
            sum.bytes += fi.size;
            if (!include) {
                plan.careful_bytes_available += fi.size;
                return;
            }
            PlanItem item;
            item.path = fi.path;
            item.size = fi.size;
            item.risk = t.risk;
            item.target_id = t.id;
            plan.items.push_back(std::move(item));
            if (t.risk == Risk::Safe) plan.safe_bytes += fi.size;
            else plan.careful_bytes_included += fi.size;
        });
    }
    return plan;
}

ApplyResult apply_plan(const CleanPlan& plan, const Environment& env, const std::vector<CleanTarget>& targets, UndoStore& undo,
                       bool confirmed, std::int64_t now_in) {
    ApplyResult res;
    if (!confirmed) {
        res.dry_run = true;
        res.messages.push_back("dry run: nothing was changed");
        return res;
    }
    res.dry_run = false;
    if (plan.items.empty()) {
        res.messages.push_back("nothing to clean");
        return res;
    }
    const std::int64_t now = now_in ? now_in : unix_now();

    JudgeCache cache;
    // Re-check that every target is still sane, right now. Anything that is not is dropped.
    std::vector<CleanTarget> checked_targets;
    for (const auto& t : targets) {
        if (target_is_sane(t, env, nullptr)) checked_targets.push_back(t);
    }
    std::string err;
    if (!undo.begin_batch(res.batch_id, err)) {
        res.dry_run = true;  // could not even open an undo batch, so nothing was touched
        res.messages.push_back("stopped before changing anything: " + err);
        return res;
    }

    for (const auto& item : plan.items) {
        // Re-check everything, right now, with fresh eyes. One cleaned-up path is used for judging AND moving.
        const fs::path np = normalize_path(item.path);
        const Verdict v = judge_impl(np, env, checked_targets, cache);
        if (v.risk == Risk::DoNotTouch || !v.target) {
            ++res.refused;
            res.messages.push_back("refused " + to_u8(item.path) + ": " + v.reason);
            continue;
        }
        if (v.risk == Risk::Careful && !plan.include_careful) {
            ++res.refused;
            res.messages.push_back("refused " + to_u8(item.path) + ": CAREFUL item without opt-in");
            continue;
        }
        if (v.risk != item.risk) {
            ++res.refused;
            res.messages.push_back("refused " + to_u8(item.path) + ": risk level changed since the plan was made");
            continue;
        }
        std::error_code ec;
        const auto st = fs::symlink_status(np, ec);
        if (ec || !fs::is_regular_file(st)) {
            ++res.refused;
            res.messages.push_back("refused " + to_u8(item.path) + ": not a plain file any more");
            continue;
        }
        if (v.target->min_age_hours > 0 &&
            now - file_mtime_unix(np) < static_cast<std::int64_t>(v.target->min_age_hours) * 3600) {
            ++res.refused;
            res.messages.push_back("refused " + to_u8(item.path) + ": changed recently");
            continue;
        }
        const std::uint64_t size = fs::file_size(np, ec);
        std::string serr;
        if (undo.store(res.batch_id, np, ec ? item.size : size, serr)) {
            ++res.moved;
            res.moved_bytes += ec ? item.size : size;
        } else {
            ++res.failed;
            res.messages.push_back("skipped " + to_u8(item.path) + ": " + serr);
        }
    }
    if (res.moved == 0) {
        // Empty batch: tidy it away so it does not clutter the undo list.
        std::error_code ec;
        const fs::path dir = undo.root() / res.batch_id;
        if (UndoStore::is_batch_id(res.batch_id) && path_is_within(normalize_path(dir), normalize_path(undo.root()))) {
            fs::remove(dir / "items.tsv", ec);
            fs::remove(dir / "batch.meta", ec);
            fs::remove(dir, ec);  // not recursive: leaves the folder alone if anything else is inside
        }
        res.batch_id.clear();
    }
    return res;
}

std::vector<std::pair<std::string, fs::path>> never_touched_list(const Environment& env) {
    auto v = env.protected_folders;
    v.erase(std::remove_if(v.begin(), v.end(), [](const auto& p) { return p.second.empty(); }), v.end());
    return v;
}

}  // namespace hem::guard
