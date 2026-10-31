// HEM Guard - cleaner. Default is a DRY RUN: it only reports. Nothing is touched until the caller
// passes confirmed = true, and even then files are MOVED to the undo folder, never deleted.
//
// Safety rules (each one has a test):
//   * Default-deny: a path is only ever touched if it sits inside a known cleanup target.
//   * Protected folders (Documents, Desktop, Pictures, Music, Videos, Downloads, OneDrive) always win.
//   * Folders that look like a project (.git, CMakeLists.txt, *.sln ...) are never entered.
//   * Links / junctions are never followed.
//   * Every item is checked AGAIN right before it is moved, so a forged or stale plan cannot hurt anything.
//   * NO registry cleaning. Not now, not later. (Almost no speed gain, real risk.)
#pragma once

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "hem_guard/config.hpp"
#include "hem_guard/undo_store.hpp"
#include "hem_guard/util.hpp"

namespace hem::guard {

enum class Risk { Safe, Careful, DoNotTouch };
const char* to_string(Risk r);

struct Environment {
    fs::path user_temp;
    fs::path windows_temp;
    fs::path local_appdata;
    fs::path windir;
    fs::path system_drive_root;
    std::vector<std::pair<std::string, fs::path>> protected_folders;  // label, path
    fs::path undo_root;  // where the undo folder lives
    std::string user_sid;  // your own account id; only YOUR Recycle Bin folder is ever a target

    // Reads the real Windows folders. On non-Windows it returns an EMPTY environment (nothing can be cleaned).
    static Environment detect();
};

struct CleanTarget {
    std::string id;
    std::string label;
    fs::path root;
    Risk risk = Risk::Safe;
    std::string file_glob;      // empty = all files
    bool recursive = true;
    int min_age_hours = 0;      // files changed more recently than this are left alone
};

// Builds the list of known cleanup places that exist on this machine.
// Targets that fail the sanity check are dropped and explained in `notes`.
std::vector<CleanTarget> default_targets(const Environment& env, std::vector<std::string>* notes = nullptr);
bool target_is_sane(const CleanTarget& t, const Environment& env, std::string* why = nullptr);

struct Verdict {
    Risk risk = Risk::DoNotTouch;
    std::string reason;
    const CleanTarget* target = nullptr;
};
// The one question the whole cleaner is built on: "may this file be touched, and how risky is it?"
Verdict judge_path(const fs::path& file, const Environment& env, const std::vector<CleanTarget>& targets);

bool looks_like_project_folder(const fs::path& dir);

struct PlanItem {
    fs::path path;
    std::uint64_t size = 0;
    Risk risk = Risk::Safe;
    std::string target_id;
};
struct SkipNote {
    fs::path path;
    std::string reason;
};
struct TargetSummary {
    std::string label;
    Risk risk = Risk::Safe;
    std::size_t files = 0;
    std::uint64_t bytes = 0;
    bool included = true;  // false: found but left out (CAREFUL without opt-in)
};

struct CleanPlan {
    bool include_careful = false;
    std::vector<PlanItem> items;
    std::vector<SkipNote> skipped;   // capped list
    std::uint64_t skipped_count = 0;
    std::map<std::string, TargetSummary> by_target;
    std::uint64_t safe_bytes = 0;
    std::uint64_t careful_bytes_included = 0;
    std::uint64_t careful_bytes_available = 0;  // found, but not in the plan
    std::uint64_t total_bytes() const { return safe_bytes + careful_bytes_included; }
};

struct PlanOptions {
    bool include_careful = false;
    std::int64_t now = 0;  // 0 = real clock
};

CleanPlan make_plan(const Environment& env, const std::vector<CleanTarget>& targets, const PlanOptions& opt = {});

struct ApplyResult {
    bool dry_run = true;
    std::string batch_id;
    std::size_t moved = 0;
    std::uint64_t moved_bytes = 0;
    std::size_t refused = 0;  // refused by the safety re-check
    std::size_t failed = 0;   // in use, locked, no permission
    std::vector<std::string> messages;
};

// confirmed == false  ->  does NOTHING and says so (dry_run = true).
ApplyResult apply_plan(const CleanPlan& plan, const Environment& env, const std::vector<CleanTarget>& targets, UndoStore& undo,
                       bool confirmed, std::int64_t now = 0);

// Things the cleaner will never touch, for display.
std::vector<std::pair<std::string, fs::path>> never_touched_list(const Environment& env);

}  // namespace hem::guard
