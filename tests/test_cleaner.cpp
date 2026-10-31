#include <algorithm>
#include <set>

#include "hem_guard/cleaner.hpp"
#include "test_support.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

using namespace hem::guard;

namespace {

struct World {
    hgt::Sandbox sb;
    Environment env;
    std::map<std::string, std::string> expect_safe_files;  // path -> content, files that SHOULD be cleaned
    fs::path old_temp_file, recent_temp_file;

    World() {
        const auto mk = [&](const std::string& rel, const std::string& content, int age_hours = 48) {
            const fs::path p = hgt::write_file(sb / rel, content);
            if (age_hours > 0) hgt::age_file(p, age_hours);
            return p;
        };
        // Folders that must never be touched.
        mk("Users/test/Documents/keep.txt", "my novel");
        mk("Users/test/Documents/sub/deep.docx", "my taxes");
        mk("Users/test/Desktop/shortcut.lnk", "desktop item");
        mk("Users/test/Pictures/photo.jpg", "photo");
        mk("Users/test/Music/song.wav", "song");
        mk("Users/test/Videos/clip.mp4", "clip");
        mk("Users/test/Downloads/installer.exe", "download");
        // Temp (should be cleaned when old).
        old_temp_file = mk("Local/Temp/old1.tmp", "old temp one");
        mk("Local/Temp/nested/old2.tmp", "old temp two");
        mk("Local/Temp/nested/deeper/old3.log", std::string(5000, 'L'));
        recent_temp_file = mk("Local/Temp/recent.tmp", "fresh temp file an app may be using", 0);
        mk("Local/Temp/desktop.ini", "[.ShellClassInfo]");
        // A project folder that happens to sit in Temp.
        mk("Local/Temp/myproject/CMakeLists.txt", "project");
        mk("Local/Temp/myproject/main.cpp", "int main(){}");
        mk("Local/Temp/gitproj/.git/config", "[core]");
        mk("Local/Temp/gitproj/src/a.c", "int a;");
        mk("Local/Temp/vsproj/App.sln", "sln");
        mk("Local/Temp/vsproj/src/b.c", "int b;");
        mk("Windows/Temp/wtemp.tmp", "windows temp");
        // Browsers.
        const std::string ud = "Local/Google/Chrome/User Data/";
        mk(ud + "Default/Cache/Cache_Data/f_000001", std::string(3000, 'c'));
        mk(ud + "Default/Code Cache/js/index", "code cache");
        mk(ud + "Default/GPUCache/data_0", "gpu cache");
        mk(ud + "Default/Cookies", "COOKIES - login sessions");
        mk(ud + "Default/Login Data", "SAVED PASSWORDS");
        mk(ud + "Default/History", "browsing history");
        mk(ud + "Default/Bookmarks", "bookmarks");
        mk(ud + "Profile 1/Cache/f_000002", "profile 1 cache");
        mk(ud + "Profile 1/Login Data", "SAVED PASSWORDS 2");
        mk(ud + "Local State", "chrome local state");
        const std::string ff = "Local/Mozilla/Firefox/Profiles/abc.default/";
        mk(ff + "cache2/entries/AAAA", "firefox cache");
        mk(ff + "cookies.sqlite", "FF COOKIES");
        mk(ff + "places.sqlite", "FF HISTORY");
        // Explorer thumbnail caches.
        const std::string ex = "Local/Microsoft/Windows/Explorer/";
        mk(ex + "thumbcache_96.db", "thumbs");
        mk(ex + "thumbcache_idx.db", "thumb index");
        mk(ex + "iconcache_32.db", "icons - not in our list");
        mk(ex + "other.txt", "something else");
        // CAREFUL places.
        mk("Windows/SoftwareDistribution/Download/update1.cab", std::string(4000, 'U'));
        mk("Drive/$Recycle.Bin/S-1-5-21-1/$R123.txt", "deleted file body");
        mk("Drive/$Recycle.Bin/S-1-5-21-1/$I123.txt", "deleted file info");
        // Something totally outside every cleanup place.
        mk("Other/random.dat", "not on any list");

        env.user_temp = sb / "Local/Temp";
        env.windows_temp = sb / "Windows/Temp";
        env.local_appdata = sb / "Local";
        env.windir = sb / "Windows";
        env.system_drive_root = sb / "Drive";
        env.undo_root = sb / "Local/HEM Guard/Undo";
        env.protected_folders = {{"Documents", sb / "Users/test/Documents"}, {"Desktop", sb / "Users/test/Desktop"},
                                 {"Pictures", sb / "Users/test/Pictures"},   {"Music", sb / "Users/test/Music"},
                                 {"Videos", sb / "Users/test/Videos"},       {"Downloads", sb / "Users/test/Downloads"}};
    }

    // The undo folder and its parent ("HEM Guard") are bookkeeping, not part of what we compare.
    std::vector<fs::path> undo_skip() const { return {env.undo_root.parent_path()}; }
    std::string fingerprint() const { return hgt::tree_fingerprint(sb.root, undo_skip()); }
};

std::set<std::string> plan_rel_paths(const World& w, const CleanPlan& plan) {
    std::set<std::string> s;
    for (const auto& i : plan.items) s.insert(to_u8(i.path.lexically_relative(w.sb.root)));
    return s;
}

bool contains(const std::set<std::string>& s, const std::string& generic_rel) {
    return s.count(to_u8(fs::path(generic_rel).make_preferred())) > 0;
}

const CleanTarget* find_target(const std::vector<CleanTarget>& t, const std::string& id) {
    for (const auto& x : t) {
        if (x.id == id) return &x;
    }
    return nullptr;
}

}  // namespace

// ----------------------------------------------------------- target list --

HG_TEST(cleaner_targets, every_known_place_is_found_and_nothing_else) {
    World w;
    const auto targets = default_targets(w.env);
    std::set<std::string> ids;
    for (const auto& t : targets) ids.insert(t.id);
    for (const char* id : {"user-temp", "windows-temp", "chrome-Default-Cache", "chrome-Default-Code Cache", "chrome-Default-GPUCache",
                           "chrome-Profile 1-Cache", "firefox-abc.default-cache2", "windows-update-cache", "thumbnail-cache",
                           "recycle-bin"}) {
        CHECK(ids.count(id) == 1);
    }
    CHECK_EQ(targets.size(), static_cast<std::size_t>(10));
    for (const auto& t : targets) {
        for (const auto& pf : w.env.protected_folders) CHECK(!path_is_within(t.root, pf.second));
    }
    CHECK(find_target(targets, "windows-update-cache")->risk == Risk::Careful);
    CHECK(find_target(targets, "recycle-bin")->risk == Risk::Careful);
    CHECK(find_target(targets, "user-temp")->risk == Risk::Safe);
    CHECK(find_target(targets, "chrome-Default-Cache")->risk == Risk::Safe);
}

HG_TEST(cleaner_targets, a_target_that_would_swallow_a_protected_folder_is_dropped) {
    World w;
    CleanTarget bad;
    bad.id = "bad";
    bad.label = "bad";
    bad.root = w.sb / "Users/test";  // contains Documents, Desktop ...
    std::string why;
    CHECK(!target_is_sane(bad, w.env, &why));
    CHECK(!why.empty());

    CleanTarget inside;
    inside.root = w.sb / "Users/test/Documents/sub";
    CHECK(!target_is_sane(inside, w.env, &why));

    CleanTarget drive;
    drive.root = fs::current_path().root_path();
    CHECK(!target_is_sane(drive, w.env, &why));

    // And the real list builder drops them: point TEMP at the profile and see what is left.
    World w2;
    w2.env.user_temp = w2.sb / "Users/test";
    std::vector<std::string> notes;
    const auto targets = default_targets(w2.env, &notes);
    CHECK(find_target(targets, "user-temp") == nullptr);
    CHECK(!notes.empty());
}

HG_TEST(cleaner_targets, never_touched_list_names_the_personal_folders) {
    World w;
    const auto list = never_touched_list(w.env);
    std::set<std::string> labels;
    for (const auto& p : list) labels.insert(p.first);
    for (const char* l : {"Documents", "Desktop", "Pictures", "Music", "Videos", "Downloads"}) CHECK(labels.count(l) == 1);
}

// ------------------------------------------------------------------ plan --

HG_TEST(cleaner_plan, safe_plan_has_exactly_the_right_files) {
    World w;
    const auto targets = default_targets(w.env);
    const auto plan = make_plan(w.env, targets);
    const auto got = plan_rel_paths(w, plan);

    // In:
    for (const char* in : {"Local/Temp/old1.tmp", "Local/Temp/nested/old2.tmp", "Local/Temp/nested/deeper/old3.log",
                           "Windows/Temp/wtemp.tmp", "Local/Google/Chrome/User Data/Default/Cache/Cache_Data/f_000001",
                           "Local/Google/Chrome/User Data/Default/Code Cache/js/index",
                           "Local/Google/Chrome/User Data/Default/GPUCache/data_0",
                           "Local/Google/Chrome/User Data/Profile 1/Cache/f_000002",
                           "Local/Mozilla/Firefox/Profiles/abc.default/cache2/entries/AAAA",
                           "Local/Microsoft/Windows/Explorer/thumbcache_96.db", "Local/Microsoft/Windows/Explorer/thumbcache_idx.db"}) {
        CHECK(contains(got, in));
    }
    CHECK_EQ(got.size(), static_cast<std::size_t>(11));

    // Out - personal data, logins, project folders, recent files, other caches, CAREFUL places, unknown places:
    for (const char* out : {"Users/test/Documents/keep.txt", "Users/test/Desktop/shortcut.lnk", "Users/test/Downloads/installer.exe",
                            "Local/Temp/recent.tmp", "Local/Temp/desktop.ini", "Local/Temp/myproject/main.cpp",
                            "Local/Temp/gitproj/src/a.c", "Local/Temp/vsproj/src/b.c",
                            "Local/Google/Chrome/User Data/Default/Cookies", "Local/Google/Chrome/User Data/Default/Login Data",
                            "Local/Google/Chrome/User Data/Default/History", "Local/Google/Chrome/User Data/Default/Bookmarks",
                            "Local/Google/Chrome/User Data/Profile 1/Login Data", "Local/Google/Chrome/User Data/Local State",
                            "Local/Mozilla/Firefox/Profiles/abc.default/cookies.sqlite",
                            "Local/Mozilla/Firefox/Profiles/abc.default/places.sqlite",
                            "Local/Microsoft/Windows/Explorer/iconcache_32.db", "Local/Microsoft/Windows/Explorer/other.txt",
                            "Windows/SoftwareDistribution/Download/update1.cab", "Drive/$Recycle.Bin/S-1-5-21-1/$R123.txt",
                            "Other/random.dat"}) {
        CHECK(!contains(got, out));
    }
    for (const auto& i : plan.items) CHECK(i.risk == Risk::Safe);
    CHECK(plan.careful_bytes_available > 0);          // it tells you the CAREFUL places exist...
    CHECK_EQ(plan.careful_bytes_included, static_cast<std::uint64_t>(0));  // ...without including them
}

HG_TEST(cleaner_plan, byte_totals_add_up) {
    World w;
    const auto plan = make_plan(w.env, default_targets(w.env));
    std::uint64_t sum = 0;
    for (const auto& i : plan.items) {
        sum += i.size;
        CHECK_EQ(i.size, static_cast<std::uint64_t>(fs::file_size(i.path)));
    }
    CHECK_EQ(plan.safe_bytes, sum);
    CHECK_EQ(plan.total_bytes(), sum);
    NOTE("plan: " + std::to_string(plan.items.size()) + " files, " + std::to_string(sum) + " bytes, " +
         std::to_string(plan.skipped_count) + " items skipped with a reason");
}

HG_TEST(cleaner_plan, careful_places_only_with_opt_in) {
    World w;
    const auto targets = default_targets(w.env);
    PlanOptions opt;
    opt.include_careful = true;
    const auto plan = make_plan(w.env, targets, opt);
    const auto got = plan_rel_paths(w, plan);
    CHECK(contains(got, "Windows/SoftwareDistribution/Download/update1.cab"));
    CHECK(contains(got, "Drive/$Recycle.Bin/S-1-5-21-1/$R123.txt"));
    CHECK(contains(got, "Drive/$Recycle.Bin/S-1-5-21-1/$I123.txt"));
    CHECK(plan.careful_bytes_included > 0);
    CHECK_EQ(plan.careful_bytes_available, static_cast<std::uint64_t>(0));
}

HG_TEST(cleaner_plan, files_recently_changed_wait_a_day) {
    World w;
    const auto targets = default_targets(w.env);
    CHECK(!contains(plan_rel_paths(w, make_plan(w.env, targets)), "Local/Temp/recent.tmp"));
    PlanOptions later;
    later.now = unix_now() + 25 * 3600;  // a day and a bit from now it is old enough
    CHECK(contains(plan_rel_paths(w, make_plan(w.env, targets, later)), "Local/Temp/recent.tmp"));
}

// ------------------------------------------------------------- verdicts --

HG_TEST(cleaner_judge, one_question_one_answer) {
    World w;
    const auto targets = default_targets(w.env);
    const auto v = [&](const std::string& rel) { return judge_path(w.sb / rel, w.env, targets); };
    CHECK(v("Local/Temp/old1.tmp").risk == Risk::Safe);
    CHECK(v("Windows/SoftwareDistribution/Download/update1.cab").risk == Risk::Careful);
    CHECK(v("Users/test/Documents/keep.txt").risk == Risk::DoNotTouch);
    CHECK(v("Users/test/Documents/keep.txt").reason.find("protected") != std::string::npos);
    CHECK(v("Other/random.dat").risk == Risk::DoNotTouch);
    CHECK(v("Local/Google/Chrome/User Data/Default/Cookies").risk == Risk::DoNotTouch);
    CHECK(v("Local/Temp/myproject/main.cpp").risk == Risk::DoNotTouch);
    CHECK(v("Local/Temp").risk == Risk::DoNotTouch);                      // the target folder itself is never "a file to clean"
    CHECK(v("Local/Temp/nope-missing.tmp").risk == Risk::Safe);           // judged by place, not by existence
    // Sneaking out with ".." must not work.
    CHECK(v("Local/Temp/../../Users/test/Documents/keep.txt").risk == Risk::DoNotTouch);
    CHECK(v("Local/Temp/nested/../../../Other/random.dat").risk == Risk::DoNotTouch);
    CHECK(judge_path("", w.env, targets).risk == Risk::DoNotTouch);
    // Empty target list means everything is DO NOT TOUCH.
    CHECK(judge_path(w.sb / "Local/Temp/old1.tmp", w.env, {}).risk == Risk::DoNotTouch);
}

// ----------------------------------------------------- dry run & confirm --

HG_TEST(cleaner_safety, dry_run_changes_nothing_at_all) {
    World w;
    const std::string before = w.fingerprint();
    const auto targets = default_targets(w.env);
    const auto plan = make_plan(w.env, targets);
    REQUIRE(!plan.items.empty());
    CHECK_EQ(w.fingerprint(), before);  // planning is read-only

    UndoStore undo(w.env.undo_root);
    const auto res = apply_plan(plan, w.env, targets, undo, /*confirmed=*/false);
    CHECK(res.dry_run);
    CHECK_EQ(res.moved, static_cast<std::size_t>(0));
    CHECK_EQ(w.fingerprint(), before);   // unconfirmed apply is read-only too
    CHECK(!fs::exists(w.env.undo_root)); // not even the undo folder was created
}

HG_TEST(cleaner_safety, confirmed_clean_moves_files_and_touches_nothing_else) {
    World w;
    const auto targets = default_targets(w.env);
    const auto plan = make_plan(w.env, targets);
    const std::string protected_before = hgt::tree_fingerprint(w.sb / "Users");
    const std::string other_before = hgt::tree_fingerprint(w.sb / "Other");
    const std::string logins_before = sha256_hex(hgt::slurp(w.sb / "Local/Google/Chrome/User Data/Default/Login Data")) +
                                      sha256_hex(hgt::slurp(w.sb / "Local/Mozilla/Firefox/Profiles/abc.default/cookies.sqlite"));

    UndoStore undo(w.env.undo_root);
    const auto res = apply_plan(plan, w.env, targets, undo, true);
    CHECK(!res.dry_run);
    CHECK_EQ(res.moved, plan.items.size());
    CHECK_EQ(res.moved_bytes, plan.safe_bytes);
    CHECK_EQ(res.refused, static_cast<std::size_t>(0));
    CHECK_EQ(res.failed, static_cast<std::size_t>(0));
    for (const auto& i : plan.items) CHECK(!fs::exists(i.path));  // gone from where they were...
    CHECK(!res.batch_id.empty());
    CHECK(fs::exists(w.env.undo_root / res.batch_id));            // ...and sitting in the undo folder

    CHECK_EQ(hgt::tree_fingerprint(w.sb / "Users"), protected_before);
    CHECK_EQ(hgt::tree_fingerprint(w.sb / "Other"), other_before);
    CHECK_EQ(sha256_hex(hgt::slurp(w.sb / "Local/Google/Chrome/User Data/Default/Login Data")) +
                 sha256_hex(hgt::slurp(w.sb / "Local/Mozilla/Firefox/Profiles/abc.default/cookies.sqlite")),
             logins_before);
    // CAREFUL places and project folders and recent files: untouched.
    CHECK(fs::exists(w.sb / "Windows/SoftwareDistribution/Download/update1.cab"));
    CHECK(fs::exists(w.sb / "Drive/$Recycle.Bin/S-1-5-21-1/$R123.txt"));
    CHECK(fs::exists(w.sb / "Local/Temp/myproject/main.cpp"));
    CHECK(fs::exists(w.sb / "Local/Temp/recent.tmp"));
}

HG_TEST(cleaner_undo, one_step_undo_puts_every_file_back_byte_for_byte) {
    World w;
    const std::string before = w.fingerprint();
    const auto targets = default_targets(w.env);
    const auto plan = make_plan(w.env, targets);
    UndoStore undo(w.env.undo_root);
    const auto res = apply_plan(plan, w.env, targets, undo, true);
    REQUIRE(res.moved > 0);
    CHECK(w.fingerprint() != before);  // something really changed...

    const auto rr = undo.restore_latest();
    CHECK_EQ(rr.restored, res.moved);
    CHECK_EQ(rr.conflicts, static_cast<std::size_t>(0));
    CHECK_EQ(rr.failed, static_cast<std::size_t>(0));
    CHECK_EQ(w.fingerprint(), before);  // ...and now the whole sandbox is identical again, every byte
    CHECK(undo.list_batches().empty()); // a fully restored batch tidies itself away
    NOTE("restored " + std::to_string(rr.restored) + " files; whole-folder SHA-256 fingerprint identical before and after");
}

HG_TEST(cleaner_undo, restore_never_overwrites_something_new) {
    World w;
    const auto targets = default_targets(w.env);
    const auto plan = make_plan(w.env, targets);
    UndoStore undo(w.env.undo_root);
    const auto res = apply_plan(plan, w.env, targets, undo, true);
    REQUIRE(res.moved > 0);
    const fs::path clash = w.sb / "Local/Temp/old1.tmp";
    hgt::write_file(clash, "a brand new file an app made after the clean");
    const auto rr = undo.restore_latest();
    CHECK_EQ(rr.conflicts, static_cast<std::size_t>(1));
    CHECK_EQ(rr.restored, res.moved - 1);
    CHECK_EQ(hgt::slurp(clash), std::string("a brand new file an app made after the clean"));
    CHECK_EQ(undo.list_batches().size(), static_cast<std::size_t>(1));  // kept, with the one leftover
    // Remove the clash, undo again: the last file comes back.
    fs::remove(clash);
    const auto again = undo.restore_latest();
    CHECK_EQ(again.restored, static_cast<std::size_t>(1));
    CHECK_EQ(hgt::slurp(clash), std::string("old temp one"));
}

HG_TEST(cleaner_undo, files_stay_recoverable_until_the_retention_time_is_up) {
    hgt::Sandbox sb;
    UndoStore undo(sb / "Undo", 7);
    const std::int64_t now = unix_now();
    std::string old_batch, new_batch, err;
    REQUIRE(undo.begin_batch(old_batch, err, now - 10 * 86400));   // created 10 days ago
    const fs::path a = hgt::write_file(sb / "work/a.tmp", "A");
    REQUIRE(undo.store(old_batch, a, 1, err));
    REQUIRE(undo.begin_batch(new_batch, err, now - 2 * 86400));    // created 2 days ago
    const fs::path b = hgt::write_file(sb / "work/b.tmp", "B");
    REQUIRE(undo.store(new_batch, b, 1, err));

    CHECK_EQ(undo.list_batches().size(), static_cast<std::size_t>(2));
    CHECK_EQ(undo.purge_expired(now), static_cast<std::size_t>(1));  // only the 10-day-old one is really gone
    const auto left = undo.list_batches();
    REQUIRE(left.size() == 1);
    CHECK_EQ(left[0].id, new_batch);
    CHECK(!fs::exists(sb / "Undo" / old_batch));
    CHECK(undo.purge_expired(now) == 0);
    // Right at the edge: not yet expired one second before, expired at the moment.
    CHECK_EQ(undo.purge_expired(left[0].expires - 1), static_cast<std::size_t>(0));
    const auto rr = undo.restore_batch(new_batch);
    CHECK_EQ(rr.restored, static_cast<std::size_t>(1));
    CHECK_EQ(hgt::slurp(b), std::string("B"));
}

HG_TEST(cleaner_undo, purge_only_touches_real_batches) {
    hgt::Sandbox sb;
    UndoStore undo(sb / "Undo", 1);
    const std::int64_t now = unix_now();
    // A folder that looks like a batch name but has no batch.meta (not ours) - must survive.
    hgt::write_file(sb / "Undo/20200101-000000-abcd/precious.txt", "not ours");
    // A folder with some other name - must survive.
    hgt::write_file(sb / "Undo/random-folder/precious.txt", "not ours either");
    // A loose file - must survive.
    hgt::write_file(sb / "Undo/loose.txt", "loose");
    CHECK_EQ(undo.purge_expired(now + 365 * 86400), static_cast<std::size_t>(0));
    CHECK(fs::exists(sb / "Undo/20200101-000000-abcd/precious.txt"));
    CHECK(fs::exists(sb / "Undo/random-folder/precious.txt"));
    CHECK(fs::exists(sb / "Undo/loose.txt"));
}

HG_TEST(cleaner_undo, a_tampered_undo_log_cannot_escape_the_batch_folder) {
    hgt::Sandbox sb;
    UndoStore undo(sb / "Undo", 7);
    std::string id, err;
    REQUIRE(undo.begin_batch(id, err));
    const fs::path victim = hgt::write_file(sb / "Secret/keep.txt", "do not move me");
    // A hand-edited log line that tries to restore a file from outside the batch.
    hgt::write_file(sb / "Undo" / id / "items.tsv", "../../Secret/keep.txt\t14\t" + tsv_escape(to_u8(sb / "Hijack/keep.txt")) + "\n");
    const auto rr = undo.restore_batch(id);
    CHECK_EQ(rr.restored, static_cast<std::size_t>(0));
    CHECK(fs::exists(victim));
    CHECK(!fs::exists(sb / "Hijack/keep.txt"));
}

// ---------------------------------------------- forged plans & safety nets --

HG_TEST(cleaner_safety, a_forged_plan_cannot_reach_protected_or_unknown_files) {
    World w;
    const auto targets = default_targets(w.env);
    const std::string before = w.fingerprint();

    CleanPlan forged;
    forged.include_careful = true;
    const auto add = [&](const std::string& rel, Risk r, const std::string& target) {
        PlanItem i;
        i.path = w.sb / rel;
        i.size = 1;
        i.risk = r;
        i.target_id = target;
        forged.items.push_back(i);
    };
    add("Users/test/Documents/keep.txt", Risk::Safe, "user-temp");                          // protected folder
    add("Users/test/Desktop/shortcut.lnk", Risk::Safe, "user-temp");
    add("Users/test/Downloads/installer.exe", Risk::Safe, "user-temp");
    add("Other/random.dat", Risk::Safe, "user-temp");                                       // not on the list
    add("Local/Google/Chrome/User Data/Default/Cookies", Risk::Safe, "chrome-Default-Cache");  // next to a cache, not in it
    add("Local/Google/Chrome/User Data/Default/Login Data", Risk::Safe, "chrome-Default-Cache");
    add("Local/Temp/../../Users/test/Documents/sub/deep.docx", Risk::Safe, "user-temp");    // ".." escape
    add("Local/Temp/myproject/main.cpp", Risk::Safe, "user-temp");                          // project folder
    add("Local/Temp/gitproj/src/a.c", Risk::Safe, "user-temp");
    add("Local/Temp/old1.tmp", Risk::Careful, "user-temp");                                 // lying about the risk level
    add("Local/Temp/recent.tmp", Risk::Safe, "user-temp");                                  // too new

    UndoStore undo(w.env.undo_root);
    const auto res = apply_plan(forged, w.env, targets, undo, true);
    CHECK_EQ(res.moved, static_cast<std::size_t>(0));
    CHECK_EQ(res.refused, forged.items.size());
    CHECK_EQ(w.fingerprint(), before);  // not one byte moved
}

HG_TEST(cleaner_safety, careful_items_are_refused_unless_the_plan_opted_in) {
    World w;
    const auto targets = default_targets(w.env);
    PlanOptions opt;
    opt.include_careful = true;
    CleanPlan plan = make_plan(w.env, targets, opt);
    plan.include_careful = false;  // someone flips the flag after the fact
    const std::string before = w.fingerprint();
    UndoStore undo(w.env.undo_root);
    const auto res = apply_plan(plan, w.env, targets, undo, true);
    CHECK(res.refused >= 3);  // update cache + recycle bin files
    CHECK(fs::exists(w.sb / "Windows/SoftwareDistribution/Download/update1.cab"));
    CHECK(fs::exists(w.sb / "Drive/$Recycle.Bin/S-1-5-21-1/$R123.txt"));
    (void)before;
}

HG_TEST(cleaner_safety, careful_clean_with_opt_in_moves_and_undoes) {
    World w;
    const auto targets = default_targets(w.env);
    PlanOptions opt;
    opt.include_careful = true;
    const auto plan = make_plan(w.env, targets, opt);
    const std::string before = w.fingerprint();
    UndoStore undo(w.env.undo_root);
    const auto res = apply_plan(plan, w.env, targets, undo, true);
    CHECK_EQ(res.moved, plan.items.size());
    CHECK(!fs::exists(w.sb / "Windows/SoftwareDistribution/Download/update1.cab"));
    undo.restore_latest();
    CHECK_EQ(w.fingerprint(), before);
}

HG_TEST(cleaner_safety, a_file_changed_after_the_plan_was_made_is_left_alone) {
    World w;
    const auto targets = default_targets(w.env);
    const auto plan = make_plan(w.env, targets);
    // An app wakes up and writes to an old temp file after we planned.
    hgt::write_file(w.sb / "Local/Temp/old1.tmp", "app is using this right now");
    UndoStore undo(w.env.undo_root);
    const auto res = apply_plan(plan, w.env, targets, undo, true);
    CHECK_EQ(res.refused, static_cast<std::size_t>(1));
    CHECK(fs::exists(w.sb / "Local/Temp/old1.tmp"));
    CHECK_EQ(hgt::slurp(w.sb / "Local/Temp/old1.tmp"), std::string("app is using this right now"));
}

HG_TEST(cleaner_safety, links_are_never_followed_into_personal_folders) {
    World w;
    if (!hgt::can_make_symlink(w.sb.root)) SKIP("this machine does not allow making symbolic links");
    std::error_code ec;
    fs::create_directory_symlink(w.sb / "Users/test/Documents", w.sb / "Local/Temp/docs-link", ec);
    REQUIRE(!ec);
    fs::create_symlink(w.sb / "Users/test/Documents/keep.txt", w.sb / "Local/Temp/keep-link.tmp", ec);
    REQUIRE(!ec);
    const auto targets = default_targets(w.env);
    const auto plan = make_plan(w.env, targets);
    for (const auto& i : plan.items) {
        CHECK(i.path.filename() != "keep.txt");
        CHECK(i.path.filename() != "deep.docx");
        CHECK(i.path.filename() != "keep-link.tmp");
    }
    // A forged plan that goes through the link is refused too.
    CleanPlan forged;
    PlanItem item;
    item.path = w.sb / "Local/Temp/docs-link/keep.txt";
    item.size = 1;
    item.risk = Risk::Safe;
    item.target_id = "user-temp";
    forged.items.push_back(item);
    PlanItem item2 = item;
    item2.path = w.sb / "Local/Temp/keep-link.tmp";
    forged.items.push_back(item2);
    UndoStore undo(w.env.undo_root);
    const auto res = apply_plan(forged, w.env, targets, undo, true);
    CHECK_EQ(res.moved, static_cast<std::size_t>(0));
    CHECK_EQ(hgt::slurp(w.sb / "Users/test/Documents/keep.txt"), std::string("my novel"));
}

HG_TEST(cleaner_safety, the_environment_is_empty_off_windows_so_nothing_can_be_cleaned) {
    if (is_windows()) SKIP("this check is about non-Windows machines");
    const auto env = Environment::detect();
    CHECK(env.user_temp.empty());
    CHECK(default_targets(env).empty());
}

HG_TEST(cleaner_safety, windows_detect_finds_real_folders_and_protects_personal_ones) {
    if (!is_windows()) SKIP("Windows only");
    const auto env = Environment::detect();
    CHECK(!env.user_temp.empty());
    CHECK(!env.windir.empty());
    CHECK(!env.undo_root.empty());
    std::set<std::string> labels;
    for (const auto& p : env.protected_folders) {
        if (!p.second.empty()) labels.insert(p.first);
    }
    for (const char* l : {"Documents", "Desktop", "Pictures", "Music", "Videos", "Downloads"}) CHECK(labels.count(l) == 1);
    // Real machine, real targets - but PLAN ONLY. This test never applies anything to the real PC.
    std::vector<std::string> notes;
    const auto targets = default_targets(env, &notes);
    for (const auto& t : targets) {
        for (const auto& pf : env.protected_folders) {
            if (!pf.second.empty()) CHECK(!path_is_within(t.root, pf.second));
        }
    }
    const auto plan = make_plan(env, targets);
    for (const auto& i : plan.items) {
        const auto v = judge_path(i.path, env, targets);
        CHECK(v.risk != Risk::DoNotTouch);
    }
    NOTE("real-PC dry run: " + std::to_string(targets.size()) + " places found, " + std::to_string(plan.items.size()) +
         " files, " + format_bytes(plan.total_bytes()) + " (nothing was changed)");
}

#ifdef _WIN32
HG_TEST(cleaner_safety, a_file_in_use_is_skipped_not_forced) {
    World w;
    const auto targets = default_targets(w.env);
    const auto plan = make_plan(w.env, targets);
    // Hold one old temp file open with no sharing, the way a running program would.
    const std::wstring locked = (w.sb / "Local/Temp/old1.tmp").wstring();
    HANDLE h = CreateFileW(locked.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    REQUIRE(h != INVALID_HANDLE_VALUE);
    UndoStore undo(w.env.undo_root);
    const auto res = apply_plan(plan, w.env, targets, undo, true);
    CloseHandle(h);
    CHECK_EQ(res.failed, static_cast<std::size_t>(1));
    CHECK_EQ(res.moved, plan.items.size() - 1);
    CHECK(fs::exists(w.sb / "Local/Temp/old1.tmp"));      // still there, untouched
    CHECK_EQ(hgt::slurp(w.sb / "Local/Temp/old1.tmp"), std::string("old temp one"));
    undo.restore_latest();
}
#endif
