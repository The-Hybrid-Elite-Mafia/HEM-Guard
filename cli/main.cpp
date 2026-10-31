// HEM Guard - command-line tool. A thin layer over hem_guard_core: it parses words, calls the engine, prints plain text.
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>

#include "hem_guard/cleaner.hpp"
#include "hem_guard/quarantine.hpp"
#include "hem_guard/reports.hpp"
#include "hem_guard/scanner.hpp"
#include "hem_guard/startup.hpp"

using namespace hem::guard;

namespace {

fs::path exe_dir() {
#ifdef _WIN32
    wchar_t buf[MAX_PATH * 4] = {};
    const DWORD n = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(sizeof(buf) / sizeof(buf[0])));
    if (n > 0) return fs::path(buf).parent_path();
#else
    std::error_code ec;
    const auto p = fs::read_symlink("/proc/self/exe", ec);
    if (!ec) return p.parent_path();
#endif
    return fs::current_path();
}

fs::path data_dir() {
    if (auto l = env_var("LOCALAPPDATA")) return from_u8(*l) / "HEM Guard";
    if (auto h = env_var("HOME")) return from_u8(*h) / ".hem-guard";
    return fs::current_path() / "HEM Guard data";
}

struct Args {
    std::vector<std::string> pos;
    std::map<std::string, std::string> opt;
    bool has(const std::string& k) const { return opt.count(k) > 0; }
    std::string get(const std::string& k, const std::string& dflt = "") const {
        const auto it = opt.find(k);
        return it == opt.end() ? dflt : it->second;
    }
};

Args parse_args(int argc, char** argv, int from) {
    Args a;
    for (int i = from; i < argc; ++i) {
        const std::string s = argv[i];
        if (s.rfind("--", 0) == 0) {
            const std::string key = s.substr(2);
            const auto eq = key.find('=');
            if (eq != std::string::npos) {
                a.opt[key.substr(0, eq)] = key.substr(eq + 1);
            } else if (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0 &&
                       (key == "rules" || key == "hashes" || key == "cpu" || key == "quarantine-dir" || key == "min-kb")) {
                a.opt[key] = argv[++i];
            } else {
                a.opt[key] = "1";
            }
        } else {
            a.pos.push_back(s);
        }
    }
    return a;
}

void line(char c = '-', int n = 72) { std::printf("%s\n", std::string(static_cast<std::size_t>(n), c).c_str()); }

void usage() {
    std::printf(
        "HEM Guard %s  -  a small, honest Windows scan-and-cleanup tool\n\n"
        "  scan <folder-or-drive>   look for known-bad files and warning signs (only reads, never deletes)\n"
        "        --quarantine             move found bad files to quarantine (restorable)\n"
        "        --quarantine-warnings    also move HIGH warning-sign files\n"
        "        --cpu 0.5                CPU share limit, 0.1 to 1.0\n"
        "  quarantine list|restore <id>   see or restore quarantined files\n"
        "  clean                    PREVIEW what could be cleaned (changes nothing)\n"
        "        --careful                also include CAREFUL places\n"
        "        --apply                  do it (asks you to type YES first); files go to the Undo folder\n"
        "  clean-undo [--list] [id] put the last clean back (or the batch you name)\n"
        "  clean-purge              remove undo copies whose time is up\n"
        "  startup list [--all]     show what starts with Windows\n"
        "  startup disable|enable <number-or-id>\n"
        "  startup undo             flip the last startup change back\n"
        "  storage <folder>         biggest folders and file types\n"
        "  dupes <folder>           find identical files (report only)\n"
        "  demo                     try everything safely on made-up files\n\n"
        "No live protection. Keep Windows Security turned on.\n",
        HEM_GUARD_VERSION);
}

// ------------------------------------------------------------------ helpers --

bool load_rules(const Args& a, RuleSet& rules, HashList& hashes) {
    const fs::path rdir = exe_dir() / "rules";
    const fs::path rf = a.has("rules") ? from_u8(a.get("rules")) : rdir / "hem_rules.txt";
    const fs::path hf = a.has("hashes") ? from_u8(a.get("hashes")) : rdir / "hem_known_bad_hashes.txt";
    std::vector<std::string> errs;
    bool ok = true;
    if (!rules.load_file(rf, errs)) {
        std::printf("Could not read the rules file: %s\n", to_u8(rf).c_str());
        ok = false;
    }
    if (!hashes.load_file(hf, errs)) {
        std::printf("Could not read the known-bad hash list: %s\n", to_u8(hf).c_str());
        ok = false;
    }
    for (const auto& e : errs) std::printf("  rules note: %s\n", e.c_str());
    std::printf("Loaded %zu pattern rules and %zu known-bad hashes.\n", rules.rules().size(), hashes.size());
    return ok;
}

const char* sev_word(Severity s) { return s == Severity::High ? "HIGH  " : (s == Severity::Medium ? "MEDIUM" : "LOW   "); }

std::unique_ptr<StartupBackend> startup_backend() { return make_windows_startup_backend(StartupLayout::system_default()); }

void print_findings(const std::vector<Finding>& findings) {
    std::vector<const Finding*> sorted;
    for (const auto& f : findings) sorted.push_back(&f);
    std::stable_sort(sorted.begin(), sorted.end(), [](const Finding* a, const Finding* b) { return a->severity > b->severity; });
    for (const auto* f : sorted) {
        std::printf("[%s] %s\n         %s: %s\n", sev_word(f->severity), to_u8(f->path).c_str(), to_string(f->kind), f->detail.c_str());
    }
}

bool confirm(const std::string& question, const Args& a) {
    if (a.has("yes")) return true;
    std::printf("%s\nType YES (capital letters) and press Enter to continue, or just press Enter to cancel: ", question.c_str());
    std::fflush(stdout);
    std::string answer;
    std::getline(std::cin, answer);
    return trim(answer) == "YES";
}

// ------------------------------------------------------------------- scan --

int cmd_scan(const Args& a) {
    if (a.pos.empty()) {
        std::printf("Tell me what to scan, for example:  scan C:\\Users\\You\\Downloads\n");
        return 1;
    }
    RuleSet rules;
    HashList hashes;
    load_rules(a, rules, hashes);

    ScanOptions opt;
    opt.rules = &rules;
    opt.hashes = &hashes;
    if (a.has("cpu")) {
        try {
            opt.cpu_share = std::clamp(std::stod(a.get("cpu")), 0.1, 1.0);
        } catch (...) {
            std::printf("--cpu needs a number such as 0.5\n");
            return 1;
        }
    }
    const fs::path qdir = a.has("quarantine-dir") ? from_u8(a.get("quarantine-dir")) : data_dir() / "Quarantine";
    opt.skip_roots = {qdir, data_dir() / "Undo"};
    const auto env = Environment::detect();
    if (!env.user_temp.empty()) opt.risky_dirs.push_back(env.user_temp);
    const auto kf = known_folders();
    if (!kf.downloads.empty()) opt.risky_dirs.push_back(kf.downloads);
    if (auto backend = startup_backend()) {
        const auto layout = StartupLayout::system_default();
        if (!layout.user_folder.empty()) opt.startup_dirs.push_back(layout.user_folder);
        if (!layout.common_folder.empty()) opt.startup_dirs.push_back(layout.common_folder);
        StartupManager mgr(*backend, {});
        for (const auto& it : mgr.list(false)) {
            if (!it.program.empty()) opt.startup_files.insert(startup_key(it.program));
        }
    }

    const fs::path target = from_u8(a.pos[0]);
    std::printf("Scanning %s  (CPU limit %.0f%%) ...\n", to_u8(target).c_str(), opt.cpu_share * 100.0);
    std::uint64_t n = 0;
    opt.on_file = [&](const fs::path&) {
        if (++n % 2000 == 0) {
            std::printf("  ... %llu files\n", static_cast<unsigned long long>(n));
            std::fflush(stdout);
        }
    };
    const auto rep = scan_path(target, opt);

    line('=');
    print_findings(rep.findings);
    if (rep.findings.empty()) std::printf("No known-bad files or warning signs found.\n");
    line();
    std::printf("Files seen %llu, read %llu, too big to read %llu, unreadable %llu, data read %s\n",
                static_cast<unsigned long long>(rep.files_seen), static_cast<unsigned long long>(rep.files_scanned),
                static_cast<unsigned long long>(rep.files_too_big), static_cast<unsigned long long>(rep.files_unreadable),
                format_bytes(rep.bytes_read).c_str());
    std::printf("Time %.1f s, CPU used by this program %.0f%% of that time\n", rep.wall_seconds, rep.cpu_share_used * 100.0);
    std::printf("\nReminder: \"nothing found\" only means no KNOWN pattern matched. It does not prove a file is safe.\n");

    if (a.has("quarantine") || a.has("quarantine-warnings")) {
        Quarantine q(qdir);
        int moved = 0;
        for (const auto& f : rep.findings) {
            const bool confirmed_bad = f.kind != FindingKind::WarningSign;
            const bool high_warning = f.kind == FindingKind::WarningSign && f.severity == Severity::High && a.has("quarantine-warnings");
            if (!confirmed_bad && !high_warning) continue;
            std::string id, err;
            if (q.quarantine_file(f.path, f.rule + ": " + f.detail, id, err)) {
                std::printf("Quarantined (id %s): %s\n", id.c_str(), to_u8(f.path).c_str());
                ++moved;
            } else {
                std::printf("Could not quarantine %s: %s\n", to_u8(f.path).c_str(), err.c_str());
            }
        }
        std::printf("%d file(s) moved to quarantine at %s. Nothing was deleted; use \"quarantine restore <id>\" to bring one back.\n",
                    moved, to_u8(qdir).c_str());
    } else if (!rep.findings.empty()) {
        std::printf("Nothing was moved or deleted. Add --quarantine to isolate the bad files (you can restore them).\n");
    }
    return rep.findings.empty() ? 0 : 2;
}

int cmd_quarantine(const Args& a) {
    const fs::path qdir = a.has("quarantine-dir") ? from_u8(a.get("quarantine-dir")) : data_dir() / "Quarantine";
    Quarantine q(qdir);
    const std::string sub = a.pos.empty() ? "list" : a.pos[0];
    if (sub == "list") {
        const auto all = q.list();
        if (all.empty()) std::printf("The quarantine is empty.\n");
        for (const auto& e : all) {
            std::printf("%s  %s  %s  %s\n   from: %s\n   why:  %s\n", e.id.c_str(), e.active ? "in quarantine" : "restored     ",
                        format_time_utc(e.time).c_str(), format_bytes(e.size).c_str(), to_u8(e.original).c_str(), e.reason.c_str());
        }
        return 0;
    }
    if (sub == "restore" && a.pos.size() >= 2) {
        std::string err;
        if (q.restore(a.pos[1], err)) {
            std::printf("Restored.\n");
            return 0;
        }
        std::printf("Could not restore: %s\n", err.c_str());
        return 1;
    }
    usage();
    return 1;
}

// ------------------------------------------------------------------ clean --

void print_plan(const Environment& env, const CleanPlan& plan) {
    std::printf("\n%-8s %-52s %8s %12s\n", "Risk", "Place", "Files", "Size");
    line();
    for (const auto& [id, s] : plan.by_target) {
        if (s.files == 0) continue;
        std::printf("%-8s %-52s %8zu %12s%s\n", to_string(s.risk), s.label.substr(0, 52).c_str(), s.files, format_bytes(s.bytes).c_str(),
                    s.included ? "" : "   (not included)");
    }
    line();
    std::printf("Would clean: %zu files, %s", plan.items.size(), format_bytes(plan.total_bytes()).c_str());
    if (plan.careful_bytes_available > 0)
        std::printf("   (+%s more in CAREFUL places; add --careful to include)", format_bytes(plan.careful_bytes_available).c_str());
    std::printf("\nLeft alone on purpose: %llu items (too new, protected, or inside project folders)\n",
                static_cast<unsigned long long>(plan.skipped_count));
    std::printf("\nNEVER touched (DO NOT TOUCH):\n");
    for (const auto& p : never_touched_list(env)) std::printf("  %-10s %s\n", p.first.c_str(), to_u8(p.second).c_str());
    std::printf("  Also: anything not on the cleanup list above. There is no registry cleaner in HEM Guard, on purpose.\n");
}

int cmd_clean(const Args& a) {
    const Environment env = Environment::detect();
    if (!is_windows() || env.user_temp.empty()) {
        std::printf("Cleaning only works on Windows. Nothing was changed.\n");
        return 1;
    }
    std::vector<std::string> notes;
    const auto targets = default_targets(env, &notes);
    for (const auto& n : notes) std::printf("Note: %s\n", n.c_str());
    PlanOptions po;
    po.include_careful = a.has("careful");
    std::printf("Looking at %zu cleanup places (reading only) ...\n", targets.size());
    const auto plan = make_plan(env, targets, po);
    print_plan(env, plan);

    if (!a.has("apply")) {
        std::printf("\nDRY RUN: nothing was changed. To really clean, run again with --apply\n");
        return 0;
    }
    if (plan.items.empty()) {
        std::printf("\nNothing to clean.\n");
        return 0;
    }
    UndoStore undo(env.undo_root);
    const auto purged = undo.purge_expired();
    if (purged) std::printf("Removed %zu old undo batch(es) whose %d days were up.\n", purged, cfg::kUndoRetentionDays);
    if (!confirm("\nMove " + std::to_string(plan.items.size()) + " files (" + format_bytes(plan.total_bytes()) +
                     ") to the HEM Guard Undo folder? They stay there " + std::to_string(cfg::kUndoRetentionDays) +
                     " days and can be put back with \"clean-undo\".",
                 a)) {
        std::printf("Cancelled. Nothing was changed.\n");
        return 0;
    }
    const auto res = apply_plan(plan, env, targets, undo, true);
    std::printf("\nMoved %zu files (%s) to the Undo folder.", res.moved, format_bytes(res.moved_bytes).c_str());
    if (res.failed) std::printf(" %zu were in use and skipped.", res.failed);
    if (res.refused) std::printf(" %zu were refused by the safety check.", res.refused);
    std::printf("\n");
    for (std::size_t i = 0; i < res.messages.size() && i < 15; ++i) std::printf("  %s\n", res.messages[i].c_str());
    if (res.messages.size() > 15) std::printf("  ... and %zu more\n", res.messages.size() - 15);
    if (!res.batch_id.empty()) std::printf("Undo with:  clean-undo     (batch %s)\n", res.batch_id.c_str());
    return 0;
}

int cmd_clean_undo(const Args& a) {
    const Environment env = Environment::detect();
    if (env.undo_root.empty()) {
        std::printf("Not available on this system.\n");
        return 1;
    }
    UndoStore undo(env.undo_root);
    if (a.has("list")) {
        const auto b = undo.list_batches();
        if (b.empty()) std::printf("No undo batches.\n");
        for (const auto& x : b)
            std::printf("%s  made %s  %zu files  %s  kept until %s\n", x.id.c_str(), format_time_utc(x.created).c_str(), x.items,
                        format_bytes(x.bytes).c_str(), format_time_utc(x.expires).c_str());
        return 0;
    }
    const auto r = a.pos.empty() ? undo.restore_latest() : undo.restore_batch(a.pos[0]);
    std::printf("Restored %zu file(s).", r.restored);
    if (r.conflicts) std::printf(" %zu not restored because something new is already there.", r.conflicts);
    if (r.missing) std::printf(" %zu were already gone.", r.missing);
    if (r.failed) std::printf(" %zu failed.", r.failed);
    std::printf("\n");
    for (const auto& m : r.messages) std::printf("  %s\n", m.c_str());
    return (r.failed || r.conflicts) ? 1 : 0;
}

int cmd_clean_purge() {
    const Environment env = Environment::detect();
    if (env.undo_root.empty()) return 1;
    UndoStore undo(env.undo_root);
    std::printf("Removed %zu expired undo batch(es).\n", undo.purge_expired());
    return 0;
}

// ---------------------------------------------------------------- startup --

int cmd_startup(const Args& a) {
    auto backend = startup_backend();
    if (!backend) {
        std::printf("The startup manager only works on Windows.\n");
        return 1;
    }
    StartupManager mgr(*backend, data_dir() / "startup-journal.tsv");
    const std::string sub = a.pos.empty() ? "list" : a.pos[0];
    const auto items = mgr.list(a.has("all"));

    if (sub == "list") {
        std::printf("%3s  %-9s %-9s %-34s %s\n", "#", "State", "Signature", "Name", "Starts");
        line();
        int n = 0;
        for (const auto& it : items) {
            std::printf("%3d  %-9s %-9s %-34s %s\n", ++n, it.enabled ? "on" : "OFF", to_string(it.signature),
                        it.name.substr(0, 34).c_str(), to_u8(it.program).c_str());
        }
        std::printf("\n\"unsigned\" means no valid digital signature was found. Plenty of honest programs are unsigned, so it is a hint, not a verdict.\n");
        std::printf("Windows' own scheduled tasks are hidden unless you add --all (and are read-only).\n");
        return 0;
    }
    if ((sub == "disable" || sub == "enable") && a.pos.size() >= 2) {
        std::string id = a.pos[1];
        if (id.find_first_not_of("0123456789") == std::string::npos) {
            const std::size_t idx = static_cast<std::size_t>(std::stoul(id));
            if (idx < 1 || idx > items.size()) {
                std::printf("There is no item number %s.\n", id.c_str());
                return 1;
            }
            id = items[idx - 1].id;
        }
        std::string err;
        const bool ok = sub == "disable" ? mgr.disable(id, err) : mgr.enable(id, err);
        std::printf(ok ? "Done. (Nothing was deleted. \"startup undo\" flips it back.)\n" : "Could not do that: %s\n", err.c_str());
        return ok ? 0 : 1;
    }
    if (sub == "undo") {
        std::string err, what;
        if (mgr.undo_last(err, &what)) {
            std::printf("Done: %s\n", what.c_str());
            return 0;
        }
        std::printf("%s\n", err.c_str());
        return 1;
    }
    usage();
    return 1;
}

// ------------------------------------------------------- storage / duplicates --

int cmd_storage(const Args& a) {
    if (a.pos.empty()) {
        std::printf("Tell me which folder, for example:  storage C:\\Users\\You\n");
        return 1;
    }
    const auto rep = storage_report(from_u8(a.pos[0]));
    std::printf("%llu files, %s in total\n\nBiggest folders:\n", static_cast<unsigned long long>(rep.total_files),
                format_bytes(rep.total_bytes).c_str());
    for (const auto& f : rep.folders) std::printf("  %12s  %8llu files  %s\n", format_bytes(f.bytes).c_str(), static_cast<unsigned long long>(f.files), to_u8(f.path).c_str());
    std::printf("\nBy file type:\n");
    for (const auto& t : rep.types) std::printf("  %12s  %8llu files  %s\n", format_bytes(t.bytes).c_str(), static_cast<unsigned long long>(t.files), t.ext.c_str());
    std::printf("\nBiggest files:\n");
    for (const auto& f : rep.biggest_files) std::printf("  %12s  %s\n", format_bytes(f.bytes).c_str(), to_u8(f.path).c_str());
    return 0;
}

int cmd_dupes(const Args& a) {
    if (a.pos.empty()) {
        std::printf("Tell me which folder, for example:  dupes C:\\Users\\You\\Pictures\n");
        return 1;
    }
    std::uint64_t min_bytes = cfg::kDupMinBytes;
    if (a.has("min-kb")) {
        try {
            min_bytes = std::stoull(a.get("min-kb")) * 1024;
        } catch (...) {
        }
    }
    const auto rep = find_duplicates(from_u8(a.pos[0]), min_bytes);
    std::printf("Looked at %llu files, fully compared %llu.\n", static_cast<unsigned long long>(rep.files_seen),
                static_cast<unsigned long long>(rep.files_hashed));
    for (const auto& g : rep.groups) {
        std::printf("\n%zu identical copies of %s (wasting %s):\n", g.paths.size(), format_bytes(g.size).c_str(), format_bytes(g.wasted_bytes()).c_str());
        for (const auto& p : g.paths) std::printf("   %s\n", to_u8(p).c_str());
    }
    std::printf("\nTotal space taken by extra copies: %s.  REPORT ONLY - HEM Guard never deletes duplicates for you.\n",
                format_bytes(rep.total_wasted).c_str());
    return 0;
}

// ------------------------------------------------------------------- demo --

#define DEMO_CHECK(cond, what)                                              \
    do {                                                                    \
        const bool ok_ = static_cast<bool>(cond);                           \
        std::printf("  [%s] %s\n", ok_ ? "ok" : "FAILED", what);            \
        if (!ok_) ++failures;                                               \
    } while (0)

int cmd_demo() {
    int failures = 0;
    std::error_code ec;
    const fs::path root = fs::temp_directory_path(ec) / "HEM Guard Demo";
    fs::remove_all(root, ec);  // only ever our own demo folder
    const auto put = [&](const std::string& rel, const std::string& body, int age_hours = 48) {
        const fs::path p = root / from_u8(rel);
        fs::create_directories(p.parent_path(), ec);
        std::FILE* f = std::fopen(to_u8(p).c_str(), "wb");
        if (f) {
            std::fwrite(body.data(), 1, body.size(), f);
            std::fclose(f);
        }
        fs::last_write_time(p, fs::file_time_type::clock::now() - std::chrono::hours(age_hours), ec);
        return p;
    };

    std::printf("HEM Guard demo. Everything below happens inside this made-up folder only:\n  %s\n\n", to_u8(root).c_str());
    const fs::path marker = put("Downloads/harmless-marker.dat", "demo junk HEM-GUARD-DEMO-MARKER-0001 demo junk");
    put("Downloads/invoice.pdf.exe", "this is only text pretending to be a program");
    put("Downloads/notes.txt", "my notes");
    const std::string same(6000, 'D');
    put("Pictures/a.bin", same);
    put("Pictures/copy-of-a.bin", same);
    put("Documents/novel.txt", "chapter one", 400);
    put("Temp/old-download.tmp", std::string(8000, 't'));
    put("Temp/new-file.tmp", "an app is using this right now", 0);
    put("Cache/page1", std::string(5000, 'c'));

    // 1. Scan
    std::printf("1) SCAN (reads only)\n");
    RuleSet rules;
    std::string err;
    rules.add_line("HEM.Demo.Marker | high | text | HEM-GUARD-DEMO-MARKER-0001", err);
    ScanOptions so;
    so.rules = &rules;
    so.cpu_share = 1.0;
    so.risky_dirs = {root / "Downloads"};
    const std::string before_scan = [&] {
        std::string s;
        for (auto& e : fs::recursive_directory_iterator(root)) s += to_u8(e.path()) + std::to_string(e.is_regular_file() ? fs::file_size(e.path()) : 0) + ";";
        return s;
    }();
    const auto rep = scan_path(root, so);
    print_findings(rep.findings);
    DEMO_CHECK(rep.findings.size() == 2, "found the harmless marker file and the fake invoice.pdf.exe");
    std::string after_scan;
    for (auto& e : fs::recursive_directory_iterator(root)) after_scan += to_u8(e.path()) + std::to_string(e.is_regular_file() ? fs::file_size(e.path()) : 0) + ";";
    DEMO_CHECK(before_scan == after_scan, "scanning changed nothing");

    // 2. Quarantine and restore
    std::printf("\n2) QUARANTINE and RESTORE\n");
    Quarantine q(root / "_quarantine");
    std::string id;
    std::string original;
    read_text_file(marker, original);
    DEMO_CHECK(q.quarantine_file(marker, "demo", id, err), "moved the marker file into quarantine");
    DEMO_CHECK(!fs::exists(marker), "it is no longer in Downloads");
    DEMO_CHECK(q.restore(id, err), "restored it");
    std::string restored;
    read_text_file(marker, restored);
    DEMO_CHECK(restored == original, "restored file is identical, byte for byte");

    // 3. Duplicates and storage
    std::printf("\n3) DUPLICATES and STORAGE (report only)\n");
    const auto dups = find_duplicates(root / "Pictures", 1);
    DEMO_CHECK(dups.groups.size() == 1 && dups.groups[0].paths.size() == 2, "found the two identical pictures; deleted nothing");
    const auto st = storage_report(root);
    std::printf("  biggest folder: %s (%s)\n", st.folders.empty() ? "-" : to_u8(st.folders[0].path.filename()).c_str(),
                st.folders.empty() ? "-" : format_bytes(st.folders[0].bytes).c_str());

    // 4. Clean: dry run, apply, undo
    std::printf("\n4) CLEAN: preview, do it, undo it\n");
    Environment env;
    env.user_temp = normalize_path(root / "Temp");
    env.local_appdata = normalize_path(root / "AppData");
    env.undo_root = normalize_path(root / "_undo" / "Undo");
    env.protected_folders = {{"Documents", normalize_path(root / "Documents")}, {"Downloads", normalize_path(root / "Downloads")},
                             {"Pictures", normalize_path(root / "Pictures")}};
    fs::create_directories(env.local_appdata / "Google" / "Chrome" / "User Data" / "Default", ec);
    fs::rename(root / "Cache", env.local_appdata / "Google" / "Chrome" / "User Data" / "Default" / "Cache", ec);
    const auto targets = default_targets(env);
    const auto plan = make_plan(env, targets);
    print_plan(env, plan);
    DEMO_CHECK(plan.items.size() == 2, "plan has the old temp file and the browser cache file, not the new temp file");
    UndoStore undo(env.undo_root);
    const auto dry = apply_plan(plan, env, targets, undo, false);
    DEMO_CHECK(dry.dry_run && dry.moved == 0 && fs::exists(root / "Temp" / "old-download.tmp"), "dry run changed nothing");
    const auto done = apply_plan(plan, env, targets, undo, true);
    DEMO_CHECK(done.moved == 2 && !fs::exists(root / "Temp" / "old-download.tmp"), "after confirming, the files moved to the Undo folder");
    DEMO_CHECK(fs::exists(root / "Documents" / "novel.txt") && fs::exists(root / "Temp" / "new-file.tmp"), "Documents and the brand-new file were left alone");
    const auto back = undo.restore_latest();
    DEMO_CHECK(back.restored == 2 && fs::exists(root / "Temp" / "old-download.tmp"), "one-step undo put everything back");

    std::printf("\n");
    fs::remove_all(root, ec);
    if (failures == 0) std::printf("DEMO PASSED - every step did what it says. (The demo folder was removed.)\n");
    else std::printf("DEMO FAILED - %d step(s) did not behave.\n", failures);
    return failures == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    if (argc < 2) {
        usage();
        return 0;
    }
    const std::string cmd = argv[1];
    const Args a = parse_args(argc, argv, 2);
    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        usage();
        return 0;
    }
    if (cmd == "version" || cmd == "--version") {
        std::printf("HEM Guard %s\n", HEM_GUARD_VERSION);
        return 0;
    }
    try {
        if (cmd == "scan") return cmd_scan(a);
        if (cmd == "quarantine") return cmd_quarantine(a);
        if (cmd == "clean") return cmd_clean(a);
        if (cmd == "clean-undo") return cmd_clean_undo(a);
        if (cmd == "clean-purge") return cmd_clean_purge();
        if (cmd == "startup") return cmd_startup(a);
        if (cmd == "storage") return cmd_storage(a);
        if (cmd == "dupes") return cmd_dupes(a);
        if (cmd == "demo") return cmd_demo();
    } catch (const std::exception& e) {
        std::printf("Something went wrong: %s\n", e.what());
        return 1;
    }
    std::printf("I do not know the command \"%s\".\n\n", cmd.c_str());
    usage();
    return 1;
}
