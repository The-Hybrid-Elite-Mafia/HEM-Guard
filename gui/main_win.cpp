// HEM Guard - the window (Windows only). Plain Win32 controls on top of hem_guard_core.
// All real work happens in the engine; this file only shows things and asks before doing anything.
// "--selftest <folder>" drives every tab on made-up files, saves screenshots and a result file, then exits.
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "hem_guard/cleaner.hpp"
#include "hem_guard/quarantine.hpp"
#include "hem_guard/reports.hpp"
#include "hem_guard/scanner.hpp"
#include "hem_guard/startup.hpp"

#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

using namespace hem::guard;

namespace {

// ------------------------------------------------------------ small helpers --
using Row = std::vector<std::wstring>;

std::wstring W(const std::string& u8) {
    if (u8.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, u8.data(), static_cast<int>(u8.size()), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, u8.data(), static_cast<int>(u8.size()), w.data(), n);
    return w;
}
std::wstring WP(const fs::path& p) { return p.wstring(); }

enum Ids {
    IDC_TAB = 100,
    IDC_STATUS = 101,
    // scan
    IDC_S_PATH = 200, IDC_S_BROWSE, IDC_S_DOWNLOADS, IDC_S_FOLDER, IDC_S_STOP, IDC_S_CPU, IDC_S_VIEW_RES, IDC_S_VIEW_Q,
    IDC_S_LIST, IDC_S_QSEL, IDC_S_QBAD, IDC_S_RESTORE, IDC_S_SUMMARY, IDC_S_LBL1, IDC_S_LBL2, IDC_S_NOTE,
    // clean
    IDC_C_PREVIEW = 300, IDC_C_CAREFUL, IDC_C_LIST, IDC_C_CLEAN, IDC_C_UNDO, IDC_C_PURGE, IDC_C_SUMMARY, IDC_C_NEVER, IDC_C_NOTE,
    // startup
    IDC_U_LIST = 400, IDC_U_REFRESH, IDC_U_OFF, IDC_U_ON, IDC_U_UNDO, IDC_U_SYSTEM, IDC_U_NOTE, IDC_U_SUMMARY,
    // storage
    IDC_T_PATH = 500, IDC_T_BROWSE, IDC_T_ANALYZE, IDC_T_DUPES, IDC_T_VIEW, IDC_T_LIST, IDC_T_SUMMARY, IDC_T_LBL, IDC_T_NOTE,
};

constexpr UINT WM_APP_DONE = WM_APP + 1;
constexpr UINT WM_APP_PROGRESS = WM_APP + 2;

// Colour codes for list rows.
enum RowColor { ROW_NONE = 0, ROW_LOW = 1, ROW_MED = 2, ROW_HIGH = 3, ROW_GREY = 4, ROW_GOOD = 5 };

struct App {
    HINSTANCE inst = nullptr;
    HWND main = nullptr, tab = nullptr, status = nullptr;
    HWND page[4] = {};
    HFONT font = nullptr, font_big = nullptr, font_small = nullptr, font_head = nullptr;
    int dpi = 96;
    bool silent = false;  // self-test: never pop up a question
    fs::path data_root_override;
    bool env_override_on = false;
    Environment env_override;

    // work thread
    std::atomic<bool> busy{false};
    std::atomic<bool> stop{false};
    std::thread worker;

    // scan
    std::vector<Finding> findings;
    int scan_view = 0;  // 0 results, 1 quarantine
    std::vector<QuarantineEntry> q_rows;
    // clean
    Environment clean_env;
    std::vector<CleanTarget> clean_targets;
    CleanPlan plan;
    bool have_plan = false;
    // startup
    std::vector<StartupItem> startup_items;
    // storage
    StorageReport storage;
    DuplicateReport dupes;
    bool have_storage = false, have_dupes = false;
    // list colours
    std::map<int, std::vector<int>> colors;
} g;

int S(int v) { return MulDiv(v, g.dpi, 96); }

fs::path exe_dir() {
    wchar_t buf[MAX_PATH * 4] = {};
    const DWORD n = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(sizeof(buf) / sizeof(buf[0])));
    return n > 0 ? fs::path(buf).parent_path() : fs::current_path();
}
fs::path data_dir() {
    if (!g.data_root_override.empty()) return g.data_root_override;
    if (auto l = env_var("LOCALAPPDATA")) return from_u8(*l) / "HEM Guard";
    return fs::current_path() / "HEM Guard data";
}
Environment current_env() {
    if (g.env_override_on) return g.env_override;
    Environment e = Environment::detect();
    return e;
}

HWND P(int idx) { return g.page[idx]; }
HWND C(int page, int id) { return GetDlgItem(g.page[page], id); }

void set_status(const std::wstring& s) { SendMessageW(g.status, SB_SETTEXTW, 0, reinterpret_cast<LPARAM>(s.c_str())); }
void set_text(HWND h, const std::wstring& s) { SetWindowTextW(h, s.c_str()); }

bool ask(const std::wstring& text, const wchar_t* title = L"HEM Guard") {
    if (g.silent) return true;
    return MessageBoxW(g.main, text.c_str(), title, MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES;
}
void tell(const std::wstring& text, UINT icon = MB_ICONINFORMATION) {
    if (g.silent) return;
    MessageBoxW(g.main, text.c_str(), L"HEM Guard", MB_OK | icon);
}

// ------------------------------------------------------------- list helpers --
void lv_setup(HWND lv, const std::vector<std::pair<const wchar_t*, int>>& cols) {
    ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    while (ListView_DeleteColumn(lv, 0)) {
    }
    int i = 0;
    for (const auto& c : cols) {
        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = const_cast<wchar_t*>(c.first);
        col.cx = S(c.second);
        ListView_InsertColumn(lv, i++, &col);
    }
}
void lv_clear(HWND lv, int id) {
    ListView_DeleteAllItems(lv);
    g.colors[id].clear();
}
void lv_add(HWND lv, int id, const Row& r, int color) {
    auto& cv = g.colors[id];
    LVITEMW it{};
    it.mask = LVIF_TEXT | LVIF_PARAM;
    it.iItem = ListView_GetItemCount(lv);
    it.lParam = static_cast<LPARAM>(cv.size());
    it.pszText = const_cast<wchar_t*>(r.empty() ? L"" : r[0].c_str());
    const int row = static_cast<int>(SendMessageW(lv, LVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&it)));
    for (std::size_t c = 1; c < r.size(); ++c) ListView_SetItemText(lv, row, static_cast<int>(c), const_cast<wchar_t*>(r[c].c_str()));
    cv.push_back(color);
}
std::vector<int> lv_selected_data(HWND lv) {  // returns each selected row's lParam (index into our own vectors)
    std::vector<int> v;
    int i = -1;
    while ((i = ListView_GetNextItem(lv, i, LVNI_SELECTED)) != -1) {
        LVITEMW it{};
        it.mask = LVIF_PARAM;
        it.iItem = i;
        ListView_GetItem(lv, &it);
        v.push_back(static_cast<int>(it.lParam));
    }
    return v;
}
void lv_select_first(HWND lv) { ListView_SetItemState(lv, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED); }

// ------------------------------------------------------------- work thread --
void run_async(const std::wstring& msg, std::function<std::function<void()>()> work) {
    if (g.busy.exchange(true)) {
        set_status(L"Busy - please wait for the current job to finish.");
        return;
    }
    if (g.worker.joinable()) g.worker.join();
    g.stop = false;
    set_status(msg);
    EnableWindow(C(0, IDC_S_STOP), TRUE);
    g.worker = std::thread([work = std::move(work)]() {
        std::function<void()> fin;
        try {
            fin = work();
        } catch (const std::exception& e) {
            const std::wstring m = L"Something went wrong: " + W(e.what());
            fin = [m] { set_status(m); };
        } catch (...) {
            fin = [] { set_status(L"Something went wrong (unknown error). Nothing else was changed."); };
        }
        PostMessageW(g.main, WM_APP_DONE, 0, reinterpret_cast<LPARAM>(new std::function<void()>(std::move(fin))));
    });
}
void post_progress(const std::wstring& s) { PostMessageW(g.main, WM_APP_PROGRESS, 0, reinterpret_cast<LPARAM>(new std::wstring(s))); }

// ----------------------------------------------------------------- scan tab --
std::wstring sev_word(Severity s) { return s == Severity::High ? L"HIGH" : s == Severity::Medium ? L"MEDIUM" : L"LOW"; }
int sev_color(Severity s) { return s == Severity::High ? ROW_HIGH : s == Severity::Medium ? ROW_MED : ROW_LOW; }

void scan_show_results() {
    HWND lv = C(0, IDC_S_LIST);
    lv_setup(lv, {{L"Level", 70}, {L"What", 120}, {L"Rule", 170}, {L"File", 420}, {L"Why", 420}});
    lv_clear(lv, IDC_S_LIST);
    std::vector<std::size_t> order(g.findings.size());
    for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::stable_sort(order.begin(), order.end(), [](std::size_t a, std::size_t b) { return g.findings[a].severity > g.findings[b].severity; });
    // The list shows the first 5000 only (a very long list is slow to draw); all are kept in memory.
    const std::size_t cap = std::min<std::size_t>(order.size(), 5000);
    g.colors[IDC_S_LIST].clear();
    HWND l = lv;
    for (std::size_t k = 0; k < cap; ++k) {
        const auto& f = g.findings[order[k]];
        LVITEMW it{};
        it.mask = LVIF_TEXT | LVIF_PARAM;
        it.iItem = static_cast<int>(k);
        it.lParam = static_cast<LPARAM>(order[k]);  // index into g.findings
        const std::wstring lvl = sev_word(f.severity);
        it.pszText = const_cast<wchar_t*>(lvl.c_str());
        const int row = static_cast<int>(SendMessageW(l, LVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&it)));
        const std::wstring kind = W(to_string(f.kind)), rule = W(f.rule), path = WP(f.path), why = W(f.detail);
        ListView_SetItemText(l, row, 1, const_cast<wchar_t*>(kind.c_str()));
        ListView_SetItemText(l, row, 2, const_cast<wchar_t*>(rule.c_str()));
        ListView_SetItemText(l, row, 3, const_cast<wchar_t*>(path.c_str()));
        ListView_SetItemText(l, row, 4, const_cast<wchar_t*>(why.c_str()));
        g.colors[IDC_S_LIST].resize(std::max<std::size_t>(g.colors[IDC_S_LIST].size(), order[k] + 1), ROW_NONE);
        g.colors[IDC_S_LIST][order[k]] = sev_color(f.severity);
    }
}

void scan_show_quarantine() {
    HWND lv = C(0, IDC_S_LIST);
    lv_setup(lv, {{L"State", 110}, {L"When (UTC)", 150}, {L"Size", 80}, {L"Original file", 420}, {L"Why", 330}, {L"Id", 110}});
    lv_clear(lv, IDC_S_LIST);
    Quarantine q(data_dir() / "Quarantine");
    g.q_rows = q.list();
    std::reverse(g.q_rows.begin(), g.q_rows.end());
    for (std::size_t i = 0; i < g.q_rows.size(); ++i) {
        const auto& e = g.q_rows[i];
        lv_add(lv, IDC_S_LIST,
               {e.active ? L"in quarantine" : L"restored", W(format_time_utc(e.time)), W(format_bytes(e.size)), WP(e.original), W(e.reason), W(e.id)},
               e.active ? ROW_MED : ROW_GREY);
    }
    set_text(C(0, IDC_S_SUMMARY), g.q_rows.empty() ? L"The quarantine is empty." : L"Quarantined files are scrambled and renamed so they cannot run. Select one and press \"Restore selected\" to bring it back.");
}

void scan_set_view(int v) {
    g.scan_view = v;
    SendMessageW(C(0, IDC_S_VIEW_RES), BM_SETCHECK, v == 0 ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(C(0, IDC_S_VIEW_Q), BM_SETCHECK, v == 1 ? BST_CHECKED : BST_UNCHECKED, 0);
    ShowWindow(C(0, IDC_S_QSEL), v == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(C(0, IDC_S_QBAD), v == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(C(0, IDC_S_RESTORE), v == 1 ? SW_SHOW : SW_HIDE);
    if (v == 0) scan_show_results();
    else scan_show_quarantine();
}

double cpu_choice() {
    const int i = static_cast<int>(SendMessageW(C(0, IDC_S_CPU), CB_GETCURSEL, 0, 0));
    static const double v[] = {0.25, 0.5, 0.75, 1.0};
    return (i >= 0 && i < 4) ? v[i] : cfg::kScanCpuShareMax;
}

fs::path get_path_text(HWND edit) {
    wchar_t buf[MAX_PATH * 4] = {};
    GetWindowTextW(edit, buf, static_cast<int>(sizeof(buf) / sizeof(buf[0])));
    std::wstring s = buf;
    while (!s.empty() && (s.back() == L' ' || s.back() == L'"')) s.pop_back();
    while (!s.empty() && (s.front() == L' ' || s.front() == L'"')) s.erase(s.begin());
    return fs::path(s);
}

void start_scan(const fs::path& target) {
    std::error_code ec;
    if (target.empty() || !fs::is_directory(target, ec)) {
        tell(L"That folder does not exist. Pick a folder to scan.", MB_ICONWARNING);
        set_status(L"Pick a folder to scan.");
        return;
    }
    const double cpu = cpu_choice();
    const fs::path rules_dir = exe_dir() / "rules";
    run_async(L"Scanning " + WP(target) + L" ...", [target, cpu, rules_dir]() -> std::function<void()> {
        auto rules = std::make_shared<RuleSet>();
        auto hashes = std::make_shared<HashList>();
        std::vector<std::string> errs;
        const bool r_ok = rules->load_file(rules_dir / "hem_rules.txt", errs);
        hashes->load_file(rules_dir / "hem_known_bad_hashes.txt", errs);

        ScanOptions opt;
        opt.rules = rules.get();
        opt.hashes = hashes.get();
        opt.cpu_share = cpu;
        opt.stop = &g.stop;
        opt.skip_roots = {data_dir() / "Quarantine", data_dir() / "Undo"};
        const Environment env = current_env();
        if (!env.user_temp.empty()) opt.risky_dirs.push_back(env.user_temp);
        const auto kf = known_folders();
        if (!kf.downloads.empty()) opt.risky_dirs.push_back(kf.downloads);
        {
            auto backend = make_windows_startup_backend(StartupLayout::system_default());
            const auto layout = StartupLayout::system_default();
            if (!layout.user_folder.empty()) opt.startup_dirs.push_back(layout.user_folder);
            if (!layout.common_folder.empty()) opt.startup_dirs.push_back(layout.common_folder);
            if (backend) {
                StartupManager mgr(*backend, {});
                for (const auto& it : mgr.list(false)) {
                    if (!it.program.empty()) opt.startup_files.insert(startup_key(it.program));
                }
            }
        }
        std::uint64_t n = 0;
        auto last = std::chrono::steady_clock::now();
        opt.on_file = [&](const fs::path& p) {
            ++n;
            const auto now = std::chrono::steady_clock::now();
            if (now - last > std::chrono::milliseconds(300)) {
                last = now;
                post_progress(L"Scanning ... " + std::to_wstring(n) + L" files. Now: " + WP(p));
            }
        };
        auto rep = std::make_shared<ScanReport>(scan_path(target, opt));
        const bool stopped = g.stop.load();
        return [rep, r_ok, stopped, target]() {
            g.findings = rep->findings;
            scan_set_view(0);
            std::wstring s;
            if (!r_ok) s += L"WARNING: the rules file could not be read, so only warning signs were checked. ";
            s += stopped ? L"Stopped early. " : L"Done. ";
            s += L"Looked at " + std::to_wstring(rep->files_seen) + L" files, read " + std::to_wstring(rep->files_scanned) + L" (" +
                 W(format_bytes(rep->bytes_read)) + L") in " + std::to_wstring(static_cast<int>(rep->wall_seconds + 0.5)) + L" s. ";
            s += g.findings.empty() ? L"Nothing known-bad and no warning signs. (That does NOT prove a file is safe.)"
                                    : std::to_wstring(g.findings.size()) + L" item(s) to look at. Nothing has been moved or deleted.";
            set_text(C(0, IDC_S_SUMMARY), s);
            set_status(stopped ? L"Scan stopped." : L"Scan finished.");
        };
    });
}

void do_quarantine(const std::vector<std::size_t>& which) {
    if (which.empty()) {
        tell(L"Nothing selected.");
        return;
    }
    if (!ask(L"Move " + std::to_wstring(which.size()) +
             L" file(s) to the HEM Guard quarantine?\n\nNothing is deleted. The files are scrambled, renamed so they cannot run, and you can restore them.")) {
        set_status(L"Cancelled. Nothing was changed.");
        return;
    }
    std::vector<Finding> items;
    for (auto i : which) {
        if (i < g.findings.size()) items.push_back(g.findings[i]);
    }
    run_async(L"Moving files to quarantine ...", [items]() -> std::function<void()> {
        Quarantine q(data_dir() / "Quarantine");
        auto moved = std::make_shared<std::vector<fs::path>>();
        std::vector<std::wstring> problems;
        for (const auto& f : items) {
            std::string id, err;
            if (q.quarantine_file(f.path, f.rule + ": " + f.detail, id, err)) moved->push_back(f.path);
            else problems.push_back(WP(f.path) + L": " + W(err));
        }
        return [moved, problems]() {
            g.findings.erase(std::remove_if(g.findings.begin(), g.findings.end(),
                                            [&](const Finding& f) { return std::find(moved->begin(), moved->end(), f.path) != moved->end(); }),
                             g.findings.end());
            scan_set_view(0);
            std::wstring s = std::to_wstring(moved->size()) + L" file(s) moved to quarantine. Nothing was deleted.";
            if (!problems.empty()) s += L" " + std::to_wstring(problems.size()) + L" could not be moved (in use or no permission): " + problems[0];
            set_text(C(0, IDC_S_SUMMARY), s);
            set_status(L"Quarantine done.");
        };
    });
}

std::vector<std::size_t> selected_findings() {
    std::vector<std::size_t> v;
    for (int d : lv_selected_data(C(0, IDC_S_LIST))) v.push_back(static_cast<std::size_t>(d));
    return v;
}

void do_restore() {
    const auto sel = lv_selected_data(C(0, IDC_S_LIST));
    if (sel.empty()) {
        tell(L"Select a quarantined file first.");
        return;
    }
    std::vector<std::string> ids;
    for (int d : sel) {
        if (d >= 0 && static_cast<std::size_t>(d) < g.q_rows.size() && g.q_rows[static_cast<std::size_t>(d)].active) ids.push_back(g.q_rows[static_cast<std::size_t>(d)].id);
    }
    if (ids.empty()) {
        tell(L"That file is already restored.");
        return;
    }
    run_async(L"Restoring ...", [ids]() -> std::function<void()> {
        Quarantine q(data_dir() / "Quarantine");
        int ok = 0;
        std::wstring problem;
        for (const auto& id : ids) {
            std::string err;
            if (q.restore(id, err)) ++ok;
            else if (problem.empty()) problem = W(err);
        }
        return [ok, problem]() {
            scan_set_view(1);
            std::wstring s = std::to_wstring(ok) + L" file(s) restored.";
            if (!problem.empty()) s += L" Could not restore one: " + problem;
            set_text(C(0, IDC_S_SUMMARY), s);
            set_status(L"Restore finished.");
        };
    });
}

// ---------------------------------------------------------------- clean tab --
std::wstring risk_word(Risk r) { return r == Risk::Safe ? L"SAFE" : r == Risk::Careful ? L"CAREFUL" : L"DO NOT TOUCH"; }

void clean_show_plan() {
    HWND lv = C(1, IDC_C_LIST);
    lv_setup(lv, {{L"Risk", 90}, {L"Place", 440}, {L"Files", 80}, {L"Size", 100}, {L"What happens", 260}});
    lv_clear(lv, IDC_C_LIST);
    for (const auto& kv : g.plan.by_target) {
        const auto& t = kv.second;
        lv_add(lv, IDC_C_LIST,
               {risk_word(t.risk), W(t.label), std::to_wstring(t.files), W(format_bytes(t.bytes)),
                t.included ? L"will be moved to the Undo folder" : L"found, but left out (tick the CAREFUL box to include)"},
               t.included ? (t.risk == Risk::Careful ? ROW_MED : ROW_GOOD) : ROW_GREY);
    }
}

void clean_refresh_info() {
    std::wstring never = L"Never touched: ";
    bool first = true;
    for (const auto& p : never_touched_list(current_env())) {
        if (!first) never += L", ";
        never += W(p.first);
        first = false;
    }
    if (first) never += L"your personal folders (Documents, Desktop, Pictures, Music, Videos, Downloads, OneDrive)";
    never += L".  No registry cleaning. Files are moved to the Undo folder, never deleted.";
    set_text(C(1, IDC_C_NEVER), never);
}

void clean_preview() {
    const bool careful = SendMessageW(C(1, IDC_C_CAREFUL), BM_GETCHECK, 0, 0) == BST_CHECKED;
    run_async(L"Looking at the clean-up places (reading only, changing nothing) ...", [careful]() -> std::function<void()> {
        const Environment env = current_env();
        std::vector<std::string> notes;
        auto targets = std::make_shared<std::vector<CleanTarget>>(default_targets(env, &notes));
        PlanOptions po;
        po.include_careful = careful;
        auto plan = std::make_shared<CleanPlan>(make_plan(env, *targets, po));
        auto envp = std::make_shared<Environment>(env);
        return [plan, targets, envp, notes]() {
            g.clean_env = *envp;
            g.clean_targets = *targets;
            g.plan = *plan;
            g.have_plan = true;
            clean_show_plan();
            clean_refresh_info();
            std::wstring s = std::to_wstring(plan->items.size()) + L" file(s), " + W(format_bytes(plan->total_bytes())) + L" ready to move to the Undo folder.";
            if (plan->careful_bytes_available > 0) s += L" Also found " + W(format_bytes(plan->careful_bytes_available)) + L" of CAREFUL items (left out).";
            if (!notes.empty()) s += L"  Note: " + W(notes[0]);
            UndoStore undo(envp->undo_root);
            const auto batches = undo.list_batches();
            if (!batches.empty()) s += L"  Undo folder holds " + std::to_wstring(batches.size()) + L" earlier clean-up(s).";
            set_text(C(1, IDC_C_SUMMARY), s);
            set_status(L"Preview ready. Nothing was changed.");
        };
    });
}

void clean_apply() {
    if (!g.have_plan || g.plan.items.empty()) {
        tell(L"Press \"Preview\" first. There is nothing to clean yet.");
        return;
    }
    if (!ask(L"Move " + std::to_wstring(g.plan.items.size()) + L" files (" + W(format_bytes(g.plan.total_bytes())) +
             L") to the HEM Guard Undo folder?\n\nThey stay there " + std::to_wstring(cfg::kUndoRetentionDays) +
             L" days and you can put them all back with \"Undo last clean\".\n\nNothing in your personal folders is touched.")) {
        set_status(L"Cancelled. Nothing was changed.");
        return;
    }
    auto plan = std::make_shared<CleanPlan>(g.plan);
    auto targets = std::make_shared<std::vector<CleanTarget>>(g.clean_targets);
    auto env = std::make_shared<Environment>(g.clean_env);
    run_async(L"Cleaning (moving files to the Undo folder) ...", [plan, targets, env]() -> std::function<void()> {
        UndoStore undo(env->undo_root);
        const auto purged = undo.purge_expired();
        auto res = std::make_shared<ApplyResult>(apply_plan(*plan, *env, *targets, undo, true));
        return [res, purged]() {
            g.have_plan = false;
            std::wstring s = L"Moved " + std::to_wstring(res->moved) + L" file(s) (" + W(format_bytes(res->moved_bytes)) + L") to the Undo folder.";
            if (res->failed) s += L" " + std::to_wstring(res->failed) + L" were in use and skipped.";
            if (res->refused) s += L" " + std::to_wstring(res->refused) + L" were refused by the safety check.";
            if (purged) s += L" Removed " + std::to_wstring(purged) + L" old undo batch(es) whose time was up.";
            set_text(C(1, IDC_C_SUMMARY), s);
            lv_clear(C(1, IDC_C_LIST), IDC_C_LIST);
            set_status(L"Clean finished. \"Undo last clean\" puts everything back.");
        };
    });
}

void clean_undo() {
    const Environment env = current_env();
    if (!ask(L"Put back the files from the most recent clean-up?")) return;
    run_async(L"Undoing the last clean ...", [env]() -> std::function<void()> {
        UndoStore undo(env.undo_root);
        auto r = std::make_shared<RestoreReport>(undo.restore_latest());
        return [r]() {
            std::wstring s = L"Restored " + std::to_wstring(r->restored) + L" file(s).";
            if (r->conflicts) s += L" " + std::to_wstring(r->conflicts) + L" were left in the Undo folder because something new already sits at the old spot (we never overwrite).";
            if (r->missing) s += L" " + std::to_wstring(r->missing) + L" were missing.";
            if (r->failed) s += L" " + std::to_wstring(r->failed) + L" failed.";
            if (!r->messages.empty()) s += L"  " + W(r->messages[0]);
            set_text(C(1, IDC_C_SUMMARY), s);
            set_status(L"Undo finished.");
        };
    });
}

void clean_purge() {
    const Environment env = current_env();
    if (!ask(L"Permanently remove undo copies that are older than " + std::to_wstring(cfg::kUndoRetentionDays) +
             L" days?\n\nThis frees disk space but those files can no longer be restored.")) return;
    run_async(L"Removing old undo copies ...", [env]() -> std::function<void()> {
        UndoStore undo(env.undo_root);
        const auto n = undo.purge_expired();
        return [n]() {
            set_text(C(1, IDC_C_SUMMARY), L"Removed " + std::to_wstring(n) + L" old undo batch(es).");
            set_status(L"Done.");
        };
    });
}

// -------------------------------------------------------------- startup tab --
void startup_fill() {
    HWND lv = C(2, IDC_U_LIST);
    lv_setup(lv, {{L"State", 70}, {L"Signature", 90}, {L"Name", 260}, {L"Starts this program", 520}, {L"Where", 150}});
    lv_clear(lv, IDC_U_LIST);
    int unsigned_on = 0;
    for (const auto& it : g.startup_items) {
        int color = ROW_NONE;
        if (!it.enabled) color = ROW_GREY;
        else if (it.system_owned) color = ROW_GREY;
        else if (it.signature == SignState::Unsigned) {
            color = ROW_MED;
            ++unsigned_on;
        }
        std::wstring where = W(to_string(it.kind));
        if (it.system_owned) where += L" (Windows, read-only)";
        lv_add(lv, IDC_U_LIST, {it.enabled ? L"on" : L"OFF", W(to_string(it.signature)), W(it.name), WP(it.program), where}, color);
    }
    set_text(C(2, IDC_U_SUMMARY),
             std::to_wstring(g.startup_items.size()) + L" startup item(s). " + std::to_wstring(unsigned_on) +
                 L" turned on without a digital signature (shown in amber) - that is a hint, not a verdict; plenty of honest programs are unsigned.");
}

void startup_refresh() {
    const bool all = SendMessageW(C(2, IDC_U_SYSTEM), BM_GETCHECK, 0, 0) == BST_CHECKED;
    run_async(L"Reading the startup list ...", [all]() -> std::function<void()> {
        auto items = std::make_shared<std::vector<StartupItem>>();
        auto backend = make_windows_startup_backend(StartupLayout::system_default());
        if (backend) {
            StartupManager mgr(*backend, data_dir() / "startup-journal.tsv");
            *items = mgr.list(all);
        }
        return [items]() {
            g.startup_items = *items;
            startup_fill();
            set_status(L"Startup list ready.");
        };
    });
}

void startup_change(bool enable) {
    const auto sel = lv_selected_data(C(2, IDC_U_LIST));
    if (sel.empty()) {
        tell(L"Select a startup item first.");
        return;
    }
    const StartupItem item = g.startup_items[static_cast<std::size_t>(sel[0])];
    if (item.system_owned) {
        tell(L"That one belongs to Windows, so HEM Guard shows it but will not change it.");
        return;
    }
    const bool all = SendMessageW(C(2, IDC_U_SYSTEM), BM_GETCHECK, 0, 0) == BST_CHECKED;
    run_async(enable ? L"Turning it on ..." : L"Turning it off ...", [item, enable, all]() -> std::function<void()> {
        auto backend = make_windows_startup_backend(StartupLayout::system_default());
        std::string err;
        bool ok = false;
        auto items = std::make_shared<std::vector<StartupItem>>();
        if (backend) {
            StartupManager mgr(*backend, data_dir() / "startup-journal.tsv");
            mgr.list(all);
            ok = enable ? mgr.enable(item.id, err) : mgr.disable(item.id, err);
            *items = mgr.list(all);
        } else {
            err = "not available";
        }
        return [items, ok, err, enable]() {
            g.startup_items = *items;
            startup_fill();
            set_status(ok ? (enable ? L"Turned on. (Nothing was deleted.)" : L"Turned off. (Nothing was deleted - \"Undo last change\" flips it back.)")
                          : L"Could not change it: " + W(err));
        };
    });
}

void startup_undo() {
    const bool all = SendMessageW(C(2, IDC_U_SYSTEM), BM_GETCHECK, 0, 0) == BST_CHECKED;
    run_async(L"Undoing the last change ...", [all]() -> std::function<void()> {
        std::string err, what;
        bool ok = false;
        auto items = std::make_shared<std::vector<StartupItem>>();
        auto backend = make_windows_startup_backend(StartupLayout::system_default());
        if (backend) {
            StartupManager mgr(*backend, data_dir() / "startup-journal.tsv");
            ok = mgr.undo_last(err, &what);
            *items = mgr.list(all);
        }
        return [items, ok, err, what]() {
            g.startup_items = *items;
            startup_fill();
            set_status(ok ? L"Done: " + W(what) : W(err));
        };
    });
}

// -------------------------------------------------------------- storage tab --
void storage_show() {
    HWND lv = C(3, IDC_T_LIST);
    lv_clear(lv, IDC_T_LIST);
    const int v = static_cast<int>(SendMessageW(C(3, IDC_T_VIEW), CB_GETCURSEL, 0, 0));
    if (v == 0) {
        lv_setup(lv, {{L"Size", 110}, {L"Files", 90}, {L"Folder", 760}});
        if (g.have_storage)
            for (const auto& f : g.storage.folders) lv_add(lv, IDC_T_LIST, {W(format_bytes(f.bytes)), std::to_wstring(f.files), WP(f.path)}, ROW_NONE);
    } else if (v == 1) {
        lv_setup(lv, {{L"Size", 110}, {L"Files", 90}, {L"File type", 200}});
        if (g.have_storage)
            for (const auto& t : g.storage.types) lv_add(lv, IDC_T_LIST, {W(format_bytes(t.bytes)), std::to_wstring(t.files), W(t.ext)}, ROW_NONE);
    } else if (v == 2) {
        lv_setup(lv, {{L"Size", 110}, {L"File", 850}});
        if (g.have_storage)
            for (const auto& b : g.storage.biggest_files) lv_add(lv, IDC_T_LIST, {W(format_bytes(b.bytes)), WP(b.path)}, ROW_NONE);
    } else {
        lv_setup(lv, {{L"Wasted", 100}, {L"Copies", 70}, {L"Each", 90}, {L"Files (first one shown)", 700}});
        if (g.have_dupes)
            for (const auto& d : g.dupes.groups) {
                std::wstring first = d.paths.empty() ? L"" : WP(d.paths[0]);
                if (d.paths.size() > 1) first += L"   (+ " + std::to_wstring(d.paths.size() - 1) + L" more identical copy/copies)";
                lv_add(lv, IDC_T_LIST, {W(format_bytes(d.wasted_bytes())), std::to_wstring(d.paths.size()), W(format_bytes(d.size)), first}, ROW_NONE);
            }
    }
}

void storage_analyze(bool dupes) {
    const fs::path target = get_path_text(C(3, IDC_T_PATH));
    std::error_code ec;
    if (target.empty() || !fs::is_directory(target, ec)) {
        tell(L"That folder does not exist. Pick a folder first.", MB_ICONWARNING);
        return;
    }
    run_async(dupes ? L"Looking for identical files (report only - nothing is deleted) ..." : L"Measuring folders ...",
              [target, dupes]() -> std::function<void()> {
                  auto sr = std::make_shared<StorageReport>();
                  auto dr = std::make_shared<DuplicateReport>();
                  if (dupes) *dr = find_duplicates(target);
                  else *sr = storage_report(target);
                  return [sr, dr, dupes]() {
                      if (dupes) {
                          g.dupes = *dr;
                          g.have_dupes = true;
                          SendMessageW(C(3, IDC_T_VIEW), CB_SETCURSEL, 3, 0);
                          set_text(C(3, IDC_T_SUMMARY), std::to_wstring(dr->groups.size()) + L" group(s) of identical files, " + W(format_bytes(dr->total_wasted)) +
                                                           L" wasted by extra copies. This is a report only - HEM Guard never deletes duplicates.");
                      } else {
                          g.storage = *sr;
                          g.have_storage = true;
                          if (SendMessageW(C(3, IDC_T_VIEW), CB_GETCURSEL, 0, 0) == 3) SendMessageW(C(3, IDC_T_VIEW), CB_SETCURSEL, 0, 0);
                          set_text(C(3, IDC_T_SUMMARY), std::to_wstring(sr->total_files) + L" files, " + W(format_bytes(sr->total_bytes)) + L" in total.");
                      }
                      storage_show();
                      set_status(L"Done. Nothing was changed.");
                  };
              });
}

// ------------------------------------------------------------------ layout --
void place(int page, int id, int x, int y, int w, int h) {
    HWND c = C(page, id);
    if (c) MoveWindow(c, x, y, w, h, TRUE);
}

void layout_scan(int w, int h) {
    const int m = S(12), bh = S(28), g2 = S(8);
    int y = m;
    place(0, IDC_S_LBL1, m, y + S(5), S(100), S(20));
    const int bw = S(84);
    place(0, IDC_S_BROWSE, w - m - bw, y, bw, bh);
    place(0, IDC_S_PATH, m + S(104), y, w - 2 * m - S(104) - bw - g2, bh);
    y += bh + g2;
    int x = m;
    place(0, IDC_S_DOWNLOADS, x, y, S(140), bh), x += S(140) + g2;
    place(0, IDC_S_FOLDER, x, y, S(130), bh), x += S(130) + g2;
    place(0, IDC_S_STOP, x, y, S(70), bh), x += S(70) + S(24);
    place(0, IDC_S_LBL2, x, y + S(5), S(80), S(20)), x += S(82);
    place(0, IDC_S_CPU, x, y, S(90), S(200));
    y += bh + g2;
    place(0, IDC_S_VIEW_RES, m, y, S(150), S(22));
    place(0, IDC_S_VIEW_Q, m + S(160), y, S(200), S(22));
    y += S(26);
    const int bottom = h - m - bh - S(70);
    place(0, IDC_S_LIST, m, y, w - 2 * m, std::max(S(80), bottom - y));
    y = bottom + g2;
    place(0, IDC_S_QSEL, m, y, S(170), bh);
    place(0, IDC_S_QBAD, m + S(178), y, S(230), bh);
    place(0, IDC_S_RESTORE, m, y, S(170), bh);
    y += bh + g2;
    place(0, IDC_S_SUMMARY, m, y, w - 2 * m, S(34));
    place(0, IDC_S_NOTE, m, y + S(34), w - 2 * m, S(30));
}

void layout_clean(int w, int h) {
    const int m = S(12), bh = S(28), g2 = S(8);
    int y = m, x = m;
    place(1, IDC_C_PREVIEW, x, y, S(200), bh), x += S(208);
    place(1, IDC_C_CAREFUL, x, y + S(3), w - x - m, S(22));
    y += bh + g2;
    const int bottom = h - m - bh - S(124);
    place(1, IDC_C_LIST, m, y, w - 2 * m, std::max(S(80), bottom - y));
    y = bottom + g2;
    x = m;
    place(1, IDC_C_CLEAN, x, y, S(210), bh), x += S(218);
    place(1, IDC_C_UNDO, x, y, S(150), bh), x += S(158);
    place(1, IDC_C_PURGE, x, y, S(260), bh);
    y += bh + g2;
    place(1, IDC_C_SUMMARY, m, y, w - 2 * m, S(36));
    place(1, IDC_C_NEVER, m, y + S(36), w - 2 * m, S(36));
    place(1, IDC_C_NOTE, m, y + S(72), w - 2 * m, S(22));
}

void layout_startup(int w, int h) {
    const int m = S(12), bh = S(28), g2 = S(8);
    int y = m, x = m;
    place(2, IDC_U_REFRESH, x, y, S(90), bh), x += S(98);
    place(2, IDC_U_OFF, x, y, S(140), bh), x += S(148);
    place(2, IDC_U_ON, x, y, S(140), bh), x += S(148);
    place(2, IDC_U_UNDO, x, y, S(160), bh), x += S(176);
    place(2, IDC_U_SYSTEM, x, y + S(3), std::max(S(200), w - x - m), S(22));
    y += bh + g2;
    const int bottom = h - m - S(64);
    place(2, IDC_U_LIST, m, y, w - 2 * m, std::max(S(80), bottom - y));
    place(2, IDC_U_SUMMARY, m, bottom + g2, w - 2 * m, S(34));
    place(2, IDC_U_NOTE, m, bottom + g2 + S(32), w - 2 * m, S(24));
}

void layout_storage(int w, int h) {
    const int m = S(12), bh = S(28), g2 = S(8);
    int y = m;
    place(3, IDC_T_LBL, m, y + S(5), S(100), S(20));
    const int bw = S(84);
    place(3, IDC_T_BROWSE, w - m - bw, y, bw, bh);
    place(3, IDC_T_PATH, m + S(104), y, w - 2 * m - S(104) - bw - g2, bh);
    y += bh + g2;
    int x = m;
    place(3, IDC_T_ANALYZE, x, y, S(170), bh), x += S(178);
    place(3, IDC_T_DUPES, x, y, S(260), bh), x += S(284);
    place(3, IDC_T_VIEW, x, y, S(190), S(200));
    y += bh + g2;
    const int bottom = h - m - S(64);
    place(3, IDC_T_LIST, m, y, w - 2 * m, std::max(S(80), bottom - y));
    place(3, IDC_T_SUMMARY, m, bottom + g2, w - 2 * m, S(34));
    place(3, IDC_T_NOTE, m, bottom + g2 + S(32), w - 2 * m, S(24));
}

int header_h() { return S(66); }

void layout_all() {
    RECT rc;
    GetClientRect(g.main, &rc);
    const int w = rc.right, h = rc.bottom;
    SendMessageW(g.status, WM_SIZE, 0, 0);
    RECT sr;
    GetWindowRect(g.status, &sr);
    const int sh = sr.bottom - sr.top;
    const int hh = header_h();
    MoveWindow(g.tab, 0, hh, w, h - hh - sh, TRUE);
    RECT tr = {0, hh, w, h - sh};
    RECT inner = {0, 0, w, h - hh - sh};
    TabCtrl_AdjustRect(g.tab, FALSE, &inner);
    const int px = inner.left, py = hh + inner.top, pw = inner.right - inner.left, ph = inner.bottom - inner.top;
    (void)tr;
    for (int i = 0; i < 4; ++i) MoveWindow(g.page[i], px, py, pw, ph, TRUE);
    layout_scan(pw, ph);
    layout_clean(pw, ph);
    layout_startup(pw, ph);
    layout_storage(pw, ph);
}

void select_tab(int i) {
    TabCtrl_SetCurSel(g.tab, i);
    for (int k = 0; k < 4; ++k) ShowWindow(g.page[k], k == i ? SW_SHOW : SW_HIDE);
}

// ---------------------------------------------------------------- creation --
HWND mk(HWND parent, const wchar_t* cls, const wchar_t* text, DWORD style, int id, DWORD ex = 0) {
    HWND h = CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g.inst, nullptr);
    SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(g.font), TRUE);
    return h;
}
HWND mkbtn(HWND p, const wchar_t* t, int id) { return mk(p, L"BUTTON", t, BS_PUSHBUTTON | WS_TABSTOP, id); }
HWND mkedit(HWND p, int id) { return mk(p, L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, id, WS_EX_CLIENTEDGE); }
HWND mklist(HWND p, int id) { return mk(p, WC_LISTVIEWW, L"", LVS_REPORT | LVS_SHOWSELALWAYS | WS_TABSTOP, id, WS_EX_CLIENTEDGE); }
HWND mklabel(HWND p, const wchar_t* t, int id, DWORD extra = 0) { return mk(p, L"STATIC", t, extra, id); }

void make_fonts() {
    if (g.font) DeleteObject(g.font);
    if (g.font_big) DeleteObject(g.font_big);
    if (g.font_small) DeleteObject(g.font_small);
    if (g.font_head) DeleteObject(g.font_head);
    auto mkf = [](int pt, int weight) {
        return CreateFontW(-MulDiv(pt, g.dpi, 72), 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    };
    g.font = mkf(9, FW_NORMAL);
    g.font_small = mkf(8, FW_NORMAL);
    g.font_big = mkf(10, FW_SEMIBOLD);
    g.font_head = mkf(20, FW_SEMIBOLD);
}

void create_pages() {
    const wchar_t* names[4] = {L"Scan", L"Clean", L"Startup", L"Storage"};
    for (int i = 0; i < 4; ++i) {
        TCITEMW ti{};
        ti.mask = TCIF_TEXT;
        ti.pszText = const_cast<wchar_t*>(names[i]);
        TabCtrl_InsertItem(g.tab, i, &ti);
        g.page[i] = CreateWindowExW(0, L"HemPage", L"", WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS, 0, 0, 10, 10, g.main, nullptr, g.inst, nullptr);
    }
    // ---- Scan
    HWND p = P(0);
    mklabel(p, L"Folder to scan:", IDC_S_LBL1);
    mkedit(p, IDC_S_PATH);
    mkbtn(p, L"Browse...", IDC_S_BROWSE);
    mkbtn(p, L"Scan my Downloads", IDC_S_DOWNLOADS);
    mkbtn(p, L"Scan this folder", IDC_S_FOLDER);
    HWND stop = mkbtn(p, L"Stop", IDC_S_STOP);
    EnableWindow(stop, FALSE);
    mklabel(p, L"CPU limit:", IDC_S_LBL2);
    HWND cpu = mk(p, L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, IDC_S_CPU);
    for (const wchar_t* s : {L"25%", L"50%", L"75%", L"100%"}) SendMessageW(cpu, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(s));
    SendMessageW(cpu, CB_SETCURSEL, 1, 0);
    mk(p, L"BUTTON", L"Results", BS_AUTORADIOBUTTON | WS_GROUP | WS_TABSTOP, IDC_S_VIEW_RES);
    mk(p, L"BUTTON", L"Quarantine (restore files)", BS_AUTORADIOBUTTON, IDC_S_VIEW_Q);
    mklist(p, IDC_S_LIST);
    mkbtn(p, L"Quarantine selected", IDC_S_QSEL);
    mkbtn(p, L"Quarantine all known-bad", IDC_S_QBAD);
    mkbtn(p, L"Restore selected", IDC_S_RESTORE);
    mklabel(p, L"Pick a folder and press Scan. The scan only reads files; it never changes or deletes anything.", IDC_S_SUMMARY);
    HWND n1 = mklabel(p, L"\"Nothing found\" only means no KNOWN pattern matched. This tool ships with test rules only, so it does not replace Windows Security.", IDC_S_NOTE);
    SendMessageW(n1, WM_SETFONT, reinterpret_cast<WPARAM>(g.font_small), TRUE);
    // ---- Clean
    p = P(1);
    mkbtn(p, L"Preview (changes nothing)", IDC_C_PREVIEW);
    mk(p, L"BUTTON", L"Also include CAREFUL places (your Recycle Bin, Windows Update cache)", BS_AUTOCHECKBOX | WS_TABSTOP, IDC_C_CAREFUL);
    mklist(p, IDC_C_LIST);
    mkbtn(p, L"Clean now (moves to Undo)", IDC_C_CLEAN);
    mkbtn(p, L"Undo last clean", IDC_C_UNDO);
    mkbtn(p, L"Free space: remove old undo copies", IDC_C_PURGE);
    mklabel(p, L"Press Preview to see what could be cleaned. Nothing changes until you press Clean now and confirm.", IDC_C_SUMMARY);
    mklabel(p, L"", IDC_C_NEVER);
    HWND n2 = mklabel(p, L"Cleaning Windows' own Temp folder and the Update cache needs administrator rights; without them those files are skipped.", IDC_C_NOTE);
    SendMessageW(n2, WM_SETFONT, reinterpret_cast<WPARAM>(g.font_small), TRUE);
    // ---- Startup
    p = P(2);
    mkbtn(p, L"Refresh", IDC_U_REFRESH);
    mkbtn(p, L"Turn OFF selected", IDC_U_OFF);
    mkbtn(p, L"Turn ON selected", IDC_U_ON);
    mkbtn(p, L"Undo last change", IDC_U_UNDO);
    mk(p, L"BUTTON", L"Also show Windows' own scheduled tasks (read-only)", BS_AUTOCHECKBOX | WS_TABSTOP, IDC_U_SYSTEM);
    mklist(p, IDC_U_LIST);
    mklabel(p, L"Press Refresh to read what starts with Windows.", IDC_U_SUMMARY);
    HWND n3 = mklabel(p, L"Turning an item off only flips Windows' own on/off switch. Nothing is ever deleted, and \"Undo last change\" flips it back.", IDC_U_NOTE);
    SendMessageW(n3, WM_SETFONT, reinterpret_cast<WPARAM>(g.font_small), TRUE);
    // ---- Storage
    p = P(3);
    mklabel(p, L"Folder to look at:", IDC_T_LBL);
    mkedit(p, IDC_T_PATH);
    mkbtn(p, L"Browse...", IDC_T_BROWSE);
    mkbtn(p, L"Show biggest folders", IDC_T_ANALYZE);
    mkbtn(p, L"Find identical files (report only)", IDC_T_DUPES);
    HWND vw = mk(p, L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, IDC_T_VIEW);
    for (const wchar_t* s : {L"Biggest folders", L"By file type", L"Biggest files", L"Identical files"}) SendMessageW(vw, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(s));
    SendMessageW(vw, CB_SETCURSEL, 0, 0);
    mklist(p, IDC_T_LIST);
    mklabel(p, L"Pick a folder and press a button. This only reads; nothing is changed.", IDC_T_SUMMARY);
    HWND n4 = mklabel(p, L"Big folders can take a while, and these two jobs cannot be cancelled yet.", IDC_T_NOTE);
    SendMessageW(n4, WM_SETFONT, reinterpret_cast<WPARAM>(g.font_small), TRUE);

    // Stacking order: the tab control sits at the very back, the pages in front of it. (Otherwise the tab
    // control's own grey body is drawn over the pages and the tab looks empty.)
    SetWindowPos(g.tab, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    for (int i = 0; i < 4; ++i) SetWindowPos(g.page[i], HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

    // defaults
    const auto kf = known_folders();
    set_text(C(0, IDC_S_PATH), WP(kf.downloads));
    set_text(C(3, IDC_T_PATH), WP(kf.downloads));
    scan_set_view(0);
    clean_show_plan();
    clean_refresh_info();
    startup_fill();
    storage_show();
}

bool browse_for(HWND owner, HWND edit) {
    BROWSEINFOW bi{};
    bi.hwndOwner = owner;
    bi.lpszTitle = L"Choose a folder";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return false;
    wchar_t path[MAX_PATH * 2] = {};
    const bool ok = SHGetPathFromIDListW(pidl, path) != FALSE;
    CoTaskMemFree(pidl);
    if (ok) SetWindowTextW(edit, path);
    return ok;
}

void on_command(int id, int code) {
    if (code == BN_CLICKED || code == CBN_SELCHANGE) {
        switch (id) {
            case IDC_S_BROWSE: browse_for(g.main, C(0, IDC_S_PATH)); break;
            case IDC_S_DOWNLOADS: {
                const auto kf = known_folders();
                set_text(C(0, IDC_S_PATH), WP(kf.downloads));
                start_scan(kf.downloads);
                break;
            }
            case IDC_S_FOLDER: start_scan(get_path_text(C(0, IDC_S_PATH))); break;
            case IDC_S_STOP:
                g.stop = true;
                set_status(L"Stopping ...");
                break;
            case IDC_S_VIEW_RES: scan_set_view(0); break;
            case IDC_S_VIEW_Q: scan_set_view(1); break;
            case IDC_S_QSEL: do_quarantine(selected_findings()); break;
            case IDC_S_QBAD: {
                std::vector<std::size_t> v;
                for (std::size_t i = 0; i < g.findings.size(); ++i)
                    if (g.findings[i].kind != FindingKind::WarningSign) v.push_back(i);
                if (v.empty()) tell(L"No known-bad files in the results. (Warning-sign items must be picked by hand.)");
                else do_quarantine(v);
                break;
            }
            case IDC_S_RESTORE: do_restore(); break;
            case IDC_C_PREVIEW: clean_preview(); break;
            case IDC_C_CAREFUL:
                if (g.have_plan) clean_preview();
                break;
            case IDC_C_CLEAN: clean_apply(); break;
            case IDC_C_UNDO: clean_undo(); break;
            case IDC_C_PURGE: clean_purge(); break;
            case IDC_U_REFRESH: startup_refresh(); break;
            case IDC_U_SYSTEM: startup_refresh(); break;
            case IDC_U_OFF: startup_change(false); break;
            case IDC_U_ON: startup_change(true); break;
            case IDC_U_UNDO: startup_undo(); break;
            case IDC_T_BROWSE: browse_for(g.main, C(3, IDC_T_PATH)); break;
            case IDC_T_ANALYZE: storage_analyze(false); break;
            case IDC_T_DUPES: storage_analyze(true); break;
            case IDC_T_VIEW: storage_show(); break;
            default: break;
        }
    }
}

void paint_header(HDC dc, const RECT& rc) {
    RECT h = {0, 0, rc.right, header_h()};
    HBRUSH b = CreateSolidBrush(RGB(20, 24, 31));
    FillRect(dc, &h, b);
    DeleteObject(b);
    RECT line = {0, header_h() - S(3), rc.right, header_h()};
    HBRUSH a = CreateSolidBrush(RGB(232, 163, 61));
    FillRect(dc, &line, a);
    DeleteObject(a);
    SetBkMode(dc, TRANSPARENT);
    HGDIOBJ old = SelectObject(dc, g.font_head);
    SetTextColor(dc, RGB(245, 245, 245));
    RECT t1 = {S(18), S(6), rc.right, S(46)};
    DrawTextW(dc, L"HEM Guard", -1, &t1, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    SelectObject(dc, g.font_small);
    SetTextColor(dc, RGB(160, 170, 185));
    RECT t2 = {S(20), S(40), rc.right, S(62)};
    DrawTextW(dc, L"Small, honest protection and clean-up. Nothing is deleted. Not a replacement for Windows Security.", -1, &t2, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    SelectObject(dc, old);
}

LRESULT on_customdraw(NMLVCUSTOMDRAW* cd) {
    const int id = static_cast<int>(cd->nmcd.hdr.idFrom);
    switch (cd->nmcd.dwDrawStage) {
        case CDDS_PREPAINT: return CDRF_NOTIFYITEMDRAW;
        case CDDS_ITEMPREPAINT: {
            const auto it = g.colors.find(id);
            const int idx = static_cast<int>(cd->nmcd.lItemlParam);
            int c = ROW_NONE;
            if (it != g.colors.end() && idx >= 0 && static_cast<std::size_t>(idx) < it->second.size()) c = it->second[static_cast<std::size_t>(idx)];
            if (c == ROW_HIGH) cd->clrTextBk = RGB(255, 222, 222);
            else if (c == ROW_MED) cd->clrTextBk = RGB(255, 241, 214);
            else if (c == ROW_LOW) cd->clrTextBk = RGB(255, 252, 230);
            else if (c == ROW_GOOD) cd->clrTextBk = RGB(228, 245, 232);
            else if (c == ROW_GREY) cd->clrText = RGB(120, 120, 120);
            return CDRF_NEWFONT;
        }
        default: return CDRF_DODEFAULT;
    }
}

LRESULT CALLBACK PageProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
        case WM_COMMAND:
        case WM_NOTIFY: return SendMessageW(g.main, m, w, l);
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORBTN: {
            HDC dc = reinterpret_cast<HDC>(w);
            SetBkMode(dc, TRANSPARENT);
            return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_WINDOW));
        }
        default: return DefWindowProcW(h, m, w, l);
    }
}

LRESULT CALLBACK MainProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
        case WM_CREATE: {
            g.main = h;
            g.dpi = static_cast<int>(GetDpiForWindow(h));
            make_fonts();
            g.status = CreateWindowExW(0, STATUSCLASSNAMEW, L"Ready.", WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0, h,
                                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_STATUS)), g.inst, nullptr);
            SendMessageW(g.status, WM_SETFONT, reinterpret_cast<WPARAM>(g.font), TRUE);
            g.tab = CreateWindowExW(0, WC_TABCONTROLW, L"", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_TABSTOP, 0, 0, 10, 10, h,
                                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_TAB)), g.inst, nullptr);
            SendMessageW(g.tab, WM_SETFONT, reinterpret_cast<WPARAM>(g.font_big), TRUE);
            create_pages();
            select_tab(0);
            layout_all();
            return 0;
        }
        case WM_SIZE:
            if (g.tab) layout_all();
            return 0;
        case WM_GETMINMAXINFO: {
            auto* mm = reinterpret_cast<MINMAXINFO*>(l);
            mm->ptMinTrackSize.x = S(820);
            mm->ptMinTrackSize.y = S(560);
            return 0;
        }
        case WM_DPICHANGED: {
            g.dpi = HIWORD(w);
            make_fonts();
            const RECT* r = reinterpret_cast<RECT*>(l);
            SetWindowPos(h, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
            EnumChildWindows(h, [](HWND c, LPARAM) -> BOOL { SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(g.font), TRUE); return TRUE; }, 0);
            layout_all();
            return 0;
        }
        case WM_ERASEBKGND: return 1;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(h, &ps);
            RECT rc;
            GetClientRect(h, &rc);
            paint_header(dc, rc);
            EndPaint(h, &ps);
            return 0;
        }
        case WM_NOTIFY: {
            auto* nh = reinterpret_cast<NMHDR*>(l);
            if (nh->idFrom == IDC_TAB && nh->code == TCN_SELCHANGE) {
                const int i = TabCtrl_GetCurSel(g.tab);
                select_tab(i);
                if (i == 2 && g.startup_items.empty() && !g.busy) startup_refresh();
                return 0;
            }
            if (nh->code == NM_CUSTOMDRAW && (nh->idFrom == IDC_S_LIST || nh->idFrom == IDC_C_LIST || nh->idFrom == IDC_U_LIST || nh->idFrom == IDC_T_LIST))
                return on_customdraw(reinterpret_cast<NMLVCUSTOMDRAW*>(l));
            return 0;
        }
        case WM_COMMAND: on_command(LOWORD(w), HIWORD(w)); return 0;
        case WM_APP_PROGRESS: {
            std::unique_ptr<std::wstring> s(reinterpret_cast<std::wstring*>(l));
            if (g.busy) set_status(*s);
            return 0;
        }
        case WM_APP_DONE: {
            std::unique_ptr<std::function<void()>> fin(reinterpret_cast<std::function<void()>*>(l));
            if (g.worker.joinable()) g.worker.join();
            g.busy = false;
            EnableWindow(C(0, IDC_S_STOP), FALSE);
            if (*fin) (*fin)();
            return 0;
        }
        case WM_CLOSE:
            if (g.busy) {
                g.stop = true;
                if (!g.silent && MessageBoxW(h, L"A job is still running. Stop it and close?", L"HEM Guard", MB_YESNO | MB_ICONQUESTION) != IDYES) return 0;
            }
            DestroyWindow(h);
            return 0;
        case WM_DESTROY:
            g.stop = true;
            if (g.worker.joinable()) g.worker.join();
            PostQuitMessage(0);
            return 0;
        default: return DefWindowProcW(h, m, w, l);
    }
}

// ---------------------------------------------------------------- self-test --
struct Test {
    std::vector<std::string> lines;
    int failed = 0;
    void check(bool ok, const std::string& what) {
        lines.push_back(std::string(ok ? "PASS  " : "FAIL  ") + what);
        if (!ok) ++failed;
    }
};

void pump(int ms_max = 120000) {
    const auto start = std::chrono::steady_clock::now();
    for (;;) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (!g.busy) break;
        if (std::chrono::steady_clock::now() - start > std::chrono::milliseconds(ms_max)) break;
        Sleep(15);
    }
    // one more round so painting settles
    for (int i = 0; i < 5; ++i) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(10);
    }
}

bool save_bitmap(HBITMAP bmp, HDC mem, int w, int h, const fs::path& file) {
    BITMAPINFOHEADER bi{};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = h;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;
    const int stride = ((w * 3 + 3) / 4) * 4;
    std::vector<unsigned char> px(static_cast<std::size_t>(stride) * static_cast<std::size_t>(h));
    GetDIBits(mem, bmp, 0, static_cast<UINT>(h), px.data(), reinterpret_cast<BITMAPINFO*>(&bi), DIB_RGB_COLORS);
    BITMAPFILEHEADER fh{};
    fh.bfType = 0x4D42;
    fh.bfOffBits = sizeof(fh) + sizeof(bi);
    fh.bfSize = fh.bfOffBits + static_cast<DWORD>(px.size());
    std::ofstream f(file, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(&fh), sizeof(fh));
    f.write(reinterpret_cast<const char*>(&bi), sizeof(bi));
    f.write(reinterpret_cast<const char*>(px.data()), static_cast<std::streamsize>(px.size()));
    return static_cast<bool>(f);
}

// Copies what is really on the screen where the window is (so it shows exactly what a person would see).
bool save_screenshot(const fs::path& file) {
    SetWindowPos(g.main, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    SetForegroundWindow(g.main);
    RedrawWindow(g.main, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW);
    Sleep(250);
    RECT rc;
    GetWindowRect(g.main, &rc);
    const int w = rc.right - rc.left, h = rc.bottom - rc.top;
    HDC screen = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(screen);
    HBITMAP bmp = CreateCompatibleBitmap(screen, w, h);
    HGDIOBJ old = SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, w, h, screen, rc.left, rc.top, SRCCOPY | CAPTUREBLT);
    SelectObject(mem, old);
    const bool ok = save_bitmap(bmp, mem, w, h, file);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);
    return ok;
}

// Asks Windows what is really on top at the middle of a control. True only if it is that control (or part of it).
bool really_on_top(HWND c) {
    RECT r;
    GetWindowRect(c, &r);
    POINT pt{(r.left + r.right) / 2, (r.top + r.bottom) / 2};
    HWND w = WindowFromPoint(pt);
    return w == c || (w && IsChild(c, w));
}

// Is this control really on screen with a real size?
std::string visible_info(HWND page, int id, const char* name) {
    HWND c = GetDlgItem(page, id);
    RECT r{};
    if (c) GetWindowRect(c, &r);
    return std::string(name) + ": " + (c && IsWindowVisible(c) ? "visible " : "NOT visible ") + std::to_string(r.right - r.left) + "x" + std::to_string(r.bottom - r.top);
}

void write_file(const fs::path& p, const std::string& s) {
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary);
    f << s;
}
std::string read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

int run_selftest(const fs::path& sb) {
    Test t;
    g.silent = true;
    fs::create_directories(sb);
    g.data_root_override = sb / "data";
    const fs::path shots = sb / "shots";
    fs::create_directories(shots);
    ShowWindow(g.main, SW_SHOW);
    UpdateWindow(g.main);
    pump(2000);

    // ---- Scan tab
    select_tab(0);
    const fs::path scandir = sb / "scan";
    write_file(scandir / "bad.txt", "xx HEM-GUARD-DEMO-MARKER-0001 yy");
    write_file(scandir / "fine.txt", "just a normal file");
    set_text(C(0, IDC_S_PATH), WP(scandir));
    start_scan(scandir);
    pump();
    t.check(!g.busy, "scan finished");
    t.check(g.findings.size() == 1, "scan found exactly the one marker file (found " + std::to_string(g.findings.size()) + ")");
    t.check(ListView_GetItemCount(C(0, IDC_S_LIST)) == 1, "scan result list shows 1 row");
    {
        const std::string a = visible_info(P(0), IDC_S_LIST, "scan list"), b = visible_info(P(0), IDC_S_DOWNLOADS, "scan button");
        t.lines.push_back("INFO  " + a + " | " + b);
        RECT rl{};
        GetWindowRect(C(0, IDC_S_LIST), &rl);
        t.check(IsWindowVisible(C(0, IDC_S_LIST)) && rl.right - rl.left > 200 && rl.bottom - rl.top > 100, "scan list is visible and has a real size");
        t.check(IsWindowVisible(C(0, IDC_S_DOWNLOADS)), "scan buttons are visible");
        t.check(really_on_top(C(0, IDC_S_LIST)), "scan list is the thing on top at its centre (not hidden behind the tab control)");
        t.check(really_on_top(C(0, IDC_S_DOWNLOADS)), "scan button is the thing on top at its centre");
    }
    save_screenshot(shots / "1-scan-results.bmp");
    lv_select_first(C(0, IDC_S_LIST));
    do_quarantine(selected_findings());
    pump();
    t.check(!fs::exists(scandir / "bad.txt"), "quarantine moved the file out of its folder");
    t.check(fs::exists(scandir / "fine.txt"), "quarantine left the other file alone");
    scan_set_view(1);
    t.check(ListView_GetItemCount(C(0, IDC_S_LIST)) == 1, "quarantine list shows 1 row");
    save_screenshot(shots / "2-scan-quarantine.bmp");
    lv_select_first(C(0, IDC_S_LIST));
    do_restore();
    pump();
    t.check(fs::exists(scandir / "bad.txt") && read_file(scandir / "bad.txt") == "xx HEM-GUARD-DEMO-MARKER-0001 yy", "restore put the file back byte-for-byte");

    // ---- Clean tab (made-up folders, never the real PC)
    select_tab(1);
    Environment e;
    e.user_temp = sb / "Local/Temp";
    e.windows_temp = sb / "Win/Temp";
    e.local_appdata = sb / "Local";
    e.windir = sb / "Win";
    e.system_drive_root = sb / "Drive";
    e.undo_root = sb / "Local/HEM Guard/Undo";
    e.user_sid = "S-1-5-21-1";
    e.protected_folders = {{"Documents", sb / "Users/test/Documents"}, {"Desktop", sb / "Users/test/Desktop"}};
    g.env_override = e;
    g.env_override_on = true;
    const auto old_time = fs::file_time_type::clock::now() - std::chrono::hours(72);
    for (const char* n : {"a.tmp", "b.tmp", "sub/c.tmp"}) {
        write_file(e.user_temp / n, std::string("temp file ") + n);
        std::error_code ec;
        fs::last_write_time(e.user_temp / n, old_time, ec);
    }
    write_file(sb / "Users/test/Documents/keep.docx", "my precious document");
    clean_preview();
    pump();
    t.check(g.have_plan && g.plan.items.size() == 3, "clean preview lists exactly the 3 temp files (found " + std::to_string(g.plan.items.size()) + ")");
    t.check(fs::exists(e.user_temp / "a.tmp"), "preview changed nothing");
    t.check(really_on_top(C(1, IDC_C_LIST)), "clean list is really on top");
    save_screenshot(shots / "3-clean-preview.bmp");
    clean_apply();
    pump();
    t.check(!fs::exists(e.user_temp / "a.tmp") && !fs::exists(e.user_temp / "sub/c.tmp"), "clean moved the temp files away");
    t.check(fs::exists(sb / "Users/test/Documents/keep.docx"), "clean never touched the personal Documents file");
    save_screenshot(shots / "4-clean-done.bmp");
    clean_undo();
    pump();
    t.check(fs::exists(e.user_temp / "a.tmp") && read_file(e.user_temp / "sub/c.tmp") == "temp file sub/c.tmp", "undo put the temp files back exactly");
    g.env_override_on = false;

    // ---- Startup tab (reads the real list of the machine; changes nothing)
    select_tab(2);
    startup_refresh();
    pump();
    t.check(!g.busy, "startup list finished (" + std::to_string(g.startup_items.size()) + " items on this machine)");
    t.check(ListView_GetItemCount(C(2, IDC_U_LIST)) == static_cast<int>(g.startup_items.size()), "startup list rows match the engine");
    t.check(really_on_top(C(2, IDC_U_LIST)), "startup list is really on top");
    save_screenshot(shots / "5-startup.bmp");

    // ---- Storage tab
    select_tab(3);
    const fs::path st = sb / "store";
    write_file(st / "big/one.bin", std::string(200000, 'A'));
    write_file(st / "big/two.bin", std::string(200000, 'A'));  // identical copy
    write_file(st / "small/x.txt", std::string(3000, 'B'));
    set_text(C(3, IDC_T_PATH), WP(st));
    storage_analyze(false);
    pump();
    t.check(g.have_storage && g.storage.total_files == 3, "storage counted 3 files (got " + std::to_string(g.storage.total_files) + ")");
    t.check(ListView_GetItemCount(C(3, IDC_T_LIST)) >= 1, "storage list has rows");
    t.check(really_on_top(C(3, IDC_T_LIST)), "storage list is really on top");
    save_screenshot(shots / "6-storage.bmp");
    storage_analyze(true);
    pump();
    t.check(g.have_dupes && g.dupes.groups.size() == 1 && g.dupes.groups[0].paths.size() == 2, "duplicate finder found the one identical pair");
    t.check(fs::exists(st / "big/one.bin") && fs::exists(st / "big/two.bin"), "duplicate finder deleted nothing");
    save_screenshot(shots / "7-duplicates.bmp");

    std::string out = "HEM Guard window self-test\n";
    for (const auto& l : t.lines) out += l + "\n";
    out += t.failed == 0 ? "RESULT: ALL PASSED\n" : "RESULT: " + std::to_string(t.failed) + " FAILED\n";
    write_file(sb / "selftest-result.txt", out);
    DestroyWindow(g.main);
    pump(3000);
    return t.failed == 0 ? 0 : 1;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int show) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);
    g.inst = inst;

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    fs::path selftest;
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::wstring(argv[i]) == L"--selftest") selftest = fs::path(argv[i + 1]);
    }
    if (argv) LocalFree(argv);

    WNDCLASSEXW pc{sizeof(pc)};
    pc.lpfnWndProc = PageProc;
    pc.hInstance = inst;
    pc.hbrBackground = GetSysColorBrush(COLOR_WINDOW);
    pc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    pc.lpszClassName = L"HemPage";
    RegisterClassExW(&pc);

    WNDCLASSEXW wc{sizeof(wc)};
    wc.lpfnWndProc = MainProc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hbrBackground = GetSysColorBrush(COLOR_WINDOW);
    wc.lpszClassName = L"HemGuardMain";
    RegisterClassExW(&wc);

    // Start at a comfortable size, but never bigger than the screen's usable area.
    const int dpi0 = static_cast<int>(GetDpiForSystem());
    RECT wa{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    const int want_w = MulDiv(1060, dpi0, 96), want_h = MulDiv(740, dpi0, 96);
    const int ww = std::min<int>(want_w, (wa.right - wa.left) * 95 / 100), wh = std::min<int>(want_h, (wa.bottom - wa.top) * 95 / 100);
    HWND h = CreateWindowExW(0, L"HemGuardMain", L"HEM Guard", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, wa.left + ((wa.right - wa.left) - ww) / 2,
                             wa.top + ((wa.bottom - wa.top) - wh) / 2, ww, wh, nullptr, nullptr, inst, nullptr);
    if (!h) return 2;
    if (!selftest.empty()) return run_selftest(selftest);
    ShowWindow(h, show);
    UpdateWindow(h);
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        // Let the Tab key and arrow keys move between the buttons of the page that is showing.
        const int cur = g.tab ? TabCtrl_GetCurSel(g.tab) : -1;
        if (cur >= 0 && cur < 4 && g.page[cur] && IsDialogMessageW(g.page[cur], &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}
