// HEM Guard - startup manager. Lists what starts with Windows, shows signed / unsigned,
// and can DISABLE / ENABLE an item. It never deletes anything.
//
// How "disable" works (same switch Windows' own Task Manager uses):
//   * Run-key items and Startup-folder items: the matching "StartupApproved" flag is flipped. The item stays in place.
//   * Scheduled tasks that run at logon: the task is switched off with Windows' schtasks tool.
// Every change goes into a small journal so "undo" can flip the last change back.
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "hem_guard/platform.hpp"
#include "hem_guard/util.hpp"

namespace hem::guard {

enum class StartupKind { RunUser, RunMachine, RunMachine32, FolderUser, FolderCommon, LogonTask };
const char* to_string(StartupKind k);

struct StartupItem {
    std::string id;       // stable id, e.g. "run-user|OneDrive"
    StartupKind kind = StartupKind::RunUser;
    std::string name;
    std::string command;  // full command line as stored
    fs::path program;     // the program it starts (best guess from the command)
    SignState signature = SignState::Unknown;
    bool enabled = true;
    bool system_owned = false;  // Windows' own scheduled tasks: shown, but read-only
};

// ---- pure helpers (tested on every platform) ----
fs::path extract_program_path(std::string_view command);

struct TaskInfo {
    std::string command;
    std::string arguments;
    bool logon = false;    // has a "when I log on" trigger
    bool enabled = true;
};
// Accepts the raw bytes of a Windows task XML file (UTF-8 or UTF-16 with BOM).
bool parse_task_xml(const std::string& raw, TaskInfo& out);

// Builds the argument list for schtasks. Empty result + error text if the task name looks unsafe.
std::vector<std::string> schtasks_change_args(const std::string& schtasks_exe, const std::string& task_name, bool enable,
                                              std::string& error);

class StartupBackend {
public:
    virtual ~StartupBackend() = default;
    virtual std::vector<StartupItem> list() = 0;
    virtual bool set_enabled(const StartupItem& item, bool enabled, std::string& error) = 0;
};

// Where Windows keeps the startup lists. Tests point this at throwaway keys and folders.
struct StartupLayout {
    struct Reg {
        StartupKind kind;
        bool machine_hive;  // true = HKEY_LOCAL_MACHINE, false = HKEY_CURRENT_USER
        std::wstring run_path;
        std::wstring approved_path;
    };
    std::vector<Reg> reg;
    fs::path user_folder, common_folder;
    std::wstring approved_user_folder, approved_common_folder;
    fs::path tasks_dir;
    fs::path schtasks_exe;
    bool include_tasks = true;
    bool all_in_current_user = false;  // TESTS ONLY: treat every "machine" hive as the current user's hive

    static StartupLayout system_default();
};
// Real Windows backend. Returns nullptr on non-Windows.
std::unique_ptr<StartupBackend> make_windows_startup_backend(const StartupLayout& layout);

class StartupManager {
public:
    StartupManager(StartupBackend& backend, fs::path journal_file);
    void set_signature_fn(std::function<SignState(const fs::path&)> fn) { sig_fn_ = std::move(fn); }

    std::vector<StartupItem> list(bool include_system_tasks = false);
    bool disable(const std::string& id, std::string& error);
    bool enable(const std::string& id, std::string& error);
    // Flips the most recent change back. `what` describes what was done.
    bool undo_last(std::string& error, std::string* what = nullptr);

private:
    bool change(const std::string& id, bool enabled, std::string& error, bool journal);
    StartupBackend& backend_;
    fs::path journal_;
    std::function<SignState(const fs::path&)> sig_fn_;
};

}  // namespace hem::guard
