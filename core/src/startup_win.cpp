// Windows backend for the startup manager.
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// order matters
#include <objbase.h>
#include <shlobj.h>
#include <shobjidl.h>

#include <cstring>

#include "hem_guard/config.hpp"
#include "hem_guard/startup.hpp"
#include "hem_guard/walk.hpp"

namespace hem::guard {

namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring expand_env(const std::wstring& s) {
    if (s.find(L'%') == std::wstring::npos) return s;
    const DWORD n = ExpandEnvironmentStringsW(s.c_str(), nullptr, 0);
    if (n == 0) return s;
    std::wstring out(n, L'\0');
    const DWORD got = ExpandEnvironmentStringsW(s.c_str(), out.data(), n);
    if (got == 0) return s;
    out.resize(got - 1);  // drop the trailing NUL
    return out;
}

const char* tag_of(StartupKind k) {
    switch (k) {
        case StartupKind::RunUser: return "run-user";
        case StartupKind::RunMachine: return "run-machine";
        case StartupKind::RunMachine32: return "run-machine32";
        case StartupKind::FolderUser: return "folder-user";
        case StartupKind::FolderCommon: return "folder-common";
        default: return "task";
    }
}

fs::path resolve_lnk(const fs::path& lnk) {
    const HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool did_init = SUCCEEDED(init);
    fs::path result;
    IShellLinkW* sl = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, reinterpret_cast<void**>(&sl)))) {
        IPersistFile* pf = nullptr;
        if (SUCCEEDED(sl->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&pf)))) {
            if (SUCCEEDED(pf->Load(lnk.c_str(), STGM_READ))) {
                wchar_t buf[MAX_PATH * 2] = {};
                WIN32_FIND_DATAW fd{};
                if (SUCCEEDED(sl->GetPath(buf, MAX_PATH * 2, &fd, SLGP_RAWPATH))) result = fs::path(expand_env(buf));
            }
            pf->Release();
        }
        sl->Release();
    }
    if (did_init) CoUninitialize();
    return result;
}

class WinBackend : public StartupBackend {
public:
    explicit WinBackend(StartupLayout layout) : L_(std::move(layout)) {}

    std::vector<StartupItem> list() override {
        std::vector<StartupItem> items;
        for (const auto& reg : L_.reg) list_run_key(reg, items);
        list_folder(L_.user_folder, StartupKind::FolderUser, hive(false), L_.approved_user_folder, items);
        list_folder(L_.common_folder, StartupKind::FolderCommon, hive(true), L_.approved_common_folder, items);
        if (L_.include_tasks) list_tasks(items);
        return items;
    }

    bool set_enabled(const StartupItem& item, bool enabled, std::string& error) override {
        switch (item.kind) {
            case StartupKind::RunUser:
            case StartupKind::RunMachine:
            case StartupKind::RunMachine32: {
                for (const auto& reg : L_.reg) {
                    if (reg.kind == item.kind) return set_approved(hive(reg.machine_hive), reg.approved_path, widen(item.name), enabled, error);
                }
                error = "this kind of startup item is not configured";
                return false;
            }
            case StartupKind::FolderUser:
                return set_approved(hive(false), L_.approved_user_folder, widen(item.name), enabled, error);
            case StartupKind::FolderCommon:
                return set_approved(hive(true), L_.approved_common_folder, widen(item.name), enabled, error);
            default: {
                const auto args = schtasks_change_args(to_u8(L_.schtasks_exe), item.name, enabled, error);
                if (args.empty()) return false;
                std::string out;
                const int code = run_process(args, out);
                if (code != 0) {
                    error = "schtasks said: " + trim(out) + (code == -1 ? " (could not start schtasks)" : "");
                    return false;
                }
                return true;
            }
        }
    }

private:
    HKEY hive(bool machine) const { return (machine && !L_.all_in_current_user) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER; }

    bool approved_enabled(HKEY h, const std::wstring& path, const std::wstring& name) const {
        HKEY k = nullptr;
        if (RegOpenKeyExW(h, path.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) return true;
        BYTE data[64] = {};
        DWORD size = sizeof data, type = 0;
        const LONG r = RegQueryValueExW(k, name.c_str(), nullptr, &type, data, &size);
        RegCloseKey(k);
        if (r != ERROR_SUCCESS || type != REG_BINARY || size < 1) return true;
        return (data[0] & 1) == 0;  // even = enabled (02, 06), odd = disabled (03, 07)
    }

    bool set_approved(HKEY h, const std::wstring& path, const std::wstring& name, bool enabled, std::string& error) const {
        HKEY k = nullptr;
        DWORD disp = 0;
        LONG r = RegCreateKeyExW(h, path.c_str(), 0, nullptr, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &k, &disp);
        if (r != ERROR_SUCCESS) {
            error = r == ERROR_ACCESS_DENIED ? "needs administrator rights" : "Windows registry error " + std::to_string(r);
            return false;
        }
        BYTE data[12] = {};
        data[0] = enabled ? 0x02 : 0x03;
        if (!enabled) {
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            std::memcpy(data + 4, &ft, 8);
        }
        r = RegSetValueExW(k, name.c_str(), 0, REG_BINARY, data, sizeof data);
        RegCloseKey(k);
        if (r != ERROR_SUCCESS) {
            error = r == ERROR_ACCESS_DENIED ? "needs administrator rights" : "Windows registry error " + std::to_string(r);
            return false;
        }
        return true;
    }

    void list_run_key(const StartupLayout::Reg& reg, std::vector<StartupItem>& items) const {
        HKEY k = nullptr;
        const HKEY h = hive(reg.machine_hive);
        if (RegOpenKeyExW(h, reg.run_path.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) return;
        DWORD count = 0, max_name = 0, max_data = 0;
        RegQueryInfoKeyW(k, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &count, &max_name, &max_data, nullptr, nullptr);
        for (DWORD i = 0; i < count; ++i) {
            std::wstring name(max_name + 1, L'\0');
            std::vector<BYTE> data(max_data + 4, 0);
            DWORD nl = max_name + 1, dl = max_data, type = 0;
            if (RegEnumValueW(k, i, name.data(), &nl, nullptr, &type, data.data(), &dl) != ERROR_SUCCESS) continue;
            if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
            name.resize(nl);
            std::wstring cmd(reinterpret_cast<wchar_t*>(data.data()), dl / sizeof(wchar_t));
            while (!cmd.empty() && cmd.back() == L'\0') cmd.pop_back();
            cmd = expand_env(cmd);

            StartupItem it;
            it.kind = reg.kind;
            it.name = narrow(name);
            it.id = std::string(tag_of(reg.kind)) + "|" + it.name;
            it.command = narrow(cmd);
            it.program = extract_program_path(it.command);
            it.enabled = approved_enabled(h, reg.approved_path, name);
            items.push_back(std::move(it));
        }
        RegCloseKey(k);
    }

    void list_folder(const fs::path& folder, StartupKind kind, HKEY h, const std::wstring& approved, std::vector<StartupItem>& items) const {
        std::error_code ec;
        if (folder.empty() || !fs::is_directory(folder, ec)) return;
        for (fs::directory_iterator it(folder, ec), end; !ec && it != end; it.increment(ec)) {
            if (!it->is_regular_file(ec)) continue;
            const std::string name = to_u8(it->path().filename());
            if (to_lower_ascii(name) == "desktop.ini") continue;
            StartupItem si;
            si.kind = kind;
            si.name = name;
            si.id = std::string(tag_of(kind)) + "|" + name;
            si.command = to_u8(it->path());
            const std::string ext = to_lower_ascii(to_u8(it->path().extension()));
            si.program = ext == ".lnk" ? resolve_lnk(it->path()) : it->path();
            si.enabled = approved_enabled(h, approved, it->path().filename().wstring());
            items.push_back(std::move(si));
        }
    }

    void list_tasks(std::vector<StartupItem>& items) const {
        std::error_code ec;
        if (L_.tasks_dir.empty() || !fs::is_directory(L_.tasks_dir, ec)) return;
        const fs::path root = L_.tasks_dir;
        walk_files(root, {}, [&](const FileInfo& fi) {
            if (fi.size == 0 || fi.size > 1024 * 1024) return;
            std::string raw;
            if (!read_text_file(fi.path, raw)) return;  // not readable without administrator rights: skipped
            TaskInfo ti;
            if (!parse_task_xml(raw, ti) || !ti.logon) return;
            StartupItem si;
            si.kind = StartupKind::LogonTask;
            si.name = "\\" + to_u8(fi.path.lexically_relative(root));
            si.id = std::string("task|") + si.name;
            si.command = trim(ti.command + (ti.arguments.empty() ? "" : " " + ti.arguments));
            si.program = extract_program_path(narrow(expand_env(widen(ti.command))));
            si.enabled = ti.enabled;
            si.system_owned = si.name.rfind(std::string(cfg::kMicrosoftTaskPrefix), 0) == 0;
            items.push_back(std::move(si));
        });
    }

    StartupLayout L_;
};

}  // namespace

StartupLayout StartupLayout::system_default() {
    StartupLayout L;
    const std::wstring run = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const std::wstring approved = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\";
    L.reg = {{StartupKind::RunUser, false, run, approved + L"Run"},
             {StartupKind::RunMachine, true, run, approved + L"Run"},
             {StartupKind::RunMachine32, true, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", approved + L"Run32"}};
    if (auto a = env_var("APPDATA")) L.user_folder = from_u8(*a) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup";
    if (auto p = env_var("ProgramData")) L.common_folder = from_u8(*p) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup";
    L.approved_user_folder = approved + L"StartupFolder";
    L.approved_common_folder = approved + L"StartupFolder";
    fs::path windir = "C:\\Windows";
    if (auto w = env_var("WINDIR")) windir = from_u8(*w);
    L.tasks_dir = windir / "System32" / "Tasks";
    L.schtasks_exe = windir / "System32" / "schtasks.exe";
    return L;
}

std::unique_ptr<StartupBackend> make_windows_startup_backend(const StartupLayout& layout) {
    return std::make_unique<WinBackend>(layout);
}

}  // namespace hem::guard

#endif
