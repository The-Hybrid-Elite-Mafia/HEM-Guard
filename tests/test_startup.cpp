#include <algorithm>
#include <cstdlib>

#include "hem_guard/startup.hpp"
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

// In-memory stand-in for Windows, used to test the manager's own logic anywhere.
class FakeBackend : public StartupBackend {
public:
    std::vector<StartupItem> items;
    int set_calls = 0;
    std::vector<StartupItem> list() override { return items; }
    bool set_enabled(const StartupItem& item, bool enabled, std::string& error) override {
        ++set_calls;
        for (auto& it : items) {
            if (it.id == item.id) {
                if (fail_next) {
                    error = "pretend failure";
                    fail_next = false;
                    return false;
                }
                it.enabled = enabled;
                return true;
            }
        }
        error = "gone";
        return false;
    }
    bool fail_next = false;
};

StartupItem item(const std::string& id, const std::string& cmd, bool enabled = true, bool system = false) {
    StartupItem i;
    i.id = id;
    i.name = id.substr(id.find('|') + 1);
    i.command = cmd;
    i.enabled = enabled;
    i.system_owned = system;
    return i;
}

std::string utf16le(const std::string& ascii, bool bom = true) {
    std::string out;
    if (bom) out += "\xff\xfe";
    for (char c : ascii) {
        out.push_back(c);
        out.push_back('\0');
    }
    return out;
}

const char* kTaskXml =
    "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"
    "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
    "  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>\n"
    "  <Settings><Enabled>true</Enabled></Settings>\n"
    "  <Actions Context=\"Author\"><Exec><Command>\"C:\\Program Files\\Cool &amp; Co\\cool.exe\"</Command>"
    "<Arguments>--start &quot;now&quot;</Arguments></Exec></Actions>\n"
    "</Task>\n";

}  // namespace

// ---------------------------------------------------- command line parsing --

HG_TEST(startup_parse, program_path_from_a_command_line) {
    CHECK_EQ(to_u8(extract_program_path("\"C:\\Program Files\\App\\app.exe\" --silent")), std::string("C:\\Program Files\\App\\app.exe"));
    CHECK_EQ(to_u8(extract_program_path("C:\\Program Files\\App\\app.exe --silent")), std::string("C:\\Program Files\\App\\app.exe"));
    CHECK_EQ(to_u8(extract_program_path("C:\\Tools\\run.bat /x")), std::string("C:\\Tools\\run.bat"));
    CHECK_EQ(to_u8(extract_program_path("C:\\Tools\\plain.exe")), std::string("C:\\Tools\\plain.exe"));
    CHECK_EQ(to_u8(extract_program_path("rundll32.exe shell32.dll,Control_RunDLL")), std::string("rundll32.exe"));
    CHECK_EQ(to_u8(extract_program_path("C:\\a.company\\x.exe -v")), std::string("C:\\a.company\\x.exe"));  // ".com" inside a folder name
    CHECK(extract_program_path("   ").empty());
}

HG_TEST(startup_parse, scheduled_task_xml_utf8_and_utf16) {
    TaskInfo t;
    REQUIRE(parse_task_xml(kTaskXml, t));
    CHECK(t.logon);
    CHECK(t.enabled);
    CHECK_EQ(t.command, std::string("\"C:\\Program Files\\Cool & Co\\cool.exe\""));
    CHECK_EQ(t.arguments, std::string("--start \"now\""));

    TaskInfo t16;
    REQUIRE(parse_task_xml(utf16le(kTaskXml), t16));
    CHECK(t16.logon);
    CHECK_EQ(t16.command, t.command);
}

HG_TEST(startup_parse, disabled_tasks_and_non_logon_tasks) {
    std::string xml = kTaskXml;
    const std::string en = "<Settings><Enabled>true</Enabled></Settings>";
    xml.replace(xml.find(en), en.size(), "<Settings><Enabled>false</Enabled></Settings>");
    TaskInfo t;
    REQUIRE(parse_task_xml(xml, t));
    CHECK(!t.enabled);

    std::string xml2 = kTaskXml;
    const std::string trig = "<LogonTrigger><Enabled>true</Enabled></LogonTrigger>";
    xml2.replace(xml2.find(trig), trig.size(), "<TimeTrigger><StartBoundary>2026-01-01T00:00:00</StartBoundary></TimeTrigger>");
    REQUIRE(parse_task_xml(xml2, t));
    CHECK(!t.logon);

    CHECK(!parse_task_xml("this is not a task file", t));
    CHECK(!parse_task_xml("", t));
}

HG_TEST(startup_parse, task_names_are_checked_before_they_reach_windows) {
    std::string err;
    const std::string exe = "C:\\Windows\\System32\\schtasks.exe";
    const auto ok = schtasks_change_args(exe, "\\Vendor\\Updater", false, err);
    REQUIRE(ok.size() == 5);
    CHECK_EQ(ok[0], exe);
    CHECK_EQ(ok[3], std::string("\\Vendor\\Updater"));
    CHECK_EQ(ok[4], std::string("/DISABLE"));
    CHECK_EQ(schtasks_change_args(exe, "\\Vendor\\Updater", true, err)[4], std::string("/ENABLE"));
    for (const char* bad : {"NoLeadingSlash", "", "\\evil\" /RU SYSTEM", "\\a|b", "\\a<b", "\\wild*card", "\\new\nline"}) {
        CHECK(schtasks_change_args(exe, bad, true, err).empty());
        CHECK(!err.empty());
    }
}

// --------------------------------------------------------------- manager --

HG_TEST(startup_manager, disable_enable_and_undo) {
    hgt::Sandbox sb;
    FakeBackend fb;
    fb.items = {item("run-user|OneApp", "\"C:\\a\\one.exe\""), item("run-user|TwoApp", "\"C:\\a\\two.exe\"")};
    StartupManager m(fb, sb / "journal.tsv");
    std::string err;
    REQUIRE(m.disable("run-user|OneApp", err));
    CHECK(!fb.items[0].enabled);
    CHECK(fb.items[1].enabled);  // only the one asked for
    REQUIRE(m.disable("run-user|TwoApp", err));
    // Undo flips the LAST change back, then the one before.
    std::string what;
    REQUIRE(m.undo_last(err, &what));
    CHECK(fb.items[1].enabled);
    CHECK(!fb.items[0].enabled);
    REQUIRE(m.undo_last(err, &what));
    CHECK(fb.items[0].enabled);
    CHECK(!m.undo_last(err));  // nothing left to undo
    // Direct enable works as well.
    REQUIRE(m.disable("run-user|OneApp", err));
    REQUIRE(m.enable("run-user|OneApp", err));
    CHECK(fb.items[0].enabled);
}

HG_TEST(startup_manager, journal_survives_a_restart) {
    hgt::Sandbox sb;
    FakeBackend fb;
    fb.items = {item("run-user|OneApp", "\"C:\\a\\one.exe\"")};
    std::string err;
    {
        StartupManager m(fb, sb / "dir/journal.tsv");
        REQUIRE(m.disable("run-user|OneApp", err));
    }
    StartupManager again(fb, sb / "dir/journal.tsv");  // new object, same journal file
    REQUIRE(again.undo_last(err));
    CHECK(fb.items[0].enabled);
}

HG_TEST(startup_manager, mistakes_are_refused_with_a_reason) {
    hgt::Sandbox sb;
    FakeBackend fb;
    fb.items = {item("run-user|A", "a.exe"), item("task|\\Microsoft\\Windows\\Foo\\Bar", "x.exe", true, /*system*/ true),
                item("run-user|Off", "off.exe", false)};
    StartupManager m(fb, sb / "j.tsv");
    std::string err;
    CHECK(!m.disable("run-user|DoesNotExist", err));
    CHECK(!err.empty());
    CHECK(!m.disable("task|\\Microsoft\\Windows\\Foo\\Bar", err));   // Windows' own task: read-only
    CHECK(err.find("own scheduled tasks") != std::string::npos);
    CHECK(fb.items[1].enabled);
    CHECK_EQ(fb.set_calls, 0);                                       // Windows was never even asked
    CHECK(!m.disable("run-user|Off", err));                          // already off
    CHECK(!m.enable("run-user|A", err));                             // already on
    fb.fail_next = true;
    CHECK(!m.disable("run-user|A", err));                            // backend failed...
    CHECK(fb.items[0].enabled);
    CHECK(!m.undo_last(err));                                        // ...so nothing was journaled
}

HG_TEST(startup_manager, listing_hides_windows_own_tasks_by_default_and_never_deletes) {
    hgt::Sandbox sb;
    FakeBackend fb;
    fb.items = {item("run-user|A", "a.exe"), item("task|\\Microsoft\\Windows\\X", "x.exe", true, true),
                item("task|\\Vendor\\Y", "y.exe")};
    StartupManager m(fb, sb / "j.tsv");
    CHECK_EQ(m.list().size(), static_cast<std::size_t>(2));
    CHECK_EQ(m.list(true).size(), static_cast<std::size_t>(3));
    CHECK_EQ(fb.items.size(), static_cast<std::size_t>(3));  // listing and disabling never remove anything
    std::string err;
    m.disable("run-user|A", err);
    CHECK_EQ(fb.items.size(), static_cast<std::size_t>(3));
}

HG_TEST(startup_manager, signature_state_is_filled_in_for_real_files_only) {
    hgt::Sandbox sb;
    const fs::path real = hgt::write_file(sb / "real.exe", "x");
    FakeBackend fb;
    fb.items = {item("run-user|Real", "\"" + to_u8(real) + "\""), item("run-user|Ghost", "\"" + to_u8(sb / "ghost.exe") + "\"")};
    StartupManager m(fb, sb / "j.tsv");
    m.set_signature_fn([](const fs::path&) { return SignState::Unsigned; });
    const auto items = m.list();
    REQUIRE(items.size() == 2);
    CHECK(items[0].signature == SignState::Unsigned);
    CHECK(items[1].signature == SignState::Unknown);  // file is not there, so we do not guess
}

// --------------------------------------------------------- Windows only --

#ifdef _WIN32

namespace {

struct TestKey {
    std::wstring path;
    TestKey() {
        const std::string r = random_hex(10);
        path = L"Software\\HEMGuardTest-" + std::wstring(r.begin(), r.end());
    }
    ~TestKey() { RegDeleteTreeW(HKEY_CURRENT_USER, path.c_str()); }
    void set_sz(const std::wstring& sub, const std::wstring& name, const std::wstring& value) const {
        RegSetKeyValueW(HKEY_CURRENT_USER, (path + L"\\" + sub).c_str(), name.c_str(), REG_SZ, value.c_str(),
                        static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
    }
    // First byte of the StartupApproved flag, or -1 if there is none.
    int approved_byte(const std::wstring& sub, const std::wstring& name) const {
        BYTE data[32] = {};
        DWORD size = sizeof data;
        if (RegGetValueW(HKEY_CURRENT_USER, (path + L"\\" + sub).c_str(), name.c_str(), RRF_RT_REG_BINARY, nullptr, data, &size) !=
            ERROR_SUCCESS)
            return -1;
        return data[0];
    }
    bool has_value(const std::wstring& sub, const std::wstring& name) const {
        return RegGetValueW(HKEY_CURRENT_USER, (path + L"\\" + sub).c_str(), name.c_str(), RRF_RT_ANY, nullptr, nullptr, nullptr) ==
               ERROR_SUCCESS;
    }
};

const StartupItem* by_id(const std::vector<StartupItem>& v, const std::string& id) {
    for (const auto& i : v) {
        if (i.id == id) return &i;
    }
    return nullptr;
}

}  // namespace

HG_TEST(startup_windows, run_key_and_startup_folder_items_really_toggle_in_the_registry) {
    hgt::Sandbox sb;
    TestKey key;  // a throwaway registry key, removed at the end - the real startup lists are never touched
    key.set_sz(L"Run", L"HemTestApp", L"\"C:\\Program Files\\HemTest\\hemtest.exe\" --background");
    key.set_sz(L"RunAll", L"HemTestAll", L"C:\\Tools\\all.exe");
    hgt::write_file(sb / "StartupFolder/demo.bat", "@echo off");

    StartupLayout L;
    L.all_in_current_user = true;
    L.reg = {{StartupKind::RunUser, false, key.path + L"\\Run", key.path + L"\\Approved\\Run"},
             {StartupKind::RunMachine, true, key.path + L"\\RunAll", key.path + L"\\Approved\\RunAll"}};
    L.user_folder = sb / "StartupFolder";
    L.approved_user_folder = key.path + L"\\Approved\\Folder";
    L.include_tasks = false;
    auto backend = make_windows_startup_backend(L);
    REQUIRE(backend != nullptr);
    StartupManager m(*backend, sb / "journal.tsv");
    m.set_signature_fn([](const fs::path&) { return SignState::Unknown; });

    auto items = m.list();
    const auto* app = by_id(items, "run-user|HemTestApp");
    REQUIRE(app != nullptr);
    CHECK(app->enabled);
    CHECK_EQ(app->command, std::string("\"C:\\Program Files\\HemTest\\hemtest.exe\" --background"));
    CHECK_EQ(to_u8(app->program), std::string("C:\\Program Files\\HemTest\\hemtest.exe"));
    CHECK(by_id(items, "run-machine|HemTestAll") != nullptr);
    REQUIRE(by_id(items, "folder-user|demo.bat") != nullptr);

    std::string err;
    REQUIRE(m.disable("run-user|HemTestApp", err));
    CHECK_EQ(key.approved_byte(L"Approved\\Run", L"HemTestApp"), 0x03);       // the same flag Task Manager writes
    CHECK(key.has_value(L"Run", L"HemTestApp"));                              // the Run entry itself is NEVER deleted
    items = m.list();
    CHECK(!by_id(items, "run-user|HemTestApp")->enabled);
    CHECK(by_id(items, "run-machine|HemTestAll")->enabled);                   // other items untouched

    REQUIRE(m.disable("folder-user|demo.bat", err));
    CHECK_EQ(key.approved_byte(L"Approved\\Folder", L"demo.bat"), 0x03);
    CHECK(fs::exists(sb / "StartupFolder/demo.bat"));                         // file never removed

    REQUIRE(m.undo_last(err));                                                // folder item back on
    CHECK_EQ(key.approved_byte(L"Approved\\Folder", L"demo.bat"), 0x02);
    REQUIRE(m.enable("run-user|HemTestApp", err));
    CHECK_EQ(key.approved_byte(L"Approved\\Run", L"HemTestApp"), 0x02);
    CHECK(by_id(m.list(), "run-user|HemTestApp")->enabled);
}

HG_TEST(startup_windows, real_system_startup_lists_can_be_read_without_changing_anything) {
    hgt::Sandbox sb;
    auto backend = make_windows_startup_backend(StartupLayout::system_default());
    REQUIRE(backend != nullptr);
    StartupManager m(*backend, sb / "journal.tsv");
    const auto items = m.list(true);
    int tasks = 0, run = 0, folders = 0, microsoft = 0;
    for (const auto& i : items) {
        if (i.kind == StartupKind::LogonTask) ++tasks;
        else if (i.kind == StartupKind::FolderUser || i.kind == StartupKind::FolderCommon) ++folders;
        else ++run;
        if (i.system_owned) ++microsoft;
        CHECK(!i.id.empty());
        CHECK(!i.name.empty());
    }
    NOTE("this machine: " + std::to_string(run) + " Run entries, " + std::to_string(folders) + " Startup-folder items, " +
         std::to_string(tasks) + " logon tasks readable (" + std::to_string(microsoft) + " Windows-owned)");
    CHECK(!fs::exists(sb / "journal.tsv"));  // listing wrote nothing
}

HG_TEST(startup_windows, a_logon_task_can_be_turned_off_and_on_with_schtasks) {
    hgt::Sandbox sb;
    const StartupLayout L = StartupLayout::system_default();
    const std::string name = "\\HEMGuardTest\\T" + random_hex(8);
    std::string out;
    const int created = run_process({to_u8(L.schtasks_exe), "/Create", "/TN", name, "/TR", "cmd.exe /c exit 0", "/SC", "ONLOGON", "/F"}, out);
    struct Cleanup {
        const StartupLayout& L;
        std::string name;
        ~Cleanup() {
            std::string o;
            run_process({to_u8(L.schtasks_exe), "/Delete", "/TN", name, "/F"}, o);
        }
    } cleanup{L, name};
    if (created != 0) SKIP("could not create a throwaway scheduled task here (" + trim(out) + ")");

    auto backend = make_windows_startup_backend(L);
    REQUIRE(backend != nullptr);
    StartupManager m(*backend, sb / "journal.tsv");
    auto items = m.list(true);
    const auto* t = by_id(items, "task|" + name);
    if (!t) SKIP("the throwaway task was created but its file is not readable by this user (needs administrator)");
    CHECK(t->enabled);
    CHECK(!t->system_owned);

    std::string err;
    REQUIRE(m.disable("task|" + name, err));
    CHECK(!by_id(m.list(true), "task|" + name)->enabled);   // Windows really says disabled
    REQUIRE(m.undo_last(err));
    CHECK(by_id(m.list(true), "task|" + name)->enabled);    // and really says enabled again
}

HG_TEST(signature, windows_programs_are_recognised_as_signed_and_plain_files_as_unsigned) {
    hgt::Sandbox sb;
    const char* windir = std::getenv("WINDIR");
    REQUIRE(windir != nullptr);
    // notepad / cmd carry their signature in a Windows catalog file, so this proves the catalog path works too.
    CHECK(check_signature(fs::path(windir) / "System32" / "cmd.exe") == SignState::Signed);
    CHECK(check_signature(fs::path(windir) / "System32" / "notepad.exe") == SignState::Signed);
    const fs::path plain = hgt::write_file(sb / "plain.exe", "MZ this is not signed");
    CHECK(check_signature(plain) == SignState::Unsigned);
    CHECK(check_signature(sb / "missing.exe") == SignState::Unknown);
}

#else

HG_TEST(startup_windows, skipped_on_this_machine) { SKIP("Windows only (registry, scheduled tasks and signature checks)"); }

HG_TEST(signature, off_windows_the_answer_is_honestly_unknown) {
    hgt::Sandbox sb;
    const fs::path f = hgt::write_file(sb / "a.exe", "x");
    CHECK(check_signature(f) == SignState::Unknown);
}

#endif
