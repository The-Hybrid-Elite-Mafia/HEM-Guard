#include "hem_guard/startup.hpp"

#include <algorithm>
#include <system_error>

#include "hem_guard/config.hpp"

namespace hem::guard {

const char* to_string(StartupKind k) {
    switch (k) {
        case StartupKind::RunUser: return "Run (this user)";
        case StartupKind::RunMachine: return "Run (all users)";
        case StartupKind::RunMachine32: return "Run (all users, 32-bit)";
        case StartupKind::FolderUser: return "Startup folder (this user)";
        case StartupKind::FolderCommon: return "Startup folder (all users)";
        default: return "Scheduled task at logon";
    }
}

fs::path extract_program_path(std::string_view command) {
    const std::string s = trim(command);
    if (s.empty()) return {};
    if (s[0] == '"') {
        const auto close = s.find('"', 1);
        if (close == std::string::npos) return from_u8(s.substr(1));
        return from_u8(s.substr(1, close - 1));
    }
    const std::string lower = to_lower_ascii(s);
    static const char* exts[] = {".exe", ".bat", ".cmd", ".com", ".scr", ".lnk", ".vbs", ".js", ".ps1", ".msi"};
    std::size_t best = std::string::npos;
    for (const char* e : exts) {
        const std::string ext = e;
        std::size_t pos = 0;
        while ((pos = lower.find(ext, pos)) != std::string::npos) {
            const std::size_t end = pos + ext.size();
            const bool boundary = end == lower.size() || lower[end] == ' ' || lower[end] == '"' || lower[end] == ',';
            if (boundary) {
                best = std::min(best, end);
                break;
            }
            pos = end;
        }
    }
    if (best != std::string::npos) return from_u8(s.substr(0, best));
    const auto sp = s.find(' ');
    return from_u8(sp == std::string::npos ? s : s.substr(0, sp));
}

namespace {

void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

std::string to_utf8_text(const std::string& raw) {
    const auto b = [&](std::size_t i) { return static_cast<unsigned char>(raw[i]); };
    if (raw.size() >= 2 && b(0) == 0xFF && b(1) == 0xFE) {  // UTF-16 little endian
        std::string out;
        for (std::size_t i = 2; i + 1 < raw.size(); i += 2) {
            std::uint32_t u = b(i) | (b(i + 1) << 8);
            if (u >= 0xD800 && u < 0xDC00 && i + 3 < raw.size()) {
                const std::uint32_t lo = b(i + 2) | (b(i + 3) << 8);
                if (lo >= 0xDC00 && lo < 0xE000) {
                    u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
                    i += 2;
                }
            }
            append_utf8(out, u);
        }
        return out;
    }
    if (raw.size() >= 3 && b(0) == 0xEF && b(1) == 0xBB && b(2) == 0xBF) return raw.substr(3);
    return raw;
}

std::string xml_text(const std::string& doc, const std::string& tag, std::size_t from = 0, std::size_t to = std::string::npos,
                     bool* found = nullptr) {
    if (found) *found = false;
    const std::string open = "<" + tag + ">";
    const std::string close = "</" + tag + ">";
    const auto a = doc.find(open, from);
    if (a == std::string::npos || (to != std::string::npos && a >= to)) return {};
    const auto b = doc.find(close, a + open.size());
    if (b == std::string::npos) return {};
    if (found) *found = true;
    std::string t = doc.substr(a + open.size(), b - a - open.size());
    // Undo the five XML escapes.
    struct R {
        const char* from;
        const char* to;
    };
    for (const R& r : {R{"&lt;", "<"}, R{"&gt;", ">"}, R{"&quot;", "\""}, R{"&apos;", "'"}, R{"&amp;", "&"}}) {
        std::size_t pos = 0;
        const std::string f = r.from;
        while ((pos = t.find(f, pos)) != std::string::npos) {
            t.replace(pos, f.size(), r.to);
            ++pos;
        }
    }
    return trim(t);
}

}  // namespace

bool parse_task_xml(const std::string& raw, TaskInfo& out) {
    out = TaskInfo{};
    const std::string doc = to_utf8_text(raw);
    if (doc.find("<Task") == std::string::npos) return false;

    const auto trig = doc.find("<LogonTrigger");
    out.logon = trig != std::string::npos;
    bool trigger_enabled = true;
    if (out.logon) {
        auto end = doc.find("</LogonTrigger>", trig);
        bool f = false;
        const std::string en = xml_text(doc, "Enabled", trig, end, &f);
        if (f && to_lower_ascii(en) == "false") trigger_enabled = false;
    }
    bool settings_enabled = true;
    const auto sa = doc.find("<Settings>");
    if (sa != std::string::npos) {
        const auto sb = doc.find("</Settings>", sa);
        bool f = false;
        const std::string en = xml_text(doc, "Enabled", sa, sb, &f);
        if (f && to_lower_ascii(en) == "false") settings_enabled = false;
    }
    out.enabled = trigger_enabled && settings_enabled;

    const auto ex = doc.find("<Exec>");
    if (ex != std::string::npos) {
        const auto exend = doc.find("</Exec>", ex);
        out.command = xml_text(doc, "Command", ex, exend);
        out.arguments = xml_text(doc, "Arguments", ex, exend);
    }
    return true;
}

std::vector<std::string> schtasks_change_args(const std::string& exe, const std::string& name, bool enable, std::string& error) {
    error.clear();
    bool ok = !name.empty() && name.size() <= 238 && name[0] == '\\' && !exe.empty();
    for (unsigned char c : name) {
        if (c < 0x20 || c == '"' || c == '*' || c == '?' || c == '<' || c == '>' || c == '|') ok = false;
    }
    if (!ok) {
        error = "that scheduled task name does not look safe to pass to Windows";
        return {};
    }
    return {exe, "/Change", "/TN", name, enable ? "/ENABLE" : "/DISABLE"};
}

// ------------------------------------------------------------------ manager --

StartupManager::StartupManager(StartupBackend& backend, fs::path journal_file)
    : backend_(backend), journal_(std::move(journal_file)), sig_fn_(check_signature) {}

std::vector<StartupItem> StartupManager::list(bool include_system) {
    auto items = backend_.list();
    std::vector<StartupItem> out;
    for (auto& it : items) {
        if (it.system_owned && !include_system) continue;
        if (it.program.empty()) it.program = extract_program_path(it.command);
        std::error_code ec;
        if (!it.program.empty() && fs::is_regular_file(it.program, ec)) it.signature = sig_fn_(it.program);
        out.push_back(std::move(it));
    }
    return out;
}

bool StartupManager::change(const std::string& id, bool enabled, std::string& error, bool journal) {
    error.clear();
    const auto items = backend_.list();
    const StartupItem* hit = nullptr;
    for (const auto& it : items) {
        if (it.id == id) hit = &it;
    }
    if (!hit) {
        error = "no startup item with that id";
        return false;
    }
    if (hit->system_owned && !cfg::kStartupAllowChangingMicrosoftTasks) {
        error = "this is one of Windows' own scheduled tasks; HEM Guard shows it but will not change it";
        return false;
    }
    if (hit->enabled == enabled) {
        error = enabled ? "already enabled" : "already disabled";
        return false;
    }
    if (!backend_.set_enabled(*hit, enabled, error)) return false;
    if (journal && !journal_.empty()) {
        std::error_code ec;
        if (journal_.has_parent_path()) fs::create_directories(journal_.parent_path(), ec);
        append_text_file(journal_, std::string(enabled ? "enable" : "disable") + "\t" + tsv_escape(id) + "\t" +
                                       std::to_string(unix_now()) + "\n");
    }
    return true;
}

bool StartupManager::disable(const std::string& id, std::string& error) { return change(id, false, error, true); }
bool StartupManager::enable(const std::string& id, std::string& error) { return change(id, true, error, true); }

bool StartupManager::undo_last(std::string& error, std::string* what) {
    error.clear();
    std::string text;
    if (journal_.empty() || !read_text_file(journal_, text)) {
        error = "there is nothing to undo";
        return false;
    }
    auto lines = split(text, '\n');
    while (!lines.empty() && lines.back().empty()) lines.pop_back();
    if (lines.empty()) {
        error = "there is nothing to undo";
        return false;
    }
    const auto f = split(lines.back(), '\t');
    if (f.size() < 2) {
        error = "the undo journal is damaged";
        return false;
    }
    const bool was_enable = f[0] == "enable";
    const std::string id = tsv_unescape(f[1]);
    if (!change(id, !was_enable, error, false)) return false;
    lines.pop_back();
    std::string rest;
    for (const auto& l : lines) rest += l + "\n";
    write_text_file(journal_, rest);
    if (what) *what = std::string(was_enable ? "turned off again: " : "turned back on: ") + id;
    return true;
}

#ifndef _WIN32
StartupLayout StartupLayout::system_default() { return {}; }
std::unique_ptr<StartupBackend> make_windows_startup_backend(const StartupLayout&) { return nullptr; }
#endif

}  // namespace hem::guard
