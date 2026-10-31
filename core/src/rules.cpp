#include "hem_guard/rules.hpp"

#include <algorithm>

#include "hem_guard/config.hpp"

namespace hem::guard {

const char* to_string(Severity s) {
    switch (s) {
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        default: return "high";
    }
}

void RuleSet::add_rule(Rule r) {
    max_len_ = std::max(max_len_, r.pattern.size());
    rules_.push_back(std::move(r));
}

bool RuleSet::add_line(std::string_view line, std::string& error) {
    const std::string t = trim(line);
    if (t.empty() || t[0] == '#') return true;
    // Split on the first three bars only, so the pattern itself may contain a bar.
    std::vector<std::string> parts;
    std::size_t start = 0;
    for (int i = 0; i < 3; ++i) {
        const auto pos = t.find('|', start);
        if (pos == std::string::npos) {
            error = "expected: NAME | severity | hex-or-text | PATTERN";
            return false;
        }
        parts.push_back(trim(std::string_view(t).substr(start, pos - start)));
        start = pos + 1;
    }
    // Keep the pattern exactly as written after the third bar, minus one leading space.
    std::string pat = t.substr(start);
    if (!pat.empty() && pat.front() == ' ') pat.erase(0, 1);

    Rule r;
    r.name = parts[0];
    if (r.name.empty()) {
        error = "rule has no name";
        return false;
    }
    const std::string sev = to_lower_ascii(parts[1]);
    if (sev == "low") r.severity = Severity::Low;
    else if (sev == "medium") r.severity = Severity::Medium;
    else if (sev == "high") r.severity = Severity::High;
    else {
        error = "severity must be low, medium or high";
        return false;
    }
    const std::string kind = to_lower_ascii(parts[2]);
    if (kind == "hex") {
        if (!hex_decode(pat, r.pattern)) {
            error = "bad hex pattern";
            return false;
        }
    } else if (kind == "text") {
        pat = trim(pat);
        r.pattern.assign(pat.begin(), pat.end());
    } else {
        error = "pattern type must be hex or text";
        return false;
    }
    if (r.pattern.size() < 4) {
        error = "pattern must be at least 4 bytes (shorter ones match too much)";
        return false;
    }
    if (r.pattern.size() > cfg::kMaxPatternBytes) {
        error = "pattern is too long";
        return false;
    }
    add_rule(std::move(r));
    return true;
}

bool RuleSet::load_file(const fs::path& p, std::vector<std::string>& errors) {
    std::string text;
    if (!read_text_file(p, text)) return false;
    int n = 0;
    for (const auto& line : split(text, '\n')) {
        ++n;
        std::string err;
        if (!add_line(line, err)) errors.push_back("line " + std::to_string(n) + ": " + err);
    }
    return true;
}

bool HashList::add_line(std::string_view line, std::string& error) {
    const std::string t = trim(line);
    if (t.empty() || t[0] == '#') return true;
    const auto sp = t.find_first_of(" \t");
    const std::string h = to_lower_ascii(sp == std::string::npos ? t : t.substr(0, sp));
    if (h.size() != 64 || h.find_first_not_of("0123456789abcdef") != std::string::npos) {
        error = "expected 64 hex characters (SHA-256)";
        return false;
    }
    const std::string name = sp == std::string::npos ? "KnownBad" : trim(t.substr(sp));
    map_[h] = name.empty() ? "KnownBad" : name;
    return true;
}

bool HashList::load_file(const fs::path& p, std::vector<std::string>& errors) {
    std::string text;
    if (!read_text_file(p, text)) return false;
    int n = 0;
    for (const auto& line : split(text, '\n')) {
        ++n;
        std::string err;
        if (!add_line(line, err)) errors.push_back("line " + std::to_string(n) + ": " + err);
    }
    return true;
}

void HashList::add(const std::string& h, const std::string& name) { map_[to_lower_ascii(h)] = name; }

const std::string* HashList::find(const std::string& h) const {
    const auto it = map_.find(h);
    return it == map_.end() ? nullptr : &it->second;
}

}  // namespace hem::guard
