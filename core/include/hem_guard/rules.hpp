// HEM Guard - detection data: byte-pattern rules and the known-bad hash list.
//
// Rules file, one rule per line (blank lines and lines starting with # are ignored):
//     NAME | low|medium|high | hex|text | PATTERN
//   example:  HEM.Demo.Marker | high | text | HEM-GUARD-DEMO-MARKER
//   example:  Some.Hex.Rule   | high | hex  | 4d 5a 90 00
//
// Hash list file, one per line:   <64 hex characters> [optional name]
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "hem_guard/util.hpp"

namespace hem::guard {

enum class Severity { Low = 1, Medium = 2, High = 3 };
const char* to_string(Severity s);

struct Rule {
    std::string name;
    Severity severity = Severity::High;
    std::vector<std::uint8_t> pattern;
};

class RuleSet {
public:
    // Returns false if the line is bad (error says why). Comment / blank lines return true and add nothing.
    bool add_line(std::string_view line, std::string& error);
    // Loads a file. Bad lines are listed in `errors` and skipped. Returns false only if the file cannot be read.
    bool load_file(const fs::path& p, std::vector<std::string>& errors);
    void add_rule(Rule r);

    const std::vector<Rule>& rules() const { return rules_; }
    std::size_t max_pattern_len() const { return max_len_; }

private:
    std::vector<Rule> rules_;
    std::size_t max_len_ = 0;
};

class HashList {
public:
    bool add_line(std::string_view line, std::string& error);
    bool load_file(const fs::path& p, std::vector<std::string>& errors);
    void add(const std::string& sha256_hex, const std::string& name);
    // Returns the name for a known-bad hash, or nullptr.
    const std::string* find(const std::string& sha256_hex) const;
    std::size_t size() const { return map_.size(); }

private:
    std::unordered_map<std::string, std::string> map_;
};

}  // namespace hem::guard
