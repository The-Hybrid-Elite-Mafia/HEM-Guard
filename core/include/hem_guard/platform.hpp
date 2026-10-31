// HEM Guard - the only place that talks to the operating system directly.
// Windows is the real target. The Linux version exists so the logic can be tested quickly.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "hem_guard/util.hpp"

namespace hem::guard {

enum class SignState { Signed, Unsigned, Unknown };
const char* to_string(SignState s);

// True for symbolic links and Windows junctions / reparse points. Never follow these.
bool is_reparse_or_symlink(const fs::path& p);

// "Signed" means a valid digital signature was verified by Windows (embedded or catalog).
// "Unsigned" means no valid signature. "Unknown" means we could not check (not Windows, or error).
SignState check_signature(const fs::path& p);

// CPU seconds this process has used so far (not wall-clock).
double process_cpu_seconds();

std::optional<std::string> env_var(const char* name);  // UTF-8

struct KnownFolders {
    fs::path profile, documents, desktop, pictures, music, videos, downloads;
};
KnownFolders known_folders();

// Runs a program (no shell). Returns its exit code, or -1 if it could not start.
int run_process(const std::vector<std::string>& args, std::string& output);

// Text form of the signed-in account id (used to find your own Recycle Bin). Empty if unknown / not Windows.
std::string current_user_sid();

bool is_windows();

}  // namespace hem::guard
