// Linux / test-only version of the platform layer.
#ifndef _WIN32

#include <sys/resource.h>

#include <cstdlib>
#include <system_error>

#include "hem_guard/platform.hpp"

namespace hem::guard {

const char* to_string(SignState s) {
    switch (s) {
        case SignState::Signed: return "signed";
        case SignState::Unsigned: return "unsigned";
        default: return "unknown";
    }
}

bool is_reparse_or_symlink(const fs::path& p) {
    std::error_code ec;
    return fs::is_symlink(fs::symlink_status(p, ec));
}

SignState check_signature(const fs::path&) { return SignState::Unknown; }

double process_cpu_seconds() {
    rusage ru{};
    getrusage(RUSAGE_SELF, &ru);
    return double(ru.ru_utime.tv_sec) + double(ru.ru_utime.tv_usec) / 1e6 + double(ru.ru_stime.tv_sec) +
           double(ru.ru_stime.tv_usec) / 1e6;
}

std::optional<std::string> env_var(const char* name) {
    const char* v = std::getenv(name);
    if (!v || !*v) return std::nullopt;
    return std::string(v);
}

KnownFolders known_folders() {
    KnownFolders k;
    const auto home = env_var("HOME");
    if (!home) return k;
    k.profile = from_u8(*home);
    k.documents = k.profile / "Documents";
    k.desktop = k.profile / "Desktop";
    k.pictures = k.profile / "Pictures";
    k.music = k.profile / "Music";
    k.videos = k.profile / "Videos";
    k.downloads = k.profile / "Downloads";
    return k;
}

int run_process(const std::vector<std::string>&, std::string& output) {
    output.clear();
    return -1;
}

bool is_windows() { return false; }

}  // namespace hem::guard

#endif
