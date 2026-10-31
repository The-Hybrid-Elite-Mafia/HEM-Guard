#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>

#include "test_support.hpp"

namespace hgt {

namespace {
struct Entry {
    const char* group;
    const char* name;
    void (*fn)();
};
std::vector<Entry>& registry() {
    static std::vector<Entry> r;
    return r;
}
}  // namespace

Ctx& ctx() {
    static Ctx c;
    return c;
}

Registrar::Registrar(const char* group, const char* name, void (*fn)()) { registry().push_back({group, name, fn}); }

void record(bool ok, const std::string& what, const char* file, int line) {
    ++ctx().checks;
    if (!ok) {
        std::string f = file;
        const auto slash = f.find_last_of("/\\");
        if (slash != std::string::npos) f = f.substr(slash + 1);
        ctx().failures.push_back(f + ":" + std::to_string(line) + "  " + what);
    }
}

Sandbox::Sandbox() {
    std::error_code ec;
    root = fs::temp_directory_path(ec) / ("hemguard-test-" + hem::guard::random_hex(10));
    fs::create_directories(root, ec);
    root = hem::guard::normalize_path(root);
}
Sandbox::~Sandbox() {
    std::error_code ec;
    // Only ever removes the folder this object created.
    if (!root.empty() && root.filename().string().rfind("hemguard-test-", 0) == 0) fs::remove_all(root, ec);
}

fs::path write_file(const fs::path& p, std::string_view content) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
    return p;
}

std::string slurp(const fs::path& p) {
    std::string s;
    hem::guard::read_text_file(p, s, 1ull << 30);
    return s;
}

void age_file(const fs::path& p, int hours) {
    std::error_code ec;
    fs::last_write_time(p, fs::file_time_type::clock::now() - std::chrono::hours(hours), ec);
}

std::string random_bytes(std::size_t n, unsigned seed) {
    std::mt19937 g(seed);
    std::string s(n, '\0');
    for (auto& c : s) c = static_cast<char>(g() & 0xFF);
    return s;
}

std::string tree_fingerprint(const fs::path& dir, const std::vector<fs::path>& skip) {
    std::vector<std::string> lines;
    std::error_code ec;
    for (fs::recursive_directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end; !ec && it != end;
         it.increment(ec)) {
        bool skipped = false;
        for (const auto& s : skip) {
            if (hem::guard::path_is_within(it->path(), s)) skipped = true;
        }
        if (skipped) continue;
        const std::string rel = hem::guard::to_u8(it->path().lexically_relative(dir));
        std::error_code e2;
        const auto st = it->symlink_status(e2);
        if (fs::is_symlink(st)) {
            lines.push_back("L:" + rel);
        } else if (fs::is_directory(st)) {
            lines.push_back("D:" + rel);
        } else if (fs::is_regular_file(st)) {
            std::string h;
            hem::guard::sha256_file(it->path(), h);
            lines.push_back("F:" + rel + ":" + std::to_string(it->file_size(e2)) + ":" + h);
        }
    }
    std::sort(lines.begin(), lines.end());
    std::string all;
    for (const auto& l : lines) all += l + "\n";
    return hem::guard::sha256_hex(all);
}

bool can_make_symlink(const fs::path& scratch) {
    std::error_code ec;
    const fs::path target = scratch / "symlink-probe-target";
    const fs::path link = scratch / "symlink-probe-link";
    fs::create_directories(target, ec);
    fs::create_directory_symlink(target, link, ec);
    const bool ok = !ec;
    fs::remove(link, ec);
    fs::remove(target, ec);
    return ok;
}

std::string eicar_string() {
    // Split so this file never contains the whole test string.
    return std::string("X5O!P%@AP[4\\PZX54(P^)7CC)7}$") + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + "$H+H*";
}

}  // namespace hgt

int main(int argc, char** argv) {
    using clock = std::chrono::steady_clock;
    std::string report_path, filter;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--report") && i + 1 < argc) report_path = argv[++i];
        else if (!std::strcmp(argv[i], "--filter") && i + 1 < argc) filter = argv[++i];
    }

    struct Row {
        std::string group, name, status, detail;
        int checks = 0;
        double ms = 0;
        std::vector<std::string> notes;
    };
    std::vector<Row> rows;
    auto& reg = hgt::registry();
    std::stable_sort(reg.begin(), reg.end(), [](const auto& a, const auto& b) { return std::strcmp(a.group, b.group) < 0; });

    int passed = 0, failed = 0, skipped = 0, total_checks = 0;
    for (const auto& e : reg) {
        if (!filter.empty() && std::string(e.group).find(filter) == std::string::npos &&
            std::string(e.name).find(filter) == std::string::npos)
            continue;
        hgt::ctx() = hgt::Ctx{};
        Row r;
        r.group = e.group;
        r.name = e.name;
        const auto t0 = clock::now();
        try {
            e.fn();
            r.status = hgt::ctx().failures.empty() ? "PASS" : "FAIL";
        } catch (const hgt::SkipTest& s) {
            r.status = "SKIP";
            r.detail = s.why;
        } catch (const hgt::AbortTest&) {
            r.status = "FAIL";
        } catch (const std::exception& ex) {
            r.status = "FAIL";
            hgt::ctx().failures.push_back(std::string("unexpected exception: ") + ex.what());
        } catch (...) {
            r.status = "FAIL";
            hgt::ctx().failures.push_back("unexpected unknown exception");
        }
        r.ms = std::chrono::duration<double, std::milli>(clock::now() - t0).count();
        r.checks = hgt::ctx().checks;
        r.notes = hgt::ctx().notes;
        if (r.status == "FAIL") {
            for (const auto& f : hgt::ctx().failures) r.detail += (r.detail.empty() ? "" : " | ") + f;
        }
        total_checks += r.checks;
        if (r.status == "PASS") ++passed;
        else if (r.status == "FAIL") ++failed;
        else ++skipped;
        std::printf("[%-4s] %-12s %-44s %4d checks %8.1f ms\n", r.status.c_str(), r.group.c_str(), r.name.c_str(), r.checks, r.ms);
        for (const auto& n : r.notes) std::printf("         measured: %s\n", n.c_str());
        if (r.status == "FAIL") std::printf("         %s\n", r.detail.c_str());
        if (r.status == "SKIP") std::printf("         skipped: %s\n", r.detail.c_str());
        rows.push_back(std::move(r));
    }

    std::printf("\nHEM Guard tests on %s: %d passed, %d failed, %d skipped, %d checks run\n",
                hem::guard::is_windows() ? "Windows" : "Linux (dev machine)", passed, failed, skipped, total_checks);

    if (!report_path.empty()) {
        std::ofstream f(report_path, std::ios::binary | std::ios::trunc);
        f << "# HEM Guard test report\n\n";
        f << "Platform: **" << (hem::guard::is_windows() ? "Windows" : "Linux (dev machine only)") << "**  \n";
        f << "Result: **" << passed << " passed, " << failed << " failed, " << skipped << " skipped** (" << total_checks
          << " individual checks)\n\n";
        f << "| Result | Group | Test | Checks | Time (ms) | Notes |\n|---|---|---|---:|---:|---|\n";
        for (const auto& r : rows) {
            std::string notes;
            for (const auto& n : r.notes) notes += (notes.empty() ? "" : "; ") + n;
            if (r.status != "PASS") notes += (notes.empty() ? "" : "; ") + r.detail;
            std::string icon = r.status == "PASS" ? "PASS" : (r.status == "FAIL" ? "**FAIL**" : "SKIP");
            for (auto& c : notes) {
                if (c == '|') c = '/';
                if (c == '\n') c = ' ';
            }
            char ms[32];
            std::snprintf(ms, sizeof ms, "%.1f", r.ms);
            f << "| " << icon << " | " << r.group << " | " << r.name << " | " << r.checks << " | " << ms << " | " << notes << " |\n";
        }
    }
    return failed == 0 ? 0 : 1;
}
