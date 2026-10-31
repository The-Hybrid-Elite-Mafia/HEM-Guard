// HEM Guard - tiny test framework (no outside library). Counts every check, records measured numbers.
#pragma once

#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

#include "hem_guard/platform.hpp"
#include "hem_guard/sha256.hpp"
#include "hem_guard/util.hpp"

namespace hgt {

namespace fs = std::filesystem;

struct SkipTest {
    std::string why;
};
struct AbortTest {};

struct Ctx {
    int checks = 0;
    std::vector<std::string> failures;
    std::vector<std::string> notes;  // measured numbers, shown in the report
};
Ctx& ctx();

struct Registrar {
    Registrar(const char* group, const char* name, void (*fn)());
};

void record(bool ok, const std::string& what, const char* file, int line);

template <class A, class B>
void record_eq(const A& a, const B& b, const char* ea, const char* eb, const char* file, int line) {
    const bool ok = (a == b);
    std::ostringstream os;
    os << ea << " == " << eb;
    if (!ok) os << "   [left: " << a << ", right: " << b << "]";
    record(ok, os.str(), file, line);
}

#define HG_TEST(group, name)                                                      \
    static void test_##group##_##name();                                          \
    static hgt::Registrar reg_##group##_##name(#group, #name, &test_##group##_##name); \
    static void test_##group##_##name()

#define CHECK(c) hgt::record(static_cast<bool>(c), #c, __FILE__, __LINE__)
#define CHECK_EQ(a, b) hgt::record_eq((a), (b), #a, #b, __FILE__, __LINE__)
#define REQUIRE(c)                                         \
    do {                                                   \
        const bool hg_ok_ = static_cast<bool>(c);          \
        hgt::record(hg_ok_, #c, __FILE__, __LINE__);       \
        if (!hg_ok_) throw hgt::AbortTest{};               \
    } while (0)
#define SKIP(why) throw hgt::SkipTest{why}
#define NOTE(text) hgt::ctx().notes.push_back(text)

// ---- helpers ----

// A throwaway folder that is removed when the test ends. Tests only ever touch files inside it.
class Sandbox {
public:
    Sandbox();
    ~Sandbox();
    Sandbox(const Sandbox&) = delete;
    Sandbox& operator=(const Sandbox&) = delete;
    fs::path root;
    fs::path operator/(const std::string& rel) const { return root / hem::guard::from_u8(rel); }
};

fs::path write_file(const fs::path& p, std::string_view content);
std::string slurp(const fs::path& p);
void age_file(const fs::path& p, int hours);  // pretend the file was last changed `hours` ago
std::string random_bytes(std::size_t n, unsigned seed);
// One SHA-256 over every path, size and content below `dir` (empty folders too). `skip` folders are left out.
std::string tree_fingerprint(const fs::path& dir, const std::vector<fs::path>& skip = {});
bool can_make_symlink(const fs::path& scratch_dir);
std::string eicar_string();  // built from pieces at run time, so this source file is not itself flagged

}  // namespace hgt
