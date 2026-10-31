#include <algorithm>

#include "hem_guard/quarantine.hpp"
#include "hem_guard/scanner.hpp"
#include "test_support.hpp"

using namespace hem::guard;

namespace {

RuleSet rules_from(std::initializer_list<const char*> lines) {
    RuleSet rs;
    for (const char* l : lines) {
        std::string err;
        if (!rs.add_line(l, err)) throw std::runtime_error(std::string("bad test rule: ") + l + " : " + err);
    }
    return rs;
}

std::string eicar_rule_line() {
    const std::string e = hgt::eicar_string();
    return "EICAR.Test | high | hex | " + hex_encode(reinterpret_cast<const std::uint8_t*>(e.data()), e.size());
}

bool has_kind(const ScanReport& r, FindingKind k) {
    return std::any_of(r.findings.begin(), r.findings.end(), [&](const Finding& f) { return f.kind == k; });
}

// A 256-byte stand-in with the shape of a Windows program header: "MZ", header offset 0x80, "PE\0\0" there.
std::string fake_pe() {
    std::string s(256, '\0');
    s[0] = 'M';
    s[1] = 'Z';
    s[0x3C] = static_cast<char>(0x80);
    s[0x80] = 'P';
    s[0x81] = 'E';
    return s;
}

ScanOptions fast_opts() {
    ScanOptions o;
    o.cpu_share = 1.0;  // tests do not need to be slowed down
    return o;
}

}  // namespace

// ------------------------------------------------------------ rule engine --

HG_TEST(scanner, finds_byte_pattern_in_memory) {
    const RuleSet rs = rules_from({"Hex.Test | high | hex | de ad be ef 01 02"});
    const std::string data = std::string("xxxx") + std::string("\xde\xad\xbe\xef\x01\x02", 6) + "yyyy";
    CHECK_EQ(scan_buffer(reinterpret_cast<const std::uint8_t*>(data.data()), data.size(), rs).size(), static_cast<std::size_t>(1));
    const std::string clean = "nothing to see here";
    CHECK(scan_buffer(reinterpret_cast<const std::uint8_t*>(clean.data()), clean.size(), rs).empty());
}

HG_TEST(scanner, eicar_test_string_detected_in_memory) {
    RuleSet rs;
    std::string err;
    REQUIRE(rs.add_line(eicar_rule_line(), err));
    const std::string e = hgt::eicar_string();
    CHECK_EQ(e.size(), static_cast<std::size_t>(68));  // the official EICAR string is 68 bytes
    const auto f = scan_buffer(reinterpret_cast<const std::uint8_t*>(e.data()), e.size(), rs);
    REQUIRE(f.size() == 1);
    CHECK_EQ(f[0].rule, std::string("EICAR.Test"));
}

HG_TEST(scanner, shipped_rules_file_loads_and_catches_eicar) {
    RuleSet rs;
    std::vector<std::string> errors;
    const fs::path file = fs::path(HEM_GUARD_SOURCE_DIR) / "rules" / "hem_rules.txt";
    REQUIRE(rs.load_file(file, errors));
    CHECK(errors.empty());
    CHECK(rs.rules().size() >= 2);
    const std::string e = hgt::eicar_string();
    CHECK(!scan_buffer(reinterpret_cast<const std::uint8_t*>(e.data()), e.size(), rs).empty());
    HashList hl;
    CHECK(hl.load_file(fs::path(HEM_GUARD_SOURCE_DIR) / "rules" / "hem_known_bad_hashes.txt", errors));
    CHECK(errors.empty());
}

HG_TEST(scanner, eicar_file_on_disk_is_detected) {
    hgt::Sandbox sb;
    RuleSet rs;
    std::string err;
    REQUIRE(rs.add_line(eicar_rule_line(), err));
    const fs::path f = hgt::write_file(sb / "eicar.com.txt", hgt::eicar_string());
    // Security software may remove the harmless test file the moment it is written. That is it doing its job.
    std::error_code ec;
    if (!fs::exists(f, ec) || fs::file_size(f, ec) != 68) SKIP("security software removed the EICAR test file before we could scan it");
    ScanOptions o = fast_opts();
    o.rules = &rs;
    const auto rep = scan_path(sb.root, o);
    CHECK(has_kind(rep, FindingKind::PatternRule));
}

HG_TEST(scanner, harmless_marker_file_detected_with_surrounding_bytes) {
    hgt::Sandbox sb;
    const RuleSet rs = rules_from({"HEM.Demo.Marker | high | text | HEM-GUARD-DEMO-MARKER-0001"});
    hgt::write_file(sb / "x/marker.dat", "junk junk HEM-GUARD-DEMO-MARKER-0001 more junk");
    hgt::write_file(sb / "x/clean.dat", "perfectly ordinary data");
    ScanOptions o = fast_opts();
    o.rules = &rs;
    const auto rep = scan_path(sb.root, o);
    REQUIRE(rep.findings.size() == 1);
    CHECK(rep.findings[0].path.filename() == "marker.dat");
    CHECK(rep.findings[0].kind == FindingKind::PatternRule);
    CHECK(rep.findings[0].severity == Severity::High);
    CHECK_EQ(rep.files_scanned, static_cast<std::uint64_t>(2));
}

HG_TEST(scanner, known_bad_hash_detected_and_clean_file_left_alone) {
    hgt::Sandbox sb;
    const std::string bad = "pretend this is a known bad file";
    hgt::write_file(sb / "bad.bin", bad);
    hgt::write_file(sb / "good.bin", "a perfectly fine file");
    HashList hl;
    hl.add(sha256_hex(bad), "Pretend.Bad");
    ScanOptions o = fast_opts();
    o.hashes = &hl;
    const auto rep = scan_path(sb.root, o);
    REQUIRE(rep.findings.size() == 1);
    CHECK(rep.findings[0].kind == FindingKind::KnownBadHash);
    CHECK_EQ(rep.findings[0].rule, std::string("Pretend.Bad"));
    CHECK_EQ(rep.findings[0].sha256, sha256_hex(bad));
}

HG_TEST(scanner, pattern_split_across_two_reads_is_still_found_at_every_offset) {
    // The scanner reads in chunks. A pattern that straddles a chunk edge must not slip through.
    const std::string pat = "SPLIT-PATTERN-0123456789";  // 24 bytes
    const RuleSet rs = rules_from({"Split.Test | high | text | SPLIT-PATTERN-0123456789"});
    hgt::Sandbox sb;
    int found = 0, total = 0;
    for (std::size_t off = 0; off <= 200; ++off) {
        std::string data(off, 'a');
        data += pat;
        data += std::string(100, 'b');
        const fs::path f = hgt::write_file(sb / "one.dat", data);
        ScanOptions o = fast_opts();
        o.rules = &rs;
        o.chunk_bytes = 64;  // tiny chunks on purpose
        const auto rep = scan_path(f, o);
        ++total;
        if (rep.findings.size() == 1) ++found;
    }
    NOTE(std::to_string(found) + " of " + std::to_string(total) + " placements found (64-byte reads)");
    CHECK_EQ(found, total);
}

HG_TEST(scanner, a_pattern_found_many_times_is_reported_once_per_file) {
    hgt::Sandbox sb;
    const RuleSet rs = rules_from({"Rep.Test | high | text | REPEATED-PATTERN"});
    std::string data;
    for (int i = 0; i < 50; ++i) data += "REPEATED-PATTERN--";
    hgt::write_file(sb / "r.dat", data);
    ScanOptions o = fast_opts();
    o.rules = &rs;
    o.chunk_bytes = 64;
    CHECK_EQ(scan_path(sb.root, o).findings.size(), static_cast<std::size_t>(1));
}

// ---------------------------------------------------------- warning signs --

HG_TEST(warnings, double_extension_in_downloads_is_medium) {
    hgt::Sandbox sb;
    hgt::write_file(sb / "Downloads/invoice.pdf.exe", "not really a program");
    ScanOptions o = fast_opts();
    o.risky_dirs = {sb / "Downloads"};
    const auto rep = scan_path(sb.root, o);
    REQUIRE(rep.findings.size() == 1);
    CHECK(rep.findings[0].kind == FindingKind::WarningSign);
    CHECK_EQ(rep.findings[0].score, cfg::kPointsExecInRiskyDir + cfg::kPointsDoubleExtension);
    CHECK(rep.findings[0].severity == Severity::Medium);
}

HG_TEST(warnings, plain_program_in_downloads_is_only_low) {
    hgt::Sandbox sb;
    hgt::write_file(sb / "Downloads/setup.exe", "xx");
    ScanOptions o = fast_opts();
    o.risky_dirs = {sb / "Downloads"};
    const auto rep = scan_path(sb.root, o);
    REQUIRE(rep.findings.size() == 1);
    CHECK(rep.findings[0].severity == Severity::Low);
}

HG_TEST(warnings, same_program_in_a_normal_folder_is_not_flagged) {
    hgt::Sandbox sb;
    hgt::write_file(sb / "Apps/tool.exe", "xx");
    ScanOptions o = fast_opts();
    o.risky_dirs = {sb / "Downloads"};
    CHECK(scan_path(sb.root, o).findings.empty());
}

HG_TEST(warnings, program_hiding_behind_a_picture_name) {
    hgt::Sandbox sb;
    hgt::write_file(sb / "photo.jpg", fake_pe());                                  // a program wearing a picture's name
    hgt::write_file(sb / "real_photo.jpg", std::string("\xff\xd8\xff\xe0", 4) + "JFIF");
    hgt::write_file(sb / "notes.txt", "MZ is just two letters, and this is a plain text file");  // must NOT be flagged
    const auto rep = scan_path(sb.root, fast_opts());
    REQUIRE(rep.findings.size() == 1);
    CHECK(rep.findings[0].path.filename() == "photo.jpg");
    CHECK_EQ(rep.findings[0].score, cfg::kPointsDisguisedExecutable);
}

HG_TEST(warnings, unsigned_program_in_startup_folder_uses_the_signature_check) {
    hgt::Sandbox sb;
    hgt::write_file(sb / "Startup/helper.exe", "xx");
    ScanOptions o = fast_opts();
    o.startup_dirs = {sb / "Startup"};

    o.signature_fn = [](const fs::path&) { return SignState::Unsigned; };
    auto rep = scan_path(sb.root, o);
    REQUIRE(rep.findings.size() == 1);
    CHECK_EQ(rep.findings[0].score, cfg::kPointsUnsignedInStartup);

    o.signature_fn = [](const fs::path&) { return SignState::Signed; };
    CHECK(scan_path(sb.root, o).findings.empty());

    o.signature_fn = [](const fs::path&) { return SignState::Unknown; };  // could not check: never accuse
    CHECK(scan_path(sb.root, o).findings.empty());
}

HG_TEST(warnings, program_named_by_a_startup_entry_is_checked_too) {
    hgt::Sandbox sb;
    const fs::path p = hgt::write_file(sb / "Apps/updater.exe", "xx");
    ScanOptions o = fast_opts();
    o.startup_files.insert(startup_key(p));
    o.signature_fn = [](const fs::path&) { return SignState::Unsigned; };
    CHECK_EQ(scan_path(sb.root, o).findings.size(), static_cast<std::size_t>(1));
}

HG_TEST(warnings, several_signs_add_up_to_high) {
    hgt::Sandbox sb;
    hgt::write_file(sb / "Temp/Startup/report.pdf.exe", "xx");  // risky dir + double ext + unsigned startup
    ScanOptions o = fast_opts();
    o.risky_dirs = {sb / "Temp"};
    o.startup_dirs = {sb / "Temp/Startup"};
    o.signature_fn = [](const fs::path&) { return SignState::Unsigned; };
    const auto rep = scan_path(sb.root, o);
    REQUIRE(rep.findings.size() == 1);
    CHECK(rep.findings[0].severity == Severity::High);
    CHECK(rep.findings[0].score >= cfg::kScoreHighFrom);
}

// ----------------------------------------------------------------- safety --

HG_TEST(scanner_safety, scanning_never_changes_a_single_file) {
    hgt::Sandbox sb;
    const RuleSet rs = rules_from({"HEM.Demo.Marker | high | text | HEM-GUARD-DEMO-MARKER-0001"});
    hgt::write_file(sb / "a/marker.dat", "HEM-GUARD-DEMO-MARKER-0001");
    hgt::write_file(sb / "a/Downloads/invoice.pdf.exe", "xx");
    hgt::write_file(sb / "b/clean.txt", "hello");
    HashList hl;
    hl.add(sha256_hex("hello"), "Pretend.Bad");
    const std::string before = hgt::tree_fingerprint(sb.root);
    ScanOptions o = fast_opts();
    o.rules = &rs;
    o.hashes = &hl;
    o.risky_dirs = {sb / "a/Downloads"};
    const auto rep = scan_path(sb.root, o);
    CHECK(rep.findings.size() >= 3);  // it really did find things...
    CHECK_EQ(hgt::tree_fingerprint(sb.root), before);  // ...and changed nothing
}

HG_TEST(scanner_safety, skip_roots_are_not_scanned) {
    hgt::Sandbox sb;
    const RuleSet rs = rules_from({"HEM.Demo.Marker | high | text | HEM-GUARD-DEMO-MARKER-0001"});
    hgt::write_file(sb / "quarantine/old.dat", "HEM-GUARD-DEMO-MARKER-0001");
    hgt::write_file(sb / "other/new.dat", "HEM-GUARD-DEMO-MARKER-0001");
    ScanOptions o = fast_opts();
    o.rules = &rs;
    o.skip_roots = {sb / "quarantine"};
    const auto rep = scan_path(sb.root, o);
    REQUIRE(rep.findings.size() == 1);
    CHECK(rep.findings[0].path.filename() == "new.dat");
}

HG_TEST(scanner_safety, files_over_the_size_limit_are_skipped_and_counted) {
    hgt::Sandbox sb;
    const RuleSet rs = rules_from({"HEM.Demo.Marker | high | text | HEM-GUARD-DEMO-MARKER-0001"});
    hgt::write_file(sb / "big.dat", "HEM-GUARD-DEMO-MARKER-0001" + std::string(200, 'x'));
    ScanOptions o = fast_opts();
    o.rules = &rs;
    o.max_file_bytes = 100;
    const auto rep = scan_path(sb.root, o);
    CHECK_EQ(rep.files_too_big, static_cast<std::uint64_t>(1));
    CHECK(rep.findings.empty());  // honest: a file we did not read cannot be called clean OR bad
}

HG_TEST(scanner_safety, links_are_not_followed) {
    hgt::Sandbox sb;
    if (!hgt::can_make_symlink(sb.root)) SKIP("this machine does not allow making symbolic links");
    const RuleSet rs = rules_from({"HEM.Demo.Marker | high | text | HEM-GUARD-DEMO-MARKER-0001"});
    hgt::write_file(sb / "outside/marker.dat", "HEM-GUARD-DEMO-MARKER-0001");
    std::error_code ec;
    fs::create_directories(sb / "scanme", ec);
    fs::create_directory_symlink(sb / "outside", sb / "scanme/link", ec);
    REQUIRE(!ec);
    ScanOptions o = fast_opts();
    o.rules = &rs;
    const auto rep = scan_path(sb / "scanme", o);
    CHECK(rep.findings.empty());
}

HG_TEST(scanner_safety, unreadable_and_missing_paths_do_not_crash) {
    hgt::Sandbox sb;
    ScanOptions o = fast_opts();
    const auto rep = scan_path(sb / "does-not-exist", o);
    CHECK(rep.findings.empty());
    CHECK_EQ(rep.files_seen, static_cast<std::uint64_t>(0));
}

// --------------------------------------------------- scan -> quarantine flow --

HG_TEST(scan_and_quarantine, found_file_is_isolated_then_restored_exactly) {
    hgt::Sandbox sb;
    const RuleSet rs = rules_from({"HEM.Demo.Marker | high | text | HEM-GUARD-DEMO-MARKER-0001"});
    const std::string content = "payload " + hgt::random_bytes(5000, 11) + "HEM-GUARD-DEMO-MARKER-0001";
    const fs::path bad = hgt::write_file(sb / "stuff/evil.dat", content);
    hgt::write_file(sb / "stuff/fine.dat", "fine");

    ScanOptions o = fast_opts();
    o.rules = &rs;
    o.skip_roots = {sb / "Q"};
    auto rep = scan_path(sb.root, o);
    REQUIRE(rep.findings.size() == 1);

    Quarantine q(sb / "Q");
    std::string id, err;
    REQUIRE(q.quarantine_file(rep.findings[0].path, rep.findings[0].rule, id, err));
    CHECK(!fs::exists(bad));
    CHECK(scan_path(sb.root, o).findings.empty());  // nothing bad left in the scanned area

    REQUIRE(q.restore(id, err));
    CHECK_EQ(hgt::slurp(bad), content);
}

// --------------------------------------------------------------- CPU limit --

HG_TEST(scanner_cpu, scan_stays_under_its_cpu_share_limit) {
    hgt::Sandbox sb;
    const RuleSet rs = rules_from({"Hex.Test | high | hex | de ad be ef 01 02 03 04"});
    HashList hl;
    hl.add(sha256_hex("not any file here"), "x");
    // About 38 MB of pseudo-random files, spread over 20 folders.
    for (int i = 0; i < 1200; ++i) {
        hgt::write_file(sb / ("d" + std::to_string(i % 20) + "/f" + std::to_string(i) + ".bin"),
                        hgt::random_bytes(32 * 1024, static_cast<unsigned>(i)));
    }
    ScanOptions free_run;
    free_run.rules = &rs;
    free_run.hashes = &hl;
    free_run.cpu_share = 1.0;  // no limit
    ScanOptions limited = free_run;
    limited.cpu_share = 0.5;

    scan_path(sb.root, free_run);  // warm-up, so both timed runs read from the same cache state
    const auto a = scan_path(sb.root, free_run);
    const auto b = scan_path(sb.root, limited);

    char buf[256];
    std::snprintf(buf, sizeof buf,
                  "no limit: busy %.0f%% of the time (OS CPU counter %.0f%%) in %.2f s | limit 50%%: busy %.0f%% (OS CPU counter %.0f%%, coarse) in %.2f s (%llu files, %s)",
                  a.busy_share * 100, a.cpu_share_used * 100, a.wall_seconds, b.busy_share * 100, b.cpu_share_used * 100, b.wall_seconds,
                  static_cast<unsigned long long>(b.files_scanned), format_bytes(b.bytes_read).c_str());
    NOTE(buf);
    CHECK_EQ(a.files_scanned, static_cast<std::uint64_t>(1200));
    CHECK_EQ(b.files_scanned, static_cast<std::uint64_t>(1200));
    // The limiter is judged by how much of the time the scan was awake (precise clock). The operating system's own
    // CPU counter is coarse (it can read far too high when a program sleeps in short slices on a busy shared machine),
    // so it is reported in the note but not used as a pass/fail test.
    CHECK(b.busy_share <= cfg::kScanCpuShareMax + 0.15);
    CHECK(a.busy_share > 0.9);  // and with no limit it really does run flat out
    CHECK(b.wall_seconds > a.wall_seconds);                   // the limiter really did slow the scan down
}
