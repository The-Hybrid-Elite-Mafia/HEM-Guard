#include <thread>

#include "hem_guard/config.hpp"
#include "hem_guard/rules.hpp"
#include "hem_guard/sha256.hpp"
#include "hem_guard/throttle.hpp"
#include "hem_guard/util.hpp"
#include "test_support.hpp"

using namespace hem::guard;

// ---------------------------------------------------------------- SHA-256 --

HG_TEST(sha256, official_test_vectors) {
    CHECK_EQ(sha256_hex(""), std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(sha256_hex("abc"), std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_EQ(sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
             std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
}

HG_TEST(sha256, one_million_a) {
    Sha256 s;
    const std::string chunk(1000, 'a');
    for (int i = 0; i < 1000; ++i) s.update(chunk.data(), chunk.size());
    CHECK_EQ(s.finish_hex(), std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

HG_TEST(sha256, chunking_never_changes_the_answer) {
    const std::string data = hgt::random_bytes(100000, 7);
    const std::string whole = sha256_hex(data);
    for (std::size_t step : {1u, 7u, 63u, 64u, 65u, 1000u}) {
        Sha256 s;
        for (std::size_t i = 0; i < data.size(); i += step) s.update(data.data() + i, std::min<std::size_t>(step, data.size() - i));
        CHECK_EQ(s.finish_hex(), whole);
    }
}

HG_TEST(sha256, file_hash_matches_memory_hash) {
    hgt::Sandbox sb;
    const std::string data = hgt::random_bytes(3 * 1024 * 1024 + 17, 3);
    const auto p = hgt::write_file(sb / "big.bin", data);
    std::string h;
    std::uint64_t n = 0;
    REQUIRE(sha256_file(p, h, &n));
    CHECK_EQ(h, sha256_hex(data));
    CHECK_EQ(n, static_cast<std::uint64_t>(data.size()));
    CHECK(!sha256_file(sb / "nope.bin", h));
}

// ------------------------------------------------------------------- util --

HG_TEST(util, hex_round_trip_and_rejects_junk) {
    std::vector<std::uint8_t> v;
    CHECK(hex_decode("4d 5A 90 00", v));
    CHECK_EQ(v.size(), static_cast<std::size_t>(4));
    CHECK_EQ(hex_encode(v.data(), v.size()), std::string("4d5a9000"));
    CHECK(!hex_decode("4d5", v));    // odd length
    CHECK(!hex_decode("zz", v));     // not hex
    CHECK(!hex_decode("", v));       // empty
}

HG_TEST(util, tsv_escaping_round_trips_nasty_text) {
    const std::string nasty = "a\tb\nc\\d\re\\\\t end";
    CHECK_EQ(tsv_unescape(tsv_escape(nasty)), nasty);
    CHECK(tsv_escape(nasty).find('\t') == std::string::npos);
    CHECK(tsv_escape(nasty).find('\n') == std::string::npos);
}

HG_TEST(util, wildcard_match) {
    CHECK(glob_match("thumbcache_*.db", "thumbcache_96.db"));
    CHECK(glob_match("THUMBCACHE_*.DB", "thumbcache_idx.db"));
    CHECK(!glob_match("thumbcache_*.db", "iconcache_32.db"));
    CHECK(!glob_match("thumbcache_*.db", "thumbcache_96.db.bak"));
    CHECK(glob_match("a?c", "abc"));
    CHECK(!glob_match("a?c", "ac"));
    CHECK(glob_match("*", "anything"));
}

HG_TEST(util, path_is_within_is_exact_about_folder_names) {
    CHECK(path_is_within("/a/b/c", "/a/b"));
    CHECK(path_is_within("/a/b", "/a/b"));
    CHECK(!path_is_within("/a/bc", "/a/b"));        // same prefix letters, different folder
    CHECK(!path_is_within("/a", "/a/b"));
    CHECK(!path_is_within("/a/b/../x", "/a/b"));    // ".." is resolved first
    CHECK(path_is_within("/a/b/../b/c", "/a/b"));
}

HG_TEST(util, windows_argument_quoting) {
    CHECK_EQ(quote_windows_arg("plain"), std::string("plain"));
    CHECK_EQ(quote_windows_arg(""), std::string("\"\""));
    CHECK_EQ(quote_windows_arg("two words"), std::string("\"two words\""));
    CHECK_EQ(quote_windows_arg("say \"hi\""), std::string("\"say \\\"hi\\\"\""));
    CHECK_EQ(quote_windows_arg("C:\\my dir\\"), std::string("\"C:\\my dir\\\\\""));
}

HG_TEST(util, formatting) {
    CHECK_EQ(format_bytes(0), std::string("0 B"));
    CHECK_EQ(format_bytes(1536), std::string("1.5 KB"));
    CHECK_EQ(format_time_utc(0), std::string("1970-01-01 00:00:00Z"));
}

HG_TEST(util, move_file_safe_never_overwrites) {
    hgt::Sandbox sb;
    hgt::write_file(sb / "a.txt", "AAA");
    hgt::write_file(sb / "b.txt", "BBB");
    std::string err;
    CHECK(!move_file_safe(sb / "a.txt", sb / "b.txt", err));
    CHECK_EQ(hgt::slurp(sb / "b.txt"), std::string("BBB"));
    CHECK_EQ(hgt::slurp(sb / "a.txt"), std::string("AAA"));
    CHECK(move_file_safe(sb / "a.txt", sb / "c.txt", err));
    CHECK_EQ(hgt::slurp(sb / "c.txt"), std::string("AAA"));
    CHECK(!std::filesystem::exists(sb / "a.txt"));
}

// ------------------------------------------------------------ rule files --

HG_TEST(rules, good_lines_parse) {
    RuleSet rs;
    std::string err;
    CHECK(rs.add_line("Demo.Marker | high | text | HEM-GUARD-DEMO-MARKER-0001", err));
    CHECK(rs.add_line("Some.Hex | medium | hex | 4d 5a 90 00 03", err));
    CHECK(rs.add_line("# a comment", err));
    CHECK(rs.add_line("   ", err));
    REQUIRE(rs.rules().size() == 2);
    CHECK_EQ(rs.rules()[0].name, std::string("Demo.Marker"));
    CHECK(rs.rules()[0].severity == Severity::High);
    CHECK_EQ(rs.rules()[1].pattern.size(), static_cast<std::size_t>(5));
    CHECK(rs.rules()[1].severity == Severity::Medium);
}

HG_TEST(rules, bad_lines_are_refused_with_a_reason) {
    RuleSet rs;
    std::string err;
    CHECK(!rs.add_line("Only.Two | high", err));
    CHECK(!rs.add_line("X | urgent | text | long enough text", err));
    CHECK(!rs.add_line("X | high | binary | abcdef", err));
    CHECK(!rs.add_line("X | high | hex | 4d zz 90 00", err));
    CHECK(!rs.add_line("X | high | text | ab", err));          // too short: would match far too much
    CHECK(!rs.add_line(" | high | text | long enough text", err));
    CHECK(rs.rules().empty());
}

HG_TEST(rules, hash_list_parsing) {
    HashList hl;
    std::string err;
    const std::string good = sha256_hex("bad file");
    CHECK(hl.add_line(good + "  Evil.Thing", err));
    CHECK(hl.add_line(good.substr(0, 63) + "0", err));
    CHECK(!hl.add_line("not-a-hash", err));
    CHECK(!hl.add_line(good.substr(0, 63), err));           // 63 characters
    CHECK(hl.add_line("# comment", err));
    REQUIRE(hl.find(good) != nullptr);
    CHECK_EQ(*hl.find(good), std::string("Evil.Thing"));
    CHECK(hl.find(sha256_hex("other")) == nullptr);
}

// --------------------------------------------------------------- throttle --

HG_TEST(throttle, sleep_math) {
    CHECK_EQ(throttle_sleep_seconds(1.0, 0.5), 1.0);
    CHECK_EQ(throttle_sleep_seconds(1.0, 0.25), 3.0);
    CHECK_EQ(throttle_sleep_seconds(1.0, 1.0), 0.0);   // no limit
    CHECK_EQ(throttle_sleep_seconds(1.0, 0.0), 0.0);   // nonsense share = no limit
    CHECK_EQ(throttle_sleep_seconds(0.0, 0.5), 0.0);
}

HG_TEST(throttle, really_pauses_in_proportion) {
    CpuThrottle t(0.5);
    std::this_thread::sleep_for(std::chrono::milliseconds(40));  // 40 ms of "work"
    t.tick();
    NOTE("asked to work 40 ms at 50%, paused " + std::to_string(t.total_slept_seconds() * 1000.0) + " ms");
    CHECK(t.total_slept_seconds() >= 0.030);
    CHECK(t.total_slept_seconds() <= 0.200);
}

HG_TEST(throttle, no_limit_never_pauses) {
    CpuThrottle t(1.0);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    t.tick();
    CHECK_EQ(t.total_slept_seconds(), 0.0);
}

// ----------------------------------------------------------------- config --

HG_TEST(config, thresholds_are_in_sensible_order) {
    CHECK(cfg::kScoreMediumFrom < cfg::kScoreHighFrom);
    CHECK(cfg::kScanCpuShareMax > 0.0 && cfg::kScanCpuShareMax <= 1.0);
    CHECK(cfg::kUndoRetentionDays >= 1);
}
