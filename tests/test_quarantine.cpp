#include <fstream>

#include "hem_guard/quarantine.hpp"
#include "test_support.hpp"

using namespace hem::guard;

namespace {
std::string fake_pe() {
    std::string s(512, '\0');
    s[0] = 'M';
    s[1] = 'Z';
    s[0x3C] = static_cast<char>(0x80);
    s[0x80] = 'P';
    s[0x81] = 'E';
    return s;
}
}  // namespace

HG_TEST(quarantine, round_trip_is_byte_for_byte_on_a_big_binary_file) {
    hgt::Sandbox sb;
    const std::string content = hgt::random_bytes(2'600'000, 99);  // crosses several 1 MB reads
    const fs::path f = hgt::write_file(sb / "work/thing.bin", content);
    Quarantine q(sb / "Q");
    std::string id, err;
    REQUIRE(q.quarantine_file(f, "test", id, err));
    CHECK(!fs::exists(f));  // it left its original place
    REQUIRE(q.restore(id, err));
    CHECK_EQ(hgt::slurp(f), content);
    CHECK_EQ(sha256_hex(hgt::slurp(f)), sha256_hex(content));
}

HG_TEST(quarantine, stored_copy_is_renamed_and_cannot_run) {
    hgt::Sandbox sb;
    const std::string program = fake_pe();
    const fs::path f = hgt::write_file(sb / "evil.exe", program);
    Quarantine q(sb / "Q");
    std::string id, err;
    REQUIRE(q.quarantine_file(f, "test", id, err));
    const fs::path payload = q.payload_path(id);
    CHECK(fs::exists(payload));
    CHECK_EQ(payload.extension().string(), std::string(".hgq"));       // renamed
    const std::string stored = hgt::slurp(payload);
    CHECK(stored.size() == program.size() + 16);
    CHECK(stored.substr(0, 2) != "MZ");                                // no longer starts like a program
    CHECK(stored.find("PE") != 0);
    CHECK(stored.find(program.substr(0, 64)) == std::string::npos);    // original bytes are not sitting in there
    // And nothing in the quarantine folder has a runnable name.
    for (const auto& e : fs::directory_iterator(sb / "Q")) {
        const auto ext = to_lower_ascii(e.path().extension().string());
        CHECK(ext != ".exe" && ext != ".dll" && ext != ".bat" && ext != ".cmd" && ext != ".scr");
    }
}

HG_TEST(quarantine, log_remembers_where_each_file_came_from) {
    hgt::Sandbox sb;
    const fs::path f = hgt::write_file(sb / "über ñ 日本/naïve file.dat", "some content");
    Quarantine q(sb / "Q");
    std::string id, err;
    REQUIRE(q.quarantine_file(f, "Pretend.Bad: reason with\ttab", id, err));
    const auto list = q.list();
    REQUIRE(list.size() == 1);
    CHECK_EQ(list[0].id, id);
    CHECK(list[0].active);
    CHECK(list[0].original == f);
    CHECK_EQ(list[0].size, static_cast<std::uint64_t>(12));
    CHECK_EQ(list[0].sha256, sha256_hex("some content"));
    CHECK_EQ(list[0].reason, std::string("Pretend.Bad: reason with\ttab"));
    REQUIRE(q.restore(id, err));
    CHECK_EQ(hgt::slurp(f), std::string("some content"));
    const auto after = q.list();
    REQUIRE(after.size() == 1);
    CHECK(!after[0].active);
    CHECK(!fs::exists(q.payload_path(id)));  // payload tidied away after a good restore
}

HG_TEST(quarantine, restore_never_overwrites_a_file_that_is_there_now) {
    hgt::Sandbox sb;
    const fs::path f = hgt::write_file(sb / "a.dat", "original");
    Quarantine q(sb / "Q");
    std::string id, err;
    REQUIRE(q.quarantine_file(f, "t", id, err));
    hgt::write_file(f, "someone made a new file here");
    CHECK(!q.restore(id, err));
    CHECK(!err.empty());
    CHECK_EQ(hgt::slurp(f), std::string("someone made a new file here"));
    CHECK(q.list()[0].active);  // still safely in quarantine
    // Restoring somewhere else still works.
    const fs::path other = sb / "elsewhere/a.dat";
    REQUIRE(q.restore(id, err, &other));
    CHECK_EQ(hgt::slurp(other), std::string("original"));
}

HG_TEST(quarantine, a_damaged_stored_file_is_never_restored) {
    hgt::Sandbox sb;
    const fs::path f = hgt::write_file(sb / "a.dat", "precious original bytes");
    Quarantine q(sb / "Q");
    std::string id, err;
    REQUIRE(q.quarantine_file(f, "t", id, err));
    {
        // Flip one byte inside the stored copy.
        std::fstream fh(q.payload_path(id), std::ios::in | std::ios::out | std::ios::binary);
        fh.seekp(20);
        fh.put('Z');
    }
    CHECK(!q.restore(id, err));
    CHECK(err.find("SHA-256") != std::string::npos);
    CHECK(!fs::exists(f));  // nothing half-restored was left behind
    bool leftovers = false;
    for (const auto& e : fs::directory_iterator(sb.root)) {
        if (e.path().filename().string().find("restoring") != std::string::npos) leftovers = true;
    }
    CHECK(!leftovers);
    CHECK(q.list()[0].active);
}

HG_TEST(quarantine, unknown_ids_and_double_restores_fail_cleanly) {
    hgt::Sandbox sb;
    Quarantine q(sb / "Q");
    std::string err;
    CHECK(!q.restore("0123456789ab", err));
    const fs::path f = hgt::write_file(sb / "a.dat", "x");
    std::string id;
    REQUIRE(q.quarantine_file(f, "t", id, err));
    REQUIRE(q.restore(id, err));
    CHECK(!q.restore(id, err));  // already restored
}

HG_TEST(quarantine, refuses_folders_missing_files_and_its_own_contents) {
    hgt::Sandbox sb;
    Quarantine q(sb / "Q");
    std::string id, err;
    fs::create_directories(sb / "somefolder");
    CHECK(!q.quarantine_file(sb / "somefolder", "t", id, err));
    CHECK(fs::exists(sb / "somefolder"));
    CHECK(!q.quarantine_file(sb / "nothing-here.dat", "t", id, err));
    const fs::path f = hgt::write_file(sb / "a.dat", "x");
    REQUIRE(q.quarantine_file(f, "t", id, err));
    CHECK(!q.quarantine_file(q.payload_path(id), "t", id, err));  // cannot quarantine the quarantine
    CHECK(fs::exists(q.payload_path(id)));
}

HG_TEST(quarantine, links_are_refused_and_the_target_is_untouched) {
    hgt::Sandbox sb;
    if (!hgt::can_make_symlink(sb.root)) SKIP("this machine does not allow making symbolic links");
    const fs::path real = hgt::write_file(sb / "real.dat", "real content");
    std::error_code ec;
    fs::create_symlink(real, sb / "link.dat", ec);
    REQUIRE(!ec);
    Quarantine q(sb / "Q");
    std::string id, err;
    CHECK(!q.quarantine_file(sb / "link.dat", "t", id, err));
    CHECK_EQ(hgt::slurp(real), std::string("real content"));
}

HG_TEST(quarantine, empty_file_round_trip) {
    hgt::Sandbox sb;
    const fs::path f = hgt::write_file(sb / "empty.dat", "");
    Quarantine q(sb / "Q");
    std::string id, err;
    REQUIRE(q.quarantine_file(f, "t", id, err));
    REQUIRE(q.restore(id, err));
    CHECK(fs::exists(f));
    CHECK_EQ(fs::file_size(f), static_cast<std::uintmax_t>(0));
}
