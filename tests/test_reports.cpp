#include <algorithm>

#include "hem_guard/reports.hpp"
#include "test_support.hpp"

using namespace hem::guard;

HG_TEST(duplicates, finds_exact_copies_and_ignores_look_alikes) {
    hgt::Sandbox sb;
    const std::string a = hgt::random_bytes(5000, 1);
    std::string almost = a;
    almost[2500] ^= 0x01;  // same size, one bit different
    hgt::write_file(sb / "x/a1.bin", a);
    hgt::write_file(sb / "y/a2.bin", a);
    hgt::write_file(sb / "z/a3.bin", a);
    hgt::write_file(sb / "x/almost.bin", almost);
    hgt::write_file(sb / "x/unique.bin", hgt::random_bytes(7000, 2));
    hgt::write_file(sb / "x/tiny1.txt", "tiny");
    hgt::write_file(sb / "x/tiny2.txt", "tiny");

    const auto rep = find_duplicates(sb.root, 1024);
    REQUIRE(rep.groups.size() == 1);
    CHECK_EQ(rep.groups[0].paths.size(), static_cast<std::size_t>(3));
    CHECK_EQ(rep.groups[0].size, static_cast<std::uint64_t>(5000));
    CHECK_EQ(rep.groups[0].sha256, sha256_hex(a));
    CHECK_EQ(rep.groups[0].wasted_bytes(), static_cast<std::uint64_t>(10000));
    CHECK_EQ(rep.total_wasted, static_cast<std::uint64_t>(10000));
    CHECK_EQ(rep.files_hashed, static_cast<std::uint64_t>(4));  // a1 a2 a3 almost; the lone-size file was never even hashed
    // Tiny files below the limit are ignored; lower the limit and they show up.
    CHECK_EQ(find_duplicates(sb.root, 1).groups.size(), static_cast<std::size_t>(2));
}

HG_TEST(duplicates, report_only_nothing_is_deleted_or_changed) {
    hgt::Sandbox sb;
    const std::string a = hgt::random_bytes(4000, 5);
    hgt::write_file(sb / "one/a.bin", a);
    hgt::write_file(sb / "two/a.bin", a);
    const std::string before = hgt::tree_fingerprint(sb.root);
    const auto rep = find_duplicates(sb.root, 1);
    CHECK_EQ(rep.groups.size(), static_cast<std::size_t>(1));
    CHECK_EQ(hgt::tree_fingerprint(sb.root), before);
}

HG_TEST(duplicates, biggest_waste_first) {
    hgt::Sandbox sb;
    const std::string small = hgt::random_bytes(2000, 1), big = hgt::random_bytes(9000, 2);
    hgt::write_file(sb / "s1", small);
    hgt::write_file(sb / "s2", small);
    hgt::write_file(sb / "b1", big);
    hgt::write_file(sb / "b2", big);
    const auto rep = find_duplicates(sb.root, 1);
    REQUIRE(rep.groups.size() == 2);
    CHECK(rep.groups[0].wasted_bytes() > rep.groups[1].wasted_bytes());
    CHECK_EQ(rep.groups[0].size, static_cast<std::uint64_t>(9000));
}

HG_TEST(storage, folder_sizes_type_totals_and_biggest_files_are_right) {
    hgt::Sandbox sb;
    hgt::write_file(sb / "music/a.wav", std::string(5000, 'a'));
    hgt::write_file(sb / "music/b.wav", std::string(3000, 'b'));
    hgt::write_file(sb / "music/deep/c.mp3", std::string(1000, 'c'));
    hgt::write_file(sb / "docs/d.txt", std::string(200, 'd'));
    hgt::write_file(sb / "docs/README", std::string(50, 'e'));
    hgt::write_file(sb / "root.txt", std::string(10, 'f'));

    const auto rep = storage_report(sb.root, 3, 10);
    CHECK_EQ(rep.total_bytes, static_cast<std::uint64_t>(9260));
    CHECK_EQ(rep.total_files, static_cast<std::uint64_t>(6));

    REQUIRE(!rep.folders.empty());
    CHECK(rep.folders[0].path == sb / "music");
    CHECK_EQ(rep.folders[0].bytes, static_cast<std::uint64_t>(9000));
    CHECK_EQ(rep.folders[0].files, static_cast<std::uint64_t>(3));
    bool docs_ok = false, deep_ok = false;
    for (const auto& f : rep.folders) {
        if (f.path == sb / "docs") docs_ok = f.bytes == 250;
        if (f.path == sb / "music/deep") deep_ok = f.bytes == 1000;
    }
    CHECK(docs_ok);
    CHECK(deep_ok);

    REQUIRE(rep.types.size() == 4);
    CHECK_EQ(rep.types[0].ext, std::string(".wav"));
    CHECK_EQ(rep.types[0].bytes, static_cast<std::uint64_t>(8000));
    CHECK_EQ(rep.types[0].files, static_cast<std::uint64_t>(2));
    bool none_ok = false;
    for (const auto& t : rep.types) {
        if (t.ext == "(none)") none_ok = t.bytes == 50;
    }
    CHECK(none_ok);

    REQUIRE(rep.biggest_files.size() == 6);
    CHECK(rep.biggest_files[0].path.filename() == "a.wav");
    CHECK_EQ(rep.biggest_files[0].bytes, static_cast<std::uint64_t>(5000));
}

HG_TEST(storage, depth_limit_and_top_n_are_respected_and_it_is_read_only) {
    hgt::Sandbox sb;
    hgt::write_file(sb / "a/b/c/d/e/f.dat", std::string(100, 'x'));
    for (int i = 0; i < 30; ++i) hgt::write_file(sb / ("many/f" + std::to_string(i) + ".dat"), std::string(10 + i, 'y'));
    const std::string before = hgt::tree_fingerprint(sb.root);
    const auto rep = storage_report(sb.root, 2, 5);
    for (const auto& f : rep.folders) {
        const auto rel = f.path.lexically_relative(sb.root);
        std::size_t depth = 0;
        for (const auto& part : rel) {
            (void)part;
            ++depth;
        }
        CHECK(depth <= 2);
    }
    CHECK(rep.folders.size() <= 5);
    CHECK(rep.biggest_files.size() <= 5);
    CHECK_EQ(hgt::tree_fingerprint(sb.root), before);
}

HG_TEST(storage, empty_and_missing_folders) {
    hgt::Sandbox sb;
    CHECK_EQ(storage_report(sb.root).total_bytes, static_cast<std::uint64_t>(0));
    CHECK_EQ(storage_report(sb / "missing").total_files, static_cast<std::uint64_t>(0));
}
