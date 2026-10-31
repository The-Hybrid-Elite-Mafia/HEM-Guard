#include "hem_guard/undo_store.hpp"

#include <algorithm>
#include <cctype>

namespace hem::guard {

namespace {

struct Item {
    std::string stored;
    std::uint64_t size = 0;
    fs::path original;
};

std::string item_line(const Item& i) {
    return i.stored + "\t" + std::to_string(i.size) + "\t" + tsv_escape(to_u8(i.original)) + "\n";
}

std::vector<Item> read_items(const fs::path& file) {
    std::vector<Item> v;
    std::string text;
    if (!read_text_file(file, text)) return v;
    for (const auto& line : split(text, '\n')) {
        if (line.empty()) continue;
        const auto f = split(line, '\t');
        if (f.size() < 3) continue;
        Item it;
        it.stored = f[0];
        try {
            it.size = std::stoull(f[1]);
        } catch (...) {
            continue;
        }
        it.original = from_u8(tsv_unescape(f[2]));
        // A stored name is only ever random hex + ".bin". Anything else is a tampered manifest.
        const bool shape_ok = it.stored.size() > 4 && it.stored.compare(it.stored.size() - 4, 4, ".bin") == 0 &&
                              it.stored.find_first_not_of("0123456789abcdef") == it.stored.size() - 4;
        if (!shape_ok) continue;
        v.push_back(std::move(it));
    }
    return v;
}

bool read_meta(const fs::path& file, std::int64_t& created, int& retention) {
    std::string text;
    if (!read_text_file(file, text)) return false;
    bool a = false, b = false;
    for (const auto& line : split(text, '\n')) {
        const auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        const auto k = trim(line.substr(0, eq));
        const auto val = trim(line.substr(eq + 1));
        try {
            if (k == "created") {
                created = std::stoll(val);
                a = true;
            } else if (k == "retention_days") {
                retention = std::stoi(val);
                b = true;
            }
        } catch (...) {
            return false;
        }
    }
    return a && b;
}

std::string make_batch_id(std::int64_t t) {
    std::string s = format_time_utc(t);  // "YYYY-MM-DD HH:MM:SSZ"
    std::string id;
    for (char c : s) {
        if (std::isdigit(static_cast<unsigned char>(c))) id.push_back(c);
    }
    // 14 digits: YYYYMMDDHHMMSS  ->  YYYYMMDD-HHMMSS-xxxx
    return id.substr(0, 8) + "-" + id.substr(8, 6) + "-" + random_hex(4);
}

}  // namespace

UndoStore::UndoStore(fs::path root, int retention_days) : retention_days_(retention_days), root_(std::move(root)) {}

bool UndoStore::is_batch_id(const std::string& s) {
    // YYYYMMDD-HHMMSS-xxxx
    if (s.size() != 20 || s[8] != '-' || s[15] != '-') return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (i == 8 || i == 15) continue;
        const char c = s[i];
        const bool digit = c >= '0' && c <= '9';
        const bool hex = c >= 'a' && c <= 'f';
        if (i < 15 ? !digit : !(digit || hex)) return false;
    }
    return true;
}

bool UndoStore::begin_batch(std::string& id_out, std::string& error, std::int64_t created) {
    if (created == 0) created = unix_now();
    std::error_code ec;
    fs::create_directories(root_, ec);
    if (ec) {
        error = "cannot create the undo folder: " + ec.message();
        return false;
    }
    const std::string id = make_batch_id(created);
    fs::create_directories(batch_dir(id), ec);
    if (ec) {
        error = "cannot create undo batch: " + ec.message();
        return false;
    }
    const std::string meta = "created=" + std::to_string(created) + "\nretention_days=" + std::to_string(retention_days_) + "\n";
    if (!write_text_file(batch_dir(id) / "batch.meta", meta)) {
        error = "cannot write undo batch info";
        return false;
    }
    id_out = id;
    return true;
}

bool UndoStore::store(const std::string& batch_id, const fs::path& original, std::uint64_t size, std::string& error) {
    if (!is_batch_id(batch_id)) {
        error = "bad batch id";
        return false;
    }
    Item it;
    it.stored = random_hex(16) + ".bin";
    it.size = size;
    it.original = original;
    const fs::path dest = batch_dir(batch_id) / it.stored;
    const fs::path log = batch_dir(batch_id) / "items.tsv";
    // Write the log line FIRST. A crash after this leaves a line pointing at nothing (harmless),
    // never a stored file that nobody knows about.
    if (!append_text_file(log, item_line(it))) {
        error = "cannot write undo log; file was left in place";
        return false;
    }
    if (!move_file_safe(original, dest, error)) {
        // Take our line back out again.
        std::vector<Item> keep;
        for (const auto& x : read_items(log)) {
            if (x.stored != it.stored) keep.push_back(x);
        }
        std::string text;
        for (const auto& x : keep) text += item_line(x);
        write_text_file(log, text);
        return false;
    }
    return true;
}

std::vector<UndoBatchInfo> UndoStore::list_batches() const {
    std::vector<UndoBatchInfo> v;
    std::error_code ec;
    if (!fs::is_directory(root_, ec)) return v;
    for (fs::directory_iterator it(root_, ec), end; !ec && it != end; it.increment(ec)) {
        const std::string name = to_u8(it->path().filename());
        if (!is_batch_id(name)) continue;
        UndoBatchInfo b;
        b.id = name;
        if (!read_meta(it->path() / "batch.meta", b.created, b.retention_days)) continue;
        b.expires = b.created + static_cast<std::int64_t>(b.retention_days) * 86400;
        for (const auto& item : read_items(it->path() / "items.tsv")) {
            ++b.items;
            b.bytes += item.size;
        }
        v.push_back(std::move(b));
    }
    std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.id < b.id; });
    return v;
}

RestoreReport UndoStore::restore_batch(const std::string& id) {
    RestoreReport r;
    if (!is_batch_id(id)) {
        r.messages.push_back("bad batch id");
        ++r.failed;
        return r;
    }
    const fs::path dir = batch_dir(id);
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) {
        r.messages.push_back("no such undo batch");
        ++r.failed;
        return r;
    }
    const auto items = read_items(dir / "items.tsv");
    std::vector<Item> remaining;
    for (const auto& it : items) {
        const fs::path stored = dir / it.stored;
        if (!it.original.is_absolute() || path_is_within(normalize_path(it.original), normalize_path(root_))) {
            ++r.failed;
            r.messages.push_back("not restored, the saved path looks wrong: " + to_u8(it.original));
            remaining.push_back(it);
            continue;
        }
        if (!fs::exists(fs::symlink_status(stored, ec))) {
            ++r.missing;
            r.messages.push_back("missing from undo folder: " + to_u8(it.original));
            continue;  // nothing left to restore; drop it from the log
        }
        if (fs::exists(fs::symlink_status(it.original, ec))) {
            ++r.conflicts;
            r.messages.push_back("not restored, something already exists there: " + to_u8(it.original));
            remaining.push_back(it);
            continue;
        }
        fs::create_directories(it.original.parent_path(), ec);
        std::string err;
        if (move_file_safe(stored, it.original, err)) {
            ++r.restored;
        } else {
            ++r.failed;
            r.messages.push_back("could not restore " + to_u8(it.original) + ": " + err);
            remaining.push_back(it);
        }
    }
    if (remaining.empty()) {
        // Whole batch is back (or gone). Remove only our two bookkeeping files, then the folder IF it is empty.
        // If anything unexpected is still inside, it stays.
        if (path_is_within(normalize_path(dir), normalize_path(root_))) {
            fs::remove(dir / "items.tsv", ec);
            fs::remove(dir / "batch.meta", ec);
            fs::remove(dir, ec);  // not recursive: fails harmlessly if something is left
        }
    } else {
        std::string text;
        for (const auto& it : remaining) text += item_line(it);
        write_text_file(dir / "items.tsv", text);
    }
    return r;
}

RestoreReport UndoStore::restore_latest() {
    const auto b = list_batches();
    if (b.empty()) {
        RestoreReport r;
        r.messages.push_back("there is nothing to undo");
        return r;
    }
    return restore_batch(b.back().id);
}

std::size_t UndoStore::purge_expired(std::int64_t now) {
    if (now == 0) now = unix_now();
    std::size_t removed = 0;
    for (const auto& b : list_batches()) {
        if (now < b.expires) continue;
        const fs::path dir = batch_dir(b.id);
        std::error_code ec;
        // Safety: only a real folder, directly inside our undo root, that carries our own batch.meta.
        if (fs::is_symlink(fs::symlink_status(dir, ec))) continue;
        if (!fs::is_regular_file(dir / "batch.meta", ec)) continue;
        if (!path_is_within(normalize_path(dir), normalize_path(root_))) continue;
        fs::remove_all(dir, ec);
        if (!ec) ++removed;
    }
    return removed;
}

}  // namespace hem::guard
