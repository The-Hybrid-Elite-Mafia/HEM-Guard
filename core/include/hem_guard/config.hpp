// HEM Guard - central config.
//
// Every working guess lives in THIS ONE FILE. Nothing else in the code base
// may hide a magic number.
//
// Labels used on every line:
//   // SPEC     - Steven asked for exactly this.
//   // ASSUMED  - a working guess. Not measured. Change it if reality says so.
//   // UNKNOWN  - we do not know the right answer. No value is claimed.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace hem::guard::cfg {

// ---------------------------------------------------------------- scanner --
inline constexpr double kScanCpuShareMax = 0.50;            // ASSUMED  scan may use at most ~half of one CPU core's time
inline constexpr std::uint64_t kScanMaxFileBytes = 256ull * 1024 * 1024;  // ASSUMED  bigger files are reported as "skipped, too big"
inline constexpr std::size_t kReadChunkBytes = 1024 * 1024; // ASSUMED  1 MB read chunks
inline constexpr std::size_t kMaxPatternBytes = 4096;       // ASSUMED  longest byte pattern a rule may have
inline constexpr std::size_t kMaxWalkDepth = 64;            // ASSUMED  folder depth limit (stops loops and runaway trees)

// Warning-sign points. Score 0 = clean, 1 = low, 2-3 = medium, 4+ = high.
inline constexpr int kPointsExecInRiskyDir = 1;             // ASSUMED  program sitting in Temp / Downloads
inline constexpr int kPointsDoubleExtension = 2;            // ASSUMED  name like invoice.pdf.exe
inline constexpr int kPointsDisguisedExecutable = 2;        // ASSUMED  program body inside a .jpg / .pdf / .txt name
inline constexpr int kPointsUnsignedInStartup = 2;          // ASSUMED  unsigned program in a startup spot
inline constexpr int kScoreMediumFrom = 2;                  // ASSUMED
inline constexpr int kScoreHighFrom = 4;                    // ASSUMED

// Extensions (lower case, with dot).
inline constexpr std::array<std::string_view, 12> kExecutableExts = {  // ASSUMED  not a complete list
    ".exe", ".scr", ".com", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".pif", ".msi", ".hta", ".dll"};
inline constexpr std::array<std::string_view, 17> kDocLikeExts = {     // ASSUMED  names that normally hold data, not programs
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip", ".csv"};

// ------------------------------------------------------------- quarantine --
// The payload is scrambled so it can never run and so other tools do not trip on it.
// This is NOT encryption and gives no secrecy.
inline constexpr std::string_view kQuarantineXorKey = "HEM-GUARD-QUARANTINE-KEY";  // ASSUMED  any fixed key is fine here
inline constexpr std::string_view kQuarantineExt = ".hgq";                       // SPEC     renamed so it cannot run
inline constexpr std::string_view kQuarantineMagic = "HGQ1";                      // ASSUMED  file format tag

// ---------------------------------------------------------------- cleaner --
inline constexpr int kUndoRetentionDays = 7;                // ASSUMED  how long undo copies are kept ("a set number of days" - SPEC)
inline constexpr int kTempMinAgeHours = 24;                 // ASSUMED  temp files newer than this are left alone (an app may be using them)
inline constexpr int kCacheMinAgeHours = 0;                 // ASSUMED  browser / thumbnail caches: no age limit
inline constexpr std::size_t kMaxSkippedListed = 500;       // ASSUMED  how many "skipped" lines a plan remembers

// Folder names whose presence marks a "project folder". The cleaner will not enter one.
inline constexpr std::array<std::string_view, 9> kProjectMarkers = {  // ASSUMED
    ".git", ".hg", ".svn", "CMakeLists.txt", "package.json", "Cargo.toml", "pom.xml", "pyproject.toml", ".vs"};
inline constexpr std::array<std::string_view, 4> kProjectMarkerExts = {  // ASSUMED  matched against file extensions
    ".sln", ".vcxproj", ".csproj", ".als"};

// ------------------------------------------------------------- duplicates --
inline constexpr std::uint64_t kDupMinBytes = 1024;         // ASSUMED  files smaller than this are ignored by the duplicate finder
inline constexpr std::size_t kDupMaxGroupsListed = 200;     // ASSUMED

// ---------------------------------------------------------------- storage --
inline constexpr int kStorageFolderDepth = 3;               // ASSUMED  folder depth the report groups by
inline constexpr std::size_t kStorageTopN = 20;             // ASSUMED

// ---------------------------------------------------------------- startup --
inline constexpr bool kStartupAllowChangingMicrosoftTasks = false;  // ASSUMED  Windows' own scheduled tasks are read-only here
inline constexpr std::string_view kMicrosoftTaskPrefix = "\\Microsoft\\Windows\\";  // ASSUMED

// ---------------------------------------------------------------- UNKNOWN --
// Real-world detection rate on live malware ........ UNKNOWN (never measured; no honest number exists)
// False-positive rate on a real PC .................. UNKNOWN (only tested on fake files)
// Speed on a full multi-terabyte drive ............... UNKNOWN (not measured)
// Browser cache folder layout in future browser versions ... UNKNOWN
// Windows Update cache: safe to clear while an update is half-installed ... UNKNOWN (so it is marked CAREFUL)
// How other security tools react to the scrambled quarantine files ... UNKNOWN
// Behaviour with two copies of HEM Guard running at once ... UNKNOWN (not locked)

}  // namespace hem::guard::cfg
