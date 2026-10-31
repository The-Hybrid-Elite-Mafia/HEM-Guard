# HEM Guard

A small, honest Windows scan-and-cleanup tool. Pure C++20, no outside libraries, no kernel driver.

* `core/` - the engine library (`hem_guard_core`): scanner, quarantine, cleaner with undo, duplicate finder, storage report, startup manager.
* `cli/` - thin command-line tool (`hem_guard_cli`).
* `tests/` - automated unit and safety tests. Run on a GitHub Actions Windows runner.
* `core/include/hem_guard/config.hpp` - every guess in one file, labelled `SPEC` / `ASSUMED` / `UNKNOWN`.
* `docs/GUIDE.txt` - the plain-words guide. `docs/HONEST-REPORT.md` - what is tested, assumed and unknown.

Not an antivirus replacement. No live protection. See the guide.
