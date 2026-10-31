# HEM Guard 0.1.0 - Honest Report

Written in plain words. Every claim below is labelled **TESTED**, **ASSUMED** or **UNKNOWN**.

## What HEM Guard is

A small Windows tool with four parts: a scanner, a cleaner, a startup manager and a storage report.
Day 1 was the engine plus a command-line tool (double-click `.bat` launchers). Day 2 added the window (Scan, Clean, Startup, Storage tabs).

## What this is NOT

- **Not an antivirus replacement.** Keep Windows Security (Defender) on.
- **No live protection.** It only looks when you run it. It never watches in the background.
- **No real malware database.** It ships with test rules only (the standard EICAR test string and a harmless HEM demo marker). Out of the box it will not find real-world malware.
- **No kernel driver, no self-protection, no cloud lookup, no machine learning, no behaviour monitoring.**
- **No registry cleaner.** (Registry cleaners are risky and do not speed up a PC.)
- **No "PC boost" and no speed claims.**
- **Not certified or tested by any independent lab.** No detection rate exists, so none is claimed.
- **The zip is not code-signed.** Windows SmartScreen may warn you the first time.

## TESTED (numbers from automated runs)

**Windows runner (the real test): 97 passed, 0 failed, 1 skipped, 856 individual checks.**
Linux extra check: 93 passed, 0 failed, 2 skipped, 627 checks. (The skipped ones are Windows-only or Linux-only by design.)

Safety behaviour, proven on made-up files only:
- Scanning never changes a file. (test: `scanning_never_changes_a_single_file`)
- A dry-run clean changes nothing at all, checked with a whole-folder SHA-256 fingerprint before and after.
- Undo puts all files back byte-for-byte (fingerprint identical: 11 files).
- Restore never overwrites a newer file.
- A forged cleanup plan cannot reach protected folders (Documents, Desktop, Pictures, Music, Videos, Downloads, OneDrive) or unknown files.
- Links and junctions are never followed.
- Quarantine round-trip is byte-for-byte on a 2.6 MB binary file.
- If the quarantine log cannot be written, the file stays exactly where it was (added after the independent review).
- A damaged stored file is refused, never restored.
- Startup disable/enable only flips the Windows "approved" flag or turns a logon task off and on. It never deletes anything. Proven on the Windows runner against the real registry and real scheduled tasks created for the test.
- A file in use is skipped, not forced (Windows runner).
- Signature check: Windows programs report as Signed, plain files as Unsigned (Windows runner).
- A pattern split across two file reads is still found: 201 of 201 placements (64-byte reads).
- CPU limit works: on the Windows runner, with no limit the scan used 96% of a CPU; with a 50% limit it stayed under the cap (37% in one run, 16% in the next - the shared runner is noisy, so treat 50% as a ceiling, not an exact figure). 1,200 files, 37.5 MB. On the Linux check it was 100% vs 50%.
- A breakage test: 12 deliberate bugs were put into the safety code one at a time and the tests caught each one. Two more were done for the review fixes and both were caught.

Independent review: a separate reviewer read the delete/restore code and found 9 problems. The data-loss ones were fixed (listed below) and each has a test.

## What the independent review found, and what was done

| Finding | Status |
|---|---|
| Quarantine could remove the only copy if the log write failed on a full disk | **Fixed.** Log is written first; nothing is removed unless it worked. Tested. |
| Original deleted before the log line existed | **Fixed.** Same change. File-changed-during-copy check added. |
| Undo could delete a stored file around a damaged log line | **Fixed.** It now only removes its own two bookkeeping files, and the folder only if empty. Tested. |
| A move could overwrite a newer file that appeared at the same moment | **Fixed on Windows** (move without replace). |
| Restore could replace a file that appeared during a long copy | **Fixed** (same no-replace move, unique temp name). |
| "Careful" clean could take other users' Recycle Bin files | **Fixed.** Only your own Recycle Bin folder. Tested. |
| Tampered log could point a restore at any path | **Fixed.** Relative or undo-folder paths are refused; forged quarantine ids ignored. Tested. |
| A TEMP setting pointing at a work folder (e.g. Dropbox) would have been cleaned | **Fixed.** The folder must really be named Temp/Tmp. Tested. |
| Small gap between "is this safe" and "move it" | **Fixed.** One cleaned-up path is used for both. |
| Logs rewritten non-atomically | **Fixed.** Written to a side file then swapped in. |

## ASSUMED (best guesses, all in one file: `core/include/hem_guard/config.hpp`)

- Scan CPU share limit 50%, max file size 256 MB, read chunk 1 MB.
- Warning-sign points and Low/Medium/High thresholds.
- Undo kept 7 days. Temp files must be 24 hours old.
- Browser cache folder layouts for Chrome, Edge and Firefox as they are today.
- Quarantine scrambling (XOR) is only to stop a file from running or being flagged - it is **not encryption**.
- The "move without replace" fix relies on how Windows behaves; it passed on the runner but a real two-programs-at-once race was not reproduced.
- File data is flushed but not forced to the physical disk (no fsync). A power cut at the worst moment could still leave a stray stored copy. The log-first order means it would not lose the original.

## UNKNOWN (not measured - do not assume)

- **Real-world detection rate: unknown.** No real malware was used or tested.
- **False-positive rate on real PCs: unknown.**
- **Scan speed on large drives (multi-TB): unknown.** Only a 37.5 MB test was timed.
- Safety of cleaning the Windows Update cache while an update is installing: unknown. It is CAREFUL and off by default.
- How other security tools react to the quarantine folder: unknown.
- Two copies of HEM Guard running at once: not tested.
- Behaviour on Windows 10 vs 11, other languages, non-C: system drives: only the GitHub Windows runner was used.
- The real startup list on *your* PC: the runner read its own list (2 Run entries, 1 Startup-folder item, 34 logon tasks, 28 Windows-owned). Run "6 Show startup" yourself to see yours.

## Pass/fail table

Every test, with its check count and time, is in the run summary of the "Windows (the real test)" job on GitHub Actions. The same table is generated by `hem_guard_tests --report`.

Real-PC dry run on the runner (nothing changed): 7 clean-up places found, 68 files, 354.4 MB.


## Day 2 - the window (version 0.1.0)

**TESTED on the GitHub Windows runner (real window, real desktop, made-up files):**
- The program opens, shows all four tabs, and every tab's main control is really on top at its centre (Windows `WindowFromPoint`), not hidden.
- Scan tab: found the one planted marker file; quarantine moved it; restore put it back byte-for-byte; the other file was never touched.
- Clean tab (made-up folders, never the real PC): preview listed exactly the 3 temp files and changed nothing; "Clean now" moved them; the personal Documents file was untouched; "Undo" put all 3 back exactly.
- Startup tab: read this runner's real startup list (9 items) and the rows match the engine. It only read; no startup item was changed.
- Storage tab: counted the 3 test files; the duplicate finder found the one identical pair and deleted nothing.
- Screenshots of every tab were taken on the runner and looked at.

**A real bug the screenshots caught:** the first versions passed all their "list has N rows" checks but the tabs were blank on screen, because the tab control was drawn on top of the pages. Fixed, and a "what is really on top" check now guards it. This is why "the numbers are right" is not the same as "it looks right".

**Another honest finding:** the Windows CPU counter is coarse. One run reported 81% against a 50% limit, though the same scan was awake only about half the time. The limit is now judged by a precise clock (busy 49% of the time at a 50% limit; 100% when unlimited). The OS counter is still shown in notes but is not trusted.

**Not tested / UNKNOWN for the window:**
- Real mouse and keyboard use by a person. The self-test calls the same functions the buttons call; it does not click.
- The "Are you sure?" pop-ups (they are skipped in the self-test), the folder Browse dialog, and Stop in the middle of a scan.
- Other screen sizes, display scaling, dark mode, screen readers. Tested at one runner size only (about 1024 pixels wide); the window shrinks to fit smaller screens.
- Cleaning your real Temp folder from the window. The engine test for that ran on made-up folders; the real-PC check was a read-only preview.
- Storage jobs cannot be cancelled once started.
- The zip is not code-signed, so SmartScreen may warn.
