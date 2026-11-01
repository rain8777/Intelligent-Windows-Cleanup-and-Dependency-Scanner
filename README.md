# Intelligent Windows Cleanup and Dependency Scanner

A free, open-source, safety-first disk cleanup assistant for Windows 10 and 11, written in plain
batch + PowerShell with no third-party dependencies.

## What does it do?
Most cleaners decide a file is "junk" because it is old or sits in a temp folder. This tool does not. For every
candidate it **investigates whether anything still needs it** before saying a word about cleanup:

1. **Finds candidates** in the places Windows applications leave data behind: `AppData\Local`, `AppData\Roaming`,
   `AppData\LocalLow`, `ProgramData`, user and Windows temp folders, and cache / log / crash-report
   sub-folders inside application folders. It never walks the whole drive.
2. **Works out which application each candidate belongs to** and whether that application is installed,
   uninstalled or uncertain, using many independent sources (uninstall registry, program folders, Store
   apps, processes, services, scheduled tasks, startup entries, shortcuts, registration keys).
3. **Checks for dependencies**: searches the registry, running processes and loaded modules, services,
   scheduled tasks, startup entries, shortcuts, PATH, and configuration/manifest/script files for references to the candidate.
4. **Looks inside** for things that must not be lost: databases, credentials, mail stores, documents,
   backups, save games, profiles, plugins and shared components.
5. **Gives every candidate exactly one verdict**, with the evidence: `PROTECTED`, `NEEDS REVIEW` or `SAFE CANDIDATE`.
6. **Optionally quarantines** the SAFE candidates you personally approve. Items are *moved*, never deleted,
   and can be restored with one menu option.

When the evidence is incomplete or conflicting, the tool keeps the file. It is designed to produce
explainable, conservative results rather than the biggest possible number.

## How can it help you?
- **Reclaim disk space with less fear.** Old caches, logs, crash dumps, temp files and leftovers from
  programs you removed can add up to many gigabytes. You see exactly *why* each item was judged safe.
- **Understand what is eating your disk.** Reports list sizes per application folder and per category, even
  for items you decide to keep.
- **Find leftovers of uninstalled software** that regular uninstallers forget, without risking data that
  still-installed programs rely on.
- **Stay in control.** Scanning is read-only. Nothing moves without your explicit approval, nothing is
  permanently deleted by the tool, and every action is logged and reversible.
- **Learn.** The per-item dependency report shows which registry keys, services, tasks and files reference a
  folder, which is useful for troubleshooting too.

It is **not** a registry cleaner, an uninstaller or a "one-click optimizer". It never edits the registry,
stops processes or services, or forces locked files.

## Requirements
| Requirement | Details |
|---|---|
| Operating system | Windows 10 or Windows 11 (64-bit recommended) |
| PowerShell | Windows PowerShell **5.1** (built into Windows 10/11). PowerShell 7 is not required |
| Language mode | PowerShell **Full Language Mode** (the default). Locked-down / Constrained Language Mode environments are not supported |
| Execution policy | No change needed; the launcher runs the script with a process-only bypass |
| Permissions | A standard account works for your own profile. **Administrator** is recommended for a fuller scan (see below) |
| Disk space | Negligible. Quarantine moves items on the *same drive*, so no extra space is needed |
| Install | None. Extract the folder and run `WinCleanup.bat`. No internet access, services or drivers |
| Time | A scan can take from a few minutes to ~15+ minutes on large profiles (the full registry search is the slowest step) |

Administrator rights are only needed to read `C:\Windows\Temp`, other users' profiles, some registry keys and
all processes' loaded modules. Without them the tool still runs, and anything it could not fully inspect is
classified NEEDS REVIEW, never SAFE.

## Disclaimer
This software is provided **as is**, without warranty. It is conservative by design, but no tool can prove that
a file is unused. **Back up important data before cleaning**, review the report before approving anything, and
start with a non-critical machine. The Windows-specific collectors (registry, services, tasks, shortcuts and
the quarantine move) have had limited real-world testing; bug reports and pull requests are very welcome.

## Folder structure
```
WinCleanup\
  WinCleanup.bat          launcher (detects admin, offers elevation)
  README.md
  config\
    settings.json         created on first run (thresholds, registry mode, profiles)
    user-rules.json       created on first run (your own protect / confirmed-uninstalled names)
  src\
    Main.ps1              menu
    Lib.Common.ps1        settings, logging, helpers, persistence
    Lib.Apps.ps1          application inventory + installed/uninstalled inference
    Lib.Deps.ps1          dependency engine (registry, files, processes, services, tasks, ...)
    Lib.Scan.ps1          candidate discovery + metadata
    Lib.Classify.ps1      three-outcome classifier
    Lib.Report.ps1        screen views, TXT/CSV export
    Lib.Quarantine.ps1    approval, quarantine, review, restore, crash recovery
  data\last_scan.json     created at runtime (latest results)
  reports\                created at runtime (timestamped .txt / .csv)
  logs\                   created at runtime (actions-YYYYMMDD.log)
```
Quarantine itself lives at `<drive>:\WinCleanup_Quarantine\` (see below).

## Install and run
1. Copy the `WinCleanup` folder anywhere (use a path without unusual Unicode characters for the `.bat`).
2. Double-click `WinCleanup.bat`.
3. Requires Windows 10/11 with built-in Windows PowerShell 5.1. Nothing else to install.

**Without administrator rights:** works for your own profile. It cannot read `C:\Windows\Temp`, other
profiles, some registry keys or some processes' loaded modules; affected candidates become NEEDS REVIEW,
never SAFE. **With administrator rights** (choose `A` at the launcher prompt; approve UAC with the *same* user account, otherwise the tool would scan the admin account's profile instead of yours): fuller inspection. To include
other users' profiles set `"ScanAllProfiles": true` in `config\settings.json` (their registry hives are not
loaded, so those items can never be SAFE).

## Menu
| # | Action |
|---|--------|
| 1 | Scan all supported locations |
| 2 | Scan potential leftovers of uninstalled applications |
| 3 | Scan installed-application data inactive > 365 days (and their cache/log sub-folders) |
| 4 | Scan uncertain application data |
| 5 | Scan recognized temp and cache folders |
| 6 | View results grouped by outcome |
| 7 | Full dependency report for one candidate Id |
| 8 | Export `.txt` + `.csv` report to `reports\` |
| 9 | Review, approve and quarantine SAFE CANDIDATE items |
| 10 | Review quarantine contents |
| 11 | Restore quarantined items |
| 12 | Exit |

Scans never modify anything. Option 9 and 11 are the only options that move files.

## Scanned locations
`%LOCALAPPDATA%`, `%APPDATA%`, `AppData\LocalLow`, `%PROGRAMDATA%`, `%TEMP%`, `C:\Windows\Temp`, plus
cache/log/crash/temp/update sub-folders found up to 5 levels deep inside application folders. The drive is
never scanned recursively. Never evaluated (listed as *skipped* in the report): `Microsoft` folders,
`Packages`, `Programs`, `Package Cache`, `SoftwareDistribution`, ClickOnce `Apps`, `regid.*`, junctions and
symlinks (never followed), and this tool's own folders.

## How a candidate is evaluated
1. **Application identity.** Evidence is gathered from the uninstall registry (32/64-bit, HKLM/HKCU), program
   folders, Store packages, running processes, services, scheduled tasks, Run keys, App Paths, Start
   Menu/Desktop shortcuts, and `Software\Vendor\App` registration keys. Status is one of Confirmed/Probably
   Installed, Confirmed/Probably Uninstalled, or Unknown.
   - *Confirmed Uninstalled* needs: no installed evidence anywhere **and** positive uninstall residue (for example a
     registry key pointing at a now-missing install folder, or a broken shortcut/task) **and** a complete
     inventory **and** no executables inside the folder (could be portable) **and** no recent activity.
   - Conflicting evidence (installed *and* residue) => Unknown.
2. **Age.** 365 days (never lower) is only a *selection* filter for installed applications. Activity uses
   write/creation times only; last-access time is deliberately ignored (it may be disabled, delayed, or
   altered by scanners). Future or pre-1980 timestamps make a candidate NEEDS REVIEW.
3. **Dependency investigation.** Every path-like string from the registry (HKLM\SOFTWARE incl. Classes/CLSID,
   Services, HKCU\Software, Environment), running processes and loaded modules, services, scheduled tasks,
   startup entries, shortcuts, PATH, and config/manifest/script files in AppData, ProgramData and Program Files
   is matched against each candidate. Each reference is:
   - **Confirmed** (service, task, startup, shortcut, file association/COM registration, PATH, running/loaded,
     inside or around an installed app's install directory, config of an installed app) => PROTECTED
   - **Direct** (an unrelated registry value or file mentions the path) => NEEDS REVIEW
   - **Self** (the application's own leftover registry/config) => recorded as a risk only
4. **Content.** Credentials, databases, mail stores, backups, virtual disks, save games, user documents,
   profile/user-data folders and shared components (plugins, runtimes) => PROTECTED (or NEEDS REVIEW inside
   recognized cache/temp folders). Configuration of a *confirmed uninstalled* app is accepted but listed as a risk.

## The three outcomes
- **PROTECTED** - evidence the item is needed or holds important data. Never moved by this tool.
- **NEEDS REVIEW** - evidence is incomplete, conflicting or insufficient (unknown app, unreadable files,
  partial registry search, direct unresolved references, mixed contents, installed-app data folders, another
  user's profile...). Excluded from quarantine.
- **SAFE CANDIDATE** - all required checks completed, a positive rule applies, no dependency or important data
  found. Only these can be quarantined, only with your approval. It means "nothing was detected", not "proven
  unused".

Priority is PROTECTED > NEEDS REVIEW > SAFE. A SAFE CANDIDATE requires one of: a confirmed-uninstalled
application leftover; a recognized cache/log/crash/temp/update folder untouched for 365+ days whose owner
is identified; or an item in a temp folder untouched for `TempAgeDays` (default 30). Whole data folders of
installed applications are never auto-qualified.

## Reports
Option 8 writes `reports\WinCleanup_Report_<timestamp>.txt` (full evidence per candidate, checks done / not
done, skipped locations, errors, limitations, totals) and `.csv` (one row per candidate). Sizes are
**potential** sizes with nested items counted once. Quarantine moves data on the same volume, so **free space
does not grow until you delete quarantine content yourself**; the report states quarantined bytes
separately.

## Quarantine and restore
Option 9: pick Ids -> each item is shown (path, size, application, evidence, risks) and needs a Y -> final
confirmation by typing `QUARANTINE` -> per-item pre-flight (re-checks size/count/timestamps vs. the scan,
running processes and loaded modules, locked files, path length) -> a journal entry is written **before** the move
-> the item is moved to `<drive>:\WinCleanup_Quarantine\Q-<timestamp>-<n>\files\<drive>\<original path>` ->
verified -> logged. Locked or changed items are left in place with the reason. No process is stopped, no
registry change is made, nothing is forced. The quarantine folder has a restricted ACL (you, Administrators,
SYSTEM); moved items keep their own ACLs. If the tool is interrupted, the next start reconciles the journal.

Option 11 moves items back to their original location. If something already exists there you can restore
beside it (`<name>.restored-<timestamp>`) or skip; nothing is silently overwritten. Option 10 lists everything,
including failed/restored entries. To free space for good, delete a `Q-...` batch folder manually once you
are confident (the tool never does this).

Limitation: quarantine/restore cannot guarantee an application returns to a perfect state (registry state,
permissions or related files may have changed in between).

## Settings (`config\settings.json`)
`InactiveDays` (>=365), `TempAgeDays` (30), `UninstalledRecentDays` (90), `ScanAllProfiles` (false),
`RegistryMode` (`Full`; `Quick` skips CLSID/TypeLib/Installer data and can never yield SAFE),
`MaxFileRefFiles`, `FileRefDepth`, `CacheSearchDepth`. A full registry search can take several minutes.
`config\user-rules.json`: `ProtectedNames` (treated as installed -> never SAFE) and `ConfirmedUninstalledNames`
(your own assertion of uninstall; dependency checks still apply).

## Known limitations and safety notes
- Absence of references is **not** proof of absence of dependencies: dynamically built paths, 8.3 short names,
  indirect or rarely used features, and encrypted/binary files cannot be detected.
- Open file handles are not enumerated during a scan; loaded modules are checked (partial without admin);
  locks are tested again only at quarantine time.
- Reading config files can update their last-access time if Windows maintains it; contents are never changed. Last-access time is not used as evidence, so this cannot distort later scans.
- Requires Full Language Mode (it uses .NET registry/file APIs); it will not run under Constrained Language Mode.
- Paths using 8.3 short names inside other programs' settings cannot be matched.
- Paths longer than 260 characters make a candidate unreadable -> NEEDS REVIEW.
- Portable apps are only detected via executables in the folder and recent activity.
- Other users' registry hives are not loaded; items from other profiles are never SAFE.
- Because the policy is "when in doubt, keep", expect many NEEDS REVIEW items and modest SAFE totals. That is by design.
- Do not use this tool as a substitute for backups before cleaning a critical system.
