# CHANGELOG - VeeamCleaner.ps1

All changes applied 2026-10-01. Findings referenced as used in [vcreview.md](vcreview.md); adjustments per the validated review in [prepatch.md](prepatch.md).

## Validation status of this patch

| Check | Result |
| --- | --- |
| `Parser::ParseFile` under Windows PowerShell 5.1.26100.9444 | **0 errors** (was 8) |
| File encoding | Pure ASCII content, saved with UTF-8 BOM (`EF BB BF`) |
| Lines over 120 characters | 0 |
| Helper functions unit-tested via AST extraction (no body execution) | All pass (details below) |
| Runtime smoke test of full script | Blocked by `#Requires -RunAsAdministrator` on this non-elevated host; parse and elevation guard confirmed. Full end-to-end run still recommended on an elevated Veeam VM |

## Critical

### C1: encoding fixed
- All 12 em-dashes (`U+2014`) replaced with ASCII hyphens; the file now contains no non-ASCII characters.
- Saved as UTF-8 **with BOM** so future edits that introduce non-ASCII characters still parse correctly under Windows PowerShell 5.1.

## High

### H1: `-WhatIf` is now truthful
- `[CmdletBinding(SupportsShouldProcess = $true)]`; every state-changing call is wrapped in `$PSCmdlet.ShouldProcess(...)`:
  - `Stop-Service` (Step 4 and Step 6)
  - MSI uninstall (`Start-Process msiexec.exe`)
  - EXE uninstall (`Start-Process <uninstaller>`)
  - leftover service removal (`sc.exe delete`)
  - file cleanup (`Remove-Item`)
  - optional registry key removal
- Per the prepatch validation, `ConfirmImpact = 'High'` was deliberately **not** added: measured under non-interactive stdin it throws a `NullReferenceException` instead of declining. Confirmation is handled explicitly in Step 3 instead.

### H2: uninstall invocation rewritten (no more `cmd /c`)
- New helper `Split-UninstallString`: quote-aware split into executable + arguments.
  - Leading-quote case parsed first, so quoted non-`.exe` targets (`"C:\...\unins000.cmd" /S`) work correctly; this closes the regression identified in prepatch against the review's original snippet.
  - Unquoted `.exe` paths with spaces handled; ambiguous unquoted paths (spaces, non-`.exe`, arguments present) are **rejected with a clear error** instead of being mis-split and executed.
  - Bare command names (`rundll32.exe`) resolved through PATH; missing executables throw before any process starts.
- Uninstallers now launch natively via `Start-Process -FilePath <exe> -ArgumentList <args> -WorkingDirectory <parent>` (also fixes L6).

### H3: silent-flag detection is per-token and anchored
- New helper `Test-SilentFlagPresent` splits the argument line into tokens and matches each against `/S`, `/VERYSILENT`, `/SILENT`, `/QUIET`, `/Q`, `/QN`, `/NORESTART`, `--SILENT`, `-S` (case-insensitive, also accepts `/FLAG=value`).
- Fixes both original failure modes: no false positive from paths like `C:/Veeam/setup.exe`, and no spurious `/S` appended when a silent flag already exists anywhere in the arguments (`/ALLUSERS /SILENT`, `/VERYSILENT`, ...). Unit-tested.

### H4: confirmation prompt replaced with guarded flow
- `Read-Host "Type YES"` removed (it also accepted lowercase due to case-insensitive `-ne`).
- Step 3 now branches:
  - `-Force`: skip prompt.
  - `-WhatIf`: skip prompt (nothing will change).
  - Interactive session (`[Environment]::UserInteractive` and input not redirected): `$PSCmdlet.ShouldContinue(...)`; user abort exits 0.
  - Non-interactive without `-Force`: warning + exit code **2** before any changes. This avoids the `NullReferenceException` that a bare `ShouldContinue` call throws when no input is available (measured in prepatch validation).

## Medium

### M1: leftover services removed and verified
- New Step 6 runs after the uninstallers: re-enumerates Veeam services, stops any still running, then removes them with `sc.exe delete` (each gated by `ShouldProcess`, failures reported with the `sc.exe` exit code).
- Step 8 verification now reports **both** remaining registry products and remaining services; the summary counts services removed/remaining.
- Registry tree removal (`HKLM:\SOFTWARE\Veeam` + WOW6432Node) is available behind the new opt-in switch `-RemoveRegistryKeys` (off by default; these keys can hold configuration/licensing data).

### M2: discovery hardened and dedup fixed
- Discovery now scans HKLM 64-bit, HKLM WOW6432Node, **and** `HKCU:\...\Uninstall`, and matches on `DisplayName` **or** `Publisher`. (Known limitation documented in code: elevated sessions see the elevation user's HKCU.)
- Replaced `Sort-Object PSChildName -Unique` (which silently dropped records sharing a sort key) with an explicit hashtable keyed by `SourcePath|PSChildName`; each entry now carries its source hive path.

### M3: deterministic uninstall order
- Sort keys are now `{ rank }, DisplayName, PSChildName`, so equally ranked products uninstall in the same reproducible order every run (Windows PowerShell sort is unstable; measured).

### M4: sort patterns escaped
- `$sortOrder` entries are matched via `[regex]::Escape(...)` inside the sort scriptblock; future entries containing regex metacharacters can no longer throw.

### M5: MSI branch hardened
- Vendor switches from `QuietUninstallString` are preserved when it contains a usable product code (previously discarded and re-derived).
- `/norestart` is appended if absent; MSI logging added via correct syntax `/L*V "<dir>\msi_<name>_<timestamp>.log"` when the log directory exists.
- Exit-code map: 0 success, 3010 success + reboot, **1605/1614 counted as already-clean**, `$null` exit code reported explicitly ("unavailable") instead of printing blank; everything else failure. Unit-tested.

### M6: file cleanup cannot escape known roots
- Candidate paths are built only when the source environment variable is present (a missing `ProgramFiles` can no longer produce `\Veeam`).
- Resolved target must start with one of the resolved roots (`%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramData%`) using ordinal case-insensitive comparison. This rejects drive-root-relative, UNC-resolved, and unrelated paths; unlike the review's depth heuristic, it also holds in UNC working-directory contexts (the bypass measured in prepatch).
- Reparse points/junctions are skipped; deletion uses `-LiteralPath`.
- Redundant `$env:ALLUSERSPROFILE\Veeam` entry removed (resolves to `ProgramData\Veeam` on Vista+).

### M7: transcript lifecycle fixed
- Default log moved from `%TEMP%` to `%SystemDrive%\VeeamRemovalLogs\VeeamRemoval_<timestamp>.log`, created best-effort with `%TEMP%` fallback.
- `Start-Transcript` wrapped in try/catch; a `$transcriptStarted` flag guards the single `Stop-Transcript`, which now lives in a `finally` block covering all exit paths (early "nothing to remove", user abort, non-interactive abort, normal completion, and unexpected termination). The three unguarded inline stops are gone.

## Low / informational

- **L1**: comment-based help examples now reference `.\VeeamCleaner.ps1`.
- **L2**: comment step labels and console headers aligned; steps renumbered 1..8 to include the new service-removal pass.
- **L3**: added pending-reboot detection (`PendingFileRenameOperations` + CBS `RebootPending`) with a warning at start; result also reported in the summary object. Running-jobs detection intentionally not implemented (requires Veeam snapins).
- **L4**: discovery accumulates into `System.Collections.Generic.List[object]` instead of `+=` array copies.
- **L5**: no line exceeds 120 characters.
- **L6**: fixed via H2's `-WorkingDirectory` on uninstaller launches.
- **L7**: script now emits a final `[pscustomobject]` summary (`ProductsFound`, `UninstalledOk`, `FailedOrSkipped`, `ServicesRemoved`, `RemainingProducts`, `RemainingServices`, `PendingReboot`, `LogPath`) via `Write-Output`; progress output remains `Write-Host`.

## New parameters and behavior changes (operator-visible)

| Item | Before | After |
| --- | --- | --- |
| `-WhatIf` | Accepted but ignored; full destructive run | Full preview; every mutation gated by `ShouldProcess` |
| `-RemoveRegistryKeys` | n/a | Opt-in deletion of `HKLM:\SOFTWARE\Veeam` (+ WOW6432Node) |
| Default log location | `%TEMP%` | `%SystemDrive%\VeeamRemovalLogs` (fallback `%TEMP%`) |
| Confirmation | `Read-Host`, accepted lowercase "yes" | `ShouldContinue` interactively; `-Force` skips; non-interactive without `-Force` aborts cleanly |
| Exit codes | Always 0 | 0 = success/no-op/user abort; 2 = non-interactive without `-Force`; 3 = completed with failures or leftovers |
| Pipeline output | None | One summary `[pscustomobject]` at the end |
| File cleanup targets | 6 entries incl. duplicate `ALLUSERSPROFILE\Veeam`, unvalidated | Env-var-guarded, root-allowlisted, reparse-safe, `-LiteralPath` |

## Unit test evidence (helpers extracted via AST from the patched file)

```text
Split-UninstallString:
  "...\sp ace\unins.cmd" /SILENT        -> exe=[...\sp ace\unins.cmd] args=[/SILENT]   ran, exit=0
  ...\unins.cmd /VERYSILENT             -> exe=[...\unins.cmd]       args=[/VERYSILENT] ran, exit=0
  "C:\Program Files\Foo\unins000.cmd" /S-> exe=[C:\Program Files\Foo\unins000.cmd]     (regression case fixed)
  C:\path with space\unins000.cmd /S    -> rejected: "ambiguous quoting"                (by design)
  MsiExec.exe /X{GUID}                  -> exe=[C:\windows\system32\msiexec.exe] args=[/X{GUID}]

Test-SilentFlagPresent:
  ''                                    False     '/ALLUSERS /SILENT'    True
  '/SILENT'                             True      '--silent'             True
  '/VERYSILENT /SUPPRESSMSGBOXES'       True      '-s'                   True

Get-UninstallResultCategory:
  0 -> success   3010 -> reboot   1605/1614 -> already-clean   1 -> failure   null -> unknown
```

## Outstanding recommendation

Run the full script end-to-end on an elevated, representative Veeam VM (or a snapshot with dummy uninstaller entries) to exercise Steps 4-8 under `-WhatIf` and then for real; this host's session is not elevated, so `#Requires -RunAsAdministrator` correctly blocks execution here.
