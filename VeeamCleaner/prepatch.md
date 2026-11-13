# Pre-Patch Validation Report: vcreview.md Fixes for VeeamCleaner.ps1

- Reviewed document: [vcreview.md](vcreview.md) (code review of [VeeamCleaner.ps1](VeeamCleaner.ps1))
- Validation date: 2026-10-01
- Validation host: Windows PowerShell `5.1.26100.9444` (same version the review reports)
- Method: independent re-measurement of every factual claim in the review (byte-level encoding scan, AST parse via `[System.Management.Automation.Language.Parser]`, pattern/line audits), plus isolated runtime probes for each proposed fix (parser snippets, `ShouldProcess`/`ShouldContinue` semantics under interactive and non-interactive stdin, sort behavior, path-resolution failure modes, transcript lifecycle).
- Scope note: `VeeamCleaner.ps1` was **not modified** during this validation. No destructive execution of the script itself was performed (it would attempt real uninstalls); all probes ran against synthetic inputs in `%TEMP%` and were removed afterward.

## Overall verdict

The review is accurate. Every finding I could test independently reproduced, including exact parse-error counts, em-dash locations, sort semantics, and transcript behavior. The proposed fixes **do remediate the identified issues for the common cases**, with three exceptions where the fix snippets as written carry their own defects and need adjustment before patching:

1. H1's `ConfirmImpact = 'High'` throws a `NullReferenceException` (not a graceful decline) when run non-interactively, measured under `stdin=NUL`.
2. H2's parser snippet mis-parses quoted non-`.exe` uninstall strings (`"C:\...\unins000.cmd" /S` yields exe = `"C:\Program`), which is a regression against the current `cmd /c` wrapper that handles that case correctly today.
3. M6's depth guard (`Split('\').Count -lt 3`) is bypassed in exactly the scenario it defends: measured `GetFullPath('\Veeam')` from a UNC session resolves to `\\server\share\Veeam`, which splits into 5 parts and passes the guard.

| ID | Issue confirmed? | Proposed fix remediates? | Adjustments required before patching |
| --- | --- | --- | --- |
| C1 | Yes, exactly as described | **Yes, fully** (measured 8 -> 0 parse errors) | None; recommend also adding UTF-8 BOM for resilience against future edits |
| H1 | Yes (zero `ShouldProcess` calls; `-WhatIf` ignored) | Yes for the gating pattern; **No as written with `ConfirmImpact='High'`** | Drop `ConfirmImpact='High'`; keep default Medium and rely on explicit confirmation gate (see H4) |
| H2 | Yes (cmd splits unquoted paths at first space) | Partially | Handle leading-quote case before the `.exe` regex; do not assign to `$args` (automatic variable); keep `Test-Path` guard but expect bare command names |
| H3 | Yes (false negative on `C:/Veeam/setup.exe` reproduced) | Partially | Check every argument token, not only the first; extract `--silent`/`-s` style args too |
| H4 | Yes (`'yes' -ne 'YES'` accepted; non-interactive behavior confirmed) | Yes, with guards | `$PSCmdlet.ShouldContinue(...)` throws when input is unavailable (measured); short-circuit on `-Force`, detect redirected input, default to clean abort |
| M1 | Yes by code reading (no service removal; verification checks registry only) | Directionally sound | Delete services only after the uninstall pass and only if still present; make `HKLM:\SOFTWARE\Veeam` tree removal opt-in |
| M2 | Yes (`-Unique` kept v2, not v1, matching the review's example exactly) | Yes, with adjustments | Capture hive/source property before keying by `"Hive\PSChildName"`; avoid `Select-Object -Property * -Unique` (dedup on all properties can leave duplicates and cause double uninstall; interacts with M5) |
| M3 | Yes (unstable sort reproduced exactly: 4,5,6,1,2,3) | Yes | Add a final tiebreak key (`PSChildName`) for total determinism |
| M4 | Yes (data used as regex at line 135) | Yes | Prefer `[regex]::Escape(...)`; `-like` reintroduces wildcard interpretation |
| M5 | Yes by code reading (success only on 0/3010 at line 186; MSI branch re-derives command and discards vendor switches from `QuietUninstallString`) | Yes | msiexec logging switch must be `/L*V "path"` (review's shorthand is loose); apply the exit-code map together with M2 to avoid false failures on double uninstall |
| M6 | Yes, and worse than stated in UNC contexts | Partially as written | Replace depth heuristic with resolved-root allowlist; drop dead `$root` line; reparse-point check and `-LiteralPath` are good |
| M7 | Yes (double `Stop-Transcript` error reproduced verbatim; parent-dir creation claim correct) | Yes | Set the transcript flag only on successful start; wrap `Start-Transcript` itself in try/catch |
| L1..L7 | All confirmed | Trivially correct as suggested | Nit: line 187 is 139 characters, not 141 (review reported UTF-8 byte length); still over 120 |

## Evidence audit: review claims vs independent measurements

All measurements taken on the delivered file at `\\voldemort\shared\agent\Projects\powershell\VeeamCleaner\VeeamCleaner.ps1`.

| Claim in vcreview.md | Review value | Measured value | Match |
| --- | --- | --- | --- |
| File size | 10,683 bytes | 10,683 bytes | Yes |
| Encoding | UTF-8 without BOM | First 4 bytes `23 52 65 71` (`#Req`), no BOM | Yes |
| Non-ASCII inventory | Only `U+2014`, 12 occurrences, 36 bytes | Bytes present: only `0xE2 0x80 0x94`; 12 em-dashes total | Yes |
| Em-dash lines | 58, 73, 81, 87, 106, 124, 146, 176, 187, 190, 200, 229 | Exactly those 12 lines | Yes |
| Line count / line endings | 253 lines, CRLF 252/252, no tabs, no trailing whitespace | 253 lines; 252 CRLF and 252 LF total (all breaks are CRLF); 0 tab lines; 0 trailing-whitespace lines | Yes |
| `Write-Host` count (L7) | 37 | 37 | Yes |
| `ShouldProcess` calls (H1) | Zero | One textual occurrence total, which is the `[CmdletBinding(SupportsShouldProcess)]` attribute at line 25; zero `$PSCmdlet.ShouldProcess(...)` invocations | Yes |
| ANSI decode mechanism (C1) | Each em-dash decodes to `â€"` ending in `U+201D`, a tokenizer string delimiter | ANSI-decoded text contains exactly 12 `U+201D` characters; parse failure follows | Yes |
| Parse errors as delivered | 8, listed lines/messages (L81 unexpected `{`, L81 missing `)`, L189/L161/L143/L81/L79 missing `}`, L253 Try without Catch) | 8 errors with identical messages and lines | Yes |
| Replacing em-dashes on lines 81, 187, 190 only | 8 -> 0 errors | Byte-level variant file parsed with 0 errors | Yes |
| Replacing all em-dashes | Fixes parsing | 0 errors | Yes |
| "Replacing comment-only em-dashes has no effect" | No effect | Nuance: replacing only the 9 comment em-dashes still fails, and changes secondary error count from 8 to 3. Comments never break parsing on their own (variant with string sites fixed parses clean), so the review's causal conclusion is right; the literal "no effect" wording understates cascade noise | Substantively yes |
| `Stop-Transcript` locations (M7) | Lines 91, 100, 253 | Exactly those lines | Yes |
| `Sort-Object PSChildName -Unique` semantics (M2) | Dedups on sort key; kept record not necessarily first seen (`{A} v2` kept) | Probe kept `v2,v3`, matching the review's example exactly | Yes |
| Sort instability (M3) | All-equal keys reorder as 4,5,6,1,2,3 | Reproduced identically on this host | Yes |
| `Start-Transcript` creates missing parents (M7 note) | Yes | Probe: nested parent dirs created automatically | Yes |
| Second `Stop-Transcript` error text (M7) | "The host is not currently transcribing." | Reproduced verbatim | Yes |
| `.Count` on `$null` safe (lines 63/89) | Returns 0 | Measured 0 | Yes |
| ADS / signature (watermarking section) | Single `:$DATA`, `NotSigned` | Confirmed | Yes |
| Long lines (L5) | Line 187 = 141 chars, line 251 = 201 chars | Line 187 = **139** chars (141 is its UTF-8 byte length), line 251 = 201 | Minor discrepancy; finding stands |
| UNC cwd noise (L6) | Observed "UNC paths are not supported..." | Reproduced live during child-process probes | Yes |

## Per-finding validation of the proposed fixes

### C1. Encoding fix: VALID, fully remediates

- Root cause confirmed end to end: no BOM + 12 em-dashes -> ANSI decode injects `U+201D` (12 occurrences) -> tokenizer treats it as a quote -> 8 parse errors under PS 5.1.
- Isolation confirmed: the three string-literal sites (lines 81, 187, 190) are the fatal ones; replacing only those yields a clean parse. Comment em-dashes contribute cascade noise but never cause failure by themselves.
- The bulk-fix snippet (`ReadAllText` UTF-8 -> replace `U+2014`/`U+2013` -> write ASCII) produces a file that parses with 0 errors and is immune to codepage differences. Writing without BOM is safe only because the result is pure ASCII; adding a UTF-8 BOM anyway protects against future edits reintroducing non-ASCII characters.
- The verification command (`ParseFile` + error count) works as stated and should be part of the post-patch checklist.

### H1. ShouldProcess gating: pattern VALID, but drop `ConfirmImpact = 'High'`

- Confirmed: attribute at line 25, zero `ShouldProcess` calls; `-WhatIf` is accepted (because of the attribute) and then ignored by every mutating call (`Stop-Service` L113, both `Start-Process` L173/L181, `Remove-Item` L217). Line references verified against the file.
- Probe: script-scope `$PSCmdlet.ShouldProcess(...)` works correctly in an advanced script under PS 5.1 (invoked via `&`): normal run executes, `-WhatIf` prints "What if:" and skips. The gating approach remediates the reported behavior.
- **Measured defect in the proposed snippet**: with `ConfirmImpact = 'High'`, a plain run with no interactive input (`cmd /c powershell -File ... < NUL`) throws `MethodInvocationException: Exception calling "ShouldProcess" ... Object reference not set to an instance of an object.` instead of declining or prompting. Behavior also varied with redirected-input state across invocation styles. A safety mechanism that can crash or silently allow depending on stdin is worse than the current honest failure.
- Recommendation: keep `[CmdletBinding(SupportsShouldProcess = $true)]` (default `ConfirmImpact` Medium, which does not auto-prompt and was measured safe) purely for `-WhatIf` truthfulness; do **not** add `ConfirmImpact='High'`; keep the explicit confirmation gate handled under H4. When wrapping, preserve the existing per-item try/catch blocks so one failure does not abort the loop.

### H2. Uninstall invocation rewrite: remediates reported case, introduces a regression

- Confirmed mechanism: `cmd.exe /c "<UninstallString>"` splits unquoted paths with spaces at the first space; exit code 1 is then recorded as "Finished with exit code ..." and the operator moves on (lines 181/190).
- Probe of the proposed parser against representative strings:

| UninstallString | Proposed parse result | Correct? |
| --- | --- | --- |
| `"C:\Program Files\Veeam\unins000.exe" /SILENT` | exe = `C:\Program Files\Veeam\unins000.exe`, args = `/SILENT` | Yes |
| `C:\Veeam\setup.exe /S` | exe = `C:\Veeam\setup.exe`, args = `/S` | Yes |
| `C:\path with space\unins000.exe` (no args) | full path as exe | Yes |
| `"C:\Program Files\Foo\unins000.cmd" /S` | exe = `"C:\Program` | **No; regression** (current `cmd /c` wrapper handles this case correctly today) |
| `C:\path with space\unins000.cmd /S` | exe = `C:\path` | No (inherently ambiguous input; acceptable to reject rather than guess) |

- Required adjustments: handle the leading-quote case first (`if raw starts with '"'`, take up to the closing quote as exe, remainder as args), then apply the `.exe` regex, then fall back to first-space split only when the path contains no spaces (or refuse). Also: the snippet assigns to `$args`, which shadows the automatic variable; use a local name such as `$argLine`. Keep `Test-Path -LiteralPath $exe` but expect it to fail for bare command names (`rundll32.exe ...` style strings), so resolve or allow those explicitly. `-WorkingDirectory (Split-Path -Parent $exe)` is correct and also closes L6.

### H3. Silent-flag detection: remediates the reported false negative, residual gaps remain

- Confirmed both directions with probes:
  - `C:/Veeam/setup.exe`: current regex `/S|/s|/quiet|/silent` matches inside `/setup`, so no flag is appended (the review's verified false negative). Proposed logic appends correctly.
  - Additional real-world bug confirmed: for `C:\Tools\setup.exe /VERYSILENT` the **current** code appends a spurious `/S` because `/VERYSILENT` matches none of its alternatives; the proposed flag list detects it.
- Residual gaps measured in the proposed snippet:
  - The anchored check inspects only the first argument token: `setup.exe /ALLUSERS /SILENT` still gets a spurious `/S` appended.
  - Extraction regex `\s(/.*)$` never captures `--silent` or `-s` style arguments, so those strings get `/S` appended on top of their own silent flag.
- Recommendation: split the argument portion into tokens and test **each** token against the flag set; append a family-appropriate flag only when no recognized silent switch exists anywhere in the args.

### H4. Confirmation prompt: valid direction, needs input-availability guards

- Confirmed: `'yes' -ne 'YES'` is False (accepted), so the printed "Type YES" contract is not enforced; `-cne` fixes it as stated.
- Non-interactive probe (`stdin=NUL`): `Read-Host` returned an empty string without throwing, so today's script aborts cleanly in that specific harness ("Aborted by user"). The review's claim covers the general case (hosts where it throws or hangs are real); either way automation must not depend on stdin.
- **Measured defect in the proposed replacement**: `$PSCmdlet.ShouldContinue(...)` throws `NullReferenceException` when input is unavailable, so a naive swap converts today's clean abort into a crash for unattended runs that forget `-Force`.
- Recommendation: gate with short-circuit and detection, e.g. `if ($Force) { ... } elseif ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) { if ($PSCmdlet.ShouldContinue(...)) { ... } else { exit 0 } } else { Write-Warning 'non-interactive without -Force; aborting'; exit 1 }`. Pick one confirmation mechanism (this or `ShouldProcess` prompts), as the review itself notes.

### M1. Service cleanup and verification: sound direction, two cautions

- Confirmed by code reading: services are stopped only (L108-L121); nothing deletes service entries; verification (L232) re-runs `Get-InstalledVeeamProducts`, which scans registry uninstall keys only, so leftover services never affect the "all removed" message.
- The fix direction (post-uninstall pass with `sc.exe delete` plus counting services in the summary) remediates it. Cautions: run the deletion pass **after** uninstallers have had their chance (some uninstallers remove their own services), only for services still present, and stop them first (already done). Wholesale removal of `HKLM:\SOFTWARE\Veeam` is aggressive (configuration/licensing data); make it opt-in rather than default.

### M2. Dedup and discovery: valid with implementation adjustments

- Confirmed semantics probe matches the review's example exactly (`{A} v1, {A} v2, {B} v3 -> v2, v3`), including the "not necessarily first kept" nuance. Discovery indeed scans only the two HKLM paths (L42-L45) and matches `DisplayName -match 'Veeam'` only (L49).
- Adjustments: current objects do not carry hive information (`Select-Object` at L50 drops it), so a `"Hive\PSChildName"` key requires adding a source property inside `Get-InstalledVeeamProducts` first. Avoid the suggested `Select-Object -Property * -Unique`: dedup on all properties keeps two entries when any property differs (for example DisplayVersion between hives) and can produce double uninstalls; use an explicit hashtable keyed by hive + child name. HKCU scanning under an elevated session sees the admin's hive, not the console user's; treat that as a known limitation rather than full coverage.

### M3. Deterministic ordering: valid fix

- Unstable sort reproduced exactly (4,5,6,1,2,3 for equal keys). `Sort-Object { rank }, DisplayName` makes ordering reproducible in practice; add `PSChildName` as a final tiebreak so ties on both prior keys cannot exist. Also apply M4's escaping inside the same scriptblock.

### M4. Escaping sort patterns: valid fix

- Confirmed the pattern-from-data risk at L135 (entries are interpolated into `-match`). `[regex]::Escape($sortOrder[$i])` is fully correct; `-like "*$entry*"` also fixes today's entries but reintroduces wildcard interpretation for future ones, so prefer the escape.

### M5. MSI branch hardening: valid with syntax correction

- Confirmed by code reading: success is only 0/3010 (L186), so 1605/1614 ("not installed") count as failures; `QuietUninstallString` is preferred as the source string (L147) but the MSI branch then re-derives `msiexec /x $guid /qn /norestart`, discarding vendor switches; no handling of a `$null` exit code.
- The proposed exit-code map and log capture remediate this. Correction: the msiexec logging switch is `/L*V "C:\path\file.log"` (review's `/L"V${log}"` shorthand would not work as written). Apply the 1605/1614-as-clean mapping together with M2 so a duplicate entry uninstalled twice does not report failure.

### M6. Delete-target hardening: direction correct, guard as written is bypassable

- Confirmed and worse than stated: with an empty env var, `"$env:ProgramFiles\Veeam"` becomes `\Veeam`. Measured on this host from a UNC session, `[System.IO.Path]::GetFullPath('\Veeam')` resolves to `\\voldemort\shared\Veeam`, whose `Split('\').Count` is 5. The review's proposed guard (`count -lt 3`) therefore **passes** it; if that share path exists, the forced recursive delete proceeds against a network location. On a local drive root the same resolution yields `C:\Veeam` (2 parts) and is refused, so the heuristic only works in the non-UNC case.
- Also: `$root = Split-Path -Qualifier $full` in the snippet is dead code (never used).
- Required adjustment: replace the depth heuristic with an allowlist built from resolved roots, for example compute `[System.IO.Path]::GetFullPath($env:ProgramFiles)`, `...Common Files...`, `$env:ProgramData` once, then require each candidate to equal a root or start with `root + '\')`, reject paths whose qualifier is not in that set (this also rejects all UNC targets), keep the reparse-point check and `-LiteralPath`, and skip empty/whitespace entries before concatenation.

### M7. Transcript handling: valid fix

- Confirmed: three unguarded `Stop-Transcript` calls (L91, L100, L253); a second stop produces exactly the quoted error; `Start-Transcript` does create missing parent directories on 5.1 (the review's parenthetical correction is right).
- The try/finally with a `$transcriptStarted` flag remediates all three exit paths. Set the flag only after a successful start and wrap `Start-Transcript` itself in try/catch so a failed start does not cascade into the body. Moving the default log to a dedicated directory is sound; note `%TEMP%` per-user is not world-writable by default, but an elevated transcript containing software inventory is disclosure-sensitive on shared/broken-ACL servers as stated.

### L1..L7: all confirmed

- L1 confirmed (help examples reference `.\Remove-VeeamComponents.ps1`, lines 18-L22).
- L2 confirmed exactly: comment labels STEP 4/5/6/7 at lines 106/124/200/229 vs console "Step 3/4/5/6" at lines 108/127/203/231.
- L3 confirmed: `#Requires -RunAsAdministrator` present at line 1; no pending-reboot or running-jobs check exists. Informational; the suggestion is reasonable and needs no code to be "validated".
- L4/L5/L6/L7 confirmed as described (see evidence table for the 139 vs 141 nit on L5; L6's UNC noise reproduced live during probes and is closed by H2's `-WorkingDirectory`).

## Defects found in the review-provided fix snippets (consolidated)

These must be corrected when the patch is written; none invalidate the underlying findings.

1. **H1**: `ConfirmImpact = 'High'` throws `NullReferenceException` under non-interactive stdin instead of declining; behavior varies with input state. Omit it and keep confirmation explicit (H4).
2. **H4**: `$PSCmdlet.ShouldContinue(...)` also throws when input is unavailable; short-circuit on `-Force`, detect redirected/non-interactive input, default to clean abort.
3. **H2**: parser mis-handles quoted non-`.exe` uninstall strings (regression vs current behavior); assigns to automatic variable `$args`.
4. **H3**: anchored check inspects only the first argument token; `--silent`/`-s` style args are never extracted. Use per-token matching over all arguments.
5. **M6**: depth heuristic is bypassed by UNC-resolved paths (measured parts=5); `$root = Split-Path -Qualifier $full` is dead code. Use a resolved-root allowlist instead.
6. **M2**: `Select-Object -Property * -Unique` dedups on all properties and can leave duplicates; hive/source property must be added before keying by `"Hive\PSChildName"`.
7. **M5**: msiexec log switch syntax in the snippet is loose; correct form is `/L*V "path"`.

## Recommended patch order (adjusted from the review)

1. C1: replace all 12 em-dashes, save ASCII with UTF-8 BOM; confirm `ParseFile` reports 0 errors on PS 5.1.
2. H1: add `$PSCmdlet.ShouldProcess(...)` around every mutating call (services, uninstallers, file cleanup) **without** `ConfirmImpact='High'`; preserve existing per-item try/catch.
3. H4 + M7: guarded confirmation flow (`-Force` short-circuit plus interactive-input detection), and wrap the body in try/finally with a `$transcriptStarted` flag; move default log location.
4. H2 + H3 combined rewrite of the uninstall invocation: quote-aware exe/args split (leading-quote case first), per-token silent-flag matching, native `Start-Process -FilePath $exe -ArgumentList $argLine -WorkingDirectory ...`.
5. M6: resolved-root allowlist plus reparse-point and `-LiteralPath` guards before any file cleanup ships.
6. M1..M5 as adjusted above; then L1/L2 cosmetic alignment.

## Post-patch validation checklist

- `Parser::ParseFile` under Windows PowerShell 5.1 reports 0 errors; byte scan shows no non-ASCII bytes (or a BOM is present).
- Run with `-WhatIf` on a VM with dummy uninstaller registry entries: zero services stopped, zero processes launched, zero files deleted.
- Run without `-Force` under `stdin=NUL`: exits cleanly with a clear message; no `NullReferenceException`.
- Quoted and unquoted uninstall strings (`.exe` and `.cmd`, paths with spaces) all launch the correct executable; verify via transcript echo of exe/args.
- Silent-flag detection appends nothing when any recognized silent switch appears anywhere in args, and appends exactly one appropriate flag otherwise.
- File cleanup refuses drive-root-relative, UNC, reparse-point, and non-allowlisted targets; uses `-LiteralPath`.
- Transcript starts once and stops exactly once on all three exit paths (early-exit, abort, normal completion).
