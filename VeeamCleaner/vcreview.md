# Code Review: VeeamCleaner.ps1

- Reviewed file: [VeeamCleaner.ps1](VeeamCleaner.ps1) (253 lines, 10,683 bytes, CRLF line endings, UTF-8 without BOM)
- Review date: 2026-10-01
- Target runtime: Windows PowerShell 5.1 (review host: `5.1.26100.9444`, ANSI codepage 1252)
- Method: manual read-through, AST analysis via `[System.Management.Automation.Language.Parser]`, byte-level encoding scan, NTFS metadata/ADS inspection, pattern scans for secrets and provenance markers, plus isolated runtime probes to confirm suspected defects. `PSScriptAnalyzer` is not installed on this host, so no automated ruleset run was performed (see "How to reproduce").

## Verdict

The logic is well organized and mostly correct, but **the script does not run at all under Windows PowerShell 5.1** because of its file encoding, and `-WhatIf` silently performs the full destructive uninstall. Fix C1 and H1 before using this on a production Veeam server.

| Severity | Count | IDs |
| --- | --- | --- |
| Critical | 1 | C1 |
| High | 4 | H1, H2, H3, H4 |
| Medium | 7 | M1..M7 |
| Low / Info | 7 | L1..L7 |
| Sensitive data found | 0 | none |
| Orphaned/unused variables | 0 | none |
| Emoji found | 0 | none |
| Em-dashes found | 12 | see section "Emoji and em-dash identification" |
| Watermarking detected | No | see section "Watermarking and provenance" |

---

## Critical

### C1. File encoding breaks parsing on Windows PowerShell 5.1 (script will not run)

The file is saved as **UTF-8 without a BOM** and contains 12 em-dash characters (`U+2014`). Windows PowerShell 5.1 reads BOM-less files using the system ANSI codepage, so each `—` decodes to the three characters `â€”`. The last of those is `U+201D`, a right double quotation mark, which the PowerShell tokenizer treats as a **string delimiter**. Every em-dash that sits inside a double-quoted string therefore terminates the string early and cascades into parse errors.

Evidence (PS 5.1, same host):

```text
Parser::ParseFile on VeeamCleaner.ps1 -> 8 parse errors:
  Line 81: Unexpected token '{' in expression or statement.
  Line 81: Missing closing ')' in expression.
  Line 189: Missing closing '}' in statement block or type definition.
  Line 161: Missing closing '}' in statement block or type definition.
  Line 253: The Try statement is missing its Catch or Finally block.
  ...
```

Isolation test: replacing the em-dashes on lines **81, 187 and 190 only** (the three that are inside string literals) drops the error count from 8 to 0. Replacing comment-only em-dashes has no effect. A minimal real-world repro confirms it is not an artifact of the parser API:

```text
# nobom.ps1 : $x = "a — b"   (UTF-8, no BOM) run with powershell.exe -File
The string is missing the terminator: ".
Unexpected token 'b"' in expression or statement.

# same bytes WITH UTF-8 BOM -> prints: a — b
```

Impact: `.\VeeamCleaner.ps1` fails immediately with parser errors on any Windows Server running Windows PowerShell 5.1 (the default shell on every supported Windows Server). It only works when launched by PowerShell 7+, which defaults to UTF-8.

Fix, in order of preference:

1. Replace all em-dashes with plain ASCII (`-`), then save as **UTF-8 with BOM** or pure ASCII. This also removes the policy violation flagged below and makes the file immune to codepage differences (RDP clipboard edits, `Get-Content | Set-Content`, Git checkout filters).
2. If you keep non-ASCII characters, always write the file as UTF-8 **with** BOM:

```powershell
# ASCII-only is the safest choice for scripts destined for Windows PowerShell 5.1
$utf8Bom = New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($path, $text, $utf8Bom)
```

Verification command to re-run after fixing:

```powershell
$p = 'VeeamCleaner.ps1'
$e = $null; $t = $null
[void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $p), [ref]$t, [ref]$e)
"parse errors: $($e.Count)"   # must be 0
```

---

## High

### H1. `SupportsShouldProcess` is declared but never honored; `-WhatIf` performs the real uninstall

[VeeamCleaner.ps1:25](VeeamCleaner.ps1:25) declares `[CmdletBinding(SupportsShouldProcess)]`, but there are **zero** `$PSCmdlet.ShouldProcess(...)` calls in the file (AST/regex count: 0). `Remove-Item` at [line 217](VeeamCleaner.ps1:217), `Stop-Service` at [line 113](VeeamCleaner.ps1:113) and both `Start-Process` calls at [lines 173 and 181](VeeamCleaner.ps1:173) are not wrapped, so `-WhatIf` is accepted by the parser and then silently ignored.

Confirmed with a minimal repro of exactly this pattern under PS 5.1:

```text
> .\whatif_demo.ps1 -WhatIf
DELETED (WhatIf IGNORED -> destructive run)
```

Impact: an operator who runs `.\VeeamCleaner.ps1 -WhatIf` to preview the change will uninstall every Veeam product on the box. This is the single most dangerous defect in the file after C1.

Fix: gate each mutating action, and drop `SupportsShouldProcess` if you do not intend to honor it.

```powershell
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(...)

# services
foreach ($svc in $veeamServices) {
    if ($PSCmdlet.ShouldProcess($svc.DisplayName, 'Stop-Service')) {
        Stop-Service -Name $svc.Name -Force -ErrorAction Stop
    }
}

# uninstallers
if ($PSCmdlet.ShouldProcess($product.DisplayName, 'Uninstall')) { ... }

# file cleanup
foreach ($path in $veeamPaths) {
    if ($PSCmdlet.ShouldProcess($path, 'Remove-Item')) {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
    }
}
```

Note that with `ConfirmImpact = 'High'` the built-in `-Confirm` already asks for confirmation, which overlaps with the custom prompt at [line 97](VeeamCleaner.ps1:97). Pick one mechanism (see H4).

### H2. Uninstall strings that are unquoted and contain spaces never execute

[VeeamCleaner.ps1:181](VeeamCleaner.ps1:181) builds `cmd.exe /c "<UninstallString>"`. When the registry value is not quoted around the executable path (very common for third-party installers), `cmd` splits at the first space and the uninstaller never starts.

Repro under PS 5.1 with a real target whose path contains a space:

```text
Running: C:\...\sp ace\unins000.cmd /SILENT   ->  cmd.exe /c "C:\...\sp ace\unins000.cmd /SILENT"
exit=1
UNINSTALLER DID NOT RUN
cmd stderr: 'C:\...\xc\sp' is not recognized as an internal or external command
```

The script only records `Finished with exit code 1` ([line 190](VeeamCleaner.ps1:190)), so the operator sees a warning and moves on. The quoted variant (`"C:\path with space\unins000.exe" /SILENT`) does work, which is why this fails inconsistently across products.

Fix: split the executable from its arguments and quote deliberately instead of round-tripping through `cmd`.

```powershell
# Robust parse of an UninstallString into (exe, args)
$raw = $uninstallCmd.Trim()
if ($raw -match '^\s*"?([^"]+?\.exe)"?\s*(.*)$') {
    $exe  = $Matches[1]
    $args = $Matches[2]
} elseif ($raw -match '^\s*(\S+)\s+(.*)$') {
    $exe  = $Matches[1]; $args = $Matches[2]   # unquoted, no spaces in path
} else {
    $exe = $raw.Replace('"',''); $args = ''
}
if (-not (Test-Path -LiteralPath $exe)) { throw "Uninstaller not found: $exe" }
$proc = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -WorkingDirectory (Split-Path -Parent $exe)
```

### H3. Silent-flag detection regex is unanchored and case-insensitive, so UI uninstallers can hang the run

[VeeamCleaner.ps1:177](VeeamCleaner.ps1:177): `if ($uninstallCmd -notmatch '/S|/s|/quiet|/silent')`. Two problems.

1. `-match`/`-notmatch` are case-insensitive, so `/S`, `/s`, and the `/silent` alternative partially overlap; `/q` style flags such as `/QN` or `/VERYSILENT` are not detected either (only `/quiet` and `/silent` substrings).
2. The pattern is unanchored, so it matches inside file paths. Verified false negative:

```text
'C:/Veeam/setup.exe'          -> silent flag considered PRESENT (/s matched "/setup") -> /S never appended
'"C:\...\unins000.exe" /SILENT' -> correctly detected
```

Impact on an unattended server run: the uninstaller launches with a GUI prompt, `Start-Process -Wait` blocks forever, and the transcript looks like a hung script.

Fix: test only the argument portion, anchored to whitespace, and cover the real installer flag families.

```powershell
$exePart = $uninstallCmd; $argPart = ''
if ($uninstallCmd -match '(?i)\s(/.*)$') { $argPart = $Matches[1] }
if ($argPart -notmatch '(?i)^\s*(/S\b|/SILENT\b|/VERYSILENT\b|/QUIET\b|/q\b|/norestart\b|--silent\b|-s\b)') {
    $uninstallCmd += ' /S'      # or /VERYSILENT for Inno Setup based installers
}
```

### H4. Interactive `Read-Host` confirmation blocks automation and weakens the stated contract

[VeeamCleaner.ps1:97](VeeamCleaner.ps1:97) uses `Read-Host "Type YES to continue"`.

- Under a non-interactive host (SCCM/Intune, Task Scheduler, `psexec -i` absent, Jenkins agent) `Read-Host` returns empty or throws; the script aborts silently in pipelines and hangs in some hosted consoles. There is no `[Environment]::UserInteractive` check and no `-NonInteractive` path other than `-Force`.
- Because `-ne` on strings is case-insensitive in PowerShell, `yes`, `Yes` and `yES` all satisfy the "Type YES" prompt, which is weaker than the contract printed to the operator. Use `-cne 'YES'` if you want it literal, or better, replace the whole block with `$PSCmdlet.ShouldContinue(...)` so `-Force` maps onto `-Confirm:$false`.

---

## Medium

### M1. Services are stopped but never removed, and verification ignores services entirely
Step 3 stops services ([line 108](VeeamCleaner.ps1:108)), but nothing removes leftover service entries or the `HKLM:\SOFTWARE\Veeam` key tree. The verification step at [lines 229-238](VeeamCleaner.ps1:229) re-checks **only** registry uninstall entries, so a run can print "All Veeam products have been removed" while `VeeamBackupSvcHost`, `VeeamMEDIASvc` and friends remain registered (they frequently do after MSI removal). Add a post-uninstall service pass (`sc.exe delete` / `Remove-ItemProperty`) and include the service count in the summary.

### M2. Dedup by `PSChildName` can silently drop products, and discovery misses HKCU entries
[VeeamCleaner.ps1:54](VeeamCleaner.ps1:54) `Sort-Object PSChildName -Unique`. Verified semantics on PS 5.1: uniqueness is evaluated **on the sort key only**, and the record kept for a duplicated key is not necessarily the first one seen.

```text
input : {A} v1, {A} v2, {B} v3
output: {A} v2, {B} v3      # one object silently discarded per duplicate key
```

If two hives ever expose the same child name for different products (or a repair/upgrade stub shares a GUID), one product is dropped from the uninstall list without any message. Also, discovery matches `DisplayName -match 'Veeam'` only ([line 49](VeeamCleaner.ps1:49)): per-user installs under `HKCU:\...\Uninstall` are never scanned, and products whose display name omits "Veeam" (some OEM/agent builds) are missed even though `Publisher` is `Veeam Software`. Prefer matching on both properties and dedup with `Select-Object -Property * -Unique` or a hashtable keyed by `"Hive\PSChildName"`.

### M3. Uninstall order among equally ranked products is nondeterministic
The rank scriptblock at [lines 131-137](VeeamCleaner.ps1:131) assigns `99` to everything unmatched, and `Sort-Object` in Windows PowerShell is **not stable**. Verified:

```text
input : K=1 for V=1..6   -> Sort-Object K returns 4,5,6,1,2,3
```

So all core components (Backup Server, Repository, Backup & Replication, Cloud Connect) uninstall in an arbitrary order between runs. For Veeam this matters: repositories and infrastructure servers should be released before the backup server. Add a secondary explicit key (for example a second rank table or `Sort-Object { ... }, DisplayName`) to make ordering reproducible.

### M4. `$sortOrder` entries are used as regex patterns without escaping
[VeeamCleaner.ps1:135](VeeamCleaner.ps1:135) `if ($name -match $sortOrder[$i])`. Today the entries happen to be regex-safe, but any future entry containing `(`, `+`, `.`, `[` will throw inside the sort scriptblock and abort the whole step. Verified failure mode:

```text
'Enterprise Manager(' -> parsing "Enterprise Manager(" - Not enough )'s.
```

Use `-like "*$($sortOrder[$i])*"` or `[regex]::Escape($sortOrder[$i])`.

### M5. MSI branch discards `QuietUninstallString` and mishandles edge-case exit codes
[VeeamCleaner.ps1:163-175](VeeamCleaner.ps1:163): once a string looks like msiexec, the script ignores whatever silent switches the vendor published in `QuietUninstallString` and re-derives a product code. It also treats every non-zero/non-3010 code as failure, including `1605`/`1614` ("product not installed", which should count as already-clean) and does not handle `$null` exit codes from `Start-Process -PassThru` (prints "exit code " with a blank). Consider logging the MSI log (`/L"V${log}"`) so failures are diagnosable, and normalizing exit codes through a small map.

### M6. Cleanup paths are built from environment variables without validation
[VeeamCleaner.ps1:205-218](VeeamCleaner.ps1:205). If `ProgramFiles` or `ProgramFiles(x86)` is unavailable in the service account's token (happens with some non-interactive tokens), `"$env:ProgramFiles\Veeam"` becomes `\Veeam`, which resolves **relative to the current drive root** (verified: built string is `\Veeam`). A recursive forced delete on a drive-root-relative path is exactly the class of bug that destroys data. Also `$env:ProgramData\Veeam` and `$env:ALLUSERSPROFILE\Veeam` are the same directory on Vista+, so one entry always misses; nothing guards against junctions/reparse points, and `-Path` is used where `-LiteralPath` belongs.

Suggested hardening:

```powershell
foreach ($path in $veeamPaths) {
    if ([string]::IsNullOrWhiteSpace($path)) { continue }
    $full = [System.IO.Path]::GetFullPath($path)
    if (-not [System.IO.Directory]::Exists($full)) { continue }
    # refuse anything that is not under a known root, and refuse reparse points
    $root = Split-Path -Qualifier $full
    if ($full.Split('\').Count -lt 3) { Write-Warning "Refusing to delete suspicious path: $full"; continue }
    if ((Get-Item -LiteralPath $full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        Write-Warning "Skipping reparse point: $full"; continue
    }
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
}
```

### M7. Transcript handling: world-writable default location, no `finally`, unbalanced stop
[VeeamCleaner.ps1:32](VeeamCleaner.ps1:32) writes the log to `$env:TEMP` by default; `%TEMP%` is per-user but a transcript of an elevated run records the full software inventory and any uninstaller output, which is disclosure-sensitive on shared servers. `Stop-Transcript` appears at [lines 91, 100 and 253](VeeamCleaner.ps1:91) with no `try/finally`; if `Start-Transcript` ever fails (permissions, `-Path` pointing at an existing directory), the trailing call emits a second error. Verified behavior on PS 5.1:

```text
Stop-Transcript : An error occurred stopping transcription: The host is not currently transcribing.
```

Wrap the body in `try { ... } finally { if ($transcriptStarted) { Stop-Transcript } }` and default to a dedicated directory such as `C:\VeeamRemovalLogs` created with restricted ACLs. (Note: PS 5.1 does create missing parent directories for `-Path`, so the common "missing folder" concern is not an issue here.)

---

## Low / informational

| ID | Location | Note |
| --- | --- | --- |
| L1 | [lines 19-22](VeeamCleaner.ps1:19) | Comment-based help examples call `.\Remove-VeeamComponents.ps1`, but the file is `VeeamCleaner.ps1`. `Get-Help .\VeeamCleaner.ps1 -Examples` therefore shows commands that do not exist. |
| L2 | [lines 106, 124, 200, 229](VeeamCleaner.ps1:106) | Comment step labels (`STEP 4..7`) are off by one relative to the console labels printed at lines 108, 127, 203, 231 (`Step 3..6`). Confusing when triaging a transcript. |
| L3 | [line 1](VeeamCleaner.ps1:1) | `#Requires -RunAsAdministrator` is valid on PS 5.1 (v4+). Nothing checks for a pending reboot (`HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations`) or running backup jobs before removal, which is the usual cause of "half removed" servers. |
| L4 | [lines 45-51](VeeamCleaner.ps1:45) | `$found += ...` builds arrays by copy; fine at this scale, but `foreach-object -MemberInfo`/generic list would be idiomatic for larger inventories. |
| L5 | [line 187](VeeamCleaner.ps1:187) (141 chars), [line 251](VeeamCleaner.ps1:251) (201 chars) | Two lines exceed 120 characters. Cosmetic, but line 187 is one of the three fatal em-dash sites from C1, so it will be touched anyway. |
| L6 | [line 181](VeeamCleaner.ps1:181) | `Start-Process` inherits the current directory. If the script is launched from a UNC share (common for this kind of tooling), `cmd.exe` prints "UNC paths are not supported. Defaulting to Windows directory." Observed in testing; harmless but noisy, and it can break uninstallers that resolve relative paths. Pass `-WorkingDirectory`. |
| L7 | 37 `Write-Host` calls | All output goes to the host, so nothing is returnable or testable: no object pipeline result for a caller or orchestrator to consume. Consider emitting a final `[pscustomobject]` summary via `Write-Output`, keeping `Write-Host` for progress only. |

---

## Sensitive information review

No sensitive data present in the file. Pattern scan results (all negative):

| Category scanned | Result |
| --- | --- |
| Password/passwd/pwd assignments | none |
| Secret, API key, access token, bearer, credential assignment | none |
| `ConvertTo-SecureString`, `-Credential`, `NetworkCredential` usage | none |
| IPv4 literals | none |
| URLs (`http://`, `https://`, `ftp://`, `smb://`) | none |
| UNC paths to named servers/shares | none |
| E-mail addresses | none |
| Domains/FQDNs (`.local`, `.corp`, `.internal`, ...) | none |
| Hardcoded computer/server names or `-ComputerName` targets | none |
| Cloud credentials (`AKIA...`, PEM blocks) | none |
| Environment-specific GUID literals | none |
| Named authors, owners, copyright/contact strings | none |

All machine-specific values come from environment variables at runtime (`$env:TEMP`, `$env:ProgramFiles`, `${env:ProgramFiles(x86)}`, `$env:ProgramData`, `$env:ALLUSERSPROFILE`), which is the correct approach. The only residual data-handling concern is where the transcript lands (M7): it records an inventory of installed software, versions and GUIDs plus uninstaller output, so keep it out of world-writable locations when you fix M7.

## Orphaned / unused variable review

AST analysis of every `VariableExpressionAst` (writes vs reads). **No orphaned variables: every assigned variable is read at least once, and all three parameters are used.** The single function defined (`Get-InstalledVeeamProducts`) is called twice ([line 61](VeeamCleaner.ps1:61), [line 232](VeeamCleaner.ps1:232)), so there is no dead code.

| Variable | Written at | Read at | Status |
| --- | --- | --- | --- |
| `$confirm` | 97 | 98 | used |
| `$failCount` | 141 | 157, 191, 195, 247, 248, 251 | used |
| `$found` | 45, 48 | 54 | used |
| `$guid` | 166, 168 | 172, 173 | used (see note) |
| `$i`, `$name`, `$rank` | 134, 132, 133/135 | 134-137 | used (sort scriptblock) |
| `$path` | 46, 214 | 47, 48, 215, 217, 218, 220 | used (two separate loops) |
| `$proc` | 173, 181 | 186, 187, 190 | used |
| `$product` | 143 | 144-150, 156, 167, 168, 194 | used |
| `$regPaths` | 41 | 46 | used |
| `$remaining` | 232 | 233, 237, 251 | used |
| `$sortOrder`, `$sortedProducts` | 130, 131 | 134, 135 / 143 | used |
| `$successCount` | 140 | 188, 246 | used |
| `$svc` | 109 | 111-116, 119 | used |
| `$uninstallCmd` | 147, 178 | 155, 163, 165, 177, 180, 182 | used |
| `$veeamPaths` | 205 | 214 | used |
| `$veeamProducts`, `$veeamServices` | 61, 76 | many | used |
| `$Force`, `$SkipFileCleanup`, `$LogPath` (params) | param block | 95 / 202 / 32, 34, 250 | all used |

Notes:
- Automatic variables only: `$_`, `$matches` ([line 166](VeeamCleaner.ps1:166)), `$null`. Nothing shadows a PowerShell automatic variable.
- `$guid` and `$proc` persist across loop iterations, which is normally a latent bug source. Here it is safe because the MSI branch throws before using a stale `$guid`; worth keeping in mind if M5 changes that control flow.
- `($veeamProducts.Count -eq 0)` at [lines 63 and 89](VeeamCleaner.ps1:63) looks risky but is fine on PS 3+: `.Count` on `$null` returns `0` (verified), so the empty-result path does not throw.

## PowerShell 5.1 compatibility validation

Parsed with Windows PowerShell **5.1.26100.9444**.

| Check | Result |
| --- | --- |
| Syntax parse of file as delivered | **FAILS: 8 parser errors** (see C1) |
| Syntax parse after replacing em-dashes in string literals only | Passes, 0 errors |
| Null-conditional `??`, null-coalescing assignment `??=` | Not used (0 occurrences), safe |
| Ternary operator `? :` | Not used, safe |
| Pipeline chain operators `&&`, `\|\|` | Not used, safe |
| `ForEach-Object -Parallel`, `-PipelineVariable` overuse | Not used, safe |
| Static method `::new()` syntax (PS 5+ only) | Not used; script uses no type instantiation, safe on even PS 4 |
| `class` / `enum` declarations | None |
| `${env:ProgramFiles(x86)}` brace form [line 208](VeeamCleaner.ps1:208) | Correct and required for 5.1, good |
| `[CmdletBinding(SupportsShouldProcess)]`, advanced function syntax | Supported in 5.1 (but see H1 for semantics) |
| `#Requires -RunAsAdministrator` [line 1](VeeamCleaner.ps1:1) | Supported since PS 4, good |
| `Start-Transcript -Path ... -Append`, `Stop-Transcript` | Supported in 5.1 (see M7 for robustness) |
| `.Count` on `$null` / single object [lines 63, 66, 80, 89](VeeamCleaner.ps1:63) | Returns 0/1 on PS 3+, verified safe |
| `Sort-Object <Property> -Unique` semantics [line 54](VeeamCleaner.ps1:54) | Works in 5.1; dedups by sort key only (see M2) |
| `-f` format operator, subexpressions `$()`, backtick `` `n `` escapes | Supported, used correctly (`\n` literals are not present) |
| Approved verb usage (`Get-InstalledVeeamProducts`) | Complies with PowerShell verb guidance |
| Line endings / tabs | CRLF throughout (252/252), no tabs, no trailing whitespace |

Bottom line: apart from the encoding problem in C1, the script uses only constructs available in Windows PowerShell 5.1 and will also run unchanged under PowerShell 7 once re-saved.

## Emoji and em-dash identification

- **Emoji: none.** A scan for surrogate pairs and the emoji/dingbat/arrow blocks (`U+1F300-U+1FAFF`, `U+2600-U+27BF`, `U+2190-U+2BFF`, variation selector `U+FE0F`) returned 0 matches.
- **Non-ASCII characters: exactly 12, all `U+2014` em-dash** (36 bytes total, all `E2 80 94`). No other non-ASCII codepoint exists in the file, so there are no smart quotes, NBSPs or zero-width characters.

| Line | Context | Inside string literal? |
| --- | --- | --- |
| [58](VeeamCleaner.ps1:58) | `# STEP 1 — Discover Veeam products` | comment only |
| [73](VeeamCleaner.ps1:73) | `# STEP 2 — Discover Veeam services` | comment only |
| [81](VeeamCleaner.ps1:81) | `Write-Host ("  {0} ({1}) — {2}" -f ...)` | **yes, fatal (C1)** |
| [87](VeeamCleaner.ps1:87) | `# STEP 3 — Confirm before proceeding` | comment only |
| [106](VeeamCleaner.ps1:106) | `# STEP 4 — Stop Veeam services` | comment only |
| [124](VeeamCleaner.ps1:124) | `# STEP 5 — Uninstall Veeam products` | comment only |
| [146](VeeamCleaner.ps1:146) | `# Build the uninstall command — prefer QuietUninstallString...` | comment only |
| [176](VeeamCleaner.ps1:176) | `# EXE-based uninstall — append silent flags if not already present` | comment only |
| [187](VeeamCleaner.ps1:187) | `' — reboot required'` inside interpolated string | **yes, fatal (C1)** |
| [190](VeeamCleaner.ps1:190) | `Write-Warning "... — may not have uninstalled cleanly."` | **yes, fatal (C1)** |
| [200](VeeamCleaner.ps1:200) | `# STEP 6 — Remove leftover files / folders` | comment only |
| [229](VeeamCleaner.ps1:229) | `# STEP 7 — Re-check registry to confirm removal` | comment only |

Safe bulk fix (also resolves C1):

```powershell
$text = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
$text = $text.Replace([string][char]0x2014, '-').Replace([string][char]0x2013, '-')
[System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))  # ASCII-only now, BOM optional
```

## Watermarking and provenance

**No watermarking or hidden provenance markers detected.** Evidence:

| Check | Result |
| --- | --- |
| Non-ASCII codepoint inventory | Only `U+2014` (em-dash). No invisible/zero-width characters, no `U+FEFF` mid-file BOMs, no Unicode tag block (`U+E0000-U+E007F`) or variation-selector based hidden payloads. |
| Homoglyph / confusable identifiers | None; all identifiers are plain ASCII. |
| Whitespace steganography | 0 lines with trailing whitespace, 0 tab characters (indentation is 4 spaces throughout). |
| Comment content | All 36 comment lines reviewed: purely functional. No author name, no e-mail, no copyright/owner/maintainer line, no "generated by"/"AI assistant"/model/version banner, no ticket IDs, no TODO/FIXME breadcrumbs left behind. |
| NTFS alternate data streams | Single stream `:$DATA` (10,683 bytes). No `Zone.Identifier` (file was not downloaded through a browser), no `UserDefined.Comment`, no `PromptServerUI`/`O:EUD` metadata streams. |
| Authenticode signature | `NotSigned`. |
| Version control provenance | No `.git` directory or commit trailers available in the folder, so no `Co-authored-by` / model attribution trailers to inspect. |
| File timestamps | CreationTime 2026-09-28 20:59 vs LastWriteTime 2026-05-27 11:11 (write precedes creation), consistent with the file being copied/restored onto this share while carrying its original timestamp. Benign, but worth knowing when you reason about change history. |

---

## Recommended remediation order

1. **C1** re-save as ASCII/UTF-8-with-BOM and replace all 12 em-dashes; confirm `ParseFile` reports 0 errors on Windows PowerShell 5.1.
2. **H1** add `$PSCmdlet.ShouldProcess(...)` around every mutating call (or remove `SupportsShouldProcess`) so `-WhatIf` is truthful.
3. **H2/H3** rewrite the uninstall invocation: parse exe and arguments, quote the path, anchor the silent-flag regex, prefer native `Start-Process -FilePath $exe -ArgumentList $args` over a `cmd /c` wrapper.
4. **H4/M7** replace `Read-Host` with `ShouldContinue`, wrap the body in `try/finally` for transcript safety, and move the default log out of `%TEMP%`.
5. **M1-M6** add service cleanup plus a verification pass that reports services too; harden discovery (HKCU + Publisher), make ordering deterministic, escape sort patterns, validate delete targets with `-LiteralPath`, reparse-point and depth guards.
6. **L1/L2** fix the example script name and align step numbering.

## How to reproduce these results

```powershell
# 1. Parse under Windows PowerShell 5.1 (this is what fails today)
$e = $null; $t = $null
[void][System.Management.Automation.Language.Parser]::ParseFile('VeeamCleaner.ps1', [ref]$t, [ref]$e)
$e | ForEach-Object { "{0}: {1}" -f $_.Extent.StartLineNumber, $_.Message }

# 2. Encoding / non-ASCII inventory
$b = [System.IO.File]::ReadAllBytes('VeeamCleaner.ps1')
"first bytes: " + (($b[0..3] | ForEach-Object { $_.ToString('X2') }) -join ' ')   # 23 52 65 71 = no BOM
($b | Where-Object { $_ -gt 127 } | Sort-Object -Unique | ForEach-Object { '0x{0:X2}' -f $_ })  # 0xE2 0x80 0x94

# 3. Alternate data streams / signature
Get-Item .\VeeamCleaner.ps1 -Stream *
Get-AuthenticodeSignature .\VeeamCleaner.ps1 | Select-Object Status, StatusMessage

# 4. Optional: install the official linter and re-run
Install-Module PSScriptAnalyzer -Scope CurrentUser -Force
Invoke-ScriptAnalyzer -Path .\VeeamCleaner.ps1 -Settings @{ Rules = @{ PSUseShouldProcessForStateChangingFunctions = @{ Severity='Warning' } } }
```

*Note: the probes that created directories under `C:\` and `%TEMP%` during testing were removed afterwards; no files outside this report were added to the project.*
