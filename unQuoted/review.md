# Code Review: unQuoted.ps1

**Date:** 2026-09-27  
**Reviewer:** Bionic (Security Engineer)  
**Scope:** Orphaned/undeclared objects, constraint compliance  

---

## 1. Orphaned Objects (Declared but Never Used)

### Finding: `-VulnerableOnly` parameter in `Get-UnquotedServiceAssessment` (line ~248)

```powershell
function Get-UnquotedServiceAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [switch]$IncludeNotVulnerable,

        [Parameter(ParameterSetName = 'VulnerableOnly')]
        [switch]$VulnerableOnly   # <-- ORPHANED: never referenced in function body
    )
```

**Issue:** The `-VulnerableOnly` parameter is declared with its own ParameterSetName but no code branch ever checks `$VulnerableOnly`. It has zero effect on execution. The only conditional that gates output is `$IncludeNotVulnerable`.

**Impact:** Low — the script runs correctly regardless, but this is dead code and misleading to callers who might expect it to filter results differently than `-IncludeNotVulnerable`.

---

## 2. Undeclared Objects (Used Without Being Defined)

**None found.** All variables are either:
- Function parameters (declared in `param()` blocks)
- Loop/iteration variables (`$service`, `$part`, `$access`, `$sec`, etc.)
- Assigned before use within the same scope
- Built-in automatic variables (`$PSCmdlet.ParameterSetName`, `$env:*`)

---

## 3. Object Lifecycle Audit (All Functions & Variables)

| Function | Declared At | Called From | Status |
|----------|-------------|-------------|--------|
| `Test-IsAdministrator` | Line ~62 | Main flow (elevation check) | OK |
| `Get-AllServices` | Line ~74 | `Get-TrulyVulnerableService`, `Get-UnquotedServiceAssessment`, `Invoke-Audit` | OK |
| `Test-ContainsSpaceInFolder` | Line ~93 | `Get-TrulyVulnerableService`, `Get-UnquotedServiceAssessment` | OK |
| `Test-ParentDirectoryWritable` | Line ~128 | `Get-TrulyVulnerableService`, `Get-UnquotedServiceAssessment` | OK |
| `Get-TrulyVulnerableService` | Line ~175 | `Invoke-FixAll` (dispatch) | OK |
| `Get-UnquotedServiceAssessment` | Line ~206 | `Invoke-Audit` (dispatch) | OK |
| `ConvertTo-HtmlEncoded` | Line ~263 | `ConvertTo-HtmlTable`, inline in `Invoke-Audit` | OK |
| `ConvertTo-HtmlTable` | Line ~271 | `Invoke-Audit` | OK |
| `Add-Section` (nested) | Line ~305 | `Invoke-Audit` | OK |
| `Invoke-Audit` | Line ~348 | Dispatch switch block | OK |
| `Invoke-FixAll` | Line ~462 | Dispatch switch block | OK |

**Variables in `Invoke-Audit`:** `$totalServices`, `$allAssessments`, `$trulyVulnerable`, `$notVulnerable`, `$report`, `$sevColour`, `$body`, `$summaryRows`, `$summaryTable`, `$hTitle`, `$hUser`, `$html`, `$resolvedPath` — all declared and used.

**Variables in `Invoke-FixAll`:** `$fixed`, `$skipped`, `$failed`, `$index`, `$svc`, `$answer`, `$verify` — all declared and used.

---

## 4. Constraint Compliance (Security Criteria)

### Constraint 1a: Space must be in a folder name, not after .exe
- **Compliant.** `Test-ContainsSpaceInFolder` splits the path by `\`, tracks whether `.exe` has been encountered (`$exeFound`), and only flags spaces that appear *before* any `.exe` component. Spaces after `.exe` (e.g., quoted arguments) are correctly ignored.

### Constraint 1b: Unprivileged user must have write access to a parent intercept directory
- **Compliant.** `Test-ParentDirectoryWritable` walks each parent directory in the path, checks ACL entries for `BUILTIN\USERS`, `NT AUTHORITY\Authenticated Users`, and `EVERYONE`, and returns `$true` only if one of those groups has Write/Modify/FullControl rights.

### Constraint 2: Non-vulnerable scanned services listed at bottom of report
- **Compliant.** The HTML report includes a third section titled "Scanned - Not Vulnerable" (line ~415) listing all unquoted-with-space services that failed the parent-writability check, with reasons why.

---

## 5. Summary

| Category | Count | Severity |
|----------|-------|----------|
| Orphaned parameters | 1 (`-VulnerableOnly`) | Low |
| Undeclared variables | 0 | None |
| Constraint violations | 0 | None |
| Functions with no callers | 0 | None |

**Verdict:** The script is structurally sound. One orphaned parameter should be removed for cleanliness, but it does not affect runtime behavior or security correctness.
