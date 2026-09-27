# unQuoted

PowerShell script that finds and remediates **unquoted Windows service paths** on the local machine (CWE-426).

An unquoted service path is a service binary path that is not wrapped in double quotes but contains a space. An attacker with write access to a directory along that path can plant a malicious executable that runs with the service's privileges at service start — a classic local privilege escalation vector.

## Requirements

- Windows
- PowerShell 5.1+ (`#Requires -Version 5.1`)
- **Administrator** — both modes fail fast with a clear error if not elevated

## Usage

```powershell
# Audit: generate a styled HTML report of all unquoted service paths (read-only)
.\unQuoted.ps1 -Audit

# Audit to a specific path, without opening the report
.\unQuoted.ps1 -Audit -OutputPath D:\Reports\unquoted.html -NoLaunch

# Interactive remediation: Yes/No prompt per unquoted service
.\unQuoted.ps1 -FixAll
```

| Mode | Parameter | Behavior |
|------|-----------|----------|
| Audit | `-Audit` | Queries all local services, flags unquoted paths, writes a self-contained HTML report. Nothing is modified. |
| Fix | `-FixAll` | Walks each unquoted service path in the terminal and prompts Yes/No. **Yes** wraps the entire `PathName` in double quotes via `Set-Service` and verifies the change; **No** skips to the next service. Ends with a fixed / skipped / failed summary. |

### Parameters

| Parameter | Set | Description |
|-----------|-----|-------------|
| `-Audit` | Audit | Run the read-only audit and generate the HTML report. |
| `-FixAll` | FixAll | Interactively remediate unquoted service paths. |
| `-OutputPath` | Audit | Report destination. Default: `.\UnquotedServices_<yyyyMMdd_HHmmss>.html` |
| `-NoLaunch` | Audit | Skip opening the report in the default browser (useful for headless sessions). |

## Detection logic

A service is flagged when its `PathName`:

1. is not empty,
2. does **not** start with `"`, and
3. contains at least one space.

Note: standard `svchost.exe` entries with `-k`/`-p` arguments are flagged by this rule (the arguments contain spaces). That is normal — quote the full string if you want to suppress the finding, or skip them during `-FixAll`.

## HTML report

The `-Audit` report is a single self-contained HTML file (no external CSS/JS) following standard report conventions:

- Summary roll-up table (severity / check / finding count) at the top
- One section per check, each with a severity badge, description, and result table
- **Unquoted Service Paths** section (High) — service name, display name, state, current path, and the proposed `QuotedPath`
- **Scan Summary** section (Info) — total services scanned, unquoted count, unquoted-and-running count
- Header with target, timestamp, and run-by identity; restricted-data classification banner; footer disclaimers
- Written UTF-8; all dynamic values HTML-encoded

## Safety notes

- `-Audit` is strictly read-only — no service configuration is touched.
- `-FixAll` only wraps the **entire existing PathName** in double quotes; it does not parse or alter arguments. Review paths with complex or embedded quotes manually.
- Binary-path changes take effect the **next time the service is restarted**.
- Every `-FixAll` change is verified by reading the path back after `Set-Service`.
