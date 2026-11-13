# whereLockOut.ps1 - Active Directory Account Lockout Investigation Tool

## Description

`whereLockOut.ps1` is a PowerShell script designed to identify, analyze, and remediate Active Directory account lockouts. It queries domain controllers for Security Event ID 4740 (account lockout events), correlates with related failure events (4625, 4771, 4776), and provides multiple operational modes including investigation, reporting, and bulk unlock.

The script features schema-validated XML parsing for reliable event extraction, comprehensive DC health monitoring, pattern analytics to detect brute-force and password spray attacks, and guarded bulk unlock functionality with protection for privileged accounts.

## Features

- **Multi-mode operation**: Report lockouts from Security logs, check current AD lock state, or run full investigations
- **Schema-validated parsing**: Uses XML element names (not positional indexing) for reliable event field extraction
- **DC health monitoring**: Reports status and performance metrics for each domain controller queried
- **Failure correlation**: Correlates 4625/4771/4771 events to identify source host, IP address, and protocol
- **Pattern analytics**: Detects brute-force attempts (single source hitting same account multiple times) and password spray attacks (single source targeting many accounts)
- **Auto-unlock ETA**: Calculates when locked accounts will automatically unlock based on domain lockout policy
- **Privileged account protection**: Refuses to unlock Domain Admins, Enterprise Admins, and other Tier-0 groups without explicit confirmation
- **Multiple output formats**: Table (console), CSV, JSON, HTML, or raw objects

## Requirements

- Windows PowerShell 5.1 (compatible with PowerShell 7)
- RSAT Active Directory module installed
- Read access to Security event logs on target domain controllers
- Appropriate permissions for unlock operations (Domain Admin or delegated rights)

## Usage

### Basic Lockout Report (Last 24 Hours)

```powershell
.\whereLockOut.ps1
```

Reports all lockouts from the last 24 hours across every DC in the current domain.

### Filter by Account and Time Window

```powershell
.\whereLockOut.ps1 -Identity jdoe,svc_backup -Since 7d
```

Returns lockout events for specified accounts over the past week.

### Check Currently Locked Accounts (AD State)

```powershell
.\whereLockOut.ps1 -Mode CurrentlyLocked -As Csv -OutputPath C:\reports\locked.csv
```

Queries AD directly for accounts whose `LockedOut` flag is true, independent of Security log retention. Exports to CSV.

### Investigate with Correlation

```powershell
.\whereLockOut.ps1 -Correlate -SuspectOnly -ThresholdAttempts 5
```

Finds accounts locked from a single source with at least 5 attempts (brute-force pattern).

### Bulk Unlock Accounts

```powershell
.\whereLockOut.ps1 -Unlock -Identity jdoe -WhatIf
```

Lists the unlock action without performing it (WhatIf mode).

To perform actual unlock:

```powershell
.\whereLockOut.ps1 -Unlock -Identity jdoe
```

### Export Results

```powershell
.\whereLockOut.ps1 -As Json -OutputPath C:\reports\lockouts.json
.\whereLockOut.ps1 -As Csv -OutputPath C:\reports\lockouts.csv
```

## Parameters

| Parameter | Description |
|-----------|-------------|
| `Mode` | Report \| CurrentlyLocked \| Investigate. Default: Report. "CurrentlyLocked" queries AD directly for accounts whose LockedOut flag is true. "Investigate" enables full correlation and analytics. |
| `Identity` | One or more account names to filter on. Server-side XPath filtering used when possible. Aliases: User, Account |
| `Since` | Time window start relative to `-Until`. Default: last 24 hours. Accepts timespans (e.g., `7d`, `12h`, `30m`) |
| `Until` | End time for query window. Default: current time |
| `All` | Query all events without time filtering. Overrides `-Since` and `-Until` |
| `MaxEvents` | Per-DC event cap. Default: 5000. Prevents unbounded Security log reads |
| `Domain` | Target domain name. Default: current user's logon domain |
| `Server` | One or more DC host names to query instead of enumerating all DCs in the target domain |
| `As` | Output format: Table \| Csv \| Json \| Html \| Object. Default: Table |
| `OutputPath` | File path (or directory) for export. No file written by default. Use `-Force` to overwrite existing files |
| `Unlock` | Guarded bulk unlock of accounts that are currently locked out in AD. Requires `-Identity`, `-Since`, or `-FromCsv` |
| `AllowPrivileged` | Permit unlocking Domain Admins, Enterprise Admins, and other Tier-0 groups. Without this switch, privileged accounts are refused |
| `FromCsv` | Path to a CSV previously exported by this tool; targets unlock from that file |
| `Correlate` | Pull 4625/4771/4776 failure events for each lockout to identify source host, IP address, and protocol (Kerberos vs NTLM) |
| `SuspectOnly` | When using `-Correlate`, emit only accounts matching heuristic patterns (brute-force or password spray) |
| `ThresholdAttempts` | Minimum attempts from one source before flagging as brute-force. Default: 3. Set to 0 to disable threshold check |
| `TimeoutSec` | Seconds per DC query before considered unreachable. Default: 30 |

## Output Fields

The report includes the following fields:

- **TimeUtc**: UTC timestamp of lockout event
- **LockedAccount**: Name of locked account
- **CallerComputer**: Computer that initiated the lockout (source system)
- **LoggingDc**: Domain controller that logged the event
- **StillLocked**: Whether account is currently locked (AD state, not log state)
- **AutoUnlockUtc**: Estimated unlock time based on domain lockout policy
- **TopSources**: Comma-separated list of source IPs/hosts and attempt counts from correlation

## Unlock Mode Behavior

When `-Unlock` is specified:

1. Validates target accounts exist and are currently locked
2. Checks for privileged account membership using SID-based detection
3. Refuses to unlock privileged accounts unless `-AllowPrivileged` is passed
4. Performs `Unlock-ADAccount` operation with `-WhatIf` support
5. Provides green confirmation on success, yellow/yellow warning on failure

### Privileged Account Detection

The script identifies privileged accounts by checking:

- Built-in Administrator (SID ending in -500)
- Built-in Guest (SID ending in -501)
- BUILTIN\Administrators (S-1-5-32-544)
- BUILTIN\Account Operators (S-1-5-32-548)
- BUILTIN\Server Operators (S-1-5-32-549)
- BUILTIN\Print Operators (S-1-5-32-550)
- BUILTIN\Backup Operators (S-1-5-32-551)
- Any group membership matching the above SIDs in `MemberOf` or `sIDHistory`

## Pattern Detection

### Brute Force
Identified when a single source (IP or workstation) makes multiple attempts against one account, exceeding `-ThresholdAttempts`.

### Password Spray
Identified when a single IP address targets more than 10 distinct accounts.

Pattern results include:
- **Pattern**: Type of attack detected
- **Source**: IP address or workstation name
- **Count**: Number of events from that source
- **Suspect**: True for flagged patterns
- **Score**: Risk score (up to 20 for brute-force, 8 for spray)
- **Reasons**: Human-readable explanation

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | One or more domain controllers had issues (not Ok or Ok_NoEvents) |
| 2 | Prerequisites not met (ActiveDirectory module unavailable, cannot determine domain) |
| 3 | Unlock operation failed due to invalid parameters |

## Examples

### Export All Lockouts from Last Week

```powershell
.\whereLockOut.ps1 -Since 7d -As Csv -OutputPath .\reports\last_week_lockouts.csv
```

### Investigate Specific Account with Full Correlation

```powershell
.\whereLockOut.ps1 -Mode Investigate -Identity svc_backup -Correlate -SuspectOnly
```

### Bulk Unlock from Previously Exported CSV

```powershell
.\whereLockOut.ps1 -Unlock -FromCsv .\reports\lockouts.csv -AllowPrivileged
```

### Check All Currently Locked Accounts (AD State) with Auto-Unlock Times

```powershell
.\whereLockOut.ps1 -Mode CurrentlyLocked | Format-Table Name, LockedOut, LockoutTime, AutoUnlockUtc -AutoSize
```

## Notes

- The script queries **all domain controllers** in the target domain by default. Use `-Server` to limit to specific DCs.
- Event 4740 events are stored in the Security log on each DC. Retention policy determines how far back you can query.
- For `CurrentlyLocked` mode, the PDC Emulator is queried for authoritative lock state.
- The script uses schema-validated XML parsing. If event schema changes (rare), a warning will be emitted indicating which element is missing or out of order.
- Correlation queries are performed against the DC that logged each 4740 event. If that DC doesn't have the related failure events, correlation data may be incomplete.

## License

This script is provided as-is for administrative use in Active Directory environments.
