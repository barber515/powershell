# AuditMe

Comprehensive Windows security audit tool. Runs 30 checks across installed software, system configuration, network posture, and credential hygiene, then exports a single collapsible HTML report with color-coded risk indicators.

## Requirements

- **OS:** Windows 7 / Server 2008 R2 or later
- **PowerShell:** 5.1 or later (`#Requires -Version 5.1`)
- **Privileges:** Run as Administrator for full coverage. Many registry, service, and credential queries fail silently without elevation.
- **Dependencies:** No external modules required. `Microsoft.PowerShell.LocalAccounts` is optional (used for user account audit on Windows 10/11).

## Quick Start

```powershell
# Default: saves report.html to the script directory
.\auditMe.ps1

# Custom output path
.\auditMe.ps1 -ExportPath "C:\Reports\audit.html"

# Condensed console output (report is identical)
.\auditMe.ps1 -OutputMode Summary
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-ExportPath` | string | `.\report.html` | Full path for the HTML report. Parent directories are created automatically. |
| `-OutputMode` | `Detailed` or `Summary` | `Detailed` | Controls console verbosity. Report output is unchanged. |

## Audit Coverage

Checks are grouped by domain. Each check carries a risk level: Critical, High, Medium, Low, Pass, or Info.

### Software & Updates
- **Installed Programs** -- Registry-based inventory of installed software; flags known risky applications (Flash, Java 6/7, Silverlight, QuickTime, RealPlayer). Reports hotfix count and most recent update.
- **Windows Update** -- Windows Update Agent history, last update date (flags >30 days), pending reboot detection, service status.

### Network & Connectivity
- **Networking** -- TCP/IP profile categories, DNS server addresses, ARP cache anomalies, listening ports (flags non-standard privileged ports), RDP exposure.
- **DNS Client** -- DHCP vs static configuration, DNS suffix search order, registration behavior.
- **Windows Time** -- W32Time service status, NTP source configuration, current time sync status.

### Hosts & Firewall
- **Hosts File** -- Parses active entries; flags suspicious patterns (malware domains, localhost redirects, IP-only entries).
- **Windows Firewall** -- Domain/Private/Public profile status; flags rules without descriptions, overly permissive address filters, and unrestricted remote access rules.

### Endpoint Protection
- **Windows Defender** -- Antimalware enabled, real-time protection, exclusion count (flags >10 and >50), disabled components, pending/expired threat definitions.
- **Third-Party AV/EDR** -- Registry-based AV inventory; running EDR service detection (CrowdStrike, SentinelOne, Carbon Black, Sophos, Kaspersky, etc.).

### Identity & Access
- **User Accounts** -- Local user inventory (requires LocalAccounts module), password policy compliance, passwordless accounts, Guest account status, local admin group membership.
- **Credential Manager** -- Stored credential targets; flags entries matching domain controllers, databases, admin accounts, and remote access systems.
- **Wi-Fi Profiles** -- Saved wireless profiles with key material; flags profiles exposing stored passwords.

### System Configuration
- **Registry Security** -- UAC configuration (EnableLUA, ConsentPromptBehaviorAdmin), LSA notification packages (flags Mimikatz indicators), Image File Execution Options debugger entries.
- **Local Security Policy** -- Password complexity, minimum length, account lockout threshold/duration, Kerberos ticket age, LSA security settings.
- **Registry Options** -- 34 security policy keys under HKLM\Policies\System; flags deviations from baseline values.
- **Startup Programs** -- HKLM/HKCU Run keys, Startup folders, Win32_StartupCommand; flags PowerShell/cmd/wscript entries and HTTP-based persistence.
- **Task Scheduler** -- SYSTEM-level tasks, script execution tasks (PowerShell, cmd, wscript), tasks with missing principals.
- **Services** -- Running service inventory; flags services from temp/AppData paths, disabled-but-running services, risky services (Print Spooler, Telnet, TFTP, Remote Registry).

### Encryption & Hardware
- **BitLocker** -- Per-volume encryption status, encryption method, key protector types.
- **TPM / Secure Boot** -- TPM presence and readiness, Secure Boot state, UEFI firmware details.
- **Credential Guard / VBS** -- Device Guard status, Virtualization Based Security, LsaCfgFlags configuration.

### Logging & Monitoring
- **Audit Policy** -- Event ID 4625 (failed logon) activity; flags disabled or low-activity logging.
- **Event Log Config** -- Max size, retention policy, overflow behavior for Security, System, Application, Setup, ForwardedEvents, and PowerShell logs.

### Remote Management
- **WinRM** -- Service status, AllowUnencrypted setting, authentication methods, listener presence, port reachability (5985/5986).

### File System
- **File System ACLs** -- Access control lists on C:\Windows, System32, Program Files, ProgramData, Temp, and AllUsersProfile; flags non-standard write/modify permissions.

### Platform Context
- **Group Policy** -- Domain membership, gpresult health, local GPO presence.
- **Print Spooler** -- Service status, PrintNightmare (CVE-2021-34527) relevance, installed printer count.
- **System Information** -- OS build, architecture, RAM, CPU, disk capacity and utilization (flags >80% and >90% usage).

## Output Format

The script produces a single HTML file with:

- **Summary cards** at the top showing counts per risk level (Critical, High, Medium, Low, Pass).
- **Collapsible sections** for each audit domain. Click headers to expand/collapse.
- **Color-coded rows** -- Critical (red), High (pink), Medium (amber), Low (green), Pass (green), Info (gray).
- **Auto-collapse** -- Non-critical sections (Installed Programs, Networking, Hosts File) collapse automatically after 800ms if they contain no critical findings.

## Predictable Export Outcomes

To ensure consistent, repeatable results:

1. **Run elevated.** Open PowerShell as Administrator before executing. Many registry keys, service permissions, and credential queries require elevation.
2. **Pin the export path.** Use `-ExportPath` with an absolute path to avoid ambiguity across working directories.
3. **Use `-OutputMode Summary`** in automated pipelines. The report is identical; this suppresses per-check console noise.
4. **Run during low activity.** The script queries Windows Update Agent COM objects and enumerates all scheduled tasks. On heavily loaded systems, some queries may time out.
5. **Clear stale temp files.** The script writes `secpol_export.sdb` to `$env:TEMP` during the Local Security Policy check. Ensure the temp directory is writable.
6. **For domain-joined machines,** run from a domain-connected network to ensure `gpresult` and `Get-CimInstance` queries resolve correctly.

## Limitations

- **Offline systems** -- Windows Update Agent queries and domain GPO checks will report incomplete data.
- **Non-admin execution** -- User account audit, some registry reads, and Credential Manager enumeration will be skipped or partial.
- **Windows Server** -- Audit Policy check uses `Get-WindowsFeature` on server OS; requires RSAT or Server Core features.
- **Third-party AV** -- Detection is registry-based. Some EDR products hide their presence from standard registry paths.
