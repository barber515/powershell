# Invoke-ADSecurityAudit

Read-only Active Directory security audit that emits a styled HTML report.

## Overview

Runs a battery of read-only AD queries covering privileged access, DCSync rights, Kerberos delegation, roastable accounts, password hygiene, stale objects, trusts, LAPS coverage, and ADCS certificate-template misconfigurations. Produces a single self-contained HTML report with a risk summary and per-section tables.

**Every query is read-only. The script makes no changes to the directory.**

## Requirements

- **PowerShell 7+**
- **ActiveDirectory module** (RSAT): `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`
- A domain-joined account with read access to the directory (some attributes like LAPS require delegated read permissions)

## Usage

```powershell
.\Invoke-ADSecurityAudit.ps1
.\Invoke-ADSecurityAudit.ps1 -InactiveDays 60 -Sections Privileged,Delegation,ADCS
.\Invoke-ADSecurityAudit.ps1 -Server dc01.contoso.com -NoLaunch -OutputPath \\fs01\audit$\ad.html
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `OutputPath` | string | `.\AD-Security-Audit_YYYYMMDD_HHMMSS.html` | Full path for the HTML report |
| `InactiveDays` | int | `90` | Threshold for flagging stale users/computers |
| `Sections` | string[] | `All` | Which sections to run: `Privileged`, `Delegation`, `DCSync`, `Roasting`, `Passwords`, `Stale`, `Trusts`, `LAPS`, `ADCS` |
| `Server` | string | Auto-located DC | Optional target DC / domain |
| `NoLaunch` | switch | Off | Do not open the report in the default browser after completion |

## Report Sections

| Section | Severity | Description |
|---------|----------|-------------|
| Privileged Group Membership | High | Effective members of high-value groups, expanded recursively |
| Orphaned adminCount=1 Objects | Medium | Users with adminCount=1 no longer in any protected group |
| Privileged Accounts NOT in Protected Users | Medium | Domain Admins not enrolled in Protected Users |
| Unconstrained Delegation | Critical | Accounts trusted for delegation to any service |
| Constrained Delegation | High | Accounts allowed to delegate to named services |
| Resource-Based Constrained Delegation | High | Computers with msDS-AllowedToActOnBehalfOfOtherIdentity set |
| DCSync Rights | Critical | Principals with DS-Replication-Get-Changes extended rights |
| Kerberoastable Accounts | High | User accounts with SPNs (crackable service tickets) |
| AS-REP Roastable Accounts | High | Accounts with Kerberos pre-authentication disabled |
| Password Never Expires | Medium | Enabled accounts with no password expiration |
| Password Not Required | High | Accounts permitting empty passwords |
| Reversible Encryption Enabled | Critical | Accounts storing passwords in recoverable form |
| krbtgt Password Age | Medium | Age of the krbtgt account password |
| Inactive Users / Computers | Medium | Enabled objects dormant beyond the threshold |
| Legacy / Unsupported OS | High | Computers running out-of-support OS versions |
| Domain / Forest Trusts | Medium | Trust configuration and SID filtering state |
| LAPS Coverage | Medium | Computers missing a managed local admin password |
| ADCS ESC1 Templates | Critical | Templates where enrollee supplies subject + broad enrollment rights |

## Security Note

The generated report contains privileged-account lists, DCSync holders, roastable service accounts, and any live ESC1 paths. **Store and transmit it as restricted material.**

## See Also

For scored, attack-path depth analysis, pair this with [PingCastle](https://www.pingcastle.com), [BloodHound](https://github.com/BloodHoundAD/BloodHound), and [Locksmith](https://github.com/PowerShellMafia/Locksmith).
