# Exchange 2019 Migration Audit Toolkit

## Overview

This toolkit provides read-only audit scripts for assessing an on-premises Exchange 2019 environment's readiness for migration to Exchange Online. The scripts analyze mailboxes, mail flow, hybrid configuration, certificates, and other dependencies to determine retirement readiness.

## Files

| File | Description |
|------|-------------|
| `ExchangeAuditCommon.psm1` | Shared module with HTML report rendering and helper functions |
| `Invoke-ExchangeMigrationAudit.ps1` | Main audit script that generates the migration assessment report |

## Requirements

### System Requirements
- **Operating System:** Windows 10/11 or Windows Server 2016+
- **PowerShell Version:** Windows PowerShell 5.1 (required for Exchange 2019 cmdlets)
- **Exchange Management Shell:** Must be accessible on the target server

### Permissions
- Exchange Organization Management or Recipient Management role
- Active Directory read permissions for computer/object queries
- Local administrator rights to access IIS logs (optional)

## Usage

### Basic Usage

Run from the **Exchange Management Shell** on one of your Mailbox servers:

```powershell
# Navigate to the script directory
cd \\voldemort\shared\agent\Projects\powershell\Exchange

# Run the audit with default settings
.\Invoke-ExchangeMigrationAudit.ps1
```

### Advanced Usage

```powershell
# Custom output location and extended analysis window
.\Invoke-ExchangeMigrationAudit.ps1 `
    -OutputDirectory "D:\AuditResults" `
    -MessageTrackingDays 90 `
    -MailboxActivityWindowDays 120 `
    -IncludeIisLogs `
    -PublicDnsServer "8.8.8.8" `
    -ExportCsv
```

### Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `OutputDirectory` | Folder for HTML report, CSV evidence, and transcript | `.\ExchangeAudit_<timestamp>` |
| `MessageTrackingDays` | Days of message tracking to analyze (1-90) | 30 |
| `MailboxActivityWindowDays` | Days to consider mailbox as "active" (7-365) | 90 |
| `MaxTrackingEvents` | Safety valve for Get-MessageTrackingLog (1,000-2,000,000) | 250,000 |
| `IncludeIisLogs` | Parse IIS HTTP logs for client access analysis | `$false` |
| `IisLogDays` | Days of IIS logs to parse (1-30) | 7 |
| `PublicDnsServer` | External DNS resolver for MX/SPF checks (IPv4 or hostname) | Internal DNS |
| `ExportCsv` | Export each section's rows to CSV files | `$false` |
| `NoLaunch` | Don't open HTML report in browser after generation | `$false` |

## Output

### Generated Files

The script creates a timestamped output folder containing:

```
ExchangeAudit_2026-11-12_143052\
├── Exchange-Migration-Audit.html    # Main HTML report (self-contained)
├── audit-transcript.txt              # PowerShell console transcript
└── csv\                              # CSV evidence files (if -ExportCsv used)
    ├── Mailboxes_by_type.csv
    ├── SMTP_relay_sources.csv
    └── ...
```

### HTML Report Sections

The generated report includes:

1. **Retirement Assessment** - Executive summary with KPI cards and verdict
2. **Blockers and Required Actions** - Ordered list of migration blockers
3. **Exchange Servers and Patch Currency** - Version information per server
4. **Server Reachability** - ICMP connectivity check
5. **Database Availability Group and Copy Health** - DAG topology and status
6. **Mailbox Databases** - Size, whitespace, backup status
7. **Mailbox Counts and Content** - Per-database statistics
8. **Recipient Inventory** - Mailboxes by type (on-prem + cloud)
9. **On-Premises Mailboxes and Activity** - User mailbox activity evidence
10. **Empty or Dormant Mailboxes** - Immediate move candidates
11. **Cloud-Hosted Mailboxes Managed Locally** - RemoteMailbox objects
12. **Mail-Enabled Users, Contacts, Groups** - Directory-managed recipients
13. **Public Folder Mailboxes and Hierarchy** - PF migration blockers
14. **Accepted Domains, MX and SPF Posture** - Internet mail flow analysis
15. **Remote Domains** - Mail flow settings per domain
16. **Receive Connectors** - SMTP submission surface
17. **Relay and Anti-Spam Bypass Permissions** - Application permissions
18. **Send Connectors and Outbound Routing** - Mail egress configuration
19. **SMTP Submission Sources** - Relay source discovery (from message tracking)
20. **Message Tracking Retention** - Evidence window analysis
21. **Local Pickup and Replay Directory Usage** - File-based submission detection
22. **Transport Rules** - Rule inventory for migration planning
23. **Journaling Rules** - Compliance dependencies
24. **Hybrid Configuration** - Hybrid management assessment
25. **Intra-Organization Connectors** - Cross-premises sharing
26. **Federation Trust** - Federation state and certificate expiry
27. **Directory Synchronisation Traces** - Azure AD Connect indicators
28. **Client Access Surface** - Virtual directory endpoints
29. **POP/IMAP/RPC Endpoint Settings** - Legacy protocol usage
30. **ActiveSync Device Partnerships** - Mobile client inventory
31. **Client Access Rules** - Client traffic rules
32. **IIS HTTP Protocol Usage** (optional) - Client endpoint analysis
33. **Certificates** - Exchange certificate inventory and expiry
34. **Transport Agents** - Third-party agent detection
35. **Migration Batches** - Historical migration batch status

## Severity Levels

| Severity | Meaning |
|----------|---------|
| **Critical** | Exchange cannot be removed or is actively exposed until addressed |
| **High** | Significant dependency requiring attention before decommission |
| **Medium** | Important consideration for migration planning |
| **Low** | Informational, minor impact on retirement timeline |
| **Info** | General information about the environment |

## Common Scenarios

### Scenario 1: Initial Assessment
```powershell
.\Invoke-ExchangeMigrationAudit.ps1 -ExportCsv
```
Run this first to get a baseline understanding of your migration readiness.

### Scenario 2: Deep Dive with Extended Tracking
```powershell
.\Invoke-ExchangeMigrationAudit.ps1 `
    -MessageTrackingDays 90 `
    -MailboxActivityWindowDays 180 `
    -IncludeIisLogs `
    -PublicDnsServer "8.8.8.8" `
    -ExportCsv
```
Use this for comprehensive analysis, especially if you suspect quiet/quarterly relay jobs.

### Scenario 3: Pre-Migration Validation
```powershell
.\Invoke-ExchangeMigrationAudit.ps1 -OutputDirectory "C:\PreMigrationCheck"
```
Run immediately before starting migration to validate current state.

## Troubleshooting

### "The Exchange cmdlets are not available in this session"

**Solution:** Open the **Exchange Management Shell** (not regular PowerShell) and run from there. PowerShell 7 is NOT supported for Exchange 2019.

### High number of "STATS ERROR" mailboxes

**Cause:** Mailbox statistics collection failed for some mailboxes.

**Action:** Check mailbox database health with `Get-MailboxDatabaseCopyStatus` and verify the mailboxes exist.

### DNS query failures for MX/SPF records

**Cause:** The specified DNS server may be unreachable or the domain may not have MX records.

**Action:** Verify DNS connectivity with `Resolve-DnsName -Name contoso.com -Type MX`. Try a different DNS server like `8.8.8.8`.

### Empty pickup directory but "No relay sources found"

**Cause:** Applications using local pickup directory won't appear in message tracking logs.

**Action:** Check the Pickup and Replay directories manually:
```powershell
Get-TransportService | Select Name, PickupDirectoryPath, ReplayDirectoryPath
Test-Path (Get-TransportService).PickupDirectoryPath
```

### "Out of support" version warnings

**Context:** Exchange Server 2019 reached end of extended support on October 14, 2025. Security updates are only available through the Extended Security Updates (ESU) program.

**Action:** Prioritize migration to Exchange Online or apply ESU if you must extend on-premises deployment.

## Next Steps

After running this audit:

1. **Review the HTML report** - Start with the "Retirement Assessment" and "Blockers" sections
2. **Address Critical blockers** - Move active mailboxes, repoint MX records
3. **Run additional audits** - Consider `Invoke-SmtpRelayDiscovery.ps1` for 90-day relay analysis
4. **Test migration** - Use test batches before full cutover
5. **Document findings** - Record all blockers and remediation steps

## Notes

- **Read-only operation:** These scripts only read data; they never modify Exchange, AD, or DNS
- **Message tracking retention:** Default is 30 days; scheduled/quarterly jobs may be invisible
- **Mailbox activity:** Mailboxes that receive mail but are never opened show as "dormant"
- **DNS resolution:** Results reflect the resolver used; split-horizon DNS may show different results

## Version Information

- **Script Version:** 1.0 (November 2026)
- **Target Platform:** Exchange Server 2019 on Windows PowerShell 5.1
- **Author:** Exchange retirement toolkit

## License

Internal use only.