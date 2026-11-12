#Requires -Version 5.0
<#
.SYNOPSIS
    Master inventory and retirement-readiness assessment for an on-premises Exchange 2019
    organisation that is moving to Exchange Online.

.DESCRIPTION
    Collects everything that determines whether the Mailbox servers can be decommissioned,
    and renders it as one self-contained HTML report:

      - what Exchange still hosts (mailboxes by type, activity evidence, public folders)
      - what still depends on it (hybrid, directory sync, accepted domains, MX posture,
        transport rules, journaling, client access surface, certificates, agents)
      - what relays through it (receive connectors, relay permissions, submission sources)

    It then computes a retirement verdict and an ordered blocker list.

    Designed for two-server estates (e.g. exchprod1a + dr-exchprod1a) but scales to any size.
    READ-ONLY: the script only calls Get-* / Test-* style cmdlets plus DNS lookups. It never
    changes Exchange, AD or DNS state.

.PARAMETER OutputDirectory
    Folder for the HTML report, CSV evidence and transcript. Default: .\ExchangeAudit_<timestamp>

.PARAMETER MessageTrackingDays
    Days of message tracking to analyse for relay-source discovery (1-90). The script reports
    what retention actually allows - most on-prem deployments keep 30 days by default.

.PARAMETER MailboxActivityWindowDays
    A mailbox that has logged on inside this window counts as "active" for the verdict.

.PARAMETER MaxTrackingEvents
    Safety valve per server for Get-MessageTrackingLog. Raise it for busy estates, or run
    Invoke-SmtpRelayDiscovery.ps1 which is tuned for long windows.

.PARAMETER IncludeIisLogs
    Also parse IIS (HTTP) logs to prove whether any client still hits the on-prem endpoints
    (OWA / EWS / EAS / MAPI / Autodiscover / RPC). Slow on busy servers; keep the window short.

.PARAMETER PublicDnsServer
    Resolver used for MX/SPF checks. Use an external resolver (e.g. 8.8.8.8) when the internal
    DNS zone is split-horizon, otherwise results reflect internal views only.

.PARAMETER ExportCsv
    Write every section's rows to CSV next to the report (recommended for evidence packs).

.EXAMPLE
    # In the Exchange Management Shell on exchprod1a:
    .\Invoke-ExchangeMigrationAudit.ps1 -ExportCsv

.EXAMPLE
    .\Invoke-ExchangeMigrationAudit.ps1 -MessageTrackingDays 90 -IncludeIisLogs -PublicDnsServer 8.8.8.8 -OutputDirectory D:\Audit

.NOTES
    Run from the Exchange Management Shell (Windows PowerShell 5.1). Requires the
    ExchangeAuditCommon.psm1 module in the same folder.
    Author: Exchange retirement toolkit v1.0 (November 2026)
#>

[CmdletBinding()]
param(
    [AllowEmptyString()]
    [string]$OutputDirectory = '',

    [ValidateRange(1, 90)]
    [int]$MessageTrackingDays = 30,

    [ValidateRange(7, 365)]
    [int]$MailboxActivityWindowDays = 90,

    [ValidateRange(1000, 2000000)]
    [int]$MaxTrackingEvents = 250000,

    [switch]$IncludeIisLogs,

    [ValidateRange(1, 30)]
    [int]$IisLogDays = 7,

    [Parameter(Mandatory=$false)]
    [ValidateScript({
        if ([string]::IsNullOrWhiteSpace($_)) { return $true }
        # Validate IPv4 address format or hostname
        if ($_ -match '^(\d{1,3}\.){3}\d{1,3}$') {
            $octets = $_.Split('.') | Where-Object { [int]$_ -ge 0 -and [int]$_ -le 255 }
            return $octets.Count -eq 4
        }
        # Allow hostname
        return $true
    })]
    [string]$PublicDnsServer = '',

    [switch]$ExportCsv,

    [switch]$NoLaunch
)

$ErrorActionPreference = 'Stop'

# =====================================================================
# Bootstrap
# =====================================================================

$modulePath = Join-Path $PSScriptRoot 'ExchangeAuditCommon.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    throw "Required module not found: $modulePath`nCopy ExchangeAuditCommon.psm1 next to this script and re-run."
}
Import-Module $modulePath -Force

$scriptRoot   = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$outDir       = New-AuditOutputDirectory -BasePath $OutputDirectory -Prefix 'ExchangeAudit'
$htmlPath     = Join-Path $outDir 'Exchange-Migration-Audit.html'
$transcriptOk = Start-AuditTranscript -Path (Join-Path $outDir 'audit-transcript.txt')

Write-Host ''
Write-Host '=========================================================' -ForegroundColor Cyan
Write-Host ' Exchange 2019 -> Exchange Online migration audit'          -ForegroundColor Cyan
Write-Host " Output: $outDir"                                    -ForegroundColor Cyan
Write-Host '=========================================================' -ForegroundColor Cyan

if (-not (Test-AuditExchangeShell)) {
    Stop-AuditTranscript
    throw @'
The Exchange cmdlets are not available in this session.

Open the "Exchange Management Shell" on one of the Mailbox servers and run this script from there.
PowerShell 7 is NOT supported for the Exchange 2019 snap-in - use Windows PowerShell 5.1 / EMS.
'@
}

$startTime = Get-Date
$startTracking = $startTime.AddDays(-1 * $MessageTrackingDays)
$activityCutoff = $startTime.AddDays(-1 * $MailboxActivityWindowDays)

# =====================================================================
# Collection
# =====================================================================

Write-Host ''
Write-Host 'Collecting organisation inventory...' -ForegroundColor Cyan
$D = @{}

$D['Org'] = Invoke-AuditStep -Name 'Organization configuration' -Script {
    Get-OrganizationConfig | Select-Object `
        Name, Guid, ExchangeVersion, PublicFoldersEnabled, DefaultPublicFolderAgeLimit, AuditLogAgeLimit
}

$D['Servers'] = Invoke-AuditStep -Name 'Exchange servers' -Script {
    Get-ExchangeServer | ForEach-Object {
        [pscustomobject]@{
            Name                = $_.Name
            Fqdn                = $_.Fqdn
            AdminDisplayVersion = [string]$_.AdminDisplayVersion
            Edition             = [string]$_.Edition
            Roles               = [string]$_.ServerRole
            AdSite              = [string]$_.Site
        }
    }
}

$D['ServersUp'] = Invoke-AuditStep -Name 'Server reachability (WinRM/TCP)' -Script {
    foreach ($s in @($D['Servers'].Data)) {
        $ping = Test-Connection -ComputerName $s.Fqdn -Count 1 -Quiet -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Server          = $s.Name
            Fqdn            = $s.Fqdn
            RespondsToPing  = if ($ping) { 'Yes' } else { 'No / ICMP blocked' }
        }
    }
}

$D['TransportSvc'] = Invoke-AuditStep -Name 'Transport service settings (per server)' -Script {
    foreach ($s in @($D['Servers'].Data)) {
        Get-TransportService -Identity $s.Name -ErrorAction SilentlyContinue | Select-Object `
            Name, PickupDirectoryPath, ReplayDirectoryPath, MaxInboundConnection,
            MaxOutboundConnection, MaxReceiveSize, MaxSendSize, TlsDomainCapabilities,
            ProtocolLoggingLevel, ReceiveProtocolLogPath, SendProtocolLogPath, `
            MessageTrackingLogEnabled, MessageTrackingLogMaxAge, MessageTrackingLogMaxDirectorySize, `
            MessageTrackingLogPath
    }
}

$D['Dag'] = Invoke-AuditStep -Name 'Database availability groups' -Script {
    Get-DatabaseAvailabilityGroup | Select-Object Name, WitnessServer, WitnessDirectory,
        AlternateWitnessServer, DatabaseAvailabilityGroupIPAddresses,
        IncrementalReplicationEnabled, DatacenterActivationMode
}

$D['DbCopies'] = Invoke-AuditStep -Name 'Mailbox database copy health' -Script {
    Get-MailboxDatabaseCopyStatus * -ErrorAction Stop | Select-Object Name, Status, CopyQueueLength,
        ReplayQueueLength, ContentIndexState, Mounted, ExemptFromServiceContinuation
}

$D['Dbs'] = Invoke-AuditStep -Name 'Mailbox databases (config + size)' -Script {
    Get-MailboxDatabase -Status | ForEach-Object {
        $sizeKB  = Get-AuditSizeKB -Size $_.DatabaseSize
        $availKB = Get-AuditSizeKB -Size $_.AvailableNewMailboxSpace
        $whitePct = $null
        if ($null -ne $sizeKB -and $sizeKB -gt 0 -and $null -ne $availKB) {
            $whitePct = [math]::Round(($availKB / $sizeKB) * 100, 1)
        }
        [pscustomobject]@{
            Name              = $_.Name
            Server            = [string]$_.Server
            Mounted           = $_.Mounted
            Recovery          = $_.Recovery
            DatabaseSizeGB    = if ($null -ne $sizeKB)  { [math]::Round($sizeKB / 1048576, 2) }  else { $null }
            WhiteSpaceGB      = if ($null -ne $availKB) { [math]::Round($availKB  / 1048576, 2) }  else { $null }
            WhiteSpacePercent = $whitePct
            LastFullBackup    = $_.LastFullBackup
            EdbFilePath       = [string]$_.EdbFilePath
            LogFolderPath     = [string]$_.LogFolderPath
        }
    }
}

$D['DbMailboxCounts'] = Invoke-AuditStep -Name 'Mailboxes per database' -Script {
    foreach ($db in @($D['Dbs'].Data)) {
        $stats = @(Get-MailboxStatistics -Database $db.Name -ErrorAction SilentlyContinue)
        [pscustomobject]@{
            Database       = $db.Name
            MailboxCount   = $stats.Count
            TotalItems     = (($stats | Measure-Object -Property ItemCount -Sum).Sum)
            TotalSizeGB    = [math]::Round(((($stats | ForEach-Object { Get-AuditSizeKB -Size $_.TotalItemSize }) |
                                Measure-Object -Sum).Sum / 1048576), 2)
        }
    }
}

Write-Host ''
Write-Host 'Collecting recipient inventory...' -ForegroundColor Cyan

$D['AllMbx'] = Invoke-AuditStep -Name 'Mailboxes (all types, on-prem + cloud-hosted)' -Script {
    Get-Mailbox -ResultSize Unlimited | ForEach-Object {
        [pscustomobject]@{
            Name                = $_.Name
            Alias               = $_.Alias
            PrimarySmtpAddress  = [string]$_.PrimarySmtpAddress
            RecipientTypeDetails = [string]$_.RecipientTypeDetails
            Database            = [string]$_.Database
            ServerName          = [string]$_.ServerName
            DistinguishedName   = [string]$_.DistinguishedName
            ExchangeGuid        = [string]$_.ExchangeGuid
            WhenChanged         = $_.WhenChanged
            LitigationHoldEnabled = $_.LitigationHoldEnabled
            ArchiveStatus       = [string]$_.ArchiveStatus
            PersistedClaims     = [string]$_.PersistedClaims
        }
    }
}

# On-prem mailboxes are the ones with a Database populated; RemoteMailbox objects have none.
$onPremMbx = @($D['AllMbx'].Data | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Database) })
$remoteMbx = @($D['AllMbx'].Data | Where-Object { $_.RecipientTypeDetails -eq 'RemoteMailbox' })

$script:MbxStatsFailed = 0
$script:OnPremMbxForStats = $onPremMbx
$D['MbxStats'] = Invoke-AuditStep -Name "Mailbox statistics ($($onPremMbx.Count) mailboxes)" -Script {
    $results = New-Object 'System.Collections.Generic.List[object]'
    $index   = 0
    $total   = @($script:OnPremMbxForStats).Count

    foreach ($m in @($script:OnPremMbxForStats)) {
        $index++
        Write-Progress -Activity 'Reading mailbox statistics' `
                      -Status ("{0} / {1} - {2}" -f $index, $total, $m.PrimarySmtpAddress) `
                      -PercentComplete (($index / [math]::Max(1, $total)) * 100)

        try {
            $identity = if ($m.DistinguishedName) { $m.DistinguishedName } else { $m.ExchangeGuid }
            $st = Get-MailboxStatistics -Identity $identity -ErrorAction Stop | Select-Object -First 1

            $results.Add([pscustomobject]@{
                Name               = $m.Name
                PrimarySmtpAddress = $m.PrimarySmtpAddress
                RecipientType      = $m.RecipientTypeDetails
                Database           = $m.Database
                ItemCount          = $st.ItemCount
                SizeKB             = Get-AuditSizeKB -Size $st.TotalItemSize
                LastLogonTime      = $st.LastLogonTime
                LastLoggedOffTime  = $st.LastLoggedOffTime
                ConnectedClients   = (($st.ConnectedMailboxes | Out-String).Trim())
            }) | Out-Null
        }
        catch {
            $script:MbxStatsFailed++
            $results.Add([pscustomobject]@{
                Name               = $m.Name
                PrimarySmtpAddress = $m.PrimarySmtpAddress
                RecipientType      = $m.RecipientTypeDetails
                Database           = $m.Database
                ItemCount          = $null
                SizeKB             = $null
                LastLogonTime      = $null
                LastLoggedOffTime  = $null
                ConnectedMailboxes = "STATS ERROR: $($_.Exception.Message)"
            }) | Out-Null
        }
    }

    Write-Progress -Activity 'Reading mailbox statistics' -Completed
    return ,$results.ToArray()
}

$D['MailUsers'] = Invoke-AuditStep -Name 'Mail-enabled users (mail users)' -Script {
    Get-MailUser -ResultSize Unlimited | ForEach-Object {
        [pscustomobject]@{
            Type               = 'MailUser'
            Name               = $_.Name
            PrimarySmtpAddress = [string]$_.PrimarySmtpAddress
            ExternalEmailAddress = (($_.ExternalEmailAddress | Out-String).Trim())
            RecipientTypeDetails = [string]$_.RecipientTypeDetails
            WhenChanged        = $_.WhenChanged
        }
    }
}

$D['MailContacts'] = Invoke-AuditStep -Name 'Mail-enabled contacts' -Script {
    Get-MailContact -ResultSize Unlimited | ForEach-Object {
        [pscustomobject]@{
            Type               = 'MailContact'
            Name               = $_.Name
            PrimarySmtpAddress = [string]$_.PrimarySmtpAddress
            ExternalEmailAddress = (($_.ExternalEmailAddress | Out-String).Trim())
            RecipientTypeDetails = [string]$_.RecipientTypeDetails
            WhenChanged        = $_.WhenChanged
        }
    }
}

$D['Groups'] = Invoke-AuditStep -Name 'Mail-enabled groups' -Script {
    Get-Group -ResultSize Unlimited -RecipientTypeDetails MailUniversalDistributionGroup, MailUniversalSecurityGroup |
        ForEach-Object {
            $memberCount = 0
            if ($_.Members) { $memberCount = @($_.Members).Count }
            [pscustomobject]@{
                Type               = 'MailEnabledGroup'
                Name               = $_.Name
                PrimarySmtpAddress = [string]$_.PrimarySmtpAddress
                GroupType          = (($_.GroupType | Out-String).Trim())
                MemberCount        = $memberCount
                ManagedBy          = (($_.ManagedBy | Out-String).Trim())
                WhenChanged        = $_.WhenChanged
            }
        }
}

$D['PfMbxs'] = Invoke-AuditStep -Name 'Public folder mailboxes' -Script {
    Get-Mailbox -ResultSize Unlimited -PublicFolder | ForEach-Object {
        [pscustomobject]@{
            Name               = $_.Name
            Database           = [string]$_.Database
            PrimarySmtpAddress = [string]$_.PrimarySmtpAddress
            ItemCount          = $null
        }
    }
}

$D['PfHierarchy'] = Invoke-AuditStep -Name 'Public folder hierarchy' -Script {
    @(Get-PublicFolder -Recurse -ErrorAction SilentlyContinue) | ForEach-Object {
        [pscustomobject]@{ Identity = [string]$_.Identity; ItemCount = $_.ItemCount }
    }
}

Write-Host ''
Write-Host 'Collecting mail flow configuration...' -ForegroundColor Cyan

$D['Domains'] = Invoke-AuditStep -Name 'Accepted domains' -Script {
    Get-AcceptedDomain | ForEach-Object {
        [pscustomobject]@{
            DomainName      = $_.DomainName.ToString()
            Mode            = [string]$_.DomainType
            MatchSubdomains = $_.MatchSubdomains
        }
    }
}

$D['RemoteDomains'] = Invoke-AuditStep -Name 'Remote domains' -Script {
    Get-RemoteDomain | Select-Object Name, DomainName, TargetDeliveryDomainName, TrustedIpAddresses
}

$D['ReceiveConnectors'] = Invoke-AuditStep -Name 'Receive connectors' -Script {
    Get-ReceiveConnector | ForEach-Object {
        $bindings = @($_.Bindings | ForEach-Object { $_.ToString() })
        $ranges   = @($_.RemoteIPRanges | ForEach-Object { $_.ToString() })
        $wildcard = $false
        foreach ($r in $ranges) {
            if ($r -match '^0\.0\.0\.0' -or $r -eq '::/0' -or $r -match '^\*') { $wildcard = $true }
        }

        [pscustomobject]@{
            Identity             = [string]$_.Identity
            TransportRole        = [string]$_.TransportRole
            Bindings             = ($bindings -join ', ')
            RemoteIpRangeCount   = $ranges.Count
            WildcardOrAnyAddress = if ($wildcard) { 'YES' } else { 'No' }
            RemoteIpRanges       = (($ranges | Select-Object -First 12) -join ', ') + $(if ($ranges.Count -gt 12) { " (+$($ranges.Count - 12) more)" } else { '' })
            AuthMechanism        = (($_.AuthMechanism | Out-String).Trim())
            PermissionGroups     = (($_.PermissionGroups | Out-String).Trim())
            AnonymousUsers       = if ($_.PermissionGroups -contains 'AnonymousUsers') { 'YES' } else { 'No' }
            TlsDomainSecurity    = [string]$_.TlsDomainSecurity
            MaxMessageSizeKB     = [math]::Round((Get-AuditSizeKB -Size $_.MaxMessageSize), 0)
            ConnectionInLimit    = $_.ConnectionInLimit
            Fqdn                 = [string]$_.Fqdn
            SmtpMaxMessagesPerConnection = $_.SmtpMaxMessagesPerConnection
        }
    }
}

$D['RelayPermissions'] = Invoke-AuditStep -Name 'Receive connector relay / bypass permissions' -Script {
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($conn in @($D['ReceiveConnectors'].Data)) {
        try {
            Get-ADPermission -Identity $conn.Identity -ExtendedRights 'ms-Exch-SMTP-Accept-Any-Recipient' -ErrorAction Stop |
                ForEach-Object {
                    [void]$rows.Add([pscustomobject]@{
                        Connector      = $conn.Identity
                        Permission     = 'ms-Exch-SMTP-Accept-Any-Recipient (relay)'
                        Principal      = [string]$_.User
                        AccessRights   = (($_.AccessRights | Out-String).Trim())
                        IsInherited    = $_.IsInherited
                    })
                }
        }
        catch { Write-Host ("        ! AD permission read failed for {0}: {1}" -f $conn.Identity, $_.Exception.Message) -ForegroundColor DarkGray }

        try {
            Get-ADPermission -Identity $conn.Identity -ExtendedRights 'ms-Exch-Bypass-Anti-Spam' -ErrorAction Stop |
                ForEach-Object {
                    [void]$rows.Add([pscustomobject]@{
                        Connector      = $conn.Identity
                        Permission     = 'ms-Exch-Bypass-Anti-Spam'
                        Principal      = [string]$_.User
                        AccessRights   = (($_.AccessRights | Out-String).Trim())
                        IsInherited    = $_.IsInherited
                    })
                }
        }
        catch { }
    }
    return ,$rows.ToArray()
}

$D['SendConnectors'] = Invoke-AuditStep -Name 'Send connectors' -Script {
    Get-SendConnector | ForEach-Object {
        [pscustomobject]@{
            Name                 = $_.Name
            AddressSpaces        = (($_.AddressSpaces | Out-String).Trim())
            SmartHosts           = (($_.SmartHosts | Out-String).Trim())
            DnsRoutingEnabled    = $_.DNSRoutingEnabled
            SourceServers        = (($_.SourceTransportServers | Out-String).Trim())
            RequireTLS           = $_.RequireTLS
            TlsAuthLevel         = [string]$_.TlsAuthLevel
            DomainSecureEnabled  = $_.DomainSecureEnabled
            Comment              = $_.Comment
            MaxMessageSizeKB     = [math]::Round((Get-AuditSizeKB -Size $_.MaxMessageSize), 0)
        }
    }
}

$D['TransportConfig'] = Invoke-AuditStep -Name 'Transport configuration' -Script {
    Get-TransportConfig | Select-Object MaxReceiveSize, MaxSendSize, MaxRecipientEnvelopeLimit,
        JournalingReportNdrTo, MaxHopCountReportDisabled, RoutingDnsGroups
}

$D['TransportRules'] = Invoke-AuditStep -Name 'Transport rules' -Script {
    Get-TransportRule -ResultSize Unlimited | ForEach-Object {
        $actions  = @($_.Actions)
        $actionText = ($_.Actions | Out-String).Trim()
        $flags = @()
        if ($actionText -match 'RedirectMessageTo')          { $flags += 'redirects mail' }
        if ($actionText -match 'JournalAndDeliver|Journal')  { $flags += 'journals' }
        if ($actionText -match 'BccMessage')                 { $flags += 'BCC' }
        if ($actionText -match 'SetHeader')                  { $flags += 'sets header' }
        if ($_.RuleVersion -and (([string]$_.RuleVersion) -notmatch '^15\.02')) { $flags += 'legacy rule schema' }

        [pscustomobject]@{
            Name              = $_.Name
            State             = [string]$_.State
            Priority          = $_.Priority
            Mode              = [string]$_.Mode
            Actions           = $actionText
            OnPremDependency  = if ($flags.Count -gt 0) { ($flags -join ', ') } else { 'None detected' }
        }
    }
}

$D['JournalRules'] = Invoke-AuditStep -Name 'Journal rules' -Script {
    Get-JournalRule | ForEach-Object {
        [pscustomobject]@{
            Name      = $_.Name
            Recipient = [string]$_.Recipient
            Scope     = [string]$_.Scope
            Enabled   = $_.Enabled
            Comment   = $_.Comment
        }
    }
}

Write-Host ''
Write-Host 'Collecting hybrid and directory-synchronisation state...' -ForegroundColor Cyan

$D['Hybrid'] = Invoke-AuditStep -Name 'Hybrid configuration' -Script {
    Get-HybridConfiguration | ForEach-Object {
        [pscustomobject]@{
            Name                 = $_.Name
            Features             = (($_.Feature | Out-String).Trim())
            Domains              = (($_.Domains | Out-String).Trim())
            TransportSettings    = (($_.TransportSettings | Out-String).Trim())
            SourceServers        = (($_.SourceTransportServers | Out-String).Trim())
            ReceiveConnector     = [string]$_.ReceiveConnector
            SendConnector        = [string]$_.SendConnector
            IntraOrgConnectors   = $_.IntraOrganizationConnectorsEnabled
            GlobalAdminAccount   = [string]$_.GlobalAdminAccount
            ServiceInstance      = [string]$_.ServiceInstance
            EndpointAddress      = [string]$_.EndpointAddress
            WhenChanged          = $_.WhenChanged
        }
    }
}

$D['IntraOrg'] = Invoke-AuditStep -Name 'Intra-organization connectors' -Script {
    Get-IntraOrganizationConnector | ForEach-Object {
        [pscustomobject]@{
            Identity     = [string]$_.Identity
            TargetAddressDomains = (($_.TargetAddressDomains | Out-String).Trim())
            DiscoveryEndpoint    = [string]$_.DiscoveryEndpoint
            Enabled              = $_.Enabled
        }
    }
}

$D['OrgRelationships'] = Invoke-AuditStep -Name 'Organization relationships' -Script {
    Get-OrganizationRelationship | ForEach-Object {
        [pscustomobject]@{
            Name               = $_.Name
            Enabled            = $_.Enabled
            DomainNames        = (($_.DomainNames | Out-String).Trim())
            TargetAutodiscoverEpr = [string]$_.TargetAutodiscoverEpr
            FreeBusyAccessLevel   = [string]$_.FreeBusyAccessLevel
            MailboxMoveEnabled    = $_.MailboxMoveEnabled
        }
    }
}

$D['Federation'] = Invoke-AuditStep -Name 'Federation trust' -Script {
    Get-FederationTrust | ForEach-Object {
        [pscustomobject]@{
            Name                  = $_.Name
            IssuerNames           = (($_.IssuerNames | Out-String).Trim())
            TokenCertificateNotAfter = $_.TokenCertificateNotAfter
            Status                = [string]$_.Status
            IsDefault             = $_.IsDefault
        }
    }
}

$D['AuthServers'] = Invoke-AuditStep -Name 'OAuth authentication servers' -Script {
    Get-AuthServer | ForEach-Object {
        [pscustomobject]@{
            Name          = $_.Name
            TargetUri     = (($_.TargetUri | Out-String).Trim())
            IssuerNames   = (($_.IssuerNames | Out-String).Trim())
            DomainController = [string]$_.DomainController
        }
    }
}

$D['RemoteMailboxes'] = Invoke-AuditStep -Name 'Cloud-hosted mailboxes managed from local AD' -Script {
    Get-RemoteMailbox -ResultSize Unlimited | ForEach-Object {
        [pscustomobject]@{
            Name               = $_.Name
            UserPrincipalName  = [string]$_.UserPrincipalName
            PrimarySmtpAddress = [string]$_.PrimarySmtpAddress
            HostedOrganizationId = [string]$_.HostedOrganizationId
            WhenChanged        = $_.WhenChanged
        }
    }
}

$D['DirSync'] = Invoke-AuditStep -Name 'Directory synchronisation traces in AD' -Script {
    $rows = New-Object 'System.Collections.Generic.List[object]'

    # MSOL_ / AAD Connect service accounts are the classic marker of a running sync engine.
    foreach ($filter in @(
            '(sAMAccountName=MSOL_*)',
            '(sAMAccountName=*AADConnect*)',
            '(sAMAccountName=*DirSync*)',
            '(sAMAccountName=*AzureADConnect*)')) {
        try {
            $searcher = New-Object System.DirectoryServices.DirectorySearcher("(objectClass=user)$filter")
            $searcher.PropertiesToLoad.AddRange(@('name', 'distinguishedName', 'description', 'lastLogonTimestamp', 'whenChanged')) | Out-Null
            foreach ($hit in $searcher.FindAll()) {
                $props = $hit.Properties
                [void]$rows.Add([pscustomobject]@{
                    Category  = 'Sync service account'
                    Name      = [string]$props['name'][0]
                    Detail    = [string]$props['description'][0]
                    Path      = [string]$props['distinguishedname'][0]
                })
            }
        }
        catch { Write-Host ("        ! ADSI filter failed ({0}): {1}" -f $filter, $_.Exception.Message) -ForegroundColor DarkGray }
    }

    # Heuristic: sync servers are usually named *sync* / *aad*.
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher(
            '(objectCategory=computer)(|(name=*sync*)(name=*aadconnect*))')
        $searcher.PropertiesToLoad.AddRange(@('name', 'operatingsystem', 'distinguishedname')) | Out-Null
        foreach ($hit in $searcher.FindAll()) {
            $props = $hit.Properties
            [void]$rows.Add([pscustomobject]@{
                Category  = 'Possible sync server (heuristic)'
                Name      = [string]$props['name'][0]
                Detail    = [string]$props['operatingsystem'][0]
                Path      = [string]$props['distinguishedname'][0]
            })
        }
    }
    catch { }

    return ,$rows.ToArray()
}

Write-Host ''
Write-Host 'Collecting client access surface...' -ForegroundColor Cyan

$D['Vdirs'] = Invoke-AuditStep -Name 'Client virtual directories' -Script {
    $rows = New-Object 'System.Collections.Generic.List[object]'

    # Property names differ between directory types, so read them defensively by name.
    function Get-VdirProperty {
        param($Object, [string[]]$Names)
        foreach ($name in $Names) {
            $prop = $Object.PSObject.Properties[$name]
            if ($null -ne $prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) { return ([string]$prop.Value) }
        }
        return ''
    }

    $sources = @(
        @{ Protocol='OWA';              Cmdlet='Get-OwaVirtualDirectory';          AuthProps=@('ClientAuthenticationMethods') },
        @{ Protocol='ECP';              Cmdlet='Get-EcpVirtualDirectory';          AuthProps=@() },
        @{ Protocol='EWS';              Cmdlet='Get-WebServicesVirtualDirectory';  AuthProps=@('ClientAuthenticationMethods') },
        @{ Protocol='ActiveSync';       Cmdlet='Get-ActiveSyncVirtualDirectory';   AuthProps=@() },
        @{ Protocol='MAPI/HTTP';        Cmdlet='Get-MapiVirtualDirectory';         AuthProps=@('ClientAuthenticationMethods') },
        @{ Protocol='Autodiscover';     Cmdlet='Get-AutodiscoverVirtualDirectory'; AuthProps=@() },
        @{ Protocol='Outlook Anywhere'; Cmdlet='Get-OutlookAnywhere';              AuthProps=@('ExternalClientAuthenticationMethods','InternalClientAuthenticationMethods') }
    )

    foreach ($src in $sources) {
        if (-not (Get-Command -Name $src.Cmdlet -ErrorAction SilentlyContinue)) { continue }
        try {
            foreach ($v in @(& $src.Cmdlet)) {
                if ($null -eq $v) { continue }

                $auth = @()
                foreach ($p in $src.AuthProps) {
                    $prop = $v.PSObject.Properties[$p]
                    if ($prop -and $prop.Value) {
                        $auth += ('{0}={1}' -f $p, (($prop.Value | Out-String).Trim() -replace '\s+', ' '))
                    }
                }

                [void]$rows.Add([pscustomobject]@{
                    Protocol       = $src.Protocol
                    Server         = Get-VdirProperty -Object $v -Names @('Server', 'ServerName')
                    InternalUrl    = (Get-VdirProperty -Object $v -Names @('InternalUrl', 'InternalHostname'))
                    ExternalUrl    = (Get-VdirProperty -Object $v -Names @('ExternalUrl', 'ExternalHostname'))
                    Authentication = ($auth -join '; ')
                })
            }
        }
        catch {
            Write-Host ("        ! {0} unavailable: {1}" -f $src.Cmdlet, $_.Exception.Message) -ForegroundColor DarkGray
        }
    }

    return ,$rows.ToArray()
}

$D['LegacyProtocols'] = Invoke-AuditStep -Name 'POP / IMAP / RPC endpoint settings' -Script {
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($s in @($D['Servers'].Data)) {
        try {
            Get-PopSettings -Server $s.Name -ErrorAction Stop | ForEach-Object {
                [void]$rows.Add([pscustomobject]@{ Server=$s.Name; Protocol='POP3'; Enabled=$_.ProtocolEnabled;
                    Port=$_.DefaultPort; UseSSL=$_.UseSSL; Banner=[string]$_.Banner })
            }
        } catch { }
        try {
            Get-ImapSettings -Server $s.Name -ErrorAction Stop | ForEach-Object {
                [void]$rows.Add([pscustomobject]@{ Server=$s.Name; Protocol='IMAP4'; Enabled=$_.ProtocolEnabled;
                    Port=$_.DefaultPort; UseSSL=$_.UseSSL; Banner=[string]$_.Banner })
            }
        } catch { }
    }
    return ,$rows.ToArray()
}

$D['MobileDevices'] = Invoke-AuditStep -Name 'ActiveSync device partnerships' -Script {
    Get-MobileDevice -ResultSize Unlimited | ForEach-Object {
        [pscustomobject]@{
            Identity      = [string]$_.Identity
            DeviceID      = [string]$_.DeviceID
            FriendlyName  = [string]$_.FriendlyName
            DeviceModel   = [string]$_.DeviceModel
            DeviceOS      = [string]$_.DeviceOS
            FirstSyncTime = $_.FirstSyncTime
            LastSuccessSync = $_.LastSuccessSync
        }
    }
}

$D['ClientAccessRules'] = Invoke-AuditStep -Name 'Client access rules' -Script {
    Get-ClientAccessRule | ForEach-Object {
        [pscustomobject]@{
            Name     = $_.Name
            Action   = [string]$_.Action
            Priority = $_.Priority
            WhenChanged = $_.WhenChanged
        }
    }
}

Write-Host ''
Write-Host 'Collecting certificates and transport agents...' -ForegroundColor Cyan

$D['Certs'] = Invoke-AuditStep -Name 'Exchange certificates' -Script {
    Get-ExchangeCertificate | ForEach-Object {
        $daysLeft = $null
        if ($_.NotAfter) { $daysLeft = [int]($_.NotAfter - (Get-Date)).TotalDays }
        [pscustomobject]@{
            FriendlyName     = [string]$_.FriendlyName
            Subject          = [string]$_.Subject
            Issuer           = [string]$_.Issuer
            NotAfter         = $_.NotAfter
            DaysRemaining    = $daysLeft
            Status           = [string]$_.Status
            Services         = (($_.Services | Out-String).Trim())
            KeySize          = $_.PublicKeySize
            SelfSigned       = $_.IsSelfSigned
            Domains          = (($_.CertificateDomains | Out-String).Trim())
            Thumbprint       = [string]$_.Thumbprint
        }
    }
}

$D['Agents'] = Invoke-AuditStep -Name 'Transport agents' -Script {
    Get-TransportAgent | ForEach-Object {
        [pscustomobject]@{
            Identity             = [string]$_.Identity
            Enabled              = $_.Enabled
            TransportPipelineStage = [string]$_.TransportPipelineState
            Priority             = $_.Priority
            Comment              = [string]$_.Comment
        }
    }
}

$D['MigrationBatches'] = Invoke-AuditStep -Name 'Migration batches' -Script {
    Get-MigrationBatch | ForEach-Object {
        [pscustomobject]@{
            Name                    = $_.Name
            Status                  = [string]$_.Status
            MigrationType           = [string]$_.MigrationType
            TotalMailboxes          = $_.TotalMailboxes
            SuccessfulMailboxes     = $_.SuccessfulMailboxes
            FailedMailboxes         = $_.FailedMailboxes
            PartiallySuccessfulMailboxes = $_.PartiallySuccessfulMailboxes
        }
    }
}

# =====================================================================
# DNS posture (MX / SPF) - answers "does internet mail still arrive here?"
# =====================================================================

Write-Host ''
Write-Host 'Checking MX and SPF posture for accepted domains...' -ForegroundColor Cyan

$exchangeFqdns = @($D['Servers'].Data | ForEach-Object { $_.Fqdn } | Where-Object { $_ })
$script:MxRows = New-Object 'System.Collections.Generic.List[object]'

foreach ($dom in @($D['Domains'].Data)) {
    $row = [pscustomobject]@{
        Domain          = $dom.DomainName
        Mode            = $dom.Mode
        MatchSubdomains = $dom.MatchSubdomains
        MxRecords       = ''
        MxTargetClass   = 'Not resolved'
        SpfRecord       = ''
        SpfIncludesEOP  = ''
        Verdict         = ''
    }

    try {
        $mxRecords = @(Resolve-AuditDnsRecord -Name $dom.DomainName -Type MX -DnsServer $PublicDnsServer)

        if (@($mxRecords).Count -gt 0) {
            $targets = @()
            foreach ($rec in ($mxRecords | Sort-Object Preference)) {
                $targets += "{0} (pref {1})" -f (Get-AuditMxHostName -Record $rec), $rec.Preference
            }
            $row.MxRecords = ($targets -join '; ')

            $firstTarget = Get-AuditMxHostName -Record ($mxRecords | Sort-Object Preference | Select-Object -First 1)

            if ([string]::IsNullOrWhiteSpace($firstTarget)) {
                $row.MxTargetClass = 'Unreadable MX record'
            }
            elseif ($firstTarget -match 'protection\.outlook\.com|mx\.microsoft') {
                $row.MxTargetClass = 'Exchange Online (EOP)'
            }
            else {
                $isOurs = $false
                foreach ($fqdn in $exchangeFqdns) {
                    if (-not $fqdn) { continue }
                    if ($firstTarget -eq $fqdn -or
                        $firstTarget.StartsWith("$fqdn.", [System.StringComparison]::InvariantCultureIgnoreCase) -or
                        $firstTarget.Equals($fqdn, [System.StringComparison]::InvariantCultureIgnoreCase)) {
                        $isOurs = $true
                        break
                    }
                }
                if ($isOurs) { $row.MxTargetClass = 'ON-PREMISES EXCHANGE' } else { $row.MxTargetClass = 'Third party / other' }
            }

            if     ($row.Mode -eq 'Authoritative' -and $row.MxTargetClass -eq 'Exchange Online (EOP)') {
                $row.Verdict = 'Cloud front door - on-premises no longer receives inbound mail for this domain'
            }
            elseif ($row.Mode -eq 'Authoritative' -and $row.MxTargetClass -eq 'ON-PREMISES EXCHANGE') {
                $row.Verdict = 'CRITICAL: MX still points at on-premises Exchange while the domain is Authoritative here'
            }
            elseif ($row.Mode -eq 'InternalRelay') {
                $row.Verdict = 'Internal relay - mail flow depends on routing to an on-premises recipient or system'
            }
            else {
                $row.Verdict = 'Review MX target against the intended Exchange Online cutover state'
            }
        }
        else {
            if ($script:AuditLastDnsError) {
                $row.MxTargetClass = "No MX record / query failed: $($script:AuditLastDnsError)"
            }
            else {
                $row.MxTargetClass = 'No MX record found'
            }
            $row.Verdict = 'Confirm whether this domain is expected to receive mail at all'
        }

        $txtRecords = @(Resolve-AuditDnsRecord -Name $dom.DomainName -Type TXT -DnsServer $PublicDnsServer)
        $spf = @($txtRecords | ForEach-Object { ((($_.Strings -join '') + ' ' + [string]$_.TXT) ).Trim() } |
                    Where-Object { $_ -match '^v=spf1' })
        if (@($spf).Count -gt 0) {
            $row.SpfRecord      = ($spf -join ' | ')
            $row.SpfIncludesEOP = if ($row.SpfRecord -match 'spf\.protection\.outlook\.com|outlook\.com') { 'Yes' } else { 'No' }
        }
    }
    catch {
        $row.MxTargetClass = "DNS check failed: $($_.Exception.Message)"
    }

    [void]$script:MxRows.Add($row)
}

# =====================================================================
# Message tracking - relay source discovery (summary; deep dive in the dedicated script)
# =====================================================================

Write-Host ''
Write-Host "Analysing message tracking logs for $MessageTrackingDays day(s)..." -ForegroundColor Cyan

$D['MtRetention'] = Invoke-AuditStep -Name 'Message tracking retention settings' -Script {
    foreach ($s in @($D['TransportSvc'].Data)) {
        [pscustomobject]@{
            Server                        = [string]$s.Name
            MessageTrackingLogEnabled     = $s.MessageTrackingLogEnabled
            MessageTrackingLogMaxAge      = $s.MessageTrackingLogMaxAge
            MessageTrackingLogMaxDirectorySizeGB = if ($s.MessageTrackingLogMaxDirectorySize) {
                [math]::Round((Get-AuditSizeKB -Size $s.MessageTrackingLogMaxDirectorySize) / 1048576, 2) } else { $null }
            MessageTrackingLogPath        = [string]$s.MessageTrackingLogPath
        }
    }
}

$D['PickupDirs'] = Invoke-AuditStep -Name 'Local pickup / replay directory usage' -Script {
    foreach ($svc in @($D['TransportSvc'].Data)) {
        foreach ($kind in @('PickupDirectoryPath', 'ReplayDirectoryPath')) {
            $path = [string]$svc.$kind
            if ([string]::IsNullOrWhiteSpace($path)) { continue }

            $fileCount = 0; $totalKB = 0; $newest = $null
            try {
                if (Test-Path -LiteralPath $path) {
                    $files = @(Get-ChildItem -LiteralPath $path -File -Recurse -ErrorAction SilentlyContinue)
                    $fileCount = $files.Count
                    foreach ($f in $files) {
                        $totalKB += [math]::Round($f.Length / 1KB, 0)
                        if (-not $newest -or $f.LastWriteTime -gt $newest) { $newest = $f.LastWriteTime }
                    }
                }
            }
            catch { }

            [pscustomobject]@{
                Server        = [string]$svc.Name
                DirectoryType = $kind
                Path          = $path
                FileCount     = $fileCount
                TotalSizeKB   = $totalKB
                NewestFile    = $newest
            }
        }
    }
}

$trackingRows   = @()
$relaySources   = @()
$internalIpSet  = New-Object 'System.Collections.Generic.HashSet[string]'

if (-not $SkipMessageTracking) {
    # Build the set of IP addresses that belong to Exchange itself so we can exclude internal hops.
    foreach ($s in @($D['Servers'].Data)) {
        foreach ($name in @($s.Fqdn, $s.Name)) {
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            try {
                foreach ($addr in [System.Net.Dns]::GetHostAddresses($name)) {
                    if ($addr.AddressFamily -eq 'InterNetwork') { [void]$internalIpSet.Add($addr.ToString()) }
                }
            }
            catch { }
        }
    }
    # DAG/IP-failover addresses are also internal hops.
    foreach ($dag in @($D['Dag'].Data)) {
        foreach ($addr in @($dag.DatabaseAvailabilityGroupIPAddresses)) {
            if ($addr) { [void]$internalIpSet.Add(([string]$addr).Trim()) }
        }
    }

    Write-Host '  Reading RECEIVE events per Mailbox server...'
    $collected = Invoke-AuditStep -Name "Message tracking RECEIVE events ($MessageTrackingDays days)" -Script {
        $rows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($s in @($D['Servers'].Data)) {
            Write-Host ("      [{0}] querying..." -f $s.Name) -ForegroundColor DarkGray
            try {
                Get-MessageTrackingLog -Server $s.Name -Start $startTracking -End $startTime `
                        -EventId RECEIVE -ResultSize $MaxTrackingEvents -ErrorAction Stop |
                    ForEach-Object {
                        [void]$rows.Add([pscustomobject]@{
                            ServerName     = $s.Name
                            Timestamp      = $_.Timestamp
                            ClientIp       = [string]$_.ClientIp
                            ClientHostname = [string]$_.ClientHostname
                            ConnectorId    = [string]$_.ConnectorId
                            Sender         = [string]$_.Sender
                            Recipients     = @($_.Recipients)
                            Source         = [string]$_.Source
                            SourceContext  = [string]$_.SourceContext
                            Directionality = [string]$_.Directionality
                            TotalBytes     = $_.TotalBytes
                        })
                    }
            }
            catch {
                Write-Host ("      ! {0}: {1}" -f $s.Name, $_.Exception.Message) -ForegroundColor Yellow
            }
        }
        return ,$rows.ToArray()
    }

    $trackingRows = @($collected.Data)
    $D['MtEvents'] = $collected
}

# Aggregate submission sources.
if (@($trackingRows).Count -gt 0) {
    Write-Host ("  Aggregating {0:N0} tracking events..." -f @($trackingRows).Count) -ForegroundColor DarkGray

    $grouped = @($trackingRows | Where-Object { $_.ClientIp } | Group-Object ClientIp)

    foreach ($g in $grouped) {
        $ip   = $g.Name
        $evts = @($g.Group)

        $isExchangeInternal = $internalIpSet.Contains([string]$ip)
        $nonStore           = @($evts | Where-Object { $_.Source -ne 'STOREDRIVER' })

        $senders    = @($evts | ForEach-Object { $_.Sender } | Where-Object { $_ } | Select-Object -Unique)
        $recipients = @()
        foreach ($e in $evts) { $recipients += @($e.Recipients) }
        $recipients = @($recipients | Where-Object { $_ } | Select-Object -Unique)

        $internalDomains = @($D['Domains'].Data | ForEach-Object { $_.DomainName.ToLowerInvariant() })
        $extRecips  = @($recipients | Where-Object {
            $r = ([string]$_).ToLowerInvariant()
            (@($internalDomains | Where-Object { $r.EndsWith("@$_") }).Count -eq 0)
        })
        $scope = 'Unknown'
        if ($recipients.Count -gt 0) {
            if    ($extRecips.Count -eq 0)          { $scope = 'InternalOnly' }
            elseif ($extRecips.Count -eq $recipients.Count) { $scope = 'ExternalOnly' }
            else                                    { $scope = 'Mixed' }
        }

        $ptr = Resolve-AuditHostName -IpAddress $ip
        $ad  = Find-AuditComputerByIp -IpAddress $ip -HostName $ptr

        $connectors = @($evts | ForEach-Object { $_.ConnectorId } | Where-Object { $_ } | Select-Object -Unique)
        $anonConnector = $false
        foreach ($c in $connectors) {
            $matchConn = @($D['ReceiveConnectors'].Data | Where-Object { $_.Identity -eq $c })
            if (@($matchConn).Count -gt 0 -and $matchConn[0].AnonymousUsers -eq 'YES') { $anonConnector = $true }
        }

        $category = Get-AuditAppCategory -HostName $ptr -ComputerName $ad.Name -Description $ad.Description `
                        -ConnectorId ($connectors -join ' ') -Senders ($senders -join ' ')

        $path = Get-AuditReplacementPath -RecipientScope $scope -Category $category `
                        -HighVolume:($evts.Count -ge 500)

        [void]$relaySources.Add([pscustomobject]@{
            ClientIp         = $ip
            Hostname         = if ($ptr) { $ptr } else { '' }
            AdComputer       = if ($ad.Name) { $ad.Name } else { '' }
            AdDescription    = if ($ad.Description) { $ad.Description } else { '' }
            Category         = $category
            Messages         = $evts.Count
            NonStoreMessages = $nonStore.Count
            UniqueSenders    = $senders.Count
            SenderSamples    = (($senders | Select-Object -First 3) -join ', ')
            Connectors       = ($connectors -join '; ')
            AnonymousPath    = if ($anonConnector) { 'YES' } else { 'No / authenticated' }
            InternalExchange = if ($isExchangeInternal) { 'YES (exclude)' } else { 'No' }
            RecipientScope   = $scope
            FirstSeen        = ($evts | Measure-Object -Property Timestamp -Minimum).Minimum
            LastSeen         = ($evts | Measure-Object -Property Timestamp -Maximum).Maximum
            RecommendedPath  = $path.Path
            Endpoint         = $path.Endpoint
        })
    }

    $relaySources = @($relaySources | Sort-Object -Property @{ Expression = { $_.Messages }; Descending = $true })
}

# =====================================================================
IIS log analysis (optional)
# =====================================================================

$iisRows = @()
if ($IncludeIisLogs) {
    Write-Host ''
    Write-Host "Parsing IIS HTTP logs for the last $IisLogDays day(s)..." -ForegroundColor Cyan
    $iisCutoff = $startTime.AddDays(-1 * $IisLogDays)

    # Protocol detection on cs-uri-stem; evaluated top-down so EAS/MAPI are not swallowed by OWA.
    function Get-AuditIisProtocol {
        param([string]$Stem)
        switch -regex ($Stem) {
            '/microsoft-server-activesync' { return 'Exchange ActiveSync' }
            '^/autodiscover'               { return 'Autodiscover' }
            '^/ews'                        { return 'EWS' }
            '^/mapi'                       { return 'MAPI over HTTP' }
            '^/rpc'                        { return 'RPC over HTTP (Outlook Anywhere)' }
            '^/ecp'                        { return 'ECP (admin console)' }
            '^/owa'                        { return 'Outlook on the web' }
            default                        { return $null }
        }
    }

    $logRoots = @()
    if ($env:SystemDrive) { $logRoots += (Join-Path $env:SystemDrive 'inetpub\logs\LogFiles') }
    $logRoots = @($logRoots | Where-Object { $_ -and (Test-Path -LiteralPath $_) })

    $iisList = New-Object 'System.Collections.Generic.List[object]'

    foreach ($root in $logRoots) {
        Write-Host ("      scanning {0}" -f $root) -ForegroundColor DarkGray
        $dirs = @()
        try { $dirs = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop | Where-Object { $_.Name -like 'W3SVC*' }) } catch { }

        foreach ($dir in $dirs) {
            $files = @()
            try {
                $files = @(Get-ChildItem -LiteralPath $dir.FullName -Filter '*.log' -File -ErrorAction Stop |
                            Where-Object { $_.LastWriteTime -ge $iisCutoff } | Sort-Object LastWriteTime)
            }
            catch { continue }

            foreach ($file in $files) {
                # Column indexes are resolved from the W3C #Fields header rather than assumed.
                $colDate = -1; $colIp = -1; $colStem = -1
                try {
                    foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
                        if ([string]::IsNullOrWhiteSpace($line)) { continue }

                        if ($line.StartsWith('#Fields:')) {
                            $fields = (($line -replace '^#Fields:\s*', '') -split '\s+')
                            $colDate = [Array]::IndexOf($fields, 'date')
                            $colIp   = [Array]::IndexOf($fields, 'c-ip')
                            $colStem = [Array]::IndexOf($fields, 'cs-uri-stem')
                            continue
                        }
                        if ($line.StartsWith('#')) { continue }

                        # Standard IIS default order as a fallback.
                        if ($colDate -lt 0) { $colDate = 0 }
                        if ($colIp   -lt 0) { $colIp   = 2 }
                        if ($colStem -lt 0) { $colStem = 6 }

                        $cols = $line.Split(' ')
                        $needed = [math]::Max($colDate, [math]::Max($colIp, $colStem))
                        if ($cols.Count -le $needed) { continue }

                        $logDate = [datetime]::MinValue
                        if (-not [datetime]::TryParseExact([string]$cols[$colDate], 'yyyy-MM-dd',
                                [System.Globalization.CultureInfo]::InvariantCulture,
                                [System.Globalization.DateTimeStyles]::None, [ref]$logDate)) { continue }
                        if ($logDate -lt $iisCutoff) { continue }

                        $protocol = Get-AuditIisProtocol -Stem (([string]$cols[$colStem]).ToLowerInvariant())
                        if (-not $protocol) { continue }

                        [void]$iisList.Add([pscustomobject]@{ Protocol = $protocol; ClientIp = ([string]$cols[$colIp]) })
                    }
                }
                catch { Write-Host ("        ! Could not read {0}: {1}" -f $file.Name, $_.Exception.Message) -ForegroundColor DarkGray }
            }
        }
    }

    $iisRows = @($iisList.ToArray())
}

# =====================================================================
# Derived assessment
# =====================================================================

Write-Host ''
Write-Host 'Computing retirement readiness...' -ForegroundColor Cyan

$statsByDn = @{}
foreach ($s in @($D['MbxStats'].Data)) {
    $key = "{0}|{1}" -f $s.PrimarySmtpAddress, $s.Name
    if (-not $statsByDn.ContainsKey($key)) { $statsByDn[$key] = $s }
}

$systemTypes = @('DiscoveryMailbox', 'ArbitrationMailbox', 'SystemMailbox', 'GroupMailbox', 'TeamMailbox', 'UnifiedMessagingMailbox')

$mailboxRows = New-Object 'System.Collections.Generic.List[object]'
foreach ($m in $onPremMbx) {
    $key  = "{0}|{1}" -f $m.PrimarySmtpAddress, $m.Name
    $stat = $null
    if ($statsByDn.ContainsKey($key)) { $stat = $statsByDn[$key] }

    $lastLogon = $null
    if ($stat) { $lastLogon = $stat.LastLogonTime }

    $status = 'Unknown - no statistics returned'
    if ($stat) {
        $hasContent = ($stat.ItemCount -gt 0)
        $recentLogon = ($null -ne $lastLogon -and $lastLogon -ge $activityCutoff)

        if     ($recentLogon)                                   { $status = 'ACTIVE - logged on inside window' }
        elseif ($hasContent -and $null -ne $lastLogon)          { $status = 'Dormant - content, no logon in window' }
        elseif ($hasContent)                                    { $status = 'Content, never logged on (or logon not recorded)' }
        else                                                    { $status = 'Empty' }
    }

    [void]$mailboxRows.Add([pscustomobject]@{
        Name               = $m.Name
        PrimarySmtpAddress = $m.PrimarySmtpAddress
        Type               = $m.RecipientTypeDetails
        Database           = $m.Database
        ItemCount          = if ($stat) { $stat.ItemCount } else { $null }
        Size               = if ($stat) { Format-AuditSize -Kilobytes $stat.SizeKB } else { '' }
        LastLogonTime      = $lastLogon
        DaysSinceLogon     = if ($null -ne $lastLogon) { [int]((Get-Date) - $lastLogon).TotalDays } else { $null }
        Status             = $status
        LitigationHold     = $m.LitigationHoldEnabled
    })
}

$activeMailboxes   = @($mailboxRows | Where-Object { $_.Status -like 'ACTIVE*' })
$dormantMailboxes  = @($mailboxRows | Where-Object { $_.Status -like 'Dormant*' -or $_.Status -like 'Content, never*' })
$emptyMailboxes    = @($mailboxRows | Where-Object { $_.Status -eq 'Empty' })
$userFacingTypes   = @('UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox')
$activeUserFacing  = @($activeMailboxes | Where-Object { $userFacingTypes -contains $_.Type })

$remoteMbxCount    = @($D['RemoteMailboxes'].Data).Count
if ($remoteMbxCount -eq 0) { $remoteMbxCount = @($remoteMbx).Count }

$mailUserCount   = @($D['MailUsers'].Data).Count
$mailContactCount= @($D['MailContacts'].Data).Count
$groupCount      = @($D['Groups'].Data).Count
$dirManagedTotal = $mailUserCount + $mailContactCount + $groupCount

$pfMbxCount      = @($D['PfMbxs'].Data).Count
$internalRelay   = @($D['Domains'].Data | Where-Object { $_.Mode -eq 'InternalRelay' })
$mxOnPrem        = @($script:MxRows | Where-Object { $_.MxTargetClass -eq 'ON-PREMISES EXCHANGE' })

$appSources      = @($relaySources | Where-Object { $_.InternalExchange -notlike 'YES*' -and $_.NonStoreMessages -gt 0 })
$anonRelayConns  = @($D['ReceiveConnectors'].Data | Where-Object { $_.AnonymousUsers -eq 'YES' -and $_.WildcardOrAnyAddress -eq 'YES' })
$anyAnonConns    = @($D['ReceiveConnectors'].Data | Where-Object { $_.AnonymousUsers -eq 'YES' })

$hybridPresent   = (@($D['Hybrid'].Data).Count -gt 0)
$dirSyncFound    = (@($D['DirSync'].Data).Count -gt 0)
$enabledTRules   = @($D['TransportRules'].Data | Where-Object { $_.State -eq 'Enabled' })
$journaling      = (@($D['JournalRules'].Data).Count -gt 0) -or ($D['TransportConfig'].Data.JournalingReportNdrTo)

$expiringCerts   = @($D['Certs'].Data | Where-Object { $null -ne $_.DaysRemaining -and $_.DaysRemaining -lt 30 })
$expiredCerts    = @($D['Certs'].Data | Where-Object { $null -ne $_.DaysRemaining -and $_.DaysRemaining -lt 0 })

$dismounted      = @($D['Dbs'].Data | Where-Object { $_.Mounted -eq $false })
$unhealthyCopies = @($D['DbCopies'].Data | Where-Object { $_.Status -notin @('Healthy', 'Mounted') })

$pickupBacklog   = @($D['PickupDirs'].Data | Where-Object { $_.FileCount -gt 0 -and $_.DirectoryType -eq 'PickupDirectoryPath' })
$replayBacklog   = @($D['PickupDirs'].Data | Where-Object { $_.FileCount -gt 0 -and $_.DirectoryType -eq 'ReplayDirectoryPath' })

# --- blocker list -----------------------------------------------------
$blockers = New-Object 'System.Collections.Generic.List[object]'
function Add-Blocker {
    param([string]$Area, [string]$Finding, [string]$Evidence, [ValidateSet('Critical','High','Medium','Low')][string]$Severity, [string]$Action)
    [void]$blockers.Add([pscustomobject]@{
        Severity = $Severity; Area = $Area; Finding = $Finding; Evidence = $Evidence; RequiredAction = $Action
    })
}

foreach ($s in @($D['Servers'].Data)) {
    $bi = Get-AuditExchangeBuildInfo -AdminDisplayVersion $s.AdminDisplayVersion
    if ($bi.SupportState -like 'Out of support*') {
        $sev = 'High'
        if ($bi.Build -lt 1544) { $sev = 'Critical' }
        Add-Blocker -Area 'Lifecycle' -Finding "$($s.Name): $($bi.Product) $($bi.CU) is out of support" `
            -Evidence "$($s.AdminDisplayVersion)" -Severity $sev `
            -Action 'Confirm ESU enrolment/patch level now, and prioritise retiring this server. Un-patched Exchange 2019 is a known target for exploitation.'
    }
}

if ($activeUserFacing.Count -gt 0) {
    Add-Blocker -Area 'Mailboxes' -Finding "$($activeUserFacing.Count) user-facing mailbox(es) still active on-premises" `
        -Evidence ("Most recent logon: {0}" -f (($activeUserFacing | Sort-Object -Property LastLogonTime -Descending | Select-Object -First 1).LastLogonTime)) `
        -Severity 'Critical' -Action 'Move these mailboxes to Exchange Online (New-MoveRequest / migration batch) before any decommission step.'
}

if ($pfMbxCount -gt 0) {
    Add-Blocker -Area 'Public folders' -Finding "$pfMbxCount public folder mailbox(es) still present" `
        -Evidence "Hierarchy items sampled: $(@($D['PfHierarchy'].Data).Count)" -Severity 'High' `
        -Action 'Migrate the public folder hierarchy to Exchange Online (New-MigrationBatch -PublicFolderToExchangeOnline), then remove the PF mailboxes.'
}

if ($remoteMbxCount -gt 0) {
    Add-Blocker -Area 'Hybrid management' -Finding "$remoteMbxCount cloud-hosted mailbox(es) are managed from local AD" `
        -Evidence 'Get-RemoteMailbox returns objects (directory-synced with Exchange writeback)' -Severity 'High' `
        -Action 'Exchange cannot be uninstalled while these objects exist: keep one management/hybrid server, or move the identities to cloud-only management first. Verify licensing with your Microsoft account team.'
}

if ($dirManagedTotal -gt 0) {
    Add-Blocker -Area 'Hybrid management' `
        -Finding "$dirManagedTotal mail-enabled user/contact/group objects live in local AD" `
        -Evidence "Mail users: $mailUserCount, contacts: $mailContactCount, groups: $groupCount" -Severity 'Medium' `
        -Action 'Either keep an on-premises Exchange for recipient management, or convert these to cloud-only mail users/groups in Exchange Online.'
}

if (@($internalRelay).Count -gt 0) {
    Add-Blocker -Area 'Mail flow' -Finding "$(@($internalRelay).Count) accepted domain(s) configured as Internal relay" `
        -Evidence (($internalRelay | ForEach-Object { $_.DomainName }) -join ', ') -Severity 'High' `
        -Action 'Internal relay implies recipients that still resolve on-premises. Move them to Authoritative in Exchange Online once no on-premises recipient remains.'
}

if (@($mxOnPrem).Count -gt 0) {
    Add-Blocker -Area 'Mail flow' -Finding 'MX record still points at on-premises Exchange' `
        -Evidence (($mxOnPrem | ForEach-Object { "$($_.Domain): $($_.MxRecords)" }) -join '; ') -Severity 'Critical' `
        -Action 'Repoint MX to the tenant EOP endpoint after confirming all mailboxes for that domain are in Exchange Online.'
}

if ($appSources.Count -gt 0) {
    Add-Blocker -Area 'SMTP relay' -Finding "$($appSources.Count) distinct submission source(s) sending through Exchange" `
        -Evidence ("Top source: {0} ({1} messages in $MessageTrackingDays days)" -f $appSources[0].ClientIp, $appSources[0].Messages) `
        -Severity 'High' -Action 'This is normally the longest pole. Run Invoke-SmtpRelayDiscovery.ps1 for 90 days, assign an owner per source, then re-point each to Direct Send / SMTP relay connector / HVE / ACS.'
}

if (@($anonRelayConns).Count -gt 0) {
    Add-Blocker -Area 'SMTP relay' -Finding "$(@($anonRelayConns).Count) receive connector(s) allow anonymous submission from any address" `
        -Evidence (($anonRelayConns | ForEach-Object { $_.Identity }) -join '; ') -Severity 'High' `
        -Action 'Restrict RemoteIPRanges now (audit finding in its own right), and record the exact ranges that must be reproduced in the replacement design.'
}

if ($pickupBacklog.Count -gt 0) {
    Add-Blocker -Area 'SMTP relay' -Finding 'Files present in the local pickup directory' `
        -Evidence (($pickupBacklog | ForEach-Object { "$($_.Server): $($_.FileCount) file(s)" }) -join '; ') -Severity 'Medium' `
        -Action 'An application is dropping .eml files locally. Identify it (file owner/ACLs) and give it a supported submission path before decommission.'
}

if ($enabledTRules.Count -gt 0) {
    Add-Blocker -Area 'Mail flow' -Finding "$($enabledTRules.Count) enabled transport rule(s) must be recreated in Exchange Online" `
        -Evidence (($enabledTRules | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', ') -Severity 'Medium' `
        -Action 'Rebuild each rule in Exchange Online (or replace with an equivalent policy), then remove from on-premises.'
}

if ($journaling) {
    Add-Blocker -Area 'Compliance' -Finding 'Journaling / NDR journal recipient configured' `
        -Evidence "Journal rules: $(@($D['JournalRules'].Data).Count); TransportConfig JournalingReportNdrTo: $($D['TransportConfig'].Data.JournalingReportNdrTo)" `
        -Severity 'Medium' -Action 'Recreate journaling in Exchange Online (journal rules / retention) before removing on-premises mail flow.'
}

if ($expiredCerts.Count -gt 0) {
    Add-Blocker -Area 'Certificates' -Finding "$($expiredCerts.Count) expired certificate(s) assigned to services" `
        -Evidence (($expiredCerts | ForEach-Object { "$($_.Subject) (services: $($_.Services))" }) -join '; ') -Severity 'Critical' `
        -Action 'Replace or remove; expired IIS/SMTP certificates break hybrid and client connectivity and are often mistaken for migration faults.'
}
elseif ($expiringCerts.Count -gt 0) {
    Add-Blocker -Area 'Certificates' -Finding "$($expiringCerts.Count) certificate(s) expire within 30 days" `
        -Evidence (($expiringCerts | ForEach-Object { "$($_.Subject): $($_.DaysRemaining)d" }) -join '; ') -Severity 'High' `
        -Action 'Renew only if the server survives past the expiry date; otherwise note as cleanup.'
}

if ($unhealthyCopies.Count -gt 0) {
    Add-Blocker -Area 'Resilience' -Finding "$($unhealthyCopies.Count) database copy/copies not healthy" `
        -Evidence (($unhealthyCopies | Select-Object -First 5 | ForEach-Object { "$($_.Name): $($_.Status)" }) -join '; ') -Severity 'Medium' `
        -Action 'Fix or accept before decommission; unhealthy copies hide data that still needs migrating.'
}

if ($dismounted.Count -gt 0) {
    Add-Blocker -Area 'Data' -Finding "$($dismounted.Count) dismounted database(s)" `
        -Evidence (($dismounted | ForEach-Object { $_.Name }) -join ', ') -Severity 'High' `
        -Action 'Determine whether archived data still lives here (EseDatabaseAvailableSpace / restore) before deleting the files.'
}

if ($dirSyncFound) {
    Add-Blocker -Area 'Identity' -Finding 'Directory synchronisation traces found in Active Directory' `
        -Evidence (($D['DirSync'].Data | Select-Object -First 3 | ForEach-Object { "$($_.Category): $($_.Name)" }) -join '; ') -Severity 'Low' `
        -Action 'Azure AD Connect is almost certainly still running and writing mail attributes. It must keep running (or be reconfigured for cloud-only management) after Exchange removal.'
}

$blockerRows = @($blockers | Sort-Object -Property @{ Expression = { switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } default { 3 } } } })

# --- verdict ----------------------------------------------------------
$verdictSeverity = 'Info'
$verdictLines = New-Object 'System.Collections.Generic.List[string]'

if ($activeUserFacing.Count -gt 0) {
    $verdictSeverity = 'Critical'
    [void]$verdictLines.Add("Exchange is still hosting live mailboxes: $($activeUserFacing.Count) user-facing mailbox(es) logged on within the last $MailboxActivityWindowDays days. Migration is not complete.")
}

if ($appSources.Count -gt 0 -and $activeUserFacing.Count -eq 0) {
    if ($verdictSeverity -eq 'Info') { $verdictSeverity = 'High' }
    [void]$verdictLines.Add("No active user mailboxes were found, but $($appSources.Count) submission source(s) are still using Exchange as an SMTP relay. The servers cannot be removed until each one is re-pointed.")
}

if ($remoteMbxCount -gt 0 -or $dirManagedTotal -gt 0 -or @($internalRelay).Count -gt 0) {
    if ($verdictSeverity -in @('Info', 'Low')) { $verdictSeverity = 'High' }
    [void]$verdictLines.Add("Directory-managed recipients still exist (cloud mailboxes: $remoteMbxCount, mail users/contacts/groups: $dirManagedTotal, internal-relay domains: $(@($internalRelay).Count)). Exchange must remain installed for recipient management, or those objects must be converted to cloud-only management first.")
}

if ($activeUserFacing.Count -eq 0 -and $appSources.Count -eq 0 -and $remoteMbxCount -eq 0 -and $dirManagedTotal -eq 0 -and @($internalRelay).Count -eq 0) {
    [void]$verdictLines.Add('No active mailboxes, no relay sources and no directory-managed recipients were detected. This estate looks ready for full removal - re-run over a 90-day window before acting.')
}

if (@($mxOnPrem).Count -gt 0) {
    $verdictSeverity = 'Critical'
    [void]$verdictLines.Add('At least one accepted domain still receives internet mail directly on the Exchange servers (MX points on-premises).')
}

if ($verdictLines.Count -eq 0) {
    [void]$verdictLines.Add('Review the individual sections below; no single dominant dependency was detected.')
}

# KPI cards and the verdict callout are rendered after the report object exists so they can
# reuse its severity colour map (see "Report assembly").

# =====================================================================
# Report assembly
# =====================================================================

Write-Host ''
Write-Host 'Building report...' -ForegroundColor Cyan

$R = New-AuditReport -Title 'Exchange 2019 Migration &amp; Retirement Audit' `
    -Subtitle 'Inventory, dependency and decommission-readiness assessment' `
    -Meta ([ordered]@{
        Target            = ($($D['Servers'].Data | ForEach-Object { $_.Name }) -join ', ')
        'Tracking window' = "$MessageTrackingDays days"
        'Activity window' = "$MailboxActivityWindowDays days"
        Script            = 'Invoke-ExchangeMigrationAudit.ps1 v1.0'
    }) `
    -SummaryDescription 'Every check performed, with severity and finding count. Rows showing ERROR mean the check could not run - investigate those first.' `
    -SummaryNote 'Severity reflects decommission impact, not CVSS risk. "Critical" means Exchange cannot be removed (or is actively exposed) until it is addressed.' `
    -FooterNotes @(
        'Read-only audit: only Get-*/Test-* cmdlets and DNS lookups were executed; no Exchange, AD or DNS state was modified.',
        "Mailbox activity relies on LastLogonTime from mailbox statistics. Mailboxes that receive mail but are never opened show as dormant, not active - validate before deleting anything.",
        'Message tracking retention is usually 30 days by default, so scheduled/quarterly jobs may be invisible. Re-run Invoke-SmtpRelayDiscovery.ps1 over 90 days before finalising the relay plan.',
        'MX/SPF results reflect the DNS view of the resolver used. With split-horizon internal DNS, re-check from an external resolver or an external network.',
        'Exchange Server 2016 and 2019 reached end of support on 14 October 2025; security updates are only available through the ESU program. Verify patch level independently.',
        'Recommendations for send paths follow Microsoft published guidance (client SMTP submission, OnPremises-type inbound connector relay, Direct Send, High Volume Email, Azure Communication Services Email). Confirm device TLS capability and egress IP design before changing production settings.'
    )

$cards = @(
    (New-AuditCard -Label 'On-prem mailboxes' -Value $onPremMbx.Count -Detail "of which $($activeMailboxes.Count) active / $($emptyMailboxes.Count) empty" -Severity $(if ($activeUserFacing.Count) { 'Critical' } else { 'Info' }) -SeverityColours $R.SeverityColours)
    (New-AuditCard -Label 'Cloud mailboxes managed locally' -Value $remoteMbxCount -Detail 'Get-RemoteMailbox objects' -Severity $(if ($remoteMbxCount) { 'High' } else { 'Info' }) -SeverityColours $R.SeverityColours)
    (New-AuditCard -Label 'SMTP relay sources' -Value $appSources.Count -Detail "in the last $MessageTrackingDays days" -Severity $(if ($appSources.Count) { 'High' } else { 'Info' }) -SeverityColours $R.SeverityColours)
    (New-AuditCard -Label 'Anonymous relay connectors' -Value @($anyAnonConns).Count -Detail "$(@($anonRelayConns).Count) with no IP restriction" -Severity $(if (@($anyAnonConns).Count) { 'High' } else { 'Info' }) -SeverityColours $R.SeverityColours)
    (New-AuditCard -Label 'MX pointing on-prem' -Value @($mxOnPrem).Count -Detail "of $(@($script:MxRows).Count) accepted domains" -Severity $(if (@($mxOnPrem).Count) { 'Critical' } else { 'Info' }) -SeverityColours $R.SeverityColours)
    (New-AuditCard -Label 'Public folder mailboxes' -Value $pfMbxCount -Detail 'classic decommission blocker' -Severity $(if ($pfMbxCount) { 'High' } else { 'Info' }) -SeverityColours $R.SeverityColours)
)

$verdictText = (($verdictLines | ForEach-Object { "&bull; $_" }) -join '<br />')
$verdictHtml = "<div class='cards'>$($cards -join '')</div>" +
    (New-AuditCallout -Heading 'Retirement assessment' -Text $verdictText -Severity $verdictSeverity -SeverityColours $R.SeverityColours)

Add-AuditSection -Report $R -Title 'Retirement assessment' -Severity $verdictSeverity `
    -Description 'Computed from the checks below: what Exchange is still doing, and therefore what must change before it can be removed.' `
    -RawHtml $verdictHtml -Data @()

Add-AuditSection -Report $R -Title 'Blockers and required actions' -Severity $(if (@($blockerRows | Where-Object { $_.Severity -eq 'Critical' }).Count) {'Critical'} elseif ($blockerRows.Count) {'High'} else {'Info'}) `
    -Description 'Ordered list of everything that must be resolved, with the evidence behind it.' `
    -Data $blockerRows

Add-AuditSection -Report $R -Title 'Exchange servers and patch currency' -Severity High `
    -Description 'Product version per server. Exchange 2019 is out of support (end of extended support 14 Oct 2025), which by itself justifies accelerating the retirement.' `
    -Data @($D['Servers'].Data | ForEach-Object {
        $bi = Get-AuditExchangeBuildInfo -AdminDisplayVersion $_.AdminDisplayVersion
        [pscustomobject]@{
            Server = $_.Name; Fqdn = $_.Fqdn; Version = $_.AdminDisplayVersion; Product = $bi.Product; CU = $bi.CU
            Edition = $_.Edition; AdSite = $_.AdSite; SupportState = $bi.SupportState
        }
    })

Add-AuditSection -Report $R -Title 'Server reachability' -Severity Info `
    -Description 'Quick ICMP check from the server running this script. "No / ICMP blocked" is common and not necessarily a fault.' `
    -Data $D['ServersUp'].Data -ErrorText $D['ServersUp'].Error

Add-AuditSection -Report $R -Title 'Database availability group and copy health' -Severity $(if (@($unhealthyCopies).Count) {'High'} else {'Info'}) `
    -Description 'DAG topology, witness server and copy status. A DR member (e.g. dr-exchprod1a) usually exists only for resilience; confirm copies are healthy before removing a member.' `
    -Data (@($D['Dag'].Data) + @($D['DbCopies'].Data)) -ErrorText $(if ($D['Dag'].Error) { $D['Dag'].Error } elseif ($D['DbCopies'].Error) { $D['DbCopies'].Error } else { $null }) `
    -Note 'A single-server DAG with a file-share witness is the most common two-node layout; the witness server must be released during decommission.'

Add-AuditSection -Report $R -Title 'Mailbox databases: size, whitespace and backup' -Severity $(if (@($dismounted).Count) {'High'} else {'Medium'}) `
    -Description 'Database inventory with logical size, whitespace and last full backup. Large whitespace plus zero mailboxes is the classic sign of a half-finished migration.' `
    -Data $D['Dbs'].Data -ErrorText $D['Dbs'].Error

Add-AuditSection -Report $R -Title 'Mailbox counts and content per database' -Severity Info `
    -Description 'Per-database mailbox count, total items and total size. A database with mailboxes but no items is a fast move; one with items needs real migration bandwidth.' `
    -Data $D['DbMailboxCounts'].Data -ErrorText $D['DbMailboxCounts'].Error

$typeSummary = @($onPremMbx | Group-Object RecipientTypeDetails | ForEach-Object {
    [pscustomobject]@{ Scope = 'On-premises'; RecipientTypeDetails = $_.Name; Count = $_.Count }
}) + @(@($D['AllMbx'].Data) | Where-Object { -not $_.Database } | Group-Object RecipientTypeDetails | ForEach-Object {
    [pscustomobject]@{ Scope = 'Cloud-hosted (RemoteMailbox view)'; RecipientTypeDetails = $_.Name; Count = $_.Count }
})

Add-AuditSection -Report $R -Title 'Recipient inventory by type' -Severity Info `
    -Description 'What Exchange actually hosts. System/arbitration/discovery mailboxes move automatically with the last user mailbox; they are not a blocker on their own.' `
    -Data $typeSummary -ErrorText $D['AllMbx'].Error

Add-AuditSection -Report $R -Title "On-premises mailboxes and activity evidence (window: $MailboxActivityWindowDays days)" `
    -Severity $(if ($activeUserFacing.Count) {'Critical'} else {'Info'}) `
    -Description 'Answers "are any mailboxes still active on-prem?". Status is derived from mailbox statistics LastLogonTime and item count.' `
    -Data @($mailboxRows | Sort-Object -Property @{ Expression = { $_.LastLogonTime }; Descending = $true }) -MaxRows 3000 `
    -Note 'A mailbox that only receives mail never updates LastLogonTime, so it appears dormant rather than active. Cross-check with Invoke-MailboxActivityAudit.ps1 before deleting anything.'

Add-AuditSection -Report $R -Title 'Empty or dormant mailboxes (immediate move candidates)' -Severity Low `
    -Description 'Mailboxes with no content, or content but no logon inside the activity window. These can usually be moved in bulk without user impact.' `
    -Data @($emptyMailboxes + $dormantMailboxes)

Add-AuditSection -Report $R -Title 'Cloud-hosted mailboxes managed from local AD' -Severity $(if ($remoteMbxCount) {'High'} else {'Info'}) `
    -Description 'Get-RemoteMailbox objects: the mailbox lives in Exchange Online but its AD account and mail attributes are synchronised from this forest. This is a hard hybrid-management dependency.' `
    -Data $D['RemoteMailboxes'].Data -ErrorText $D['RemoteMailboxes'].Error

$dirManagedRows = @($D['MailUsers'].Data) + @($D['MailContacts'].Data) + @($D['Groups'].Data)
Add-AuditSection -Report $R -Title 'Mail-enabled users, contacts and groups in local AD' -Severity $(if ($dirManagedTotal) {'Medium'} else {'Info'}) `
    -Description 'These objects can only be edited with on-premises Exchange tooling while they remain directory-synchronised. They determine whether a management-only Exchange server must survive the retirement.' `
    -Data $dirManagedRows

Add-AuditSection -Report $R -Title 'Public folder mailboxes and hierarchy' -Severity $(if ($pfMbxCount) {'High'} else {'Info'}) `
    -Description 'Public folders are one of the most common late-discovered blockers. If any exist, migrate the hierarchy to Exchange Online before removing the last Mailbox server.' `
    -Data (@($D['PfMbxs'].Data) + @($D['PfHierarchy'].Data | Select-Object -First 200)) -ErrorText $(if ($D['PfMbxs'].Error) { $D['PfMbxs'].Error } else { $D['PfHierarchy'].Error })

Add-AuditSection -Report $R -Title 'Accepted domains, MX and SPF posture' -Severity $(if (@($mxOnPrem).Count) {'Critical'} elseif (@($internalRelay).Count) {'High'} else {'Info'}) `
    -Description 'Answers "does Exchange still receive internet mail?". Authoritative + MX on EOP means the domain is already cloud-front-doored; Internal relay means routing still depends on on-premises recipients.' `
    -Data $script:MxRows

Add-AuditSection -Report $R -Title 'Remote domains' -Severity Info `
    -Description 'Per-recipient-domain mail flow settings. Remote domains that only existed to route to an external system may be retired with the servers.' `
    -Data $D['RemoteDomains'].Data -ErrorText $D['RemoteDomains'].Error

Add-AuditSection -Report $R -Title 'Receive connectors (SMTP submission surface)' -Severity $(if (@($anonRelayConns).Count) {'High'} else {'Medium'}) `
    -Description 'Every receive connector with bindings, address ranges and permission groups. Wildcard RemoteIPRanges plus AnonymousUsers is an open relay for the internal network and must be reproduced deliberately in the replacement design.' `
    -Data $D['ReceiveConnectors'].Data -ErrorText $D['ReceiveConnectors'].Error

Add-AuditSection -Report $R -Title 'Relay and anti-spam bypass permissions per connector' -Severity $(if (@($D['RelayPermissions'].Data).Count) {'High'} else {'Info'}) `
    -Description 'Explicit ms-Exch-SMTP-Accept-Any-Recipient (relay) and ms-Exch-Bypass-Anti-Spam grants. Each principal here is an application or group that must be accounted for in the new design.' `
    -Data $D['RelayPermissions'].Data -ErrorText $D['RelayPermissions'].Error

Add-AuditSection -Report $R -Title 'Send connectors and outbound routing' -Severity Info `
    -Description 'How mail leaves. Smart hosts pointing at a third-party filter or an on-premises appliance must be re-homed; DNS-routed connectors to "*" usually disappear with the servers.' `
    -Data $D['SendConnectors'].Data -ErrorText $D['SendConnectors'].Error

if ($appSources.Count -gt 0) {
    Add-AuditSection -Report $R -Title "SMTP submission sources discovered in message tracking (top $($appSources.Count))" -Severity High `
        -Description 'Distinct client IPs that submitted mail to Exchange, excluding the Exchange servers themselves and mailbox-originated (STOREDRIVER) events. Each row is an application, device or service that must be re-pointed.' `
        -Data ($appSources | Select-Object -First 150) `
        -Note 'Run Invoke-SmtpRelayDiscovery.ps1 for the full worksheet (owner assignment, recipient scope per source, daily volume trend and pickup-directory evidence).'
}
else {
    Add-AuditSection -Report $R -Title 'SMTP submission sources discovered in message tracking' -Severity Info `
        -Description 'No non-Exchange submission sources were found in the analysed window. Confirm with a 90-day run before treating this as proof that relay traffic does not exist.' `
        -Data @() -ErrorText $(if ($D['MtEvents'].Error) { $D['MtEvents'].Error } else { $null })
}

Add-AuditSection -Report $R -Title 'Message tracking retention and coverage' -Severity Medium `
    -Description 'How far back the evidence goes. If MessageTrackingLogMaxAge is shorter than your analysis window, quiet/quarterly relay jobs are invisible.' `
    -Data $D['MtRetention'].Data -ErrorText $D['MtRetention'].Error

Add-AuditSection -Report $R -Title 'Local pickup and replay directory usage' -Severity $(if ($pickupBacklog.Count) {'Medium'} else {'Info'}) `
    -Description 'Applications that write .eml files directly into the Transport pickup folder. These never appear as network clients, so they are easy to miss during a relay inventory.' `
    -Data $D['PickupDirs'].Data -ErrorText $D['PickupDirs'].Error

Add-AuditSection -Report $R -Title 'Transport rules' -Severity $(if ($enabledTRules.Count) {'Medium'} else {'Info'}) `
    -Description 'Rules must be rebuilt in Exchange Online. Flags highlight rules that redirect, journal or stamp headers - the ones most likely to break mail flow if dropped.' `
    -Data $D['TransportRules'].Data -ErrorText $D['TransportRules'].Error

Add-AuditSection -Report $R -Title 'Journaling rules' -Severity $(if (@($D['JournalRules'].Data).Count) {'Medium'} else {'Info'}) `
    -Description 'Compliance dependencies. Journal targets are frequently external archives that must be re-pointed at Exchange Online journaling.' `
    -Data $D['JournalRules'].Data -ErrorText $D['JournalRules'].Error

Add-AuditSection -Report $R -Title 'Hybrid configuration' -Severity $(if ($hybridPresent) {'Medium'} else {'Info'}) `
    -Description 'The hybrid configuration object, its connectors and the tenant it is bound to. A populated object means recipient management and mail attributes still depend on this forest.' `
    -Data $D['Hybrid'].Data -ErrorText $(if ($hybridPresent) { $null } else { "No hybrid configuration found: $($D['Hybrid'].Error)" })

Add-AuditSection -Report $R -Title 'Intra-organization connectors, organization relationships and OAuth' -Severity Info `
    -Description 'Free/busy, cross-premises sharing and OAuth trust objects. These are removed by the hybrid deprecation steps once no on-premises mailbox remains.' `
    -Data (@($D['IntraOrg'].Data) + @($D['OrgRelationships'].Data) + @($D['AuthServers'].Data))

Add-AuditSection -Report $R -Title 'Federation trust' -Severity Info `
    -Description 'Federation trust state, including token certificate expiry. Only relevant if hybrid or federation sharing is still in use.' `
    -Data $D['Federation'].Data -ErrorText $D['Federation'].Error

Add-AuditSection -Report $R -Title 'Directory synchronisation traces in Active Directory' -Severity $(if ($dirSyncFound) {'Medium'} else {'Info'}) `
    -Description 'MSOL_/AAD Connect service accounts and computers with sync-like names. If Azure AD Connect stops, mail attributes stop syncing - it must outlive Exchange or be reconfigured.' `
    -Data $D['DirSync'].Data -ErrorText $D['DirSync'].Error

Add-AuditSection -Report $R -Title 'Client access surface (virtual directories)' -Severity Medium `
    -Description 'Published endpoints and their authentication methods. Any externally published endpoint still receiving traffic means clients have not finished moving.' `
    -Data $D['Vdirs'].Data -ErrorText $D['Vdirs'].Error

Add-AuditSection -Report $R -Title 'POP / IMAP / RPC endpoint settings' -Severity Info `
    -Description 'Legacy protocol listeners. If POP/IMAP are enabled, some client or application may still depend on them; they must be disabled before the server goes away.' `
    -Data $D['LegacyProtocols'].Data -ErrorText $D['LegacyProtocols'].Error

Add-AuditSection -Report $R -Title 'ActiveSync device partnerships' -Severity $(if (@($D['MobileDevices'].Data).Count) {'Medium'} else {'Info'}) `
    -Description 'Any partnership means a mobile client is still homed on-premises. Devices must move with their mailbox.' `
    -Data $D['MobileDevices'].Data -ErrorText $D['MobileDevices'].Error

Add-AuditSection -Report $R -Title 'Client access rules' -Severity Info `
    -Description 'Rules that block or redirect client traffic by network/application. They often encode the historical split between on-premises and cloud clients.' `
    -Data $D['ClientAccessRules'].Data -ErrorText $D['ClientAccessRules'].Error

if ($IncludeIisLogs) {
    $iisSummary = @()
    if (@($iisRows).Count -gt 0) {
        $iisSummary = @($iisRows | Group-Object Protocol | ForEach-Object {
            [pscustomobject]@{
                Protocol      = $_.Name
                Requests      = $_.Count
                UniqueClients = (@($_.Group | ForEach-Object { $_.ClientIp } | Select-Object -Unique).Count)
            }
        })
    }
    Add-AuditSection -Report $R -Title "IIS HTTP protocol usage (last $IisLogDays days)" -Severity $(if (@($iisRows).Count) {'Medium'} else {'Info'}) `
        -Description 'Request counts per protocol parsed from the IIS logs on this server. Non-zero EWS/EAS/OWA traffic proves that clients are still hitting on-premises endpoints.' `
        -Data $iisSummary -Note 'Only the local server is parsed. Repeat on the DR member, or centralise log analysis for a complete picture.'
}

Add-AuditSection -Report $R -Title 'Certificates' -Severity $(if ($expiredCerts.Count) {'Critical'} elseif ($expiringCerts.Count) {'High'} else {'Info'}) `
    -Description 'Certificate inventory with expiry and service assignment. Watch the SMTP+IIS certificates used by hybrid connectors.' `
    -Data $D['Certs'].Data -ErrorText $D['Certs'].Error

Add-AuditSection -Report $R -Title 'Transport agents' -Severity Info `
    -Description 'Third-party agents (AV, DLP, fax, archiving) installed into the transport pipeline. They are a common reason mail flow breaks after an uninstall and often have their own migration path.' `
    -Data @($D['Agents'].Data | ForEach-Object {
        [pscustomobject]@{
            Identity = $_.Identity; Enabled = $_.Enabled; Stage = $_.TransportPipelineStage
            Priority = $_.Priority; Comment = $_.Comment
        }
    }) -ErrorText $D['Agents'].Error

Add-AuditSection -Report $R -Title 'Migration batches' -Severity Info `
    -Description 'Historic and in-flight migration batches. Completed batches confirm the migration path already used; failed ones often explain leftover mailboxes.' `
    -Data $D['MigrationBatches'].Data -ErrorText $D['MigrationBatches'].Error

Add-AuditSection -Report $R -Title 'Organisation and transport configuration baseline' -Severity Info `
    -Description 'Key organisation/transport settings worth capturing before removal (message size limits, journaling NDR target, audit log age, public folder mode).' `
    -Data (@($D['Org'].Data) + @($D['TransportConfig'].Data))

$failedSteps = New-Object 'System.Collections.Generic.List[object]'
foreach ($entry in @($D.GetEnumerator() | Where-Object { $_.Value.Error })) {
    [void]$failedSteps.Add([pscustomobject]@{ Step = $entry.Value.Name; Error = $entry.Value.Error })
}
if (@($trackingRows).Count -gt 0) {
    [void]$failedSteps.Add([pscustomobject]@{
        Step  = 'Message tracking events collected'
        Error = ('{0} RECEIVE events analysed over {1} day(s)' -f @($trackingRows).Count.ToString('N0'), $MessageTrackingDays)
    })
}
if ($script:MbxStatsFailed -gt 0) {
    [void]$failedSteps.Add([pscustomobject]@{
        Step  = 'Mailbox statistics'
        Error = "$($script:MbxStatsFailed) mailbox(es) returned no statistics; their status shows as unknown"
    })
}

Add-AuditSection -Report $R -Title 'Audit execution notes' -Severity $(if (@($D.GetEnumerator() | Where-Object { $_.Value.Error }).Count) {'Medium'} else {'Info'}) `
    -Description 'Checks that returned an error, plus data-volume context. An ERROR row in the summary usually means a cmdlet needs different permissions or the feature is not deployed.' `
    -Data $failedSteps

# =====================================================================
# Output
# =====================================================================

Write-AuditReport -Report $R -Path $htmlPath -NoLaunch:$NoLaunch `
    -GeneratedBy 'Invoke-ExchangeMigrationAudit.ps1 v1.0'

if ($ExportCsv) {
    Export-AuditCsv -Report $R -Directory (Join-Path $outDir 'csv')
}

$elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
Write-Host ''
Write-Host ("Audit complete in {0}s. Evidence folder: {1}" -f $elapsed, $outDir) -ForegroundColor Green
Write-Host ''
Write-Host 'Next steps:' -ForegroundColor Cyan
Write-Host '  1. Run Invoke-SmtpRelayDiscovery.ps1 with -Days 90 for the relay worksheet.' -ForegroundColor DarkGray
Write-Host '  2. Run Invoke-HybridDependencyAudit.ps1 to confirm whether hybrid management is still required.' -ForegroundColor DarkGray
Write-Host '  3. Run Invoke-MailboxActivityAudit.ps1 if any on-prem mailboxes remain.' -ForegroundColor DarkGray

if ($transcriptOk) { Stop-AuditTranscript }
