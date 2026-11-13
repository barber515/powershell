#Requires -Version 5.1

<#
.SYNOPSIS
    Exchange Server Audit Script - Read-only assessment of Exchange 2019 environment

.DESCRIPTION
    This script performs a comprehensive read-only audit of Microsoft Exchange 2019 servers.
    It collects configuration, patch levels, certificates, transport settings, addresses,
    and health information, generating a detailed HTML report.

.PARAMETER Server
    Specific Exchange server to audit. If omitted, all Exchange servers in the environment
    will be discovered and audited.

.PARAMETER OutputPath
    Path where the HTML report will be saved. Default: .\ExchangeAudit_YYYYMMDD_HHmmss.html

.PARAMETER NoLaunch
    Suppress automatic opening of the generated HTML report in the default browser.

.EXAMPLE
    PS> .\Invoke-ExchangeAudit.ps1
    Audits all Exchange servers and saves report to current directory.

.EXAMPLE
    PS> .\Invoke-ExchangeAudit.ps1 -Server "EX01"
    Audits only the specified server EX01.

.EXAMPLE
    PS> .\Invoke-ExchangeAudit.ps1 -OutputPath "C:\Reports\ExchangeAudit.html" -NoLaunch
    Saves report to specified path without opening it in browser.

.NOTES
    Author: Exchange Administrator
    Version: 1.0.0
    Date: 2026-11-12
    
    This script is read-only and does not modify any configuration.
    Requires Exchange Management Shell or appropriate Exchange cmdlets.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Server,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$NoLaunch
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

#region Helper Functions

function ConvertTo-HtmlEncoded {
    [CmdletBinding()]
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    [System.Net.WebUtility]::HtmlEncode($Text)
}

function ConvertTo-HtmlTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Rows
    )

    if (-not $Rows -or @($Rows).Count -eq 0) {
        return '<p class="empty">No results &mdash; nothing flagged for this check.</p>'
    }

    $cols = ($Rows | Select-Object -First 1).PSObject.Properties.Name
    $sb   = [System.Text.StringBuilder]::new()

    [void]$sb.Append('<table><thead><tr>')
    foreach ($c in $cols) {
        [void]$sb.Append("<th>$(ConvertTo-HtmlEncoded $c)</th>")
    }
    [void]$sb.Append('</tr></thead><tbody>')

    foreach ($r in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $cols) {
            $val = [string]$r.$c
            [void]$sb.Append("<td>$(ConvertTo-HtmlEncoded $val)</td>")
        }
        [void]$sb.Append('</tr>')
    }

    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function Add-Section {
    [CmdletBinding()]
    param(
        [string]$Title,
        [string]$Description,
        [ValidateSet('Critical', 'High', 'Medium', 'Info')]
        [string]$Severity = 'Info',
        [scriptblock]$Query
    )

    Write-Verbose ("  - {0}" -f $Title)

    $obj = [ordered]@{
        Title       = $Title
        Description = $Description
        Severity    = $Severity
        Rows        = @()
        Count       = 0
        Error       = $null
    }

    try {
        $result    = & $Query
        $obj.Rows  = @($result)
        $obj.Count = @($result).Count
    }
    catch {
        $obj.Error = $_.Exception.Message
    }

    $report.Add([pscustomobject]$obj)
}

# Determine output path with timestamp
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $OutputPath = Join-Path -Path $PWD -ChildPath "ExchangeAudit_$timestamp.html"
}

Write-Host "Starting Exchange Environment Audit..." -ForegroundColor Cyan

# Initialize report collection
$report = [System.Collections.Generic.List[object]]::new()

# Get Exchange server information
try {
    if ($Server) {
        Write-Verbose "Auditing specific server: $Server"
        $exchangeServers = Get-ExchangeServer $Server -ErrorAction Stop
    }
    else {
        Write-Verbose "Discovering all Exchange servers..."
        $exchangeServers = Get-ExchangeServer | Sort-Object Name
        Write-Host "Found $($exchangeServers.Count) Exchange server(s)" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to retrieve Exchange server information: $_"
    exit 1
}

if (-not $exchangeServers) {
    Write-Error "No Exchange servers found in the environment."
    exit 1
}

# Get organization-level information
try {
    $organization = Get-OrganizationConfig -ErrorAction Stop
    $orgName = $organization.Name
}
catch {
    $orgName = "Unknown"
    Write-Warning "Could not retrieve organization configuration: $_"
}

# Get domain controller info
try {
    $domainInfo = Get-ADDomain -ErrorAction SilentlyContinue | Select-Object DNSRoot, Forest
}
catch {
    $domainInfo = [pscustomobject]@{
        DNSRoot = "Unknown"
        Forest  = "Unknown"
    }
}

# Build report sections

Write-Host "Gathering server configuration..." -ForegroundColor Cyan

# Section: Server Configuration
Add-Section -Title 'Exchange Server Configuration' -Description 'Detailed configuration of all Exchange servers in the environment.' -Severity 'Info' -Query {
    $exchangeServers | Select-Object Name, Site, Edition, AdminDisplayVersion, ServerRole,
        @ { n = 'IsMailboxServer'; e = { $_.ServerRoles -match 'Mailbox' } },
        @ { n = 'IsEdgeServer'; e = { $_.ServerRoles -match 'Edge' } },
        @ { n = 'IsHubTransportServer'; e = { $_.ServerRoles -match 'HubTransport' } }
}

# Section: Patch Levels
Add-Section -Title 'Exchange Server Update Rollups' -Description 'Current update rollup level for each Exchange server. Critical to maintain recent updates for security.' -Severity 'High' -Query {
    $exchangeServers | Select-Object Name,
        @ { n = 'ProductVersion'; e = { $_.AdminDisplayVersion.Major } },
        @ { n = 'BuildNumber'; e = { $_.AdminDisplayVersion.Build } },
        @ { n = 'ServicePack'; e = { $_.AdminDisplayVersion.ServicePack } },
        @ { n = 'UpdateRollup'; e = {
            if ($_.AdminDisplayVersion.Revision) {
                "RU$($_.AdminDisplayVersion.Revision)"
            }
            else {
                "No RU installed"
            }
        }},
        LastUpgradePatchTime
}

# Section: Database Availability Group (DAG) Configuration
Add-Section -Title 'Database Availability Groups' -Description 'DAG configuration and member status for mailbox servers.' -Severity 'Info' -Query {
    try {
        $dags = Get-DatabaseAvailabilityGroup -ErrorAction Stop
        if ($dags) {
            foreach ($dag in $dags) {
                [pscustomobject]@{
                    Name                  = $dag.Name
                    Servers               = ($dag.Servers -join '; ')
                    WitnessServer         = $dag.WitnessServer
                    WitnessDirectory      = $dag.WitnessDirectory
                    AutomaticDatabaseMountDag = $dag.AutomaticDatabaseMountDag
                    DatacenterAwareReplicationMode = $dag.DatacenterAwareReplicationMode
                }
            }
        }
        else {
            [pscustomobject]@{
                Name                  = "No DAGs configured"
                Servers               = "N/A"
                WitnessServer         = "N/A"
                WitnessDirectory      = "N/A"
                AutomaticDatabaseMountDag = "N/A"
                DatacenterAwareReplicationMode = "N/A"
            }
        }
    }
    catch {
        [pscustomobject]@{
            Name                  = "Error retrieving DAGs"
            Servers               = $_.Exception.Message
            WitnessServer         = "N/A"
            WitnessDirectory      = "N/A"
            AutomaticDatabaseMountDag = "N/A"
            DatacenterAwareReplicationMode = "N/A"
        }
    }
}

# Section: Mailbox Databases
Add-Section -Title 'Mailbox Database Configuration' -Description 'Configuration of all mailbox databases including replication and mount status.' -Severity 'Info' -Query {
    try {
        $databases = Get-MailboxDatabase -Status -ErrorAction Stop | Where-Object { $_.Server -in $exchangeServers.Name }
        
        if ($databases) {
            $databases | Select-Object Name, ServerName, DatabaseName,
                @ { n = 'Mounted'; e = { $_.Mounted } },
                @ { n = 'DatabaseSize'; e = { [math]::Round($_.DatabaseSize.ToBytes() / 1GB, 2) } },
                @ { n = 'AvailableNewMailboxSpace'; e = { [math]::Round($_.AvailableNewMailboxSpace.ToBytes() / 1MB, 2) } },
                LogFolderPath, EdbFilePath,
                @ { n = 'CircularLoggingEnabled'; e = { $_.CircularLoggingEnabled } },
                @ { n = 'CopyCount'; e = { $_.CopyCount } },
                LastFullBackup, LastIncrementalBackup
        }
        else {
            [pscustomobject]@{
                Name                  = "No mailbox databases found"
                ServerName            = "N/A"
                DatabaseName          = "N/A"
                Mounted               = "N/A"
                DatabaseSize          = "N/A"
                AvailableNewMailboxSpace = "N/A"
                LogFolderPath         = "N/A"
                EdbFilePath           = "N/A"
                CircularLoggingEnabled = "N/A"
                CopyCount             = "N/A"
                LastFullBackup        = "N/A"
                LastIncrementalBackup = "N/A"
            }
        }
    }
    catch {
        [pscustomobject]@{
            Name                  = "Error retrieving databases"
            ServerName            = $_.Exception.Message
            DatabaseName          = "N/A"
            Mounted               = "N/A"
            DatabaseSize          = "N/A"
            AvailableNewMailboxSpace = "N/A"
            LogFolderPath         = "N/A"
            EdbFilePath           = "N/A"
            CircularLoggingEnabled = "N/A"
            CopyCount             = "N/A"
            LastFullBackup        = "N/A"
            LastIncrementalBackup = "N/A"
        }
    }
}

Write-Host "Gathering certificate information..." -ForegroundColor Cyan

# Section: Certificates
Add-Section -Title 'Exchange Certificates' -Description 'SSL/TLS certificates installed on Exchange servers. Critical for secure communication.' -Severity 'Critical' -Query {
    try {
        $certs = Get-ExchangeCertificate | Where-Object { $_.PrivateKeyIsExportable -eq $true -or $_.Services -match 'SMTP|IIS' }
        
        if ($certs) {
            $certs | Select-Object Thumbprint, Subject,
                @ { n = 'Services'; e = { ($_.Services -join ', ') } },
                @ { n = 'Issuer'; e = { $_.Issuer } },
                NotBefore, NotAfter,
                @ { n = 'DaysUntilExpired'; e = { [math]::Max(0, ($_.NotAfter - (Get-Date)).Days) } },
                @ { n = 'IsExpired'; e = { $_.NotAfter -lt (Get-Date) } },
                @ { n = 'IsSelfSigned'; e = { $_.Issuer -eq $_.Subject } }
        }
        else {
            [pscustomobject]@{
                Thumbprint           = "No certificates found"
                Services             = "N/A"
                Issuer               = "N/A"
                NotBefore            = "N/A"
                NotAfter             = "N/A"
                DaysUntilExpired     = "N/A"
                IsExpired            = "N/A"
                IsSelfSigned         = "N/A"
            }
        }
    }
    catch {
        [pscustomobject]@{
            Thumbprint           = "Error retrieving certificates"
            Services             = $_.Exception.Message
            Issuer               = "N/A"
            NotBefore            = "N/A"
            NotAfter             = "N/A"
            DaysUntilExpired     = "N/A"
            IsExpired            = "N/A"
            IsSelfSigned         = "N/A"
        }
    }
}

Write-Host "Gathering transport configuration..." -ForegroundColor Cyan

# Section: Transport Configuration
Add-Section -Title 'Transport Configuration' -Description 'Send and receive connector configurations for mail flow.' -Severity 'Info' -Query {
    try {
        $sendConnectors = Get-SendConnector | Select-Object Name, AddressSpaces,
            @ { n = 'SmartHosts'; e = { ($_.SmartHosts -join '; ') } },
            @ { n = 'SourceTransportServers'; e = { ($_.SourceTransportServers -join '; ') } },
            @ { n = 'Enabled'; e = { $_.Enabled } },
            @ { n = 'TlsSettings'; e = { $_.TlsSettings } }
        
        $receiveConnectors = Get-ReceiveConnector | Select-Object Name, Server,
            @ { n = 'AuthMechanism'; e = { ($_.AuthMechanism -join '; ') } },
            @ { n = 'PermissionGroups'; e = { ($_.PermissionGroups -join '; ') } },
            @ { n = 'Enabled'; e = { $_.Enabled } },
            @ { n = 'Fqdn'; e = { $_.Fqdn } }
        
        [pscustomobject]@{
            Section    = "Send Connectors"
            Data       = $sendConnectors
        }
        [pscustomobject]@{
            Section    = "Receive Connectors"
            Data       = $receiveConnectors
        }
    }
    catch {
        [pscustomobject]@{
            Section    = "Transport Configuration Error"
            Data       = $_.Exception.Message
        }
    }
}

# Section: Transport Queues
Add-Section -Title 'Transport Queue Status' -Description 'Current status of transport queues on mailbox servers.' -Severity 'High' -Query {
    try {
        $queueStatus = @()
        
        foreach ($server in $exchangeServers | Where-Object { $_.ServerRoles -match 'Mailbox' }) {
            $queues = Get-Queue -Server $server.Name -ErrorAction SilentlyContinue
            foreach ($queue in $queues) {
                $queueStatus += [pscustomobject]@{
                    Server          = $server.Name
                    Identity        = $queue.Identity
                    Status          = $queue.Status
                    MessageCount    = $queue.MessageCount
                    DeferredMessageCount = $queue.DeferredMessageCount
                    NextHopCategory = $queue.NextHopCategory
                    LastError       = $queue.LastError
                }
            }
        }
        
        $queueStatus | Sort-Object Server, MessageCount -Descending
    }
    catch {
        [pscustomobject]@{
            Server          = "Error"
            Identity        = $_.Exception.Message
            Status          = "N/A"
            MessageCount    = 0
            DeferredMessageCount = 0
            NextHopCategory = "N/A"
            LastError       = "N/A"
        }
    }
}

Write-Host "Gathering address configuration..." -ForegroundColor Cyan

# Section: Address Lists and SMTP Domains
Add-Section -Title 'Address Configuration' -Description 'Accepted domains, address lists, and email policies.' -Severity 'Info' -Query {
    try {
        $acceptedDomains = Get-AcceptedDomain | Select-Object Name, DomainName,
            @ { n = 'DomainType'; e = { $_.DomainType } },
            @ { n = 'IsDefault'; e = { $_.IsDefault } },
            @ { n = 'EnableOutboundReply'; e = { $_.EnableOutboundReply } }
        
        $emailPolicies = Get-EmailAddressPolicy | Select-Object Name,
            @ { n = 'EnabledEmailAddressTemplates'; e = { ($_.EnabledEmailAddressTemplates -join '; ') } },
            @ { n = 'LdapRecipientFilter'; e = { $_.LdapRecipientFilter } },
            @ { n = 'ContainsRecipients'; e = { $_.ContainsRecipients } },
            LastModified
        
        [pscustomobject]@{
            Section    = "Accepted Domains"
            Data       = $acceptedDomains
        }
        [pscustomobject]@{
            Section    = "Email Address Policies"
            Data       = $emailPolicies
        }
    }
    catch {
        [pscustomobject]@{
            Section    = "Address Configuration Error"
            Data       = $_.Exception.Message
        }
    }
}

# Section: Mailbox Statistics
Add-Section -Title 'Mailbox Server Statistics' -Description 'Overall mailbox counts and database sizes per server.' -Severity 'Info' -Query {
    try {
        $mailboxStats = @()
        
        foreach ($server in $exchangeServers | Where-Object { $_.ServerRoles -match 'Mailbox' }) {
            $stats = Get-MailboxStatistics -Server $server.Name -ErrorAction SilentlyContinue
            if ($stats) {
                $dbSizes = $stats | Group-Object Database | Select-Object Name,
                    @ { n = 'MailboxCount'; e = { $_.Count } },
                    @ { n = 'TotalSizeGB'; e = { [math]::Round(($_.Group | Measure-Object -Property TotalItemSize -Sum).Sum / 1GB, 2) } }
                
                $mailboxStats += [pscustomobject]@{
                    Server              = $server.Name
                    MailboxCount        = $stats.Count
                    DatabaseCount       = ($dbSizes | Measure-Object).Count
                    TotalStorageGB      = [math]::Round(($stats | Measure-Object -Property TotalItemSize -Sum).Sum / 1GB, 2)
                }
            }
        }
        
        $mailboxStats
    }
    catch {
        [pscustomobject]@{
            Server              = "Error"
            MailboxCount        = $_.Exception.Message
            DatabaseCount       = "N/A"
            TotalStorageGB      = "N/A"
        }
    }
}

Write-Host "Gathering health information..." -ForegroundColor Cyan

# Section: Server Health Status
Add-Section -Title 'Server Health Status' -Description 'Health status of critical Exchange services and components.' -Severity 'Critical' -Query {
    try {
        $healthStatus = @()
        
        foreach ($server in $exchangeServers) {
            # Get service health
            $services = Get-Service -ComputerName $server.Name -ErrorAction SilentlyContinue | 
                Where-Object { $_.DisplayName -match 'Microsoft Exchange' } |
                Select-Object Name, DisplayName, Status
            
            # Get database copy status for mailbox servers
            if ($server.ServerRoles -match 'Mailbox') {
                $dbCopies = Get-MailboxDatabaseCopyStatus -Server $server.Name -ErrorAction SilentlyContinue
                
                foreach ($dbCopy in $dbCopies) {
                    $healthStatus += [pscustomobject]@{
                        Server              = $server.Name
                        Component           = "Database Copy: $($dbCopy.DatabaseName)"
                        Status              = $dbCopy.Status
                        ContentIndexState   = $dbCopy.ContentIndexState
                        CopyQueueLength     = $dbCopy.CopyQueueLength
                        ReplayQueueLength   = $dbCopy.ReplayQueueLength
                        LastInspectedLogTime = $dbCopy.LastInspectedLogTime
                    }
                }
            }
            
            # Add service health for Exchange services
            foreach ($service in $services) {
                if ($service.Status -eq 'Stopped') {
                    $healthStatus += [pscustomobject]@{
                        Server              = $server.Name
                        Component           = "Service: $($service.DisplayName)"
                        Status              = "Stopped"
                        ContentIndexState   = "N/A"
                        CopyQueueLength     = "N/A"
                        ReplayQueueLength   = "N/A"
                        LastInspectedLogTime = "N/A"
                    }
                }
            }
        }
        
        $healthStatus
    }
    catch {
        [pscustomobject]@{
            Server              = "Error"
            Component           = $_.Exception.Message
            Status              = "N/A"
            ContentIndexState   = "N/A"
            CopyQueueLength     = "N/A"
            ReplayQueueLength   = "N/A"
            LastInspectedLogTime = "N/A"
        }
    }
}

# Section: Database Availability Group Health
Add-Section -Title 'DAG Health Status' -Description 'Health of database availability groups and database copies.' -Severity 'High' -Query {
    try {
        $dagHealth = @()
        
        foreach ($server in $exchangeServers | Where-Object { $_.ServerRoles -match 'Mailbox' }) {
            $dbCopies = Get-MailboxDatabaseCopyStatus -Server $server.Name -ErrorAction SilentlyContinue
            
            foreach ($dbCopy in $dbCopies) {
                # Check for unhealthy states
                $isUnhealthy = $false
                $issues = @()
                
                if ($dbCopy.Status -ne 'Mounted' -and $dbCopy.Status -ne 'Healthy') {
                    $isUnhealthy = $true
                    $issues += "Status: $($dbCopy.Status)"
                }
                
                if ($dbCopy.CopyQueueLength -gt 10) {
                    $isUnhealthy = $true
                    $issues += "Copy Queue: $($dbCopy.CopyQueueLength)"
                }
                
                if ($dbCopy.ReplayQueueLength -gt 10) {
                    $isUnhealthy = $true
                    $issues += "Replay Queue: $($dbCopy.ReplayQueueLength)"
                }
                
                if ($dbCopy.ContentIndexState -ne 'Healthy') {
                    $isUnhealthy = $true
                    $issues += "Content Index: $($dbCopy.ContentIndexState)"
                }
                
                $dagHealth += [pscustomobject]@{
                    Server              = $server.Name
                    Database            = $dbCopy.DatabaseName
                    CopyStatus          = $dbCopy.Status
                    ContentIndex        = $dbCopy.ContentIndexState
                    CopyQueueLength     = $dbCopy.CopyQueueLength
                    ReplayQueueLength   = $dbCopy.ReplayQueueLength
                    IsUnhealthy         = $isUnhealthy
                    Issues              = ($issues -join '; ')
                }
            }
        }
        
        # Sort by unhealthy status first
        $dagHealth | Sort-Object { -not $_.IsUnhealthy }, Server, Database
    }
    catch {
        [pscustomobject]@{
            Server              = "Error"
            Database            = $_.Exception.Message
            CopyStatus          = "N/A"
            ContentIndex        = "N/A"
            CopyQueueLength     = "N/A"
            ReplayQueueLength   = "N/A"
            IsUnhealthy         = $true
            Issues              = "N/A"
        }
    }
}

Write-Host "Gathering organizational configuration..." -ForegroundColor Cyan

# Section: Organization Configuration
Add-Section -Title 'Organization Configuration' -Description 'High-level organization settings and features.' -Severity 'Info' -Query {
    try {
        $orgConfig = Get-OrganizationConfig | Select-Object Name, DisplayName,
            @ { n = 'ExchangeVersion'; e = { $_.ExchangeVersion } },
            @ { n = 'DefaultClientVersion'; e = { $_.DefaultClientVersion } },
            @ { n = 'OwaPolicy'; e = { $_.OwaMailboxPolicy } },
            @ { n = 'EwsEnabled'; e = { $_.EwsEnabled } },
            @ { n = 'MapiHttpEnabled'; e = { $_.MapiHttpEnabled } },
            @ { n = 'ImapEnabled'; e = { $_.ImapEnabled } },
            @ { n = 'PopEnabled'; e = { $_.PopEnabled } },
            @ { n = 'ActiveSyncEnabled'; e = { $_.ActiveSyncEnabled } }
        
        $transportConfig = Get-TransportConfig | Select-Object Name,
            @ { n = 'MaxSendSize'; e = { $_.MaxSendSize } },
            @ { n = 'MaxReceiveSize'; e = { $_.MaxReceiveSize } },
            @ { n = 'ExternalDsnEnabled'; e = { $_.ExternalDsnEnabled } },
            @ { n = 'InternalDsnEnabled'; e = { $_.InternalDsnEnabled } },
            @ { n = 'DsnFormat'; e = { $_.DsnFormat } }
        
        [pscustomobject]@{
            Section    = "Organization Configuration"
            Data       = $orgConfig
        }
        [pscustomobject]@{
            Section    = "Transport Configuration"
            Data       = $transportConfig
        }
    }
    catch {
        [pscustomobject]@{
            Section    = "Organization Configuration Error"
            Data       = $_.Exception.Message
        }
    }
}

# Section: Client Access Settings
Add-Section -Title 'Client Access Configuration' -Description 'Client access server settings and virtual directory configurations.' -Severity 'Info' -Query {
    try {
        $casSettings = @()
        
        foreach ($server in $exchangeServers | Where-Object { $_.ServerRoles -match 'Mailbox' }) {
            # Get OWA virtual directories
            $owaVdirs = Get-OwaVirtualDirectory -Server $server.Name -ErrorAction SilentlyContinue | 
                Select-Object Name, Server,
                @ { n = 'InternalUrl'; e = { $_.InternalUrl } },
                @ { n = 'ExternalUrl'; e = { $_.ExternalUrl } },
                @ { n = 'FormsAuthentication'; e = { $_.FormsAuthentication } },
                @ { n = 'WindowsAuthentication'; e = { $_.WindowsAuthentication } }
            
            # Get ECP virtual directories
            $ecpVdirs = Get-EcpVirtualDirectory -Server $server.Name -ErrorAction SilentlyContinue | 
                Select-Object Name, Server,
                @ { n = 'InternalUrl'; e = { $_.InternalUrl } },
                @ { n = 'ExternalUrl'; e = { $_.ExternalUrl } }
            
            # Get MAPI virtual directories
            $mapiVdirs = Get-MapiVirtualDirectory -Server $server.Name -ErrorAction SilentlyContinue | 
                Select-Object Name, Server,
                @ { n = 'InternalUrl'; e = { $_.InternalUrl } },
                @ { n = 'ExternalUrl'; e = { $_.ExternalUrl } }
            
            # Get EWS virtual directories
            $ewsVdirs = Get-WebServicesVirtualDirectory -Server $server.Name -ErrorAction SilentlyContinue | 
                Select-Object Name, Server,
                @ { n = 'InternalUrl'; e = { $_.InternalUrl } },
                @ { n = 'ExternalUrl'; e = { $_.ExternalUrl } },
                @ { n = 'BasicAuthentication'; e = { $_.BasicAuthentication } }
            
            $casSettings += [pscustomobject]@{
                Server              = $server.Name
                Component           = "OWA Virtual Directories"
                Data                = $owaVdirs
            }
            $casSettings += [pscustomobject]@{
                Server              = $server.Name
                Component           = "ECP Virtual Directories"
                Data                = $ecpVdirs
            }
            $casSettings += [pscustomobject]@{
                Server              = $server.Name
                Component           = "MAPI Virtual Directories"
                Data                = $mapiVdirs
            }
            $casSettings += [pscustomobject]@{
                Server              = $server.Name
                Component           = "EWS Virtual Directories"
                Data                = $ewsVdirs
            }
        }
        
        $casSettings
    }
    catch {
        [pscustomobject]@{
            Server              = "Error"
            Component           = $_.Exception.Message
            Data                = "N/A"
        }
    }
}

Write-Host "Building HTML report..." -ForegroundColor Cyan

# Build summary table
$summaryRows = $report | ForEach-Object {
    [pscustomobject]@{
        Severity = $_.Severity
        Check    = $_.Title
        Findings = if ($_.Error) { 'ERROR' } else { $_.Count }
    }
}
$summaryTable = ConvertTo-HtmlTable -Rows $summaryRows

# Define severity colors
$sevColour = @{
    Critical = '#c0392b'
    High     = '#e67e22'
    Medium   = '#f1c40f'
    Info     = '#3498db'
}

# Build HTML body
$body = [System.Text.StringBuilder]::new()

foreach ($sec in $report) {
    $colour = $sevColour[$sec.Severity]

    # Section heading with severity badge, title, and result count
    [void]$body.Append("<section><h2 style='border-left:6px solid $colour'>")
    [void]$body.Append("<span class='badge' style='background:$colour'>$($sec.Severity)</span> ")
    [void]$body.Append((ConvertTo-HtmlEncoded $sec.Title))

    $countLabel = if ($sec.Error) { 'error' } else { "$($sec.Count) result(s)" }
    [void]$body.Append("<span class='count'>$countLabel</span></h2>")

    # Description paragraph
    [void]$body.Append("<p class='desc'>$(ConvertTo-HtmlEncoded $sec.Description)</p>")

    # Body content: error message or data table
    if ($sec.Error) {
        [void]$body.Append("<p class='error'>Query error: $(ConvertTo-HtmlEncoded $sec.Error)</p>")
    }
    else {
        # Handle sections with multiple tables (like Transport, Address, CAS)
        if ($sec.Rows -and $sec.Rows[0] -is [pscustomobject] -and $sec.Rows[0].PSObject.Properties.Name -contains 'Section') {
            foreach ($tableData in $sec.Rows) {
                [void]$body.Append("<h3>$(ConvertTo-HtmlEncoded $tableData.Section)</h3>")
                if ($tableData.Data -is [array]) {
                    [void]$body.Append((ConvertTo-HtmlTable -Rows $tableData.Data))
                }
                else {
                    [void]$body.Append("<p class='error'>Error: $(ConvertTo-HtmlEncoded $tableData.Data)</p>")
                }
            }
        }
        # Handle sections with single table
        elseif ($sec.Rows -and @($sec.Rows).Count -gt 0) {
            # Check if first row has Data property (nested tables)
            if (@($sec.Rows)[0].PSObject.Properties.Name -contains 'Data') {
                foreach ($tableData in $sec.Rows) {
                    [void]$body.Append("<h3>$(ConvertTo-HtmlEncoded $tableData.Section)</h3>")
                    if ($tableData.Data -is [array]) {
                        [void]$body.Append((ConvertTo-HtmlTable -Rows $tableData.Data))
                    }
                    else {
                        [void]$body.Append("<p class='error'>Error: $(ConvertTo-HtmlEncoded $tableData.Data)</p>")
                    }
                }
            }
            else {
                [void]$body.Append((ConvertTo-HtmlTable -Rows $sec.Rows))
            }
        }
        else {
            [void]$body.Append('<p class="empty">No results &mdash; nothing flagged for this check.</p>')
        }
    }

    [void]$body.Append('</section>')
}

# Build header metadata
$hTitle   = "Exchange Environment Audit Report"
$hForest  = $domainInfo.Forest
$hRunBy   = "$env:USERDOMAIN\$env:USERNAME"
if ($Server) {
    $hTarget  = $Server
}
else {
    $hTarget  = "$($exchangeServers.Count) server(s)"
}

# Generate timestamp for report
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

# Build complete HTML document
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>$hTitle</title>
<style>
    :root { font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
    body { margin: 0; background: #f4f6f8; color: #222; }

    /* ---- Header ---- */
    header { background: #1f2d3d; color: #fff; padding: 24px 40px; }
    header h1 { margin: 0 0 4px; font-size: 22px; }
    header .meta { font-size: 13px; color: #b8c4d0; }
    header .classification {
        display: inline-block; margin-top: 12px;
        background: #c0392b; color: #fff;
        font-size: 11px; font-weight: 600;
        padding: 3px 10px; border-radius: 3px;
        text-transform: uppercase; letter-spacing: .05em;
    }

    /* ---- Layout ---- */
    main { max-width: 1200px; margin: 24px auto; padding: 0 24px; }
    section {
        background: #fff; border-radius: 8px;
        box-shadow: 0 1px 3px rgba(0,0,0,.1);
        margin-bottom: 20px; padding: 16px 20px;
    }

    /* ---- Section headers ---- */
    h2 { font-size: 16px; padding-left: 12px; display: flex; align-items: center; gap: 10px; }
    .badge {
        color: #fff; font-size: 11px; font-weight: 600;
        padding: 2px 8px; border-radius: 10px;
        text-transform: uppercase; letter-spacing: .04em;
    }
    .count { margin-left: auto; font-size: 12px; color: #888; font-weight: 400; }
    .desc  { font-size: 13px; color: #555; margin: 4px 0 12px; }

    /* ---- Tables ---- */
    table { border-collapse: collapse; width: 100%; font-size: 13px; }
    th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #eaeef1; }
    th { background: #f0f3f6; font-weight: 600; }
    tr:hover td { background: #fafbfc; }

    /* ---- Status messages ---- */
    .empty { color: #27ae60; font-size: 13px; font-style: italic; }
    .error { color: #c0392b; font-size: 13px; }

    /* ---- Summary overrides ---- */
    .summary th, .summary td { border-bottom: 1px solid #ddd; }

    /* ---- Footer ---- */
    footer { max-width: 1200px; margin: 0 auto 40px; padding: 0 24px; font-size: 12px; color: #999; }
</style>
</head>
<body>

<header>
    <h1>$hTitle</h1>
    <div class="meta">
        Target: $hTarget &nbsp;|&nbsp;
        Generated: $timestamp &nbsp;|&nbsp;
        Run by: $(ConvertTo-HtmlEncoded $hRunBy)
    </div>
    <!-- Remove or edit if the report does not contain sensitive data -->
    <div class="classification">Restricted &mdash; Exchange environment audit</div>
</header>

<main>
    <section class="summary">
        <h2 style="border-left:6px solid #1f2d3d">Summary</h2>
        <p class="desc">Overview of all checks and their finding counts.</p>
        $summaryTable
    </section>

    $($body.ToString())
</main>

<footer>
    Read-only audit. No Exchange configuration was modified.
    Report generated on $timestamp from server $env:COMPUTERNAME.
    For remediation guidance, refer to Microsoft Exchange documentation.
</footer>

</body>
</html>
"@

# Write HTML report
try {
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Report written to: $OutputPath" -ForegroundColor Green
    
    # Optionally open in browser
    if (-not $NoLaunch) {
        try { 
            Start-Process -FilePath $OutputPath -ErrorAction Stop
            Write-Host "Report opened in default browser." -ForegroundColor Cyan
        }
        catch {
            Write-Warning "Could not open report in browser: $_"
        }
    }
}
catch {
    Write-Error "Failed to write HTML report: $_"
    exit 1
}

Write-Host "Exchange Environment Audit completed successfully." -ForegroundColor Green
