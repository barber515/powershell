#Requires -Version 5.1

<#
.SYNOPSIS
    Comprehensive Windows Security Audit Tool
    
.DESCRIPTION
    Performs a complete security assessment of the Windows system covering:
    
    1. Installed Programs & Updates (risky software detection)
    2. Windows Update Status (patch currency)
    3. Networking Configuration (TCP/IP, DNS, ARP, listening ports)
    4. Hosts File Analysis (malicious domain detection)
    5. Windows Defender Status & Exceptions (real-time protection, exclusions)
    6. Third-Party AV/EDR Inventory
    7. Windows Firewall Rules (overly permissive rules, missing descriptions)
    8. Shared Resources (SMB share permissions analysis)
    9. Task Scheduler (system-level tasks, PowerShell/CMD execution)
    10. Registry Security Settings (UAC, LSA packages, IFEO debugging)
    11. User Accounts & Groups (disabled accounts, passwordless accounts, admin membership)
    12. UAC Configuration (elevation prompts, virtualization settings)
    13. Audit Policy Settings (event logging, log sizes)
    14. Local Security Policy (password, lockout, Kerberos, network access)
    15. Services Audit (running services, permissions)
    16. Startup Programs (persistence mechanisms)
    17. BitLocker / Disk Encryption (data-at-rest protection)
    18. PowerShell Configuration (execution policy, logging, AMSI)
    19. TPM / Secure Boot (foundation for BitLocker, Credential Guard, VBS)
    20. Event Log Configuration (log sizes, retention, overflow policies)
    21. WinRM / Remote Management (remote access configuration)
    22. Credential Guard / VBS (credential theft prevention)
    23. File System ACLs (critical path permissions)
    24. DNS Client Configuration (DHCP vs static, DNS suffix search)
    25. Windows Time Service (NTP configuration, time sync status)
    26. Print Spooler Status (PrintNightmare relevance)
    27. Group Policy Results (applied policies)
    28. Registry Security Options (LSA protection, UAC options, etc.)
    29. Saved Wi-Fi Profiles (stored credentials)
    30. Credential Manager (stored credentials)
    31. System Information (OS build, architecture, RAM, disk, CPU)
    
    Reports are exported to a collapsible HTML report with color-coded risk indicators.

    Coverage note: run elevated (Run as Administrator) for complete results. Defender threat
    history, BitLocker, TPM, Secure Boot, the Security event log, SMB share ACLs and other users'
    account details require administrator rights; an unelevated run still completes and marks
    those checks as unavailable rather than failing them.

.PARAMETER ExportPath
    Path where the HTML report will be saved. Defaults to the script directory.

.PARAMETER OutputMode
    Either "Detailed" for full output or "Summary" for condensed results.

.EXAMPLE
    PS> .\auditMe.ps1
    Runs a full security audit and exports report to AuditMe\report.html

.EXAMPLE
    PS> .\auditMe.ps1 -ExportPath "C:\Reports\SecurityAudit.html" -Verbose
    Runs audit with verbose output and saves HTML to custom location

.EXAMPLE
    PS> .\auditMe.ps1 -OutputMode Summary
    Runs audit with condensed output mode
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateScript({
        $dir = Split-Path $_ -Parent
        if (-not (Test-Path $dir)) {
            $null = New-Item -ItemType Directory -Path $dir -Force -ErrorAction SilentlyContinue
        }
        return (Test-Path $dir -PathType Container)
    })]
    [string]$ExportPath = ".\report.html",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Detailed", "Summary")]
    [string]$OutputMode = "Detailed",

    [Parameter(Mandatory = $false)]
    [switch]$NoLaunch
)

$ErrorActionPreference = "Continue"

# Strict mode 1.0 catches references to uninitialised variables (the class of bug that silently
# produces empty findings) while still tolerating the `$null.Foo` / `.Count` guards this script
# relies on. Version 2.0/Latest additionally throws PropertyNotFoundException for any missing
# property - including properties read off a cmdlet that returned $null - which would abort whole
# audit sections inside their own catch blocks and be mis-reported as "query failed".
Set-StrictMode -Version 1.0

# --- Configuration ---
$AuditResults = @{}
$VerboseOutput = ($OutputMode -eq "Detailed")

# Several checks (Defender status, BitLocker, TPM, Security event log, other users' accounts,
# SMB share ACLs) need elevation; record it so sections can say so instead of "query failed".
$IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# Pre-initialize all audit section keys to avoid null errors on first +=
$AuditSections = @(
    "InstalledPrograms", "WindowsUpdate", "Networking", "HostsFile",
    "WindowsDefender", "ThirdPartyAV", "WindowsFirewall", "NetworkShares",
    "TaskScheduler", "RegistrySecurity", "UserAccounts", "AuditPolicy",
    "LocalSecurityPolicy", "Services", "StartupPrograms", "BitLocker",
    "PowerShellConfig", "TPM_SecureBoot", "EventLogConfig", "WinRM",
    "CredentialGuard", "FileSystemACLs", "DNSClient", "WindowsTime",
    "PrintSpooler", "GroupPolicy", "RegistryOptions", "WifiProfiles",
    "CredentialManager", "SystemInfo"
)
foreach ($section in $AuditSections) {
    $AuditResults[$section] = @()
}


# --- Progress & Output Functions ---
function Write-ProgressOutput {
    param(
        [string]$Message,
        [switch]$Verbose = $false
    )

    if ($VerboseOutput -or $Verbose) {
        Write-Host "  → $Message"
    }
}

function Write-RiskOutput {
    param(
        [string]$Detail,
        [string]$RiskLevel
    )

    if (-not $VerboseOutput) { return }

    switch ($RiskLevel) {
        "Critical"   { Write-Host "  🔴 CRITICAL: $Detail" -ForegroundColor Red; break }
        "High"       { Write-Host "  🔴 HIGH:     $Detail" -ForegroundColor Red; break }
        "Medium"     { Write-Host "  🟠 MEDIUM:   $Detail" -ForegroundColor Yellow; break }
        "Low"        { Write-Host "  🔵 LOW:      $Detail" -ForegroundColor Cyan; break }
        "Pass"       { Write-Host "  ✅ PASS:     $Detail" -ForegroundColor Green; break }
        default      { Write-Host "  ℹ️ INFO:     $Detail" -ForegroundColor Gray }
    }
}

# --- HTML Report Generator ---
function Generate-HTMLReport {
    param(
        [string]$Title,
        [string[]]$Sections,
        [hashtable]$Results,
        [hashtable]$RiskCounts
    )

    # =====================================================================
    # Audit key -> report section title. $sectionDescriptions (below) is keyed by these titles.
    # =====================================================================
    $sectionTitles = [ordered]@{
        InstalledPrograms   = 'Installed Programs'
        WindowsUpdate       = 'Windows Update'
        Networking          = 'Networking'
        HostsFile           = 'Hosts File'
        WindowsDefender     = 'Windows Defender'
        ThirdPartyAV        = 'Third-Party AV'
        WindowsFirewall     = 'Firewall'
        NetworkShares       = 'Network Shares'
        TaskScheduler       = 'Task Scheduler'
        RegistrySecurity    = 'Registry Security'
        UserAccounts        = 'User Accounts'
        AuditPolicy         = 'Audit Policy'
        LocalSecurityPolicy = 'Local Security Policy'
        Services            = 'Services'
        StartupPrograms     = 'Startup Programs'
        BitLocker           = 'BitLocker'
        PowerShellConfig    = 'PowerShell Config'
        TPM_SecureBoot      = 'TPM / Secure Boot'
        EventLogConfig      = 'Event Log Config'
        WinRM               = 'WinRM'
        CredentialGuard     = 'Credential Guard'
        FileSystemACLs      = 'File System ACLs'
        DNSClient           = 'DNS Client'
        WindowsTime         = 'Windows Time'
        PrintSpooler        = 'Print Spooler'
        GroupPolicy         = 'Group Policy'
        RegistryOptions     = 'Registry Options'
        WifiProfiles        = 'Wi-Fi Profiles'
        CredentialManager   = 'Credential Manager'
        SystemInfo          = 'System Information'
    }

    # =====================================================================
    # Section descriptions (template §3)
    # =====================================================================
    $sectionDescriptions = @{
        'Installed Programs'    = 'Inventory of installed software and Windows hotfixes. Flags known risky or deprecated applications and checks update currency.'
        'Windows Update'        = 'Windows Update agent status, update history, and patch currency. Identifies systems that have not received updates within the last 30 days.'
        'Networking'            = 'TCP/IP profile status, DNS configuration, ARP cache analysis, and listening port inventory. Detects public DNS usage and open RDP ports.'
        'Hosts File'            = 'Analysis of the local hosts file for suspicious or malicious domain entries commonly associated with malware and phishing.'
        'Windows Defender'      = 'Microsoft Defender Antimalware status including real-time protection, exclusions count, and disabled components.'
        'Third-Party AV'        = 'Inventory of third-party antivirus and EDR solutions installed on the system.'
        'Firewall'              = 'Windows Defender Firewall rule analysis identifying overly permissive rules, missing descriptions, and dangerous inbound rules.'
        'Network Shares'        = 'SMB share enumeration and permission analysis to identify overly permissive network shares.'
        'Task Scheduler'        = 'Analysis of scheduled tasks for system-level tasks, PowerShell/CMD execution, and potential persistence mechanisms.'
        'Registry Security'     = 'UAC configuration, LSA notification packages, and Image File Execution Options (IFEO) debugging entries.'
        'User Accounts'         = 'Local user account audit including disabled accounts, passwordless accounts, password policies, and local administrator membership.'
        'Audit Policy'          = 'Security event logging configuration including audit policy settings, log sizes, and retention policies.'
        'Local Security Policy' = 'Local security policy settings for password complexity, lockout thresholds, Kerberos, and network access restrictions.'
        'Services'              = 'Running services inventory with startup type analysis and permission checks on service binaries.'
        'Startup Programs'      = 'Startup program inventory from registry Run keys and startup folder for persistence detection.'
        'BitLocker'             = 'BitLocker and disk encryption status to verify data-at-rest protection.'
        'PowerShell Config'     = 'PowerShell execution policy, script block logging, transcription, and AMSI configuration.'
        'TPM / Secure Boot'     = 'Trusted Platform Module (TPM) presence and Secure Boot status for foundation of BitLocker, Credential Guard, and VBS.'
        'Event Log Config'      = 'Windows Event Log configuration including maximum sizes, retention policies, and overflow behavior for critical logs.'
        'WinRM'                 = 'Windows Remote Management (WinRM) configuration including authentication methods, unencrypted traffic settings, and listener status.'
        'Credential Guard'      = 'Device Guard and Virtualization-Based Security (VBS) status for credential theft prevention.'
        'File System ACLs'      = 'Access Control List analysis on critical system paths to identify non-standard or overly permissive permissions.'
        'DNS Client'            = 'DNS client configuration including DHCP vs static, DNS suffix search lists, and DNS registration settings.'
        'Windows Time'          = 'Windows Time Service (W32Time) configuration, NTP source, and time synchronization status.'
        'Print Spooler'         = 'Print Spooler service status and PrintNightmare (CVE-2021-34527) relevance assessment.'
        'Group Policy'          = 'Group Policy results including domain membership, applied policies, and local GPO settings.'
        'Registry Options'      = 'Registry security options including UAC settings, local account token filter, and other security-relevant registry values.'
        'Wi-Fi Profiles'        = 'Saved Wi-Fi network profiles with stored key material analysis for potential credential exposure.'
        'Credential Manager'    = 'Stored credentials in Windows Credential Manager flagged for potentially risky targets (domain controllers, databases, etc.).'
        'System Information'    = 'System hardware and software inventory including OS details, CPU, RAM, disk space, and PowerShell version.'
    }

    # =====================================================================
    # Severity colour map (template §3)
    # =====================================================================
    $sevColour = @{
        Critical = '#c0392b'   # dark red - immediate action required
        High     = '#e67e22'   # orange  - significant risk, review soon
        Medium   = '#f1c40f'   # yellow  - noteworthy, investigate when convenient
        Low      = '#8e44ad'   # purple  | minor issue
        Pass     = '#27ae60'   # green   | verified good
        Info     = '#3498db'   # blue    | informational / clean state
    }

    # =====================================================================
    # Helper: encode a string for safe HTML output (template §1)
    # =====================================================================
    function ConvertTo-HtmlEncoded {
        param([string]$Value)
        if ($null -eq $Value) { return '' }
        [System.Net.WebUtility]::HtmlEncode($Value)
    }

    # =====================================================================
    # Helper: table renderer (template §2) - auto-detects columns from first row
    # =====================================================================
    function ConvertTo-HtmlTable {
        param([object[]]$Rows)
        if (-not $Rows -or @($Rows).Count -eq 0) {
            return '<p class="empty">No results &mdash; nothing flagged for this check.</p>'
        }
        $cols = ($Rows | Select-Object -First 1).PSObject.Properties.Name
        $sb   = [System.Text.StringBuilder]::new()
        [void]$sb.Append('<table><thead><tr>')
        foreach ($c in $cols) { [void]$sb.Append("<th>$(ConvertTo-HtmlEncoded $c)</th>") }
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

    # =====================================================================
    # Issue #3: Build structured report model from $AuditResults
    # Each section object has: Title, Description, Severity, Rows, Count, Error
    # =====================================================================
    function Get-HighestSeverity {
        param($items)
        $order = @('Critical','High','Medium','Low','Pass','Info')
        foreach ($sev in $order) {
            foreach ($item in $items) {
                if ($null -ne $item.RiskLevel -and $item.RiskLevel -eq $sev) { return $sev }
            }
        }
        return 'Info'
    }

    function Map-ItemSeverityToSectionSeverity {
        param([string]$highestItemSeverity)
        # Section-level Severity only supports Critical/High/Medium/Info (template §3)
        switch ($highestItemSeverity) {
            'Critical' { return 'Critical' }
            'High'     { return 'High' }
            'Medium'   { return 'Medium' }
            default    { return 'Info' }  # Low, Pass, Info all map to Info at section level
        }
    }

    $report = [System.Collections.Generic.List[object]]::new()

    foreach ($secKey in $Sections) {
        if (-not $Results.ContainsKey($secKey)) { continue }

        $items = @($Results[$secKey])
        $sectionTitle = if ($sectionTitles.Contains($secKey)) { [string]$sectionTitles[$secKey] } else { [string]$secKey }

        # Determine section-level severity and error status (template §3)
        $hasErrorItem = $false
        if ($null -ne $items) {
            foreach ($item in $items) {
                if (-not [string]::IsNullOrEmpty($item.RiskLevel) -and $item.RiskLevel -eq 'ERROR') {
                    $hasErrorItem = $true
                    break
                }
            }
        }

        $highestSeverity = Get-HighestSeverity -items $items
        $sectionSeverity = Map-ItemSeverityToSectionSeverity -highestItemSeverity $highestSeverity

        if ($hasErrorItem) {
            $sectionSeverity = 'Critical'  # Errors are critical severity (template §3)
        }

        $obj = [ordered]@{
            Title       = $sectionTitle
            Description = $sectionDescriptions[$secKey]
            Severity    = $sectionSeverity
            Rows        = @($items)
            Count       = if ($null -ne $items) { @($items).Count } else { 0 }
            Error       = if ($hasErrorItem) { 'Query error: one or more items flagged as ERROR' } else { $null }
        }

        $report.Add([pscustomobject]$obj)
    }

    # =====================================================================
    # Issue #4: Summary table using pre-assigned section-level properties (template §4)
    # =====================================================================
    $summaryRows = $report | ForEach-Object {
        [pscustomobject]@{
            Severity = $_.Severity
            Check    = $_.Title
            Findings = if ($_.Error) { 'ERROR' } else { $_.Count }
        }
    }
    $summaryTableHtml = ConvertTo-HtmlTable -Rows $summaryRows

    # =====================================================================
    # Issue #5: Build HTML body using <section><h2> structure with .desc paragraphs (template §5)
    # =====================================================================
    $body = [System.Text.StringBuilder]::new()

    foreach ($sec in $report) {
        $colour = $sevColour[$sec.Severity]

        # Section heading with severity badge, title, and result count (template §5)
        [void]$body.Append("<section class=""audit-section"" id=""section-$(($sec.Title -replace '[^a-zA-Z0-9]', '').ToLower())"">")
        [void]$body.Append("<h2 style='border-left:6px solid $colour'>")
        [void]$body.Append("<span class='badge' style='background:$colour'>$($sec.Severity)</span> ")
        [void]$body.Append((ConvertTo-HtmlEncoded $sec.Title))

        $countLabel = if ($sec.Error) { 'error' } else { "$($sec.Count) result(s)" }
        [void]$body.Append("<span class='count'>$countLabel</span></h2>")

        # Description paragraph (template §5)
        [void]$body.Append("<p class='desc'>$(ConvertTo-HtmlEncoded $sec.Description)</p>")

        # Body content: error message or data table (template §5)
        if ($sec.Error) {
            [void]$body.Append("<p class='error'>$(ConvertTo-HtmlEncoded $sec.Error)</p>")
        } else {
            [void]$body.Append((ConvertTo-HtmlTable -Rows $sec.Rows))
        }

        [void]$body.Append('</section>')
    }

    # =====================================================================
    # Gather metadata (template §6)
    # =====================================================================
    $computerName = $env:COMPUTERNAME
    $timestamp = Get-Date -Format 'MMMM dd, yyyy HH:mm:ss'
    $runBy = "$env:USERDOMAIN\$env:USERNAME"

    # Domain / Forest metadata
    $domainInfo = ''
    $forestInfo = ''
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        if ($null -ne $domain) {
            $domainInfo = $domain.Name
            $forestInfo = $domain.Forest.Name
        }
    } catch {
        $domainInfo = 'Not domain-joined'
        $forestInfo = 'N/A'
    }

    # Target DC
    $targetDC = 'N/A'
    try {
        $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDomainController()
        if ($null -ne $dc) {
            $targetDC = $dc.Name
        }
    } catch {
        $targetDC = 'Not domain-joined'
    }

    # =====================================================================
    # Issue #9: Full HTML document aligned with template §9 layout
    # Preserving custom CSS enhancements (responsive design, sticky headers)
    # =====================================================================
    $hTitle   = ConvertTo-HtmlEncoded $Title
    $hTarget  = ConvertTo-HtmlEncoded $targetDC
    $hUser    = ConvertTo-HtmlEncoded $runBy

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>$hTitle - Security Audit Report</title>
<style>
    :root { font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
    body { margin: 0; background: #f4f6f8; color: #222; padding: 2rem; line-height: 1.6; }

    /* ---- Header (template §9) ---- */
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

    /* ---- Layout (template §9) ---- */
    main { max-width: 1200px; margin: 24px auto; padding: 0 24px; }
    section {
        background: #fff; border-radius: 8px;
        box-shadow: 0 1px 3px rgba(0,0,0,.1);
        margin-bottom: 20px; padding: 16px 20px;
    }

    /* ---- Section headers (template §9) ---- */
    h2 { font-size: 16px; padding-left: 12px; display: flex; align-items: center; gap: 10px; margin: 0; }
    .badge {
        color: #fff; font-size: 11px; font-weight: 600;
        padding: 2px 8px; border-radius: 10px;
        text-transform: uppercase; letter-spacing: .04em;
    }
    .count { margin-left: auto; font-size: 12px; color: #888; font-weight: 400; }
    .desc  { font-size: 13px; color: #555; margin: 4px 0 12px; }

    /* ---- Tables (template §9) ---- */
    table { border-collapse: collapse; width: 100%; font-size: 13px; }
    th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #eaeef1; }
    th { background: #f0f3f6; font-weight: 600; white-space: nowrap; position: sticky; top: 0; z-index: 10; }
    tr:hover td { background: #fafbfc; }

    /* === Custom enhancement: severity status classes (WCAG-aware) === */
    .status-critical { color: #c0392b; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; }
    .status-high     { color: #e67e22; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; }
    .status-medium   { color: #d4a017; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; }
    .status-low      { color: #3498db; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; }
    .status-pass     { color: #27ae60; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; }
    .status-info     { color: #95a5a6; text-transform: capitalize; }

    /* ---- Status messages (template §9) ---- */
    .empty { color: #27ae60; font-size: 13px; font-style: italic; padding: 1.5rem; text-align: center; }
    .error { color: #c0392b; font-size: 13px; }

    /* ---- Summary overrides (template §4) ---- */
    .summary th, .summary td { border-bottom: 1px solid #ddd; }

    /* ---- Footer (template §8-9) ---- */
    footer { max-width: 1200px; margin: 0 auto 40px; padding: 0 24px; font-size: 12px; color: #999; }

    /* === Custom enhancement: responsive design === */
    @media (max-width: 768px) {
        body { padding: 1rem; }
        th, td { font-size: 0.8rem !important; padding: 0.5rem 0.75rem !important; }
    }
</style>
</head>
<body>

<header>
    <h1>$hTitle</h1>
    <div class="meta">
        Target: $hTarget &nbsp;|&nbsp;
        Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp;
        Run by: $hUser
    </div>
    <!-- Remove or edit if the report does not contain sensitive data -->
    <div class="classification">Restricted &mdash; contains privileged-account and attack-path detail</div>
</header>

<main>
    <section class="summary">
        <h2 style="border-left:6px solid #1f2d3d">Summary</h2>
        <p class="desc">Overview of all checks and their finding counts.</p>
        $summaryTableHtml
    </section>

    $($body.ToString())
</main>

<footer>
    Read-only audit. No directory objects were modified.<br>
    LastLogonTimestamp-based checks may lag true activity by up to ~14 days &mdash; validate before acting.<br>
    Generated by AuditMe v1.0 - Windows Security Audit Tool.
</footer>

</body>
</html>
"@
}


function Write-AuditError {
    param(
        [string]$Context,
        [string]$ErrorMessage
    )
    Write-Warning "  [$Context] $ErrorMessage"
}

# Reads a property that may legitimately be missing (OS build or elevation differences) without throwing
# under strict mode and without producing an empty column in the report.
function Get-OptionalProperty {
    param(
        [object]$InputObject,
        [string]$Name
    )

    if ($null -eq $InputObject) { return $null }

    foreach ($prop in @($InputObject.PSObject.Properties)) {
        if ($prop.Name -eq $Name) { return $prop.Value }
    }

    return $null
}

# --- Audit Functions ---

function Audit-InstalledPrograms {
    param($AuditResults)

    Write-ProgressOutput "Auditing installed programs and updates..." -Verbose:$false

    # Use registry-based query instead of Win32_Product (deprecated, triggers expensive consistency check)
    $programs = @()
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"
    )

    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            try {
                $keys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                foreach ($key in $keys) {
                    $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                    if ($null -ne $props -and -not [string]::IsNullOrEmpty($props.DisplayName)) {
                        $programs += [PSCustomObject]@{
                            Name      = $props.DisplayName
                            Version   = $props.DisplayVersion
                            InstallDate = $props.InstallDate
                            Publisher = $props.Publisher
                        }
                    }
                }
            } catch {
                Write-AuditError -Context "Registry Uninstall Query" -ErrorMessage $_.Exception.Message
            }
        }
    }

    $programs = $programs | Sort-Object Name

    if ($null -eq $programs -or $programs.Count -eq 0) {
        $AuditResults["InstalledPrograms"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Installed Programs Query"
            Detail    = "No programs found via registry (may require elevated privileges)"
        }
    }

    # Known risky/unwanted software patterns
    $riskyPatterns = @(
        @{Name="Adobe Flash Player"; RiskLevel="High"},
        @{Name="Java Runtime Environment"; RiskLevel="Medium"},
        @{Name="Java(TM) 7"; RiskLevel="Medium"},
        @{Name="Java(TM) 6"; RiskLevel="Medium"},
        @{Name="Silverlight"; RiskLevel="Medium"},
        @{Name="QuickTime"; RiskLevel="Medium"},
        @{Name="RealPlayer"; RiskLevel="High"},
        @{Name="WinRAR"; RiskLevel="Low"}
    )

    foreach ($program in $programs) {
        if ([string]::IsNullOrEmpty($program.Name)) { continue }

        # Check for risky software
        $foundRisky = $riskyPatterns | Where-Object {$_.Name -eq $program.Name}
        
        if ([string]::IsNullOrEmpty($foundRisky.RiskLevel)) {
            $riskLevel = "Info"
        } else {
            $riskLevel = $foundRisky.RiskLevel
        }
        
        $AuditResults["InstalledPrograms"] += [PSCustomObject]@{
            RiskLevel = $riskLevel
            Name      = $program.Name
            Detail    = "v$($program.Version) | Installed: $($program.InstallDate)"
        }

        $riskLabel = if ($foundRisky.RiskLevel) { $foundRisky.RiskLevel } else { "" }
        Write-RiskOutput "$($program.Name) v$($program.Version) - $riskLabel" $riskLevel
    }

    # Check for missing critical updates (hotfixes)
    try {
        $hotfixes = Get-HotFix | Select-Object HotFixID, Description, InstalledOn | Sort-Object InstalledOn -Descending
        
        if ($null -ne $hotfixes) {
            $AuditResults["InstalledPrograms"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Recent Updates"
                Detail    = "$($hotfixes.Count) hotfix(es) found | Most recent: $($hotfixes[0].HotFixID)"
            }
        } else {
            $AuditResults["InstalledPrograms"] += [PSCustomObject]@{
                RiskLevel = "Medium"
                Name      = "Windows Update"
                Detail    = "Unable to query hotfix information (requires elevated privileges)"
            }
        }
    } catch {
        Write-AuditError -Context "HotFix Query" -ErrorMessage $_.Exception.Message
    }

    Write-ProgressOutput "Found $($programs.Count) installed programs." -Verbose:$false
}

function Audit-WindowsUpdate {
    param($AuditResults)

    Write-ProgressOutput "Auditing Windows Update status..." -Verbose:$false

    # Method 1: Check WindowsUpdate.log (Windows 10/11)
    try {
        $wuLogPath = "$env:SystemRoot\WindowsUpdate.log"
        if (Test-Path $wuLogPath) {
            $logContent = Get-Content $wuLogPath -TotalCount 50 -ErrorAction SilentlyContinue
            $lastUpdateTime = $logContent | Select-String "ReportEvent.*EventId = 28" | Select-Object -Last 1
            if ($null -ne $lastUpdateTime) {
                $AuditResults["WindowsUpdate"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "WindowsUpdate Log"
                    Detail    = "Log found at $wuLogPath"
                }
            }
        }
    } catch {
        Write-AuditError -Context "WindowsUpdate Log" -ErrorMessage $_.Exception.Message
    }

    # Method 2: Check installed updates via WUA (Windows Update Agent)
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $totalUpdates = $updateSearcher.GetTotalHistoryCount()
        
        $AuditResults["WindowsUpdate"] += [PSCustomObject]@{
            RiskLevel = "Info"
            Name      = "Windows Update History"
            Detail    = "$totalUpdates update history entries found"
        }

        # Get last few updates
        # QueryHistory returns oldest-first, so sort explicitly before picking "Last Update".
        $historyCount   = [Math]::Min(200, [Math]::Max([int]$totalUpdates, 1))
        $history        = @($updateSearcher.QueryHistory(0, $historyCount))
        $recentUpdates  = @($history | Where-Object { $null -ne $_.Date } | Sort-Object Date -Descending)

        if ($recentUpdates.Count -gt 0) {
            $lastUpdate = [pscustomobject](@($recentUpdates | Select-Object -First 1)[0])
            $lastDate   = $lastUpdate.Date.ToString("yyyy-MM-dd")

            $AuditResults["WindowsUpdate"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Last Update"
                Detail    = "$($lastUpdate.Title) on $lastDate ($(@($history).Count) history entries reviewed)"
            }

            # Patch currency against a 30-day baseline.
            $daysSinceUpdate = (Get-Date) - $lastUpdate.Date

            if ($daysSinceUpdate.Days -gt 30) {
                Write-Host "    ⚠️ Last update was $($daysSinceUpdate.Days) days ago." -ForegroundColor Yellow
                $AuditResults["WindowsUpdate"] += [PSCustomObject]@{
                    RiskLevel = if ($daysSinceUpdate.Days -gt 60) { "High" } else { "Medium" }
                    Name      = "Update Currency"
                    Detail    = "Last update was $($daysSinceUpdate.Days) days ago (over the 30-day baseline)"
                }
            } else {
                $AuditResults["WindowsUpdate"] += [PSCustomObject]@{
                    RiskLevel = "Pass"
                    Name      = "Update Currency"
                    Detail    = "Last update was $($daysSinceUpdate.Days) days ago"
                }
            }

            # Failed updates are as much of a gap as missing ones.
            $failedUpdates = @($history | Where-Object { [bool]$_.IsError -and -not $_.ResultCode })
            if ($failedUpdates.Count -gt 0) {
                $AuditResults["WindowsUpdate"] += [PSCustomObject]@{
                    RiskLevel = "Medium"
                    Name      = "Failed Updates In History"
                    Detail    = "$($failedUpdates.Count) update(s) in the last $(@($history).Count) history entries reported an error (latest: $(@($failedUpdates | Sort-Object Date -Descending)[0].Title))"
                }
            }
        } else {
            $AuditResults["WindowsUpdate"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Update History"
                Detail    = "No update history entries returned (fresh install or history cleared)"
            }
        }

        # Check for pending reboots (indicates updates not fully applied)
        $pendingRebootKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"
        )
        foreach ($key in $pendingRebootKeys) {
            if (Test-Path $key) {
                $AuditResults["WindowsUpdate"] += [PSCustomObject]@{
                    RiskLevel = "Medium"
                    Name      = "Pending Reboot"
                    Detail    = "Reboot required at $key"
                }
                break
            }
        }

    } catch {
        Write-AuditError -Context "Windows Update Agent" -ErrorMessage $_.Exception.Message
        $AuditResults["WindowsUpdate"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Windows Update Agent"
            Detail    = "Unable to query WUA (requires elevated privileges)"
        }
    }

    # Method 3: Check Windows Update service status
    try {
        $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        if ($null -ne $wuService) {
            if ($wuService.Status -eq "Running") {
                $AuditResults["WindowsUpdate"] += [PSCustomObject]@{
                    RiskLevel = "Pass"
                    Name      = "Windows Update Service"
                    Detail    = "Service is running"
                }
            } else {
                $AuditResults["WindowsUpdate"] += [PSCustomObject]@{
                    RiskLevel = "High"
                    Name      = "Windows Update Service"
                    Detail    = "Service is $($wuService.Status) (should be Running)"
                }
            }
        }
    } catch {
        Write-AuditError -Context "Windows Update Service" -ErrorMessage $_.Exception.Message
    }

    Write-ProgressOutput "Windows Update audit complete." -Verbose:$false
}

function Audit-Networking {
    param($AuditResults)

    Write-ProgressOutput "Auditing network configuration..." -Verbose:$false

    # TCP/IP Profile Status
    try {
        $tcpProfiles = @(Get-NetConnectionProfile | Select-Object InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity)

        foreach ($profile in $tcpProfiles) {
            $riskLevel = if ($profile.IPv4Connectivity -eq 'Disconnected' -or ([string]::IsNullOrWhiteSpace([string]$profile.IPv4Connectivity) -and [string]::IsNullOrWhiteSpace([string]$profile.IPv6Connectivity))) { "Low" } else { "Pass" }

            $AuditResults["Networking"] += [PSCustomObject]@{
                RiskLevel = $riskLevel
                Name      = "TCP/IP Profile: $($profile.InterfaceAlias)"
                Detail    = "Category: $($profile.NetworkCategory) | IPv4: $($profile.IPv4Connectivity) | IPv6: $($profile.IPv6Connectivity)"
            }

            # An interface on the Public network with full connectivity is worth an operator's attention.
            if ("$($profile.NetworkCategory)" -eq 'Public' -and "$($profile.IPv4Connectivity)" -eq 'Internet') {
                Write-RiskOutput "$($profile.InterfaceAlias) is connected to a Public network category" "Info"
            } else {
                Write-RiskOutput "$($profile.InterfaceAlias): $($profile.NetworkCategory)" $riskLevel
            }
        }

        if ($tcpProfiles.Count -eq 0) {
            $AuditResults["Networking"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "TCP/IP Profiles"
                Detail    = "No network profiles returned"
            }
        }
    } catch {
        Write-AuditError -Context "TCP/IP Profiles" -ErrorMessage $_.Exception.Message
        $AuditResults["Networking"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "TCP/IP Profile"
            Detail    = $_.Exception.Message
        }
    }

    # DNS Configuration
    try {
        $dnsConfig = @(Get-DnsClientServerAddress -ErrorAction Stop | Where-Object { @($_.ServerAddresses).Count -gt 0 })

        # Public resolvers bypass internal DNS policy, split-horizon records and content filtering; on a
        # domain-joined host they also break Kerberos/DNS-based authentication lookups.
        $publicDnsServers = @{
            '8.8.8.8'='Google DNS'; '8.8.4.4'='Google DNS'; '1.1.1.1'='Cloudflare DNS'; '1.0.0.1'='Cloudflare DNS'
            '208.67.222.222'='OpenDNS'; '208.67.220.220'='OpenDNS'; '9.9.9.9'='Quad9'; '149.112.112.112'='Quad9'
        }

        foreach ($dns in $dnsConfig) {
            $servers = @($dns.ServerAddresses)

            $AuditResults["Networking"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "DNS Servers: $($dns.InterfaceAlias)"
                Detail    = "$($servers -join ', ')"
            }

            foreach ($server in $servers) {
                if ($publicDnsServers.ContainsKey([string]$server)) {
                    Write-Host "    ⚠️ Public DNS server on $($dns.InterfaceAlias): $server ($($publicDnsServers[[string]$server]))" -ForegroundColor Yellow
                    $AuditResults["Networking"] += [PSCustomObject]@{
                        RiskLevel = "Medium"
                        Name      = "Public DNS Server In Use"
                        Detail    = "$($dns.InterfaceAlias) uses $server ($($publicDnsServers[[string]$server])) - bypasses internal DNS policy and filtering"
                    }
                }
            }
        }

        if ($dnsConfig.Count -eq 0) {
            $AuditResults["Networking"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "DNS Servers"
                Detail    = "No interfaces with DNS server addresses returned"
            }
        }

    } catch {
        Write-AuditError -Context "DNS Query" -ErrorMessage $_.Exception.Message
    }

    # Neighbor cache analysis. Get-NetARP does not exist - the cmdlet is Get-NetNeighbor and its
    # link-layer column is LinkAddress (there is no MACAddress/StartTime).
    try {
        $arpCache = @(Get-NetNeighbor -ErrorAction Stop | Where-Object { $_.IPAddress } |
                      Select-Object IPAddress, InterfaceAlias, LinkAddress, State)

        Write-ProgressOutput "$($arpCache.Count) ARP/NDP neighbour entries." -Verbose:$false

        $seenAddresses = @{}
        $malformed     = 0
        $conflicts     = 0

        foreach ($entry in $arpCache) {
            $mac = [string]$entry.LinkAddress
            if ([string]::IsNullOrWhiteSpace($mac)) { continue }

            # A well-formed Ethernet address has exactly six octets, separated by '-' or ':'.
            $separatorCount = ([regex]::Matches($mac, '[-:]')).Count
            if ($separatorCount -ne 5) {
                $malformed++
                Write-Host "    ⚠️ Malformed link-layer address: $($entry.IPAddress) -> $mac" -ForegroundColor Yellow
                $AuditResults["Networking"] += [PSCustomObject]@{
                    RiskLevel = "High"
                    Name      = "Malformed ARP/NDP Entry"
                    Detail    = "$($entry.IPAddress) on $($entry.InterfaceAlias) has link-layer address $mac ($($entry.State))"
                }
            }

            # The same address claimed by two different MACs is the classic spoofing signature.
            if ($seenAddresses.ContainsKey($entry.IPAddress)) {
                if ([string]$seenAddresses[$entry.IPAddress] -ne $mac) {
                    $conflicts++
                    Write-Host "    ⚠️ ARP conflict for $($entry.IPAddress): $($seenAddresses[$entry.IPAddress]) vs $mac" -ForegroundColor Yellow
                    $AuditResults["Networking"] += [PSCustomObject]@{
                        RiskLevel = "High"
                        Name      = "Duplicate IP In ARP/NDP Cache"
                        Detail    = "$($entry.IPAddress) claimed by $($seenAddresses[$entry.IPAddress]) and $mac ($($entry.InterfaceAlias))"
                    }
                }
            } else {
                $seenAddresses[$entry.IPAddress] = $mac
            }
        }

        if ($malformed -eq 0 -and $conflicts -eq 0) {
            $AuditResults["Networking"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "ARP/NDP Cache"
                Detail    = "$($arpCache.Count) entries reviewed; no malformed link-layer addresses or duplicate-IP conflicts"
            }
        }

    } catch {
        Write-AuditError -Context "ARP/NDP Cache" -ErrorMessage $_.Exception.Message
    }

    # Netstat - Listening Ports Analysis (more reliable than Get-NetTCPConnection on some Windows versions)
    # Listening ports. netstat is used because Get-NetTCPConnection has been unreliable on some builds.
    try {
        $listeningPorts = [System.Collections.Generic.List[object]]::new()

        foreach ($line in @(netstat -ano 2>$null)) {
            if ($line -match '^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+LISTENING\s+(\d+)') {
                $listeningPorts.Add([pscustomobject]@{
                    LocalAddress  = $matches[1]
                    LocalPort     = [int]$matches[2]
                    RemoteAddress = $matches[3]
                    RemotePort    = [int]$matches[4]
                    OwningProcess = [int]$matches[5]
                })
            }
        }

        # Resolve process names once instead of calling Get-Process per listening port.
        $processNamesByPid = @{}
        foreach ($proc in @(Get-Process -ErrorAction SilentlyContinue)) {
            if (-not [string]::IsNullOrWhiteSpace($proc.ProcessName)) { $processNamesByPid[[int]$proc.Id] = [string]$proc.ProcessName }
        }

        # Ports that are expected to be served by system components.
        $expectedPrivilegedPorts = @(53, 80, 123, 445, 135, 137, 138, 139)
        $inventory               = [System.Collections.Generic.List[string]]::new()

        foreach ($port in $listeningPorts) {
            if ($processNamesByPid.ContainsKey($port.OwningProcess)) {
                $processName = [string]$processNamesByPid[$port.OwningProcess]
            } else {
                # System processes (PID 4 and below) are not always enumerable without elevation.
                $processName = "PID $($port.OwningProcess)"
            }

            if ($port.LocalPort -lt 1024 -and $expectedPrivilegedPorts -notcontains $port.LocalPort) {
                if ($processName -match '^(svchost|System|services|MoCMRT|spoolsv)$') {
                    $AuditResults["Networking"] += [PSCustomObject]@{
                        RiskLevel = "Info"
                        Name      = "Privileged Port: $($port.LocalPort)"
                        Detail    = "$processName listening on $($port.LocalAddress):$($port.LocalPort)"
                    }
                } else {
                    Write-Host "    ⚠️ Non-standard privileged port: $([int]$port.LocalPort) - $processName" -ForegroundColor Yellow
                    $AuditResults["Networking"] += [PSCustomObject]@{
                        RiskLevel = "Medium"
                        Name      = "Unusual Privileged Port"
                        Detail    = "$processName listening on $($port.LocalAddress):$($port.LocalPort)"
                    }
                }
            } else {
                $inventory.Add("$($port.LocalPort)/$($processName)")
            }
        }

        # Aggregate the ordinary listeners into one row instead of one row per port.
        if ($inventory.Count -gt 0) {
            $sample = (@($inventory | Select-Object -First 30) -join ', ')
            $AuditResults["Networking"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "Listening Ports"
                Detail    = "$($inventory.Count) expected listeners: $sample$(if ($inventory.Count -gt 30) { ' ...' } else { '' })"
            }
        }

        Write-ProgressOutput "$($listeningPorts.Count) TCP listeners reviewed." -Verbose:$false

    } catch {
        Write-Host "  ⚠️ Could not query listening ports: $_" -ForegroundColor Yellow
    }

    # IPv6 Configuration Check
    # IPv6 posture. IPGlobalProperties has no IPv6Properties member; the per-adapter binding is authoritative.
    try {
        $ipv6Bindings = @(Get-NetAdapterBinding -ComponentID 'ms_tcpip6' -ErrorAction Stop)
        $ipv6Enabled  = @($ipv6Bindings | Where-Object { $_.Enabled })

        if ($ipv6Bindings.Count -eq 0) {
            $AuditResults["Networking"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "IPv6 Status"
                Detail    = "No adapter bindings returned; unable to determine whether IPv6 is enabled"
            }
        } elseif ($ipv6Enabled.Count -eq 0) {
            Write-Host "  ✅ IPv6 is disabled on all adapters." -ForegroundColor Green
            $AuditResults["Networking"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "IPv6 Status"
                Detail    = "Disabled on all $($ipv6Bindings.Count) adapter bindings (reduces attack surface, may break IPv6-only resources)"
            }
        } else {
            Write-Host "    ℹ️ IPv6 enabled on $($ipv6Enabled.Count) of $($ipv6Bindings.Count) adapters" -ForegroundColor Cyan
            $AuditResults["Networking"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "IPv6 Status"
                Detail    = "Enabled on $($ipv6Enabled.Count) of $($ipv6Bindings.Count) adapter bindings: $(@($ipv6Enabled | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', ')"
            }
        }

    } catch {
        Write-AuditError -Context "IPv6 Check" -ErrorMessage $_.Exception.Message
    }

    # Check for open RDP port
    try {
        $rdpListening = Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, OwningProcess
        
        if ($null -ne $rdpListening) {
            Write-Host "    ⚠️ RDP (port 3389) is listening on $($rdpListening.LocalAddress)" -ForegroundColor Yellow
            $AuditResults["Networking"] += [PSCustomObject]@{
                RiskLevel = if ($rdpListening.LocalAddress -eq "::" -or $rdpListening.LocalAddress -eq "0.0.0.0") { "High" } else { "Low" }
                Name      = "Remote Desktop (RDP)"
                Detail    = "$($rdpListening.LocalAddress):3389 | PID: $($rdpListening.OwningProcess)"
            }
        } else {
            $AuditResults["Networking"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "Remote Desktop (RDP)"
                Detail    = "Port 3389 is not listening"
            }
        }

    } catch {
        Write-AuditError -Context "RDP Check" -ErrorMessage $_.Exception.Message
    }

    Write-ProgressOutput "Network audit complete." -Verbose:$false
}

function Audit-HostsFile {
    param($AuditResults)

    Write-ProgressOutput "Auditing hosts file..." -Verbose:$false

    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'

    if (-not (Test-Path -LiteralPath $hostsPath)) {
        $AuditResults["HostsFile"] += [PSCustomObject]@{
            RiskLevel = "High"
            Name      = "Hosts File Status"
            Detail    = "Not found at expected location: $hostsPath"
        }
        Write-Warning "  Hosts file not found at $hostsPath"
        return
    }

    try {
        # Comments and blank lines are not entries. The previous implementation skipped the first line of
        # the file unconditionally, which silently dropped a real entry when the file did not start with a comment.
        $rawLines    = @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop)
        $hostEntries = @($rawLines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -notmatch '^\s*#' })

        $parsedEntries = foreach ($entry in $hostEntries) {
            $clean = (($entry -split '#', 2)[0]).Trim()          # drop inline comments
            if ([string]::IsNullOrWhiteSpace($clean)) { continue }

            $fields = @($clean -split '\s+')
            if ($fields.Count -lt 2) { continue }

            [pscustomobject]@{
                Line    = $clean
                Address = $fields[0]
                Names   = @($fields[1..($fields.Count - 1)])
            }
        }
        $parsedEntries = @($parsedEntries)

        Write-Host "  → Hosts file has $($parsedEntries.Count) active entries." -ForegroundColor Cyan

        if ($parsedEntries.Count -eq 0) {
            $AuditResults["HostsFile"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "Hosts File Entries"
                Detail    = "No custom entries configured"
            }
        } else {
            # 1. Names that strongly suggest a tampered or joke entry.
            $keywordPattern = '(?i)(^|[.\-])(malware|evil|hack(er)?|crack(ed)?|pirate|torrent|phish(ing)?|spam|xxx)([.\-]|$)'

            # 2. Vendor/security domains redirected away from a loopback/null address - classic malware
            #    behaviour used to break updates and security tooling.
            $vendorPattern = '(?i)(^|\.)(microsoft|windowsupdate|update\.microsoft|microsoftstore|officecdn\.microsoft|symantec|mcafee|norton|trendmicro|eset|kaspersky|sophos|bitdefender|malwarebytes|avast|avg|avira|crowdstrike|sentinelone|nvidia|adobe|google|gvt1)\.'
            $nullRoutes    = @('0.0.0.0', '127.0.0.1', '::1', '255.255.255.255')

            $maliciousDomains = @('malware.com','evil.com','hack.com','crack.com','pirate.com','torrent.com','phish.com','spam.com')
            $listed           = 0

            foreach ($entry in $parsedEntries) {
                foreach ($name in $entry.Names) {
                    # Known-bad literal domains are findings on their own.
                    if ($maliciousDomains -contains $name.ToLower()) {
                        Write-Host "    🔴 Malicious domain found: $name" -ForegroundColor Red
                        $AuditResults["HostsFile"] += [PSCustomObject]@{
                            RiskLevel = "Critical"
                            Name      = "Malicious Host Entry"
                            Detail    = "$($entry.Address) -> $name (known-bad domain)"
                        }
                    }

                    if ($name -match $keywordPattern) {
                        Write-Host "    ⚠️ Suspicious host name: $name" -ForegroundColor Yellow
                        $AuditResults["HostsFile"] += [PSCustomObject]@{
                            RiskLevel = "High"
                            Name      = "Suspicious Host Entry"
                            Detail    = "$($entry.Address) -> $name (suspicious keyword)"
                        }
                    }

                    if ($name -match $vendorPattern -and $nullRoutes -notcontains $entry.Address) {
                        Write-Host "    🔴 Vendor domain redirected to a routable address: $name -> $($entry.Address)" -ForegroundColor Red
                        $AuditResults["HostsFile"] += [PSCustomObject]@{
                            RiskLevel = "Critical"
                            Name      = "Vendor Domain Redirected"
                            Detail    = "$($entry.Address) -> $name (security/update infrastructure must not resolve to a routable host)"
                        }
                    }
                }

                if ($listed -lt 40) {
                    $listed++
                    $AuditResults["HostsFile"] += [PSCustomObject]@{
                        RiskLevel = "Info"
                        Name      = "Host Entry"
                        Detail    = "$($entry.Line)"
                    }
                }
            }

            if ($parsedEntries.Count -gt $listed) {
                $AuditResults["HostsFile"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "Host Entries (truncated)"
                    Detail    = "$($parsedEntries.Count - $listed) further entries omitted from the listing"
                }
            }

            # 3. The same name mapped to more than one address is a load-balancing trick used by redirectors.
            foreach ($group in @($parsedEntries | ForEach-Object { $_.Names } | Group-Object | Where-Object { $_.Count -gt 1 })) {
                $addresses = @()
                foreach ($entry in $parsedEntries) {
                    if (@($entry.Names | Where-Object { $_ -eq $group.Name }).Count -gt 0) { $addresses += $entry.Address }
                }
                if (@($addresses | Select-Object -Unique).Count -gt 1) {
                    Write-Host "    ⚠️ Host '$($group.Name)' resolves to multiple addresses: $(@($addresses | Select-Object -Unique) -join ', ')" -ForegroundColor Yellow
                    $AuditResults["HostsFile"] += [PSCustomObject]@{
                        RiskLevel = "Medium"
                        Name      = "Duplicate Host Mapping"
                        Detail    = "$($group.Name) -> $(@($addresses | Select-Object -Unique) -join ', ')"
                    }
                }
            }

            $AuditResults["HostsFile"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Hosts File Inventory"
                Detail    = "$($parsedEntries.Count) entries in $hostsPath"
            }
        }

    } catch {
        Write-Warning "Could not read hosts file: $_"
        $AuditResults["HostsFile"] += [PSCustomObject]@{
            RiskLevel = "High"
            Name      = "Read Error"
            Detail    = $_.Exception.Message
        }
    }

    Write-ProgressOutput "Hosts audit complete." -Verbose:$false
}

function Audit-WindowsDefender {
    param($AuditResults)

    Write-ProgressOutput "Auditing Windows Defender status..." -Verbose:$false

    # Get-MpComputerStatus/Get-MpPreference fail when a third-party AV is registered, when the service is
    # stopped, or when running unelevated. Initialise first so later blocks never reference an unset variable.
    $defenderStatus = $null
    $mpPref         = $null

    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    } catch {
        Write-AuditError -Context "Get-MpComputerStatus" -ErrorMessage $_.Exception.Message
    }

    try {
        $mpPref = Get-MpPreference -ErrorAction Stop
    } catch {
        Write-AuditError -Context "Get-MpPreference" -ErrorMessage $_.Exception.Message
    }

    if ($null -eq $defenderStatus -and $null -eq $mpPref) {
        Write-Host "  ⚠️ Microsoft Defender is not installed or unavailable." -ForegroundColor Yellow
        $AuditResults["WindowsDefender"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Antimalware Engine"
            Detail    = "Microsoft Defender not available (third-party AV registered, service stopped, or elevation required)"
        }
        Write-ProgressOutput "Defender audit complete." -Verbose:$false
        return
    }

    # ------------------------------------------------------------------
    # Protection state (properties come from MSFT_MpComputerStatus)
    # ------------------------------------------------------------------
    if ($null -ne $defenderStatus) {
        $amEnabled = [bool]$defenderStatus.AMServiceEnabled -and
                     ([bool]$defenderStatus.AntivirusEnabled -or [bool]$defenderStatus.AntispywareEnabled)

        if (-not $amEnabled) {
            Write-Host "  🔴 WARNING: Microsoft Defender antimalware is DISABLED!" -ForegroundColor Red
            $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                RiskLevel = "Critical"
                Name      = "Antimalware Status"
                Detail    = "AMServiceEnabled=$($defenderStatus.AMServiceEnabled) AntivirusEnabled=$($defenderStatus.AntivirusEnabled) AntispywareEnabled=$($defenderStatus.AntispywareEnabled)"
            }
        } else {
            Write-Host "  ✅ Microsoft Defender is enabled." -ForegroundColor Green
            $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "Antimalware Status"
                Detail    = "Engine running (mode: $($defenderStatus.AMRunningMode)) | AV signatures: $($defenderStatus.AntivirusSignatureVersion) updated $($defenderStatus.AntivirusSignatureLastUpdated)"
            }
        }

        # Real-time protection - the property is RealTimeProtectionEnabled (capital T).
        if (-not [bool]$defenderStatus.RealTimeProtectionEnabled) {
            Write-Host "  🔴 Real-time protection is DISABLED!" -ForegroundColor Red
            $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                RiskLevel = "Critical"
                Name      = "Real-Time Protection"
                Detail    = "Disabled (major security risk)"
            }
        } else {
            Write-Host "  ✅ Real-time protection is enabled." -ForegroundColor Green
            $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "Real-Time Protection"
                Detail    = "Active | On-access protection: $($defenderStatus.OnAccessProtectionEnabled) | Behaviour monitoring: $($defenderStatus.BehaviorMonitorEnabled)"
            }
        }

        # Signature currency. AntivirusSignatureAge is a UInt32; Defender reports the sentinel
        # 4294967295 (0xFFFFFFFF) when no age is known, which would overflow an [int] cast.
        $signatureAge = [uint32]$defenderStatus.AntivirusSignatureAge
        if ($null -ne $defenderStatus.AntivirusSignatureAge -and $signatureAge -ne [uint32]::MaxValue) {
            if ([int]$signatureAge -gt 2 -or [bool]$defenderStatus.DefenderSignaturesOutOfDate) {
                Write-Host "    ⚠️ Antimalware signatures are $($signatureAge) day(s) old." -ForegroundColor Yellow
                $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                    RiskLevel = if ([int]$signatureAge -gt 7) { "High" } else { "Medium" }
                    Name      = "Signature Currency"
                    Detail    = "AV signatures $signatureAge day(s) old (last updated $($defenderStatus.AntivirusSignatureLastUpdated)); out-of-date flag=$($defenderStatus.DefenderSignaturesOutOfDate)"
                }
            } else {
                $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                    RiskLevel = "Pass"
                    Name      = "Signature Currency"
                    Detail    = "AV signatures updated $signatureAge day(s) ago ($($defenderStatus.AntivirusSignatureLastUpdated))"
                }
            }
        }

        # Tamper protection stops malware (and users) from turning Defender off.
        if ($null -ne $defenderStatus.PSObject.Properties['IsTamperProtected']) {
            if ([bool]$defenderStatus.IsTamperProtected) {
                $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                    RiskLevel = "Pass"
                    Name      = "Tamper Protection"
                    Detail    = "Enabled (settings cannot be changed by malware or standard users)"
                }
            } else {
                Write-Host "  ⚠️ Tamper protection is disabled." -ForegroundColor Yellow
                $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                    RiskLevel = "High"
                    Name      = "Tamper Protection"
                    Detail    = "Disabled (protection settings can be turned off remotely or by malware)"
                }
            }
        }

        # Last full scan age. FullScanAge is a UInt32; Defender reports the sentinel
        # 4294967295 (0xFFFFFFFF) when no full scan has ever completed.
        if ($null -ne $defenderStatus.FullScanAge) {
            $fullScanAge = [uint32]$defenderStatus.FullScanAge
            if ($fullScanAge -eq [uint32]::MaxValue) {
                $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                    RiskLevel = "Medium"
                    Name      = "Last Full Scan"
                    Detail    = "No full scan on record (Defender reports 0xFFFFFFFF sentinel)"
                }
            } else {
                $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                    RiskLevel = if ($fullScanAge -gt 7) { "Medium" } else { "Pass" }
                    Name      = "Last Full Scan"
                    Detail    = "$fullScanAge day(s) ago (source: $($defenderStatus.LastFullScanSource))"
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # Configuration that disables protection, plus exclusions (MSFT_MpPreference)
    # ------------------------------------------------------------------
    if ($null -ne $mpPref) {
        $disabledComponents = [System.Collections.Generic.List[string]]::new()
        if ([bool]$mpPref.DisableRealtimeMonitoring)   { $disabledComponents.Add('Real-time monitoring') }
        if ([bool]$mpPref.DisableIOAVProtection)       { $disabledComponents.Add('Download/attachment scanning (IOAV)') }
        if ([bool]$mpPref.DisableBehaviorMonitoring)   { $disabledComponents.Add('Behaviour monitoring') }
        if ($null -ne $mpPref.PSObject.Properties['DisableOnAccessProtection'] -and [bool]$mpPref.DisableOnAccessProtection) {
            $disabledComponents.Add('On-access protection')
        }

        if ($disabledComponents.Count -gt 0) {
            foreach ($component in $disabledComponents) {
                Write-Host "  🔴 $component is DISABLED!" -ForegroundColor Red
            }
            $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                RiskLevel = "Critical"
                Name      = "Disabled Components"
                Detail    = ($disabledComponents -join ', ')
            }
        }

        # Exclusions are the most common way protection is quietly weakened.
        $excludedPaths      = @($mpPref.ExcludePath)
        $excludedExtensions = @($mpPref.ExcludeExtension)
        $excludedFiles      = @($mpPref.ExcludeFile)
        $excludedProcesses  = @($mpPref.ExcludeProcess)
        $totalExclusions    = $excludedPaths.Count + $excludedExtensions.Count + $excludedFiles.Count + $excludedProcesses.Count

        Write-Host "    ℹ️ Exclusions: $($excludedPaths.Count) paths, $($excludedExtensions.Count) extensions, $($excludedFiles.Count) files, $($excludedProcesses.Count) processes" -ForegroundColor Cyan

        # Process/path exclusions pointing at user-writable locations deserve attention.
        $riskyExclusionPattern = '(?i)(%|\\temp\\|\\appdata\\|\\users\\public|\\\.$|\*$)'
        $riskyExclusions       = @(($excludedPaths + $excludedProcesses) | Where-Object { "$_" -match $riskyExclusionPattern })

        if ($totalExclusions -gt 0) {
            $riskLevel = if ($riskyExclusions.Count -gt 0) { "High" } elseif ($totalExclusions -gt 50) { "Medium" } else { "Low" }
            $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                RiskLevel = $riskLevel
                Name      = "Exclusions Configured"
                Detail    = "$totalExclusions exclusions | paths: $(@($excludedPaths | Select-Object -First 5) -join ', ')" + $(if ($riskyExclusions.Count -gt 0) { " | broad/temp-scoped: $(@($riskyExclusions | Select-Object -First 5) -join ', ')" } else { "" })
            }
        } else {
            $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "Exclusions Configured"
                Detail    = "No exclusions configured"
            }
        }

        # Cloud-delivered protection and automatic sample submission.
        if ($null -ne $mpPref.PSObject.Properties['SubmitSamplesConsent']) {
            $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                RiskLevel = if ([int]$mpPref.SubmitSamplesConsent -eq 0) { "Low" } else { "Pass" }
                Name      = "Automatic Sample Submission"
                Detail    = "SubmitSamplesConsent=$($mpPref.SubmitSamplesConsent)"
            }
        }
    }

    # ------------------------------------------------------------------
    # Active/unremediated threats (replaces the non-existent Get-MpThreatProtection)
    # ------------------------------------------------------------------
    try {
        $threats = @(Get-MpThreat -ErrorAction Stop | Where-Object { [bool]$_.IsActive -or [bool]$_.DidFailToRemediate })

        if ($threats.Count -gt 0) {
            foreach ($threat in @($threats | Select-Object -First 10)) {
                Write-Host "    🔴 Active threat: $($threat.ThreatName) (id $($threat.ThreatID), state $($threat.State))" -ForegroundColor Red
                $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                    RiskLevel = "Critical"
                    Name      = "Active Threat"
                    Detail    = "$($threat.ThreatName) | ID $($threat.ThreatID) | active=$($threat.IsActive) remediationFailed=$($threat.DidFailToRemediate)"
                }
            }
        } else {
            $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "Active Threats"
                Detail    = "No active or unremediated threats reported by the antimalware client"
            }
        }

        $recentDetections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue |
                              Where-Object { $_.Resources -and (Get-Date) - $_.InitialDetectionTime -lt (New-TimeSpan -Days 30) })
        if ($recentDetections.Count -gt 0) {
            $AuditResults["WindowsDefender"] += [PSCustomObject]@{
                RiskLevel = "Medium"
                Name      = "Recent Detections"
                Detail    = "$($recentDetections.Count) detection(s) in the last 30 days (latest: $(@($recentDetections | Sort-Object InitialDetectionTime -Descending)[0].InitialDetectionTime))"
            }
        }
    } catch {
        Write-Warning "  Could not check Defender threat status: $_"
    }

    if (-not $IsElevated) {
        $AuditResults["WindowsDefender"] += [PSCustomObject]@{
            RiskLevel = "Info"
            Name      = "Coverage Note"
            Detail    = "Run elevated for full Defender state (threat history and some preference data are restricted)"
        }
    }

    Write-ProgressOutput "Defender audit complete." -Verbose:$false
}

function Audit-ThirdPartyAV {
    param($AuditResults)

    Write-ProgressOutput "Auditing third-party AV/EDR inventory..." -Verbose:$false

    # Check for installed antivirus products via registry
    $avPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows Defender",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Defender",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    )

    $avProducts = @()

    # The authoritative inventory of registered protection products is the Security Center WMI namespace.
    try {
        $securityCenter = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)

        foreach ($product in $securityCenter) {
            $displayName = [string]$product.displayName
            if ([string]::IsNullOrWhiteSpace($displayName)) { continue }

            # productState encodes the status in its low byte: 01 off, 02 on, 03 out of date/snoozed.
            $statusBits = ('{0:x4}' -f ([int]$product.productState)).Substring(2, 2)
            $stateText  = switch ($statusBits) {
                '01'      { 'DISABLED' }
                '02'      { 'enabled' }
                '03'      { 'out of date / snoozed' }
                default   { "unknown (productState=$($product.productState))" }
            }

            if (@($avProducts | Where-Object { $_ -eq $displayName }).Count -eq 0) { $avProducts += $displayName }

            Write-Host "    ℹ️ Security Center reports: $displayName ($stateText)" -ForegroundColor Cyan
            $AuditResults["ThirdPartyAV"] += [PSCustomObject]@{
                RiskLevel = if ($statusBits -eq '02') { "Pass" } elseif ($statusBits -eq '01') { "High" } else { "Medium" }
                Name      = "Registered Protection Product: $displayName"
                Detail    = "Security Center status: $stateText | type=$($product.productType)"
            }
        }

        if ($securityCenter.Count -gt 0) {
            Write-ProgressOutput "$($securityCenter.Count) protection product(s) registered with Security Center." -Verbose:$false
        }
    } catch {
        # root\SecurityCenter2 is not present on every SKU (e.g. some Server Core / Nano installs).
        Write-ProgressOutput "SecurityCenter2 unavailable: $($_.Exception.Message)" -Verbose:$false
    }
    # Windows Defender presence
    try {
        $defenderKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender" -ErrorAction SilentlyContinue
        if ($null -ne $defenderKey) {
            $avProducts += "Windows Defender"
        }
    } catch {
        # Defender not installed or no access
    }

    # Check for common third-party AV products
    $avRegistryPaths = @{
        "McAfee" = "HKLM:\SOFTWARE\McAfee"
        "Symantec\Defender" = "HKLM:\SOFTWARE\Symantec\Defender"
        "Symantec\Endpoint Protection" = "HKLM:\SOFTWARE\Symantec\Endpoint Protection"
        "CrowdStrike" = "HKLM:\SOFTWARE\CrowdStrike"
        "SentinelOne" = "HKLM:\SOFTWARE\SentinelOne"
        "Carbon Black" = "HKLM:\SOFTWARE\Carbon Black"
        "Trend Micro" = "HKLM:\SOFTWARE\Trend Micro"
        "F-Secure" = "HKLM:\SOFTWARE\F-Secure"
        "ESET" = "HKLM:\SOFTWARE\ESET"
        "Kaspersky" = "HKLM:\SOFTWARE\KasperskyLab"
        "Sophos" = "HKLM:\SOFTWARE\Sophos"
        "Bitdefender" = "HKLM:\SOFTWARE\Bitdefender"
        "Avast" = "HKLM:\SOFTWARE\Avast Software"
        "AVG" = "HKLM:\SOFTWARE\AVG"
        "Panda" = "HKLM:\SOFTWARE\Panda Security"
        "Comodo" = "HKLM:\SOFTWARE\Comodo"
        "Webroot" = "HKLM:\SOFTWARE\Webroot"
        "Norton" = "HKLM:\SOFTWARE\Norton"
        "Avira" = "HKLM:\SOFTWARE\Avira"
        "ClamAV" = "HKLM:\SOFTWARE\ClamAV"
        "Microsoft Defender Antivirus" = "HKLM:\SOFTWARE\Microsoft\Microsoft Antimalware"
    }

    foreach ($entry in $avRegistryPaths.GetEnumerator()) {
        try {
            if (Test-Path $entry.Value) {
                $avProducts += $entry.Key
            }
        } catch {
            # Skip inaccessible paths
        }
    }

    # Check for EDR agents via services
    $edrServices = @(
        "CSFalconService",      # CrowdStrike
        "SentinelAgent",        # SentinelOne
        "CbDefense",            # Carbon Black
        "sophosendpoint",       # Sophos
        "F-Secure Service",     # F-Secure
        "klnagent",             # Kaspersky
        "epoagent",             # Symantec
        "mbam",                 # Malwarebytes
        "defenderatp",          # Microsoft Defender ATP
        "msascui",              # Windows Defender
        "WdFilter",             # Windows Defender Filter
        "WdNisDrv",             # Windows Defender Network Inspection
        "SenseClient",          # Microsoft Defender for Endpoint
        "MsMpEng",              # Windows Defender Antivirus
        "AMFilter",             # Windows Defender Antimalware
        "WinDefend"             # Windows Defender Service
    )

    $edrAgents = @()
    foreach ($svc in $edrServices) {
        try {
            $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($null -ne $service -and $service.Status -eq "Running") {
                $edrAgents += $svc
            }
        } catch {
            # Service not found
        }
    }

    if ($avProducts.Count -gt 0) {
        $AuditResults["ThirdPartyAV"] += [PSCustomObject]@{
            RiskLevel = "Pass"
            Name      = "Antivirus Products"
            Detail    = "Detected: $($avProducts -join ', ')"
        }
    } else {
        $AuditResults["ThirdPartyAV"] += [PSCustomObject]@{
            RiskLevel = "High"
            Name      = "Antivirus Products"
            Detail    = "No antivirus products detected"
        }
    }

    if ($edrAgents.Count -gt 0) {
        $AuditResults["ThirdPartyAV"] += [PSCustomObject]@{
            RiskLevel = "Pass"
            Name      = "EDR Agents"
            Detail    = "Running: $($edrAgents -join ', ')"
        }
    } else {
        $AuditResults["ThirdPartyAV"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "EDR Agents"
            Detail    = "No EDR agents detected"
        }
    }

    Write-ProgressOutput "Third-party AV/EDR audit complete." -Verbose:$false
}

function Audit-Firewall {
    param($AuditResults)

    Write-ProgressOutput "Auditing Windows Firewall rules..." -Verbose:$false

    # ------------------------------------------------------------------
    # 1. Per-profile state (Domain / Private / Public)
    # ------------------------------------------------------------------
    $profilesEnabled = 0
    $profilesFound   = 0

    foreach ($profileName in @("Domain", "Private", "Public")) {
        try {
            $fwProfile = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop
            $profilesFound++

            if ($fwProfile.Enabled) {
                $profilesEnabled++
                Write-Host "  ✅ $($profileName) Profile: Enabled" -ForegroundColor Green
            } else {
                Write-Host "  🔴 $($profileName) Profile: Firewall is DISABLED!" -ForegroundColor Red
                $AuditResults["WindowsFirewall"] += [PSCustomObject]@{
                    RiskLevel = if ($profileName -eq "Public") { "Critical" } else { "High" }
                    Name      = "Firewall Profile Disabled"
                    Detail    = "$($profileName) profile is disabled - inbound traffic is unrestricted for this network class"
                }
            }
        } catch {
            Write-AuditError -Context "Firewall Profile: $profileName" -ErrorMessage $_.Exception.Message
        }
    }

    if ($profilesFound -eq 0) {
        $AuditResults["WindowsFirewall"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Firewall Status"
            Detail    = "Unable to read firewall profiles (Windows Firewall subsystem not accessible)"
        }
        Write-ProgressOutput "Firewall audit complete." -Verbose:$false
        return
    }

    $AuditResults["WindowsFirewall"] += [PSCustomObject]@{
        RiskLevel = if ($profilesEnabled -eq $profilesFound) { "Pass" } else { "High" }
        Name      = "Firewall Profiles Enabled"
        Detail    = "$profilesEnabled of $profilesFound firewall profiles enabled"
    }

    # ------------------------------------------------------------------
    # 2. Enabled inbound allow rules
    # ------------------------------------------------------------------
    try {
        $inboundRules = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop)
        Write-Host "  → Found $($inboundRules.Count) enabled inbound allow rules." -ForegroundColor Cyan

        if ($inboundRules.Count -eq 0) {
            $AuditResults["WindowsFirewall"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "Inbound Allow Rules"
                Detail    = "No enabled inbound allow rules"
            }
        } else {
            # 2a. Missing descriptions - aggregated into one finding instead of one row per rule.
            $undescribed = @($inboundRules | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.Description) })
            if ($undescribed.Count -gt 0) {
                $examples = (@($undescribed | Select-Object -First 5 | ForEach-Object { $_.DisplayName }) -join '; ')
                $AuditResults["WindowsFirewall"] += [PSCustomObject]@{
                    RiskLevel = if ($undescribed.Count -gt 20) { "Medium" } else { "Low" }
                    Name      = "Rules Without Description"
                    Detail    = "$($undescribed.Count) inbound allow rules have no description. Examples: $examples"
                }
            }

            # 2b. Overly permissive remote access. Port and address filters can only be resolved with a
            #     per-rule WMI round-trip (~50 ms), so they are resolved for the rules that could expose a
            #     management surface rather than for every rule on the machine.
            $remoteSurfacePattern = '(?i)(remote|desktop|admin|file and printer|network discovery|net\.bios|network location server|winrm|windows remote management|powershell|print|rpc endpoint)'

            $sensitivePorts = @{
                '21'    = 'FTP'
                '23'    = 'Telnet'
                '25'    = 'SMTP'
                '110'   = 'POP3'
                '135'   = 'RPC'
                '137'   = 'NetBIOS name'
                '138'   = 'NetBIOS datagram'
                '139'   = 'NetBIOS session/SMB'
                '445'   = 'SMB'
                '1433'  = 'MSSQL'
                '1434'  = 'MSSQL browser'
                '3306'  = 'MySQL'
                '3389'  = 'RDP'
                '5432'  = 'PostgreSQL'
                '5900'  = 'VNC'
                '5985'  = 'WinRM (HTTP)'
                '5986'  = 'WinRM (HTTPS)'
                '6379'  = 'Redis'
                '27017' = 'MongoDB'
            }

            $candidates = @($inboundRules | Where-Object { $_.DisplayName -match $remoteSurfacePattern })
            Write-ProgressOutput "Resolving port/address filters for $($candidates.Count) remote-surface rules..." -Verbose:$false

            $permissive  = [System.Collections.Generic.List[object]]::new()
            $restricted   = 0

            foreach ($rule in $candidates) {
                try {
                    # A rule is only "from anywhere" when one of its address filters is Any.
                    $remoteAny = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop |
                                   Where-Object { "$($_.RemoteAddress)" -eq 'Any' }).Count -gt 0

                    if (-not $remoteAny) { $restricted++; continue }

                    foreach ($pf in @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
                        $localPort = [string]$pf.LocalPort
                        $protocol  = "$($pf.Protocol)"
                        $matched   = $null
                        $anyPort   = $false

                        foreach ($token in $localPort.Split(',')) {
                            $t = $token.Trim()
                            if ($t -eq 'Any') { $anyPort = $true; continue }
                            $basePort = ($t -split '-')[0]
                            if ($sensitivePorts.ContainsKey($basePort)) {
                                $matched = "$($sensitivePorts[$basePort]) ($protocol/$t)"
                            }
                        }

                        if ($null -ne $matched) {
                            $permissive.Add([pscustomobject]@{ Risk='High'; Rule=$rule.DisplayName; Port="$protocol/$localPort"; Why=$matched })
                        } elseif ($anyPort -and $protocol -notmatch '^ICMP') {
                            $permissive.Add([pscustomobject]@{ Risk='Medium'; Rule=$rule.DisplayName; Port="$protocol/Any"; Why='allows any port from any remote address' })
                        }
                    }
                } catch {
                    Write-AuditError -Context "Firewall Rule: $($rule.DisplayName)" -ErrorMessage $_.Exception.Message
                }
            }

            $AuditResults["WindowsFirewall"] += [PSCustomObject]@{
                RiskLevel = if ($permissive.Count -eq 0) { "Pass" } else { "Info" }
                Name      = "Inbound Remote Surface"
                Detail    = "$($candidates.Count) remote-surface rules checked; $restricted restricted to local subnet/specific addresses; $($permissive.Count) accept traffic from Any"
            }

            foreach ($finding in @($permissive | Select-Object -First 25)) {
                Write-Host "    🔴 $($finding.Risk) inbound: $($finding.Rule) [$($finding.Port)] - $($finding.Why)" -ForegroundColor Red
                $AuditResults["WindowsFirewall"] += [PSCustomObject]@{
                    RiskLevel = $finding.Risk
                    Name      = "Permissive Inbound Rule"
                    Detail    = "$($finding.Rule) | $($finding.Port) from Any | $($finding.Why)"
                }
            }

            if ($permissive.Count -gt 25) {
                $AuditResults["WindowsFirewall"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "Permissive Inbound Rules (truncated)"
                    Detail    = "$($permissive.Count - 25) further permissive rules omitted from the listing"
                }
            }
        }

    } catch {
        Write-Warning "  Could not query firewall rules: $_"
        $AuditResults["WindowsFirewall"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Inbound Rules Query"
            Detail    = "Failed to retrieve inbound rules: $_"
        }
    }

    # ------------------------------------------------------------------
    # 3. Outbound filtering posture
    # ------------------------------------------------------------------
    try {
        $outboundRules = @(Get-NetFirewallRule -Direction Outbound -ErrorAction Stop)
        $blockOut      = @($outboundRules | Where-Object { $_.Action -eq 'Block' -and $_.Enabled })

        Write-ProgressOutput "Outbound rules: $($outboundRules.Count) total, $($blockOut.Count) blocking." -Verbose:$false

        if ($blockOut.Count -eq 0) {
            $AuditResults["WindowsFirewall"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Outbound Filtering"
                Detail    = "$($outboundRules.Count) outbound rules, none blocking (default Windows posture: outbound is not restricted)"
            }
        } else {
            $AuditResults["WindowsFirewall"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "Outbound Filtering"
                Detail    = "$($blockOut.Count) blocking outbound rule(s) out of $($outboundRules.Count)"
            }
        }

    } catch {
        Write-AuditError -Context "Firewall Outbound Rules" -ErrorMessage $_.Exception.Message
    }

    Write-ProgressOutput "Firewall audit complete." -Verbose:$false
}

function Audit-Shares {
    param($AuditResults)

    Write-ProgressOutput "Auditing network shares..." -Verbose:$false

    try {
        $shares = @(Get-SmbShare -ErrorAction Stop | Sort-Object Name)

        if ($shares.Count -eq 0) {
            Write-Host "  ✅ No active SMB shares found." -ForegroundColor Green

            $AuditResults["NetworkShares"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "SMB Shares"
                Detail    = "No active shares configured"
            }
        } else {
            # Broad identities are the ones worth flagging. Grants to Administrators/SYSTEM on hidden admin
            # shares (C$, ADMIN$) are normal Windows behaviour; Get-SmbShareAccess exposes the real ACLs,
            # which Get-SmbShare itself does not.
            $broadIdentities = @('Everyone', 'Authenticated Users', 'Guests', 'Anonymous Logon', 'WORLD')

            Write-Host "  → Found $($shares.Count) SMB share(s)." -ForegroundColor Cyan

            foreach ($share in $shares) {
                $access = @()
                try {
                    $access = @(Get-SmbShareAccess -Name $share.Name -ErrorAction Stop)
                } catch {
                    Write-AuditError -Context "SMB Share ACL: $($share.Name)" -ErrorMessage $_.Exception.Message
                }

                $grants   = @($access | Where-Object { "$($_.AccessControlType)" -ne 'Denied' })
                $risky    = [System.Collections.Generic.List[object]]::new()
                $shareKind = if ($share.Special) { "special (hidden) share" } else { "regular share" }

                foreach ($grant in $grants) {
                    $identity    = [string]$grant.AccountOrGroupName
                    $lastSegment = ($identity -split '\\')[-1]

                    if (@($broadIdentities | Where-Object { $_ -eq $lastSegment }).Count -gt 0) {
                        $risky.Add([pscustomobject]@{ Identity = $identity; Rights = [string]$grant.FileSystemRights })
                    }
                }

                if ($risky.Count -eq 0) {
                    Write-Host "  ✅ Share '$($share.Name)': no broad (Everyone/Guests) access granted." -ForegroundColor Green

                    $AuditResults["NetworkShares"] += [PSCustomObject]@{
                        RiskLevel = "Pass"
                        Name      = "SMB Share: $($share.Name)"
                        Detail    = "$($share.Path) | $shareKind | explicit grants: $(@($grants).Count)"
                    }
                    continue
                }

                foreach ($entry in $risky) {
                    $writeAccess = ("$($entry.Rights)" -match '(?i)(full|modify|change)')
                    $riskLevel   = if ($share.Special -and $writeAccess) { "Critical" } elseif ($writeAccess) { "High" } else { "Medium" }

                    Write-Host "    🔴 Share '$($share.Name)' grants '$($entry.Rights)' to $($entry.Identity)" -ForegroundColor Red

                    $AuditResults["NetworkShares"] += [PSCustomObject]@{
                        RiskLevel = $riskLevel
                        Name      = "Broad Share Access: $($share.Name)"
                        Detail    = "$($share.Path) | $shareKind | $($entry.Identity) -> $($entry.Rights)"
                    }
                }
            }

            if (-not $IsElevated) {
                $AuditResults["NetworkShares"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "Share ACL Coverage"
                    Detail    = "Run elevated to read share access entries that are restricted to administrators"
                }
            }
        }

    } catch {
        Write-Warning "  Could not query SMB shares: $_"
        $AuditResults["NetworkShares"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "SMB Shares Query"
            Detail    = "Failed to retrieve share information: $_ (Get-SmbShare may require elevation)"
        }
    }

    Write-ProgressOutput "Share audit complete." -Verbose:$false
}

function Audit-TaskScheduler {
    param($AuditResults)

    Write-ProgressOutput "Auditing Task Scheduler entries..." -Verbose:$false

    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' })

        if ($tasks.Count -eq 0) {
            Write-Host "  ℹ️ No enabled scheduled tasks found (or require elevated privileges)." -ForegroundColor Cyan

            $AuditResults["TaskScheduler"] += [PSCustomObject]@{
                RiskLevel = "Medium"
                Name      = "Scheduled Tasks Query"
                Detail    = "No enabled tasks returned (run elevated to see all tasks)"
            }
        } else {
            # Interpreters commonly abused for persistence / living-off-the-land execution.
            $scriptInterpreters = '(?i)^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|msiexec|bash|sh)(\.exe)?$'
            $suspiciousPath     = '(?i)(\\temp\\|\\appdata\\|\\downloads\\|\\public\\|\\programdata\\)'

            $systemTasks = 0
            $userTasks   = 0
            $flagged     = [System.Collections.Generic.List[object]]::new()

            foreach ($task in $tasks) {
                $principal = $task.Principal
                $userId    = [string]$principal.UserId
                $groupId   = [string]$principal.GroupId
                # LogonType is an enum (Interactive, Password, S4U, Session, ...); it is never an integer,
                # so the previous [int] cast threw and aborted the whole task loop.
                $logonType = [string]$principal.LogonType

                $isSystem = ($userId -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$') -or
                            ($groupId -match '^S-1-5-(18|19|20)$')

                if ($isSystem) { $systemTasks++ } else { $userTasks++ }

                $executables = @($task.Actions | ForEach-Object { [string]$_.Executable } | Where-Object { $_ })
                $arguments   = (@($task.Actions | ForEach-Object { [string]$_.Arguments } | Where-Object { $_ }) -join ' ')
                $runLevel    = [string]$principal.RunLevel

                foreach ($exe in $executables) {
                    $leaf     = [System.IO.Path]::GetFileName($exe)
                    $isScript = ($leaf -match $scriptInterpreters)
                    $badPath  = ($exe -match $suspiciousPath)

                    if (-not $isScript -and -not $badPath) { continue }

                    $riskLevel = if ($badPath) { 'High' } elseif ($isSystem) { 'Medium' } else { 'Low' }
                    $runsAs     = if ([string]::IsNullOrWhiteSpace($userId)) { if ($groupId) { $groupId } else { "SYSTEM (LogonType=$logonType)" } } else { $userId }

                    $flagged.Add([pscustomobject]@{
                        Risk    = $riskLevel
                        Name    = [string]$task.TaskName
                        User    = $runsAs
                        Exe     = $exe
                        Args    = $arguments
                        Highest = ($runLevel -eq 'Highest')
                    })
                }
            }

            Write-Host "  → Found $($tasks.Count) enabled scheduled tasks ($systemTasks SYSTEM/service, $userTasks user)." -ForegroundColor Cyan

            $AuditResults["TaskScheduler"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Scheduled Tasks Inventory"
                Detail    = "$($tasks.Count) enabled tasks ($systemTasks run as SYSTEM/services, $userTasks as user accounts); $($flagged.Count) flagged for review"
            }

            foreach ($finding in @($flagged | Select-Object -First 40)) {
                $suffix = if ($finding.Highest) { " [RunLevel=Highest]" } else { "" }
                Write-Host "    🔴 [$($finding.Risk)] Task '$($finding.Name)' ($($finding.User)) -> $($finding.Exe) $($finding.Args)$suffix" -ForegroundColor Red

                $AuditResults["TaskScheduler"] += [PSCustomObject]@{
                    RiskLevel = $finding.Risk
                    Name      = "Task Runs Script Interpreter / Unusual Path"
                    Detail    = "$($finding.Name) | runs as $($finding.User) | $($finding.Exe) $($finding.Args)$suffix"
                }
            }

            if ($flagged.Count -gt 40) {
                $AuditResults["TaskScheduler"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "Flagged Tasks (truncated)"
                    Detail    = "$($flagged.Count - 40) further flagged tasks omitted from the listing"
                }
            }
        }

    } catch {
        Write-Warning "  Could not query Task Scheduler: $_"
        $AuditResults["TaskScheduler"] += [PSCustomObject]@{
            RiskLevel = "High"
            Name      = "Task Scheduler Query"
            Detail    = "Failed to retrieve task information: $_"
        }
    }

    Write-ProgressOutput "Task scheduler audit complete." -Verbose:$false
}

function Audit-RegistrySecurity {
    param($AuditResults)

    Write-ProgressOutput "Auditing registry security settings..." -Verbose:$false

    # ------------------------------------------------------------------
    # UAC configuration
    # ------------------------------------------------------------------
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    try {
        $uacSettings = Get-ItemProperty -Path $uacPath -ErrorAction SilentlyContinue

        if ($null -eq $uacSettings) {
            Write-Host "  ℹ️ UAC policy registry key not found." -ForegroundColor Gray
            $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                RiskLevel = "Medium"
                Name      = "UAC Configuration"
                Detail    = "Unable to read $uacPath"
            }
        } else {
            # Absent values mean the OS default applies; document that instead of guessing.
            $enableLua = $uacSettings.EnableLUA
            if ($null -eq $enableLua) {
                $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "UAC EnableLUA"
                    Detail    = "Not configured (OS default: UAC enabled)"
                }
            } elseif ([int]$enableLua -eq 0) {
                Write-Host "  🔴 CRITICAL: UAC is COMPLETELY DISABLED!" -ForegroundColor Red
                $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                    RiskLevel = "Critical"
                    Name      = "UAC Status"
                    Detail    = "EnableLUA=0 (UAC completely disabled; all admin tasks run with the full token)"
                }
            } else {
                Write-Host "  ✅ UAC is enabled (EnableLUA=$enableLua)." -ForegroundColor Green
                $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                    RiskLevel = "Pass"
                    Name      = "UAC Status"
                    Detail    = "EnableLUA=$enableLua"
                }
            }

            $consentAdmin = $uacSettings.ConsentPromptBehaviorAdmin
            if ($null -eq $consentAdmin) {
                $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "UAC Admin Consent Prompt"
                    Detail    = "ConsentPromptBehaviorAdmin not configured (OS default: 5 on clients, 1 on servers)"
                }
            } elseif ([int]$consentAdmin -eq 0) {
                Write-Host "  🔴 UAC prompts are NEVER shown to administrators!" -ForegroundColor Red
                $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                    RiskLevel = "High"
                    Name      = "UAC Admin Consent Prompt"
                    Detail    = "ConsentPromptBehaviorAdmin=0 (admin actions elevate silently)"
                }
            } elseif ([int]$consentAdmin -eq 2) {
                Write-Host "  ⚠️ UAC only prompts for non-administrator actions." -ForegroundColor Yellow
                $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                    RiskLevel = "Medium"
                    Name      = "UAC Admin Consent Prompt"
                    Detail    = "ConsentPromptBehaviorAdmin=2 (prompt on secure desktop only for other users)"
                }
            } else {
                $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                    RiskLevel = if ([int]$consentAdmin -eq 1 -or [int]$consentAdmin -eq 5) { "Pass" } else { "Low" }
                    Name      = "UAC Admin Consent Prompt"
                    Detail    = "ConsentPromptBehaviorAdmin=$consentAdmin (1=always prompt, 5=prompt with secure desktop)"
                }
            }

            $secureDesktop = $uacSettings.PromptOnSecureDesktop
            if ($null -ne $secureDesktop) {
                if ([int]$secureDesktop -eq 0) {
                    Write-Host "    ⚠️ UAC prompts do not use the secure desktop." -ForegroundColor Yellow
                    $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                        RiskLevel = "Medium"
                        Name      = "Prompt On Secure Desktop"
                        Detail    = "PromptOnSecureDesktop=0 (elevation dialogs can be spoofed by user-mode code)"
                    }
                } else {
                    $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                        RiskLevel = "Pass"
                        Name      = "Prompt On Secure Desktop"
                        Detail    = "PromptOnSecureDesktop=1"
                    }
                }
            }

            if ($null -ne $uacSettings.FilterAdministratorToken) {
                $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                    RiskLevel = if ([int]$uacSettings.FilterAdministratorToken -eq 0) { "Low" } else { "Pass" }
                    Name      = "Filter Administrator Token"
                    Detail    = "FilterAdministratorToken=$($uacSettings.FilterAdministratorToken) (1 forces admin approval mode for the built-in administrator)"
                }
            }
        }

    } catch {
        Write-Warning "  Could not query UAC registry: $_"
    }

    # ------------------------------------------------------------------
    # LSA notification packages (credential-theft persistence). The value lives under Control\Lsa,
    # not Services\Lsa\Parameters.
    # ------------------------------------------------------------------
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

    try {
        $lsaPackages = Get-ItemProperty -Path $lsaPath -ErrorAction SilentlyContinue
        $packageValue = if ($null -ne $lsaPackages) { $lsaPackages.NotificationPackages } else { $null }

        if ([string]::IsNullOrWhiteSpace([string]$packageValue)) {
            Write-Host "  ✅ No custom LSA notification packages configured." -ForegroundColor Green
            $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "LSA Notification Packages"
                Detail    = "NotificationPackages not set (only built-in authentication packages load)"
            }
        } else {
            # A string array method (.Split) does not exist on arrays; use the -split operator.
            $packages = @($packageValue -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

            Write-Host "  ℹ️ LSA Notification Packages: $($packages.Count)" -ForegroundColor Cyan

            # Anything beyond the built-in set deserves investigation (Mimikatz, credential dumpers).
            $knownPackages = @('kerberos', 'msv1_0', 'schannel', 'negotiate', 'credman', 'pku2u', 'livessp', 'cloudap', 'tspkg', 'kdc', 'wdigest', 'tspkg')

            foreach ($pkg in $packages) {
                $name = $pkg.Trim()
                if (@($knownPackages | Where-Object { $name -match "(?i)^$_$" }).Count -gt 0) { continue }

                Write-Host "    🔴 Non-standard LSA package: '$name'" -ForegroundColor Red
                $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                    RiskLevel = "Critical"
                    Name      = "Non-Standard LSA Package"
                    Detail    = "$name (LSA packages run inside LSASS; used by credential theft tools and some legitimate AV products)"
                }
            }

            $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "LSA Notification Packages"
                Detail    = "$($packages.Count) configured: $($packages -join ', ')"
            }
        }

    } catch {
        Write-Warning "  Could not query LSA settings: $_"
        $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "LSA Configuration"
            Detail    = "Unable to retrieve LSA settings"
        }
    }

    # ------------------------------------------------------------------
    # Image File Execution Options (IFEO): debugger hijacks and AMSI/visibility tampering.
    # Get-ChildItem returns provider paths, so PSChildName is the value used to build subkey paths.
    # ------------------------------------------------------------------
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

    try {
        $ifeoKeys = @(Get-ChildItem -LiteralPath $ifeoPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName)
        $scriptingHosts = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wmic.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'wscript.exe', 'cscript.exe')

        Write-ProgressOutput "$($ifeoKeys.Count) IFEO entries present." -Verbose:$false

        foreach ($key in $ifeoKeys) {
            $subKeyPath = Join-Path $ifeoPath ([string]$key)

            try {
                $values = Get-ItemProperty -LiteralPath $subKeyPath -ErrorAction SilentlyContinue
                if ($null -eq $values) { continue }

                # 1. Debugger hijack: any executable name with a Debugger value gets replaced at launch.
                if (-not [string]::IsNullOrWhiteSpace([string]$values.Debugger)) {
                    Write-Host "    🔴 IFEO Debugger on '$key' -> $($values.Debugger)" -ForegroundColor Red
                    $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                        RiskLevel = "Critical"
                        Name      = "IFEO Debugger Hijack"
                        Detail    = "$key launches via '$($values.Debugger)' (a debugger value replaces the process at launch time)"
                    }
                }

                # 2. UseFilter=0 on a scripting host is the documented trick used to hide PowerShell from
                #    antimalware/AMSI scanning.
                if ($scriptingHosts -contains $key.ToLower() -and $null -ne $values.PSObject.Properties['UseFilter'] -and [int]$values.UseFilter -eq 0) {
                    Write-Host "    🔴 IFEO UseFilter=0 on '$key' (antimalware scanning bypass indicator)" -ForegroundColor Red
                    $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                        RiskLevel = "High"
                        Name      = "IFEO UseFilter Disabled"
                        Detail    = "$key has UseFilter=0, a known technique for hiding script-host activity from scanning components"
                    }
                }

                # 3. GlobalFlag/DebugPort entries on production hosts are usually leftovers or tampering.
                if ($null -ne $values.PSObject.Properties['DebugPort']) {
                    Write-Host "    ⚠️ IFEO DebugPort on '$key' -> $($values.DebugPort)" -ForegroundColor Yellow
                    $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                        RiskLevel = "Medium"
                        Name      = "IFEO Debug Port"
                        Detail    = "$key has DebugPort=$($values.DebugPort) configured"
                    }
                }
            } catch {
                Write-AuditError -Context "IFEO Entry: $key" -ErrorMessage $_.Exception.Message
            }
        }

        if ($ifeoKeys.Count -eq 0) {
            $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "Image File Execution Options"
                Detail    = "No IFEO entries configured"
            }
        } else {
            $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
                RiskLevel = if ($ifeoKeys.Count -gt 50) { "Low" } else { "Info" }
                Name      = "Image File Execution Options"
                Detail    = "$($ifeoKeys.Count) IFEO entries present (checked for Debugger, UseFilter and DebugPort values)"
            }
        }

    } catch {
        Write-Warning "  Could not query IFEO: $_"
        $AuditResults["RegistrySecurity"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "IFEO Configuration"
            Detail    = "Unable to retrieve IFEO settings"
        }
    }

    Write-ProgressOutput "Registry security audit complete." -Verbose:$false
}

function Audit-UserAccounts {
    param($AuditResults)

    Write-ProgressOutput "Auditing user accounts..." -Verbose:$false

    # Check for LocalAccounts module (requires RSAT or Windows 10/11 client)
    if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.LocalAccounts)) {
        $AuditResults["UserAccounts"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "LocalAccounts Module"
            Detail    = "Microsoft.PowerShell.LocalAccounts module not available; user account audit skipped"
        }
        Write-Host "  ⚠️ LocalAccounts module not available; skipping user account audit." -ForegroundColor Yellow
        return
    }

    # Get local users
    try {
        $users = Get-LocalUser | Select-Object Name, Enabled, PasswordNeverExpires, PasswordLastSet, 
                                                 AccountExpired, UserMayChangePassword | Sort-Object Name
        
        foreach ($user in $users) {
            if ([string]::IsNullOrEmpty($user.Name)) { continue }

            # Skip built-in accounts (usually start with special characters or are well-known)
            if ($user.Name -match '^\$|Administrator|Guest|SYSTEM') { continue }

            # Check for disabled users that should be removed
            # Disabled accounts stay enumerable and can be re-enabled by any local administrator.
            if (-not $user.Enabled) {
                Write-Host "    ℹ️  Disabled account: $($user.Name)" -ForegroundColor Gray

                $AuditResults["UserAccounts"] += [PSCustomObject]@{
                    RiskLevel = if ($user.PasswordNeverExpires) { "Low" } else { "Info" }
                    Name      = "Disabled Account"
                    Detail    = "$($user.Name) | Password Never Expires: $($user.PasswordNeverExpires)"
                }
                continue
            }

            if ($user.AccountExpired) {
                Write-Host "    ⚠️ Account '$($user.Name)' is expired." -ForegroundColor Yellow

                $AuditResults["UserAccounts"] += [PSCustomObject]@{
                    RiskLevel = "Medium"
                    Name      = "Expired Account"
                    Detail    = "$($user.Name) | User may change password: $($user.UserMayChangePassword)"
                }
                continue
            }

            # Active account. PasswordLastSet is $null when no password has been recorded; the previous
            # code called [DateTime]::IsInfinity() on a boolean and subtracted the timestamp from 1970,
            # which threw and then inverted every age comparison.
            if ($null -eq $user.PasswordLastSet) {
                Write-Host "    🔴 Account '$($user.Name)' has no recorded password-set time." -ForegroundColor Red

                $AuditResults["UserAccounts"] += [PSCustomObject]@{
                    RiskLevel = if ($IsElevated) { "High" } else { "Medium" }
                    Name      = "Password Never Set"
                    Detail    = "$($user.Name) | PasswordLastSet is unset$(if (-not $IsElevated) { ' (some account properties require elevation)' })"
                }
            } elseif ($user.PasswordNeverExpires) {
                Write-Host "    ⚠️ Account '$($user.Name)' has 'Password never expires' enabled." -ForegroundColor Yellow

                $AuditResults["UserAccounts"] += [PSCustomObject]@{
                    RiskLevel = "Medium"
                    Name      = "Password Never Expires"
                    Detail    = "$($user.Name) | PasswordLastSet: $($user.PasswordLastSet)"
                }
            } else {
                $passwordAge  = (Get-Date) - $user.PasswordLastSet
                $passwordDays = [math]::Round($passwordAge.TotalDays, 0)

                if ($passwordAge.TotalDays -gt 90) {
                    Write-Host "    ⚠️ Account '$($user.Name)' hasn't changed its password in $passwordDays days." -ForegroundColor Yellow

                    $AuditResults["UserAccounts"] += [PSCustomObject]@{
                        RiskLevel = "Low"
                        Name      = "Password Age"
                        Detail    = "$($user.Name): last changed $passwordDays days ago (over the 90-day baseline)"
                    }
                } else {
                    Write-Host "  ✅ Account '$($user.Name)' password is within the 90-day policy." -ForegroundColor Green

                    $AuditResults["UserAccounts"] += [PSCustomObject]@{
                        RiskLevel = "Pass"
                        Name      = "Password Policy Compliance"
                        Detail    = "$($user.Name): last changed $passwordDays days ago"
                    }
                }
            }
        }

    } catch {
        Write-Warning "  Could not list local users: $_"
        $AuditResults["UserAccounts"] += [PSCustomObject]@{
            RiskLevel = "High"
            Name      = "Local Users Query"
            Detail    = "Failed to retrieve user accounts: $_"
        }
    }
    # Check for passwordless accounts
    try {
        $passwordless = Get-LocalUser | Where-Object {$_.Name -notmatch '^\$'} | 
                        Where-Object {$_.PasswordLastSet -eq [DateTime]::MinValue} | Select-Object Name, Enabled
        
        foreach ($account in $passwordless) {
            Write-Host "    🔴 Passwordless account: $($account.Name)" -ForegroundColor Red
            
            if ($account.Enabled) {
                Write-Host "       ⚠️ This passwordless account is ENABLED!" -ForegroundColor Red
            } else {
                Write-Host "       ℹ️  This passwordless account is disabled." -ForegroundColor Cyan
            }
            
            $AuditResults["UserAccounts"] += [PSCustomObject]@{
                RiskLevel = if ($account.Enabled) { "High" } else { "Medium" }
                Name      = "Passwordless Account"
                Detail    = "$($account.Name)"
            }

        }

    } catch {
        Write-AuditError -Context "Passwordless Account Check" -ErrorMessage $_.Exception.Message
    }

    # Check Guest account status
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        
        if ($null -ne $guest) {
            Write-Host "  ℹ️ Guest account: Enabled=$($guest.Enabled)" -ForegroundColor Cyan
            
            $AuditResults["UserAccounts"] += [PSCustomObject]@{
                RiskLevel = if ($guest.Enabled) { "Critical" } else { "Pass" }
                Name      = "Guest Account Status"
                Detail    = "Enabled: $($guest.Enabled) | PasswordNeverExpires: $($guest.PasswordNeverExpires)"
            }

            if ($guest.Enabled) {
                Write-Host "  🔴 GUEST ACCOUNT IS ENABLED - Major security risk!" -ForegroundColor Red
                
                $AuditResults["UserAccounts"] += [PSCustomObject]@{
                    RiskLevel = "Critical"
                    Name      = "Guest Account Security"
                    Detail    = "The Guest account is enabled and accessible to any network user"
                }

            } else {
                Write-Host "  ✅ Guest account is disabled (recommended)." -ForegroundColor Green
            }
        } else {
            Write-Host "  ℹ️ No Guest account found." -ForegroundColor Gray
            
            $AuditResults["UserAccounts"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "Guest Account"
                Detail    = "No Guest account exists (good)"
            }
        }

    } catch {
        Write-AuditError -Context "Guest Account Check" -ErrorMessage $_.Exception.Message
    }

    # Check local group memberships - Administrators group
    try {
        $adminMembers = Get-LocalGroupMember -Name 'Administrators' | Select-Object Name, ObjectClass
        
        foreach ($member in $adminMembers) {
            Write-Host "  ℹ️ Admin member: $($member.Name)" -ForegroundColor Cyan
            
            # Warn about non-standard admin members
            if ($member.Name -ne 'Administrator') {
                Write-Host "     ⚠️ Non-standard account '$($member.Name)' is a local administrator." -ForegroundColor Yellow
            }

            $AuditResults["UserAccounts"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Local Administrator Group Member"
                Detail    = "$($member.Name)"
            }
        }

        Write-Host "  → Found $($adminMembers.Count) active local administrator(s)." -ForegroundColor Green

    } catch {
        Write-Warning "  Could not query Administrators group: $_"
        $AuditResults["UserAccounts"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Admin Group Membership"
            Detail    = "Could not retrieve administrator members: $_"
        }
    }

    Write-ProgressOutput "User account audit complete." -Verbose:$false
}

function Audit-AuditPolicy {
    param($AuditResults)

    Write-ProgressOutput "Auditing security audit policy..." -Verbose:$false

    # ------------------------------------------------------------------
    # 1. Effective system audit policy (auditpol). The previous implementation never read the audit
    #    policy; it only probed Windows features and looked for event ID 4625.
    # ------------------------------------------------------------------
    $auditPolOutput = @(auditpol /get /category:* 2>&1)

    if ($LASTEXITCODE -ne 0) {
        $elevationNote = if (-not $IsElevated) { " (reading the audit policy requires elevation)" } else { "" }
        $AuditResults["AuditPolicy"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Audit Policy Query"
            Detail    = "auditpol /get failed with exit code $LASTEXITCODE$elevationNote : $(@($auditPolOutput | Where-Object { "$_" }) | Select-Object -First 1)"
        }
    } else {
        # Only English auditpol output is parsed; on localized systems the keywords are absent and we say so.
        $policyLines = @($auditPolOutput | Where-Object { "$_" -match 'Success|Failure|No Audit' })

        if ($policyLines.Count -eq 0) {
            $AuditResults["AuditPolicy"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Audit Policy"
                Detail    = "auditpol output did not contain recognisable (English) audit keywords; review the policy manually"
            }
        } else {
            $audited   = @($policyLines | Where-Object { "$_" -match 'Success|Failure' })
            $notAudited = @($policyLines | Where-Object { "$_" -notmatch 'Success|Failure' })

            # Subcategories an auditor expects to be on, matched against the English names.
            $mustAudit = @(
                @{ Pattern = '(?i)Security State Change';   Why = 'shows security log start/stop and clearing' }
                @{ Pattern = '(?i)\bLogon\b';               Why = 'logon auditing is required to trace access' }
                @{ Pattern = '(?i)Sensitive Privilege Use'; Why = 'detects token/privilege abuse' }
                @{ Pattern = '(?i)Audit Policy Change';     Why = 'detects an attacker disabling logging' }
                @{ Pattern = '(?i)Security Extension Extensibility Point'; Why = 'detects LSA package loading (credential theft)' }
            )

            $gaps = [System.Collections.Generic.List[string]]::new()
            foreach ($must in $mustAudit) {
                $line = @($notAudited | Where-Object { "$_" -match $must.Pattern } | Select-Object -First 1)
                if (@($line).Count -gt 0) {
                    $gaps.Add("$(@($line)[0]) [$($must.Why)]")
                }
            }

            Write-Host "  → Audit policy: $($audited.Count) subcategories with auditing enabled, $($notAudited.Count) without." -ForegroundColor Cyan

            $AuditResults["AuditPolicy"] += [PSCustomObject]@{
                RiskLevel = if ($audited.Count -eq 0) { "High" } elseif ($gaps.Count -gt 0) { "Medium" } else { "Pass" }
                Name      = "Audit Policy Coverage"
                Detail    = "$($audited.Count) of $($policyLines.Count) subcategories have auditing enabled; $($notAudited.Count) disabled"
            }

            foreach ($gap in $gaps) {
                Write-Host "    ⚠️ Not audited: $gap" -ForegroundColor Yellow
                $AuditResults["AuditPolicy"] += [PSCustomObject]@{
                    RiskLevel = "Medium"
                    Name      = "Important Subcategory Not Audited"
                    Detail    = $gap
                }
            }

            if ($audited.Count -eq 0) {
                Write-Host "  🔴 No audit subcategories are enabled - security event logging is effectively off." -ForegroundColor Red
            }
        }
    }

    # ------------------------------------------------------------------
    # 2. Security log configuration (size / overwrite behaviour). Reading the Security log ACL needs elevation.
    # ------------------------------------------------------------------
    try {
        $securityLog = Get-WinEvent -ListLog Security -ErrorAction Stop

        if ($null -ne $securityLog) {
            $maxSizeMB   = [math]::Round($securityLog.LogMaximumSize / 1MB, 0)
            $currentSize = [math]::Round($securityLog.LogSize / 1MB, 1)

            Write-Host "    ℹ️ Security log: $(@($securityLog.RecordCount)) records, ${maxSizeMB}MB max ($($securityLog.LogMode)), currently ${currentSize}MB" -ForegroundColor Cyan

            $AuditResults["AuditPolicy"] += [PSCustomObject]@{
                RiskLevel = if ($maxSizeMB -lt 100) { "Medium" } else { "Pass" }
                Name      = "Security Log Size"
                Detail    = "$($securityLog.RecordCount) records | max ${maxSizeMB}MB | mode $($securityLog.LogMode) | current ${currentSize}MB$(if ($maxSizeMB -lt 100) { ' (CIS recommends >=2GB for the Security log)' } else { '' })"
            }

            if ("$($securityLog.LogMode)" -eq 'Retention') {
                $AuditResults["AuditPolicy"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "Security Log Retention"
                    Detail    = "Retention mode enabled: oldest events are archived rather than overwritten"
                }
            }

            if ($securityLog.LogSize -ge ($securityLog.LogMaximumSize * 0.9)) {
                Write-Host "    ⚠️ Security log is at $(@([math]::Round(($securityLog.LogSize / $securityLog.LogMaximumSize) * 100, 0)))% of its maximum size." -ForegroundColor Yellow
                $AuditResults["AuditPolicy"] += [PSCustomObject]@{
                    RiskLevel = "Medium"
                    Name      = "Security Log Nearly Full"
                    Detail    = "${currentSize}MB of ${maxSizeMB}MB used; oldest events will be lost (mode $($securityLog.LogMode))"
                }
            }
        }
    } catch {
        $elevationNote = if (-not $IsElevated) { " - reading the Security log configuration requires elevation" } else { "" }
        Write-Warning "  Could not read Security log configuration: $_"
        $AuditResults["AuditPolicy"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Security Log Configuration"
            Detail    = "Unable to query the Security log$elevationNote : $($_.Exception.Message)"
        }
    }

    # ------------------------------------------------------------------
    # 3. Liveness check: are failed logons actually being recorded?
    # ------------------------------------------------------------------
    try {
        $oneHourAgo   = (Get-Date).AddHours(-1)
        $recentEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; ID = 4625; StartTime = $oneHourAgo } -ErrorAction Stop | Measure-Object)

        if ($recentEvents.Count -eq 0) {
            Write-Host "    ℹ️ No failed logon events in the last hour (idle host or logging disabled)." -ForegroundColor Gray
            $AuditResults["AuditPolicy"] += [PSCustomObject]@{
                RiskLevel = "Low"
                Name      = "Failed Login Detection"
                Detail    = "No Event ID 4625 in the last hour; on an idle host this is expected, otherwise check that logon auditing is enabled"
            }
        } else {
            Write-Host "  ✅ Security logging appears active: $($recentEvents.Count) failed logon event(s) in the last hour." -ForegroundColor Green
            $AuditResults["AuditPolicy"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "Failed Login Detection"
                Detail    = "$($recentEvents.Count) Event ID 4625 events in the last hour (logging active)"
            }
        }
    } catch {
        # "No events were found that match the specified selection criteria" is a normal outcome, not an error.
        if ($_.Exception.Message -match 'No events were found') {
            $AuditResults["AuditPolicy"] += [PSCustomObject]@{
                RiskLevel = "Low"
                Name      = "Failed Login Detection"
                Detail    = "No Event ID 4625 in the last hour; on an idle host this is expected, otherwise check that logon auditing is enabled"
            }
        } else {
            Write-Warning "  Could not query security event logs: $_"
            $AuditResults["AuditPolicy"] += [PSCustomObject]@{
                RiskLevel = "Medium"
                Name      = "Failed Login Detection"
                Detail    = "Unable to retrieve Event ID 4625 events (reading the Security log requires elevation): $_"
            }
        }
    }

    Write-ProgressOutput "Audit policy check complete." -Verbose:$false
}

# ============================================================================
# NEW AUDIT FUNCTIONS — Critical & Important Gaps
# ============================================================================

function Audit-LocalSecurityPolicy {
    param($AuditResults)

    Write-ProgressOutput "Auditing local security policy..." -Verbose:$false

    # Export and parse secpol via secedit
    try {
        $tempSecpol = "$env:TEMP\secpol_export.sdb"
        secedit /export /cfg $tempSecpol /quiet 2>$null
        
        if (Test-Path $tempSecpol) {
            $secpolContent = Get-Content $tempSecpol -ErrorAction SilentlyContinue
            
            # Password Policy
            $pwdComplexity = $secpolContent | Select-String "PasswordComplexity" | Select-Object -First 1
            if ($null -ne $pwdComplexity) {
                $complexityVal = ($pwdComplexity -split '=')[1].Trim()
                if ($complexityVal -eq '0') {
                    $AuditResults["LocalSecurityPolicy"] += [PSCustomObject]@{
                        RiskLevel = "High"
                        Name      = "Password Complexity"
                        Detail    = "Password complexity is DISABLED (requires uppercase, lowercase, numbers, special chars)"
                    }
                } else {
                    $AuditResults["LocalSecurityPolicy"] += [PSCustomObject]@{
                        RiskLevel = "Pass"
                        Name      = "Password Complexity"
                        Detail    = "Password complexity is enabled"
                    }
                }
            }

            # Minimum Password Age
            $minPwdAge = $secpolContent | Select-String "MinimumPasswordLength" | Select-Object -First 1
            if ($null -ne $minPwdAge) {
                $minLen = ($minPwdAge -split '=')[1].Trim()
                if ([int]$minLen -lt 14) {
                    $AuditResults["LocalSecurityPolicy"] += [PSCustomObject]@{
                        RiskLevel = "Medium"
                        Name      = "Minimum Password Length"
                        Detail    = "Set to $minLen characters (recommend 14+)"
                    }
                } else {
                    $AuditResults["LocalSecurityPolicy"] += [PSCustomObject]@{
                        RiskLevel = "Pass"
                        Name      = "Minimum Password Length"
                        Detail    = "Set to $minLen characters"
                    }
                }
            }

            # Account Lockout Policy
            $lockoutThreshold = $secpolContent | Select-String "LockoutBadCount" | Select-Object -First 1
            if ($null -ne $lockoutThreshold) {
                $threshold = ($lockoutThreshold -split '=')[1].Trim()
                if ([int]$threshold -eq 0) {
                    $AuditResults["LocalSecurityPolicy"] += [PSCustomObject]@{
                        RiskLevel = "High"
                        Name      = "Account Lockout Threshold"
                        Detail    = "Account lockout is DISABLED"
                    }
                } else {
                    $AuditResults["LocalSecurityPolicy"] += [PSCustomObject]@{
                        RiskLevel = "Pass"
                        Name      = "Account Lockout Threshold"
                        Detail    = "Lockout after $threshold failed attempts"
                    }
                }
            }

            $lockoutDuration = $secpolContent | Select-String "LockoutDuration" | Select-Object -First 1
            if ($null -ne $lockoutDuration) {
                $duration = ($lockoutDuration -split '=')[1].Trim()
                $AuditResults["LocalSecurityPolicy"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "Account Lockout Duration"
                    Detail    = "Lockout duration: $duration minutes"
                }
            }

            # Kerberos Policy
            $maxTicketAge = $secpolContent | Select-String "MaxTicketAge" | Select-Object -First 1
            if ($null -ne $maxTicketAge) {
                $ticketAge = ($maxTicketAge -split '=')[1].Trim()
                if ([int]$ticketAge -gt 10) {
                    $AuditResults["LocalSecurityPolicy"] += [PSCustomObject]@{
                        RiskLevel = "Low"
                        Name      = "Kerberos Ticket Max Age"
                        Detail    = "Max ticket age: $ticketAge hours (recommend ≤10)"
                    }
                } else {
                    $AuditResults["LocalSecurityPolicy"] += [PSCustomObject]@{
                        RiskLevel = "Pass"
                        Name      = "Kerberos Ticket Max Age"
                        Detail    = "Max ticket age: $ticketAge hours"
                    }
                }
            }

            # Network Access: Sharing and security model
            $netAccess = $secpolContent | Select-String "NetworkAccessSharingSecurityModel" | Select-Object -First 1
            if ($null -ne $netAccess) {
                $model = ($netAccess -split '=')[1].Trim()
                $AuditResults["LocalSecurityPolicy"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "Network Access Sharing Model"
                    Detail    = "Model: $model"
                }
            }

            # Clean up temp file
            Remove-Item $tempSecpol -ErrorAction SilentlyContinue

        } else {
            $AuditResults["LocalSecurityPolicy"] += [PSCustomObject]@{
                RiskLevel = "Medium"
                Name      = "Secpol Export"
                Detail    = "Unable to export security policy"
            }
        }

    } catch {
        Write-AuditError -Context "Local Security Policy" -ErrorMessage $_.Exception.Message
        $AuditResults["LocalSecurityPolicy"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Local Security Policy"
            Detail    = "Unable to query local security policy: $_"
        }
    }

    # Check LSA registry keys for security settings
    try {
        $lsaKeys = @(
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="FullPrivilegeAuditing"; Key="FullPrivilegeAuditing"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LimitBlankPasswordUse"; Key="LimitBlankPasswordUse"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="NoLMHash"; Key="NoLMHash"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Key="LmCompatibilityLevel"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="DisableDomainCreds"; Key="DisableDomainCreds"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="EveryoneIncludesAnonymous"; Key="EveryoneIncludesAnonymous"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"; Key="RestrictAnonymous"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Key="RestrictAnonymousSAM"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="SCENoApplyGPOList"; Key="SCENoApplyGPOList"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="UseMachineId"; Key="UseMachineId"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="DisableIPSecHardening"; Key="DisableIPSecHardening"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="FilterAdministratorToken"; Key="FilterAdministratorToken"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RunAsPPL"; Key="RunAsPPL"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LsaCfgFlags"; Key="LsaCfgFlags"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\JunctionManager"; Name="NoX86Transactions"; Key="NoX86Transactions"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="allownullsessionfill"; Key="allownullsessionfill"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinClientSec"; Key="NTLMMinClientSec"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="NTLMMinServerSec"; Key="NTLMMinServerSec"}
        )

        foreach ($entry in $lsaKeys) {
            try {
                $val = Get-ItemProperty -Path $entry.Path -Name $entry.Key -ErrorAction SilentlyContinue
                if ($null -ne $val -and $null -ne $val.($entry.Key)) {
                    $AuditResults["LocalSecurityPolicy"] += [PSCustomObject]@{
                        RiskLevel = "Info"
                        Name      = "LSA Setting: $($entry.Name)"
                        Detail    = "$($entry.Key) = $($val.($entry.Key))"
                    }
                }
            } catch {
                # Skip inaccessible keys
            }
        }

    } catch {
        Write-AuditError -Context "LSA Registry Keys" -ErrorMessage $_.Exception.Message
    }

    Write-ProgressOutput "Local security policy audit complete." -Verbose:$false
}

function Audit-Services {
    param($AuditResults)

    Write-ProgressOutput "Auditing services..." -Verbose:$false

    try {
        $runningServices = @(Get-Service | Where-Object { $_.Status -eq 'Running' })

        # One bulk CIM query instead of one query per running service (the old code made a WMI call per
        # service and read a non-existent ServiceName property for its BinaryPath column).
        $serviceDetails = @{}
        foreach ($svcDetail in @(Get-CimInstance -ClassName Win32_Service -Property Name, DisplayName, PathName, StartMode, State, StartName -ErrorAction SilentlyContinue)) {
            if (-not [string]::IsNullOrWhiteSpace($svcDetail.Name) -and -not $serviceDetails.ContainsKey($svcDetail.Name)) {
                $serviceDetails[$svcDetail.Name] = $svcDetail
            }
        }

        Write-Host "  → $($runningServices.Count) services running ($($serviceDetails.Count) service records read)." -ForegroundColor Cyan

        if ($runningServices.Count -eq 0) {
            $AuditResults["Services"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "Running Services"
                Detail    = "No running services found (unusual)"
            }
        } else {
            $AuditResults["Services"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Running Services Count"
                Detail    = "$($runningServices.Count) services currently running"
            }

            $namedAccountServices = [System.Collections.Generic.List[string]]::new()

            # Binaries outside the protected Windows directories are writable by non-admins.
            $suspiciousPathPattern = '(?i)(\\temp\\|\\appdata\\|\\downloads\\|\\users\\public\\|\\programdata\\)'

            foreach ($svc in $runningServices) {
                if (-not $serviceDetails.ContainsKey($svc.Name)) { continue }

                $detail     = $serviceDetails[$svc.Name]
                $binaryPath = [string]$detail.PathName
                if ([string]::IsNullOrWhiteSpace($binaryPath)) { continue }

                if ($binaryPath -match $suspiciousPathPattern) {
                    Write-Host "    🔴 Service '$($svc.DisplayName)' runs from an unusual path" -ForegroundColor Red
                    $AuditResults["Services"] += [PSCustomObject]@{
                        RiskLevel = "High"
                        Name      = "Service From Suspicious Path"
                        Detail    = "$($svc.DisplayName) [$($svc.Name)] -> $binaryPath"
                    }
                }

                # Unquoted paths containing spaces allow a privileged service to load an attacker binary.
                $unquotedWithSpace = (-not $binaryPath.StartsWith('"')) -and ($binaryPath -match '^\S*\\[^"]*\s')
                if ($unquotedWithSpace) {
                    Write-Host "    ⚠️ Unquoted service path: $($svc.Name)" -ForegroundColor Yellow
                    $AuditResults["Services"] += [PSCustomObject]@{
                        RiskLevel = "Medium"
                        Name      = "Unquoted Service Path"
                        Detail    = "$($svc.DisplayName) [$($svc.Name)] -> $binaryPath (a space-containing unquoted path is a local privilege-escalation primitive)"
                    }
                }

                # Services running under a named account rather than SYSTEM/built-in service accounts.
                if (-not [string]::IsNullOrWhiteSpace([string]$detail.StartName) -and $detail.StartName -notmatch '^(LocalSystem|NT AUTHORITY\\|\.\\|BUILTIN\\|Managed Service|NT SERVICE\\)') {
                    $namedAccountServices.Add("$($svc.Name)=$($detail.StartName)")
                }
            }

            if ($namedAccountServices.Count -gt 0) {
                $AuditResults["Services"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "Services Running As Named Accounts"
                    Detail    = "$($namedAccountServices.Count) services: $(@($namedAccountServices | Select-Object -First 10) -join ', ')"
                }
            }

            # Known high-value services, reported only when actually running.
            $riskyServices = @{
                'Spooler'        = @{ Name='Print Spooler';    Risk='Medium'; Reason='PrintNightmare (CVE-2021-34527) attack surface; disable on hosts that do not print' }
                'RemoteRegistry' = @{ Name='Remote Registry';  Risk='High';   Reason='allows remote modification of the registry' }
                'TlntSvr'        = @{ Name='Telnet Server';    Risk='High';   Reason='unencrypted remote access' }
                'TFTPD32'        = @{ Name='TFTP Server';      Risk='Medium'; Reason='unencrypted file transfer' }
                'WinRM'          = @{ Name='Windows Remote Mgmt'; Risk='Info'; Reason='remote shell listener; verify it is intentional and firewalled' }
                'W32Time'        = @{ Name='Windows Time';     Risk='Low';    Reason='time synchronisation service (see Windows Time section)' }
            }

            foreach ($svc in $runningServices) {
                if (-not $riskyServices.ContainsKey($svc.Name)) { continue }

                $info = $riskyServices[$svc.Name]
                Write-Host "    ℹ️ $($info.Name) [$($svc.Name)] is running - $($info.Reason)" -ForegroundColor Cyan
                $AuditResults["Services"] += [PSCustomObject]@{
                    RiskLevel = $info.Risk
                    Name      = "Service: $($info.Name)"
                    Detail    = "$($svc.DisplayName) [$($svc.Name)] running ($($svc.StartType)) - $($info.Reason)"
                }
            }
        }

    } catch {
        Write-AuditError -Context "Services Audit" -ErrorMessage $_.Exception.Message
        $AuditResults["Services"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Services Audit"
            Detail    = "Unable to query services: $_"
        }
    }

    Write-ProgressOutput "Services audit complete." -Verbose:$false
}

function Audit-StartupPrograms {
    param($AuditResults)

    Write-ProgressOutput "Auditing startup programs..." -Verbose:$false

    $startupEntries = @()

    # HKLM Run keys
    $runKeys = @(
        @{ Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";       Scope="HKLM" },
        @{ Path="HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Scope="HKLM-WOW64" },
        @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";       Scope="HKCU" },
        @{ Path="HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Scope="HKCU-WOW64" },
        @{ Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";   Scope="HKLM-RunOnce" }
    )

    foreach ($key in $runKeys) {
        if (-not (Test-Path -LiteralPath $key.Path)) { continue }

        try {
            $items = Get-ItemProperty -LiteralPath $key.Path -ErrorAction SilentlyContinue
            if ($null -eq $items) { continue }

            foreach ($prop in @($items.PSObject.Properties)) {
                # Exclude the registry provider's own properties and the unnamed (Default) value; both were
                # previously counted as startup entries.
                if ($prop.Name -match '^PS' -or $prop.Name -eq '(default)') { continue }
                if ([string]::IsNullOrWhiteSpace([string]$prop.Value)) { continue }

                $startupEntries += [PSCustomObject]@{
                    Name  = $prop.Name
                    Path  = [string]$prop.Value
                    Scope = $key.Scope
                }
            }
        } catch {
            Write-AuditError -Context "Startup Key: $($key.Path)" -ErrorMessage $_.Exception.Message
        }
    }

    # Startup folder (all users)
    $startupFolders = @(
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            try {
                $files = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    $startupEntries += [PSCustomObject]@{
                        Name = $file.Name
                        Path = $file.FullName
                        Scope = "StartupFolder"
                    }
                }
            } catch {
                # Skip inaccessible folders
            }
        }
    }

    # Win32_StartupCommand via CIM
    try {
        $startupCmds = Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction SilentlyContinue
        if ($null -ne $startupCmds) {
            foreach ($cmd in $startupCmds) {
                if (-not [string]::IsNullOrEmpty($cmd.Name) -and -not [string]::IsNullOrEmpty($cmd.Command)) {
                    $startupEntries += [PSCustomObject]@{
                        Name = $cmd.Name
                        Path = $cmd.Command
                        Scope = "Win32_StartupCommand"
                    }
                }
            }
        }
    } catch {
        # Skip CIM query failures
    }

    if ($startupEntries.Count -gt 0) {
        $AuditResults["StartupPrograms"] += [PSCustomObject]@{
            RiskLevel = "Info"
            Name      = "Startup Programs Count"
            Detail    = "$($startupEntries.Count) startup entries found across all scopes"
        }

        # Flag suspicious entries
        $suspiciousPatterns = @(
            @{Pattern='(?i)(powershell|cmd|wscript|cscript|mshta|certutil|bitsadmin)\s'; Risk="High"},
            @{Pattern='(?i)(temp|appdata|downloads)\s'; Risk="Medium"},
            @{Pattern='(?i)(http|https)://'; Risk="Medium"}
        )

        foreach ($entry in $startupEntries) {
            foreach ($pattern in $suspiciousPatterns) {
                if ($entry.Path -match $pattern.Pattern) {
                    $AuditResults["StartupPrograms"] += [PSCustomObject]@{
                        RiskLevel = $pattern.Risk
                        Name      = "Suspicious Startup Entry"
                        Detail    = "$($entry.Name): $($entry.Path) [Scope: $($entry.Scope)]"
                    }
                    break
                }
            }
        }

        # List all entries
        foreach ($entry in $startupEntries) {
            $AuditResults["StartupPrograms"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Startup Entry"
                Detail    = "$($entry.Name): $($entry.Path) [Scope: $($entry.Scope)]"
            }
        }

    } else {
        $AuditResults["StartupPrograms"] += [PSCustomObject]@{
            RiskLevel = "Pass"
            Name      = "Startup Programs"
            Detail    = "No startup entries found"
        }
    }

    Write-ProgressOutput "Startup programs audit complete." -Verbose:$false
}

function Audit-BitLocker {
    param($AuditResults)

    Write-ProgressOutput "Auditing BitLocker / disk encryption..." -Verbose:$false

    # Get-BitLockerVolume returns nothing without elevation, so an empty result is reported as a coverage
    # gap rather than as "no volumes". Property names: VolumeStatus, ProtectionStatus, PercentEncrypted,
    # EncryptionMethod, KeyProtector (there is no VolumeProtectionStatus).
    try {
        $volumes = @(Get-BitLockerVolume -ErrorAction Stop)

        if ($volumes.Count -eq 0) {
            if (-not $IsElevated) {
                Write-Host "  ℹ️ BitLocker state unavailable (requires elevation)." -ForegroundColor Gray
                $AuditResults["BitLocker"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "BitLocker Status"
                    Detail    = "Get-BitLockerVolume returns no volumes when run unelevated - rerun elevated to audit disk encryption"
                }
            } else {
                Write-Host "  ⚠️ No BitLocker volumes returned (edition may not include BitLocker)." -ForegroundColor Yellow
                $AuditResults["BitLocker"] += [PSCustomObject]@{
                    RiskLevel = "Medium"
                    Name      = "BitLocker Status"
                    Detail    = "No fixed volumes reported by the BitLocker provider (Home editions do not include BitLocker; verify device encryption instead)"
                }
            }

            Write-ProgressOutput "BitLocker audit complete." -Verbose:$false
            return
        }

        foreach ($vol in $volumes) {
            $mountPoint       = [string](Get-OptionalProperty -InputObject $vol -Name 'MountPoint')
            $volumeStatus     = [string](Get-OptionalProperty -InputObject $vol -Name 'VolumeStatus')
            $protectionStatus = [string](Get-OptionalProperty -InputObject $vol -Name 'ProtectionStatus')
            $percentEncrypted = Get-OptionalProperty -InputObject $vol -Name 'PercentEncrypted'
            $encryptionMethod = [string](Get-OptionalProperty -InputObject $vol -Name 'EncryptionMethod')

            $protected = ($volumeStatus -match '(?i)FullyEncrypted|Protection On' -or $protectionStatus -match '(?i)^On$')

            if ($protected) {
                Write-Host "  ✅ BitLocker is enabled on $mountPoint (${percentEncrypted}% encrypted)." -ForegroundColor Green
            } else {
                Write-Host "    🔴 BitLocker is NOT protecting $mountPoint (VolumeStatus=$volumeStatus)" -ForegroundColor Red
            }

            $AuditResults["BitLocker"] += [PSCustomObject]@{
                RiskLevel = if ($protected) { "Pass" } else { "High" }
                Name      = "BitLocker Volume: $mountPoint"
                Detail    = "VolumeStatus=$volumeStatus | ProtectionStatus=$protectionStatus | encrypted=${percentEncrypted}% | method=$encryptionMethod"
            }

            # Key protectors decide who can unlock the volume; recovery-key-only volumes are a support risk.
            foreach ($kp in @(Get-OptionalProperty -InputObject $vol -Name 'KeyProtector')) {
                if ($null -eq $kp) { continue }

                $kind = [string](Get-OptionalProperty -InputObject $kp -Name 'KeyMaterialType')
                if ([string]::IsNullOrWhiteSpace($kind)) { $kind = [string](Get-OptionalProperty -InputObject $kp -Name 'KeyProtectorType') }

                $AuditResults["BitLocker"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "Key Protector: $mountPoint"
                    Detail    = "$kind | id=$(Get-OptionalProperty -InputObject $kp -Name 'KeyIdentifier')"
                }
            }
        }

        # A volume that is encrypted but whose protection is suspended still accepts unauthenticated boot.
        foreach ($vol in @($volumes | Where-Object { ([string](Get-OptionalProperty -InputObject $_ -Name 'ProtectionStatus')) -match '(?i)^Off$' })) {
            $AuditResults["BitLocker"] += [PSCustomObject]@{
                RiskLevel = "Medium"
                Name      = "BitLocker Protection Suspended"
                Detail    = "$(Get-OptionalProperty -InputObject $vol -Name 'MountPoint') has protection suspended; resume it once maintenance is finished"
            }
        }

    } catch {
        Write-AuditError -Context "BitLocker" -ErrorMessage $_.Exception.Message
        $AuditResults["BitLocker"] += [PSCustomObject]@{
            RiskLevel = if (-not $IsElevated) { "Info" } else { "Medium" }
            Name      = "BitLocker"
            Detail    = "Unable to query BitLocker status$(if (-not $IsElevated) { ' (requires elevation)' } else { '' }): $_"
        }
    }

    Write-ProgressOutput "BitLocker audit complete." -Verbose:$false
}

function Audit-PowerShellConfig {
    param($AuditResults)

    Write-ProgressOutput "Auditing PowerShell configuration..." -Verbose:$false

    # ------------------------------------------------------------------
    # Execution policy per scope
    # ------------------------------------------------------------------
    try {
        $execPolicies = @(Get-ExecutionPolicy -List -ErrorAction Stop)

        foreach ($policy in $execPolicies) {
            if ([string]::IsNullOrWhiteSpace([string]$policy.ExecutionPolicy)) { continue }

            $riskLevel = "Pass"
            switch ("$($policy.ExecutionPolicy)") {
                'Unrestricted' { $riskLevel = 'High' }
                'Bypass'       { $riskLevel = 'Medium' }
                'RemoteSigned' { $riskLevel = 'Pass' }
                'AllSigned'    { $riskLevel = 'Pass' }
                default        { $riskLevel = 'Low' }
            }

            $AuditResults["PowerShellConfig"] += [PSCustomObject]@{
                RiskLevel = $riskLevel
                Name      = "Execution Policy ($($policy.Scope))"
                Detail    = "$($policy.Scope): $($policy.ExecutionPolicy)"
            }
        }

        $unrestricted = @($execPolicies | Where-Object { "$($_.ExecutionPolicy)" -eq 'Unrestricted' })
        if ($unrestricted.Count -gt 0) {
            Write-Host "  🔴 Unrestricted execution policy at scope(s): $(@($unrestricted | ForEach-Object { $_.Scope }) -join ', ')" -ForegroundColor Red
            $AuditResults["PowerShellConfig"] += [PSCustomObject]@{
                RiskLevel = "High"
                Name      = "Execution Policy Risk"
                Detail    = "Unrestricted execution policy in effect (unsigned local and downloaded scripts run without a prompt)"
            }
        }

    } catch {
        Write-AuditError -Context "PowerShell Execution Policy" -ErrorMessage $_.Exception.Message
    }

    # ------------------------------------------------------------------
    # Logging / visibility policies. These live under HKLM:\SOFTWARE\Policies\... , not
    # HKLM:\SOFTWARE\PolicyDefinitions (which is where ADMX source files are staged, not policy state).
    # ------------------------------------------------------------------
    $loggingChecks = @(
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Key='EnableScriptBlockLogging';   Name='Script Block Logging';     MissingRisk='Medium'; Note='without it, the commands run inside a script are not recorded' }
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';      Key='EnableTranscripting';        Name='PowerShell Transcription'; MissingRisk='Low';      Note='module/system transcription of interactive sessions' }
    )

    foreach ($check in $loggingChecks) {
        try {
            $policyValue = $null
            $item = Get-ItemProperty -LiteralPath $check.Path -ErrorAction SilentlyContinue
            if ($null -ne $item) { $policyValue = $item.($check.Key) }

            if ([int]$policyValue -eq 1) {
                Write-Host "  ✅ $($check.Name): enabled." -ForegroundColor Green
                $AuditResults["PowerShellConfig"] += [PSCustomObject]@{
                    RiskLevel = "Pass"
                    Name      = $check.Name
                    Detail    = "$($check.Key)=1 ($($check.Path))"
                }
            } else {
                $stateText = if ($null -eq $policyValue) { 'not configured' } else { "set to $policyValue" }
                Write-Host "  ⚠️ $($check.Name): $stateText." -ForegroundColor Yellow

                $AuditResults["PowerShellConfig"] += [pscustomobject]@{
                    RiskLevel = $check.MissingRisk
                    Name      = $check.Name
                    Detail    = "$($check.Key) is $stateText ($($check.Path)) - $($check.Note)"
                }
            }
        } catch {
            Write-AuditError -Context $check.Name -ErrorMessage $_.Exception.Message
        }
    }

    # ------------------------------------------------------------------
    # Language mode / Constrained Language Mode (the real CLM indicator, instead of a registry guess)
    # ------------------------------------------------------------------
    try {
        $languageMode  = [string]$ExecutionContext.SessionState.LanguageMode
        $lockdownValue = $null
        $clmItem       = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -ErrorAction SilentlyContinue

        if ($null -ne $clmItem) {
            foreach ($prop in @($clmItem.PSObject.Properties)) {
                if ($prop.Name -eq '__PSLockdownPolicy') { $lockdownValue = $prop.Value }
            }
        }

        Write-Host "    ℹ️ PowerShell language mode: $languageMode (policy value __PSLockdownPolicy=$lockdownValue)" -ForegroundColor Cyan

        $AuditResults["PowerShellConfig"] += [PSCustomObject]@{
            RiskLevel = if ($languageMode -eq 'ConstrainedLanguage' -or $languageMode -eq 'RestrictedLanguage') { "Pass" } else { "Low" }
            Name      = "PowerShell Language Mode"
            Detail    = "Current session language mode: $languageMode; __PSLockdownPolicy=$(if ($null -eq $lockdownValue) { 'not configured' } else { $lockdownValue })$(if ($languageMode -ne 'ConstrainedLanguage') { ' (constrained language mode / WDAC would limit attacker use of the shell)' } else { '' })"
        }

        $AuditResults["PowerShellConfig"] += [PSCustomObject]@{
            RiskLevel = "Info"
            Name      = "PowerShell Version"
            Detail    = "Version: $($PSVersionTable.PSVersion.ToString()) | Edition: $($PSVersionTable.PSEdition)"
        }

    } catch {
        Write-AuditError -Context "PowerShell Language Mode" -ErrorMessage $_.Exception.Message
    }

    # ------------------------------------------------------------------
    # AMSI has no supported on/off registry switch; report the component and rely on the IFEO UseFilter
    # check in Registry Security for tampering indicators.
    # ------------------------------------------------------------------
    try {
        $amsiDll = Join-Path $env:SystemRoot 'System32\amsi.dll'

        if (Test-Path -LiteralPath $amsiDll) {
            $amsiVersion = (Get-Item -LiteralPath $amsiDll).VersionInfo.FileVersion
            $AuditResults["PowerShellConfig"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "AMSI Component"
                Detail    = "amsi.dll present ($amsiVersion); PowerShell script content is visible to the installed antimalware scanner. Tampering indicator: IFEO UseFilter=0 (see Registry Security)."
            }
        } else {
            $AuditResults["PowerShellConfig"] += [PSCustomObject]@{
                RiskLevel = "Medium"
                Name      = "AMSI Component"
                Detail    = "amsi.dll not found at $amsiDll"
            }
        }
    } catch {
        Write-AuditError -Context "AMSI Check" -ErrorMessage $_.Exception.Message
    }

    Write-ProgressOutput "PowerShell configuration audit complete." -Verbose:$false
}

function Audit-TPM_SecureBoot {
    param($AuditResults)

    Write-ProgressOutput "Auditing TPM and Secure Boot..." -Verbose:$false

    # ------------------------------------------------------------------
    # TPM. Get-Tpm requires elevation: unelevated it returns an object with no useful properties
    # rather than throwing, so the property presence is checked explicitly.
    # ------------------------------------------------------------------
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $tpmPresent = Get-OptionalProperty -InputObject $tpm -Name 'TpmPresent'

        if ($null -eq $tpmPresent) {
            Write-Host "  ℹ️ TPM state unavailable (Get-Tpm requires elevation)." -ForegroundColor Gray
            $AuditResults["TPM_SecureBoot"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "TPM Status"
                Detail    = $(if ($IsElevated) { 'Get-Tpm returned no TPM data on this system' } else { 'Get-Tpm returns no data when run unelevated - rerun elevated to audit TPM/BitLocker state' })
            }
        } else {
            $tpmReady     = [bool](Get-OptionalProperty -InputObject $tpm -Name 'TpmReady')
            $tpmEnabled   = [bool](Get-OptionalProperty -InputObject $tpm -Name 'TpmEnabled')
            $tpmActivated = [bool](Get-OptionalProperty -InputObject $tpm -Name 'TpmActivated')
            $manufacturer = Get-OptionalProperty -InputObject $tpm -Name 'ManufacturerId'
            $specVersion  = Get-OptionalProperty -InputObject $tpm -Name 'SpecVersion'

            if (-not [bool]$tpmPresent) {
                Write-Host "  🔴 No TPM detected." -ForegroundColor Red
                $AuditResults["TPM_SecureBoot"] += [PSCustomObject]@{
                    RiskLevel = "High"
                    Name      = "TPM Not Present"
                    Detail    = "No TPM detected (BitLocker, Credential Guard and VBS depend on it)"
                }
            } else {
                Write-Host "  ✅ TPM present (manufacturer $manufacturer, spec $specVersion)." -ForegroundColor Green
                $AuditResults["TPM_SecureBoot"] += [PSCustomObject]@{
                    RiskLevel = if ($tpmReady) { "Pass" } else { "Medium" }
                    Name      = "TPM Present"
                    Detail    = "present=$tpmPresent enabled=$tpmEnabled activated=$tpmActivated ready=$tpmReady | manufacturer=$manufacturer spec=$specVersion"
                }

                if (-not $tpmReady) {
                    Write-Host "    ⚠️ TPM is present but not ready (enabled/activated/initialised)." -ForegroundColor Yellow
                    $AuditResults["TPM_SecureBoot"] += [PSCustomObject]@{
                        RiskLevel = "Medium"
                        Name      = "TPM Not Ready"
                        Detail    = "enabled=$tpmEnabled activated=$tpmActivated - initialise the TPM so BitLocker/VBS can use it"
                    }
                }
            }
        }

    } catch {
        Write-AuditError -Context "TPM" -ErrorMessage $_.Exception.Message
        $AuditResults["TPM_SecureBoot"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "TPM Status"
            Detail    = "Unable to query TPM: $_"
        }
    }

    # ------------------------------------------------------------------
    # Secure Boot. Confirm-SecureBootUEFI needs elevation; the read-only state key works unelevated.
    # Get-SecureBootUEFI lists UEFI variables and has no .Enabled property (the old code relied on it).
    # ------------------------------------------------------------------
    $secureBoot = $null
    $secureBootSource = 'unknown'

    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        $secureBootSource = 'Confirm-SecureBootUEFI'
    } catch {
        $stateValue = Get-OptionalProperty -InputObject (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue) -Name 'UEFISecureBootEnabled'
        if ($null -ne $stateValue) {
            $secureBoot = ([int]$stateValue -eq 1)
            $secureBootSource = 'registry (SecureBoot\State\UEFISecureBootEnabled)'
        }
    }

    if ($null -eq $secureBoot) {
        Write-Host "  ℹ️ Secure Boot status unknown (legacy BIOS or elevation required)." -ForegroundColor Gray
        $AuditResults["TPM_SecureBoot"] += [PSCustomObject]@{
            RiskLevel = "Info"
            Name      = "Secure Boot"
            Detail    = "Unable to determine Secure Boot state; Confirm-SecureBootUEFI requires elevation and no UEFI state key is present (legacy BIOS?)"
        }
    } elseif ([bool]$secureBoot) {
        Write-Host "  ✅ Secure Boot is enabled." -ForegroundColor Green
        $AuditResults["TPM_SecureBoot"] += [PSCustomObject]@{
            RiskLevel = "Pass"
            Name      = "Secure Boot"
            Detail    = "Enabled (source: $secureBootSource)"
        }
    } else {
        Write-Host "  ⚠️ Secure Boot is disabled." -ForegroundColor Yellow
        $AuditResults["TPM_SecureBoot"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Secure Boot"
            Detail    = "Disabled (source: $secureBootSource) - untrusted boot components are not blocked, weakening BitLocker/VBS/Credential Guard"
        }
    }

    # ------------------------------------------------------------------
    # Firmware/BIOS inventory (informational).
    # ------------------------------------------------------------------
    try {
        $firmware = @(Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue)

        if ($firmware.Count -gt 0) {
            $AuditResults["TPM_SecureBoot"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "UEFI Firmware"
                Detail    = "BIOS version: $(@($firmware)[0].SMBIOSBIOSVersion) | manufacturer: $(@($firmware)[0].Manufacturer) | release: $(@($firmware)[0].ReleaseDate)"
            }
        }
    } catch {
        # Non-fatal inventory query
    }

    Write-ProgressOutput "TPM / Secure Boot audit complete." -Verbose:$false
}

function Audit-EventLogConfig {
    param($AuditResults)

    Write-ProgressOutput "Auditing event log configuration..." -Verbose:$false

    # EventLogConfiguration exposes MaximumSizeInBytes / FileSize / LogMode / RecordCount (the previous
    # code read LogMaximumSize, RetentionEnabled and OverflowAction, which do not exist on this object).
    $logsToCheck = @(
        @{ Name='Security';                               MinMB=1024; RiskIfSmall='Medium' }
        @{ Name='System';                                 MinMB=512;  RiskIfSmall='Low' }
        @{ Name='Application';                            MinMB=512;  RiskIfSmall='Low' }
        @{ Name='Setup';                                  MinMB=64;   RiskIfSmall='Info' }
        @{ Name='ForwardedEvents';                        MinMB=512;  RiskIfSmall='Low' }
        @{ Name='Windows PowerShell';                     MinMB=64;   RiskIfSmall='Medium' }
        @{ Name='Microsoft-Windows-PowerShell/Operational'; MinMB=64; RiskIfSmall='Medium' }
    )

    foreach ($logSpec in $logsToCheck) {
        $logName = $logSpec.Name

        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction Stop

            if ($null -eq $log) {
                $AuditResults["EventLogConfig"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "Event Log: $logName"
                    Detail    = "Log not found or not configured on this system"
                }
                continue
            }

            $maxMB   = [math]::Round($log.MaximumSizeInBytes / 1MB, 0)
            $usedMB  = [math]::Round($log.FileSize / 1MB, 1)
            $logMode = "$($log.LogMode)"

            Write-Host "    ℹ️ $($logName): $(@($log.RecordCount)) records | max ${maxMB}MB | ${usedMB}MB used | mode $logMode" -ForegroundColor Cyan

            if (-not [bool]$log.IsEnabled) {
                Write-Host "    🔴 Event log '$logName' is disabled!" -ForegroundColor Red
                $AuditResults["EventLogConfig"] += [PSCustomObject]@{
                    RiskLevel = "High"
                    Name      = "Event Log Disabled: $logName"
                    Detail    = "The log is not accepting events (IsEnabled=false)"
                }
            }

            if ($maxMB -lt $logSpec.MinMB) {
                Write-Host "    ⚠️ '$logName' maximum size ${maxMB}MB is below the recommended $($logSpec.MinMB)MB." -ForegroundColor Yellow
                $AuditResults["EventLogConfig"] += [PSCustomObject]@{
                    RiskLevel = $logSpec.RiskIfSmall
                    Name      = "Event Log Size: $logName"
                    Detail    = "Maximum size ${maxMB}MB (recommended >=$($logSpec.MinMB)MB); events roll over sooner than the retention window"
                }
            } else {
                $AuditResults["EventLogConfig"] += [PSCustomObject]@{
                    RiskLevel = "Pass"
                    Name      = "Event Log: $logName"
                    Detail    = "$(@($log.RecordCount)) records | max ${maxMB}MB | mode $logMode"
                }
            }

            # Circular logs overwrite the oldest events; for the Security log that shortens the forensic window.
            if ($logMode -eq 'Circular' -and $logName -eq 'Security') {
                $AuditResults["EventLogConfig"] += [PSCustomObject]@{
                    RiskLevel = "Low"
                    Name      = "Security Log Overwrites Oldest Events"
                    Detail    = "LogMode=Circular with ${maxMB}MB capacity; consider archiving or a larger log to keep the forensic window"
                }
            }

            if ([bool]$log.IsLogFull) {
                Write-Host "    ⚠️ Event log '$logName' reports itself full." -ForegroundColor Yellow
                $AuditResults["EventLogConfig"] += [PSCustomObject]@{
                    RiskLevel = "Medium"
                    Name      = "Event Log Full: $logName"
                    Detail    = "${usedMB}MB of ${maxMB}MB used and the log reports it is full (mode $logMode)"
                }
            }

        } catch {
            $elevationNote = if (-not $IsElevated -and $logName -eq 'Security') { " - reading the Security log configuration requires elevation" } else { "" }
            Write-AuditError -Context "Event Log: $logName" -ErrorMessage $_.Exception.Message
            $AuditResults["EventLogConfig"] += [PSCustomObject]@{
                RiskLevel = if ($logName -eq 'Security' -and -not $IsElevated) { "Info" } else { "Medium" }
                Name      = "Event Log: $logName"
                Detail    = "Unable to query the log configuration$elevationNote : $($_.Exception.Message)"
            }
        }
    }

    Write-ProgressOutput "Event log configuration audit complete." -Verbose:$false
}

function Audit-WinRM {
    param($AuditResults)

    Write-ProgressOutput "Auditing WinRM / remote management..." -Verbose:$false

    # ------------------------------------------------------------------
    # Service state
    # ------------------------------------------------------------------
    try {
        $winrmService = Get-Service -Name WinRM -ErrorAction Stop

        if ($winrmService.Status -eq 'Running') {
            Write-Host "  ℹ️ WinRM service is running (start type: $($winrmService.StartType))." -ForegroundColor Cyan
            $AuditResults["WinRM"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "WinRM Service Status"
                Detail    = "Status=$($winrmService.Status) StartType=$($winrmService.StartType) (remote shell surface - verify it is intended and firewalled)"
            }
        } else {
            Write-Host "  ✅ WinRM service is stopped ($($winrmService.Status))." -ForegroundColor Green
            $AuditResults["WinRM"] += [PSCustomObject]@{
                RiskLevel = "Pass"
                Name      = "WinRM Service Status"
                Detail    = "Status=$($winrmService.Status) StartType=$($winrmService.StartType)"
            }
        }
    } catch {
        $AuditResults["WinRM"] += [PSCustomObject]@{
            RiskLevel = "Info"
            Name      = "WinRM Service Status"
            Detail    = "WinRM service not present: $($_.Exception.Message)"
        }
    }

    # ------------------------------------------------------------------
    # Listener ports (Get-NetTCPConnection avoids the noise Test-NetConnection produces).
    # ------------------------------------------------------------------
    try {
        foreach ($portSpec in @(@{ Port=5985; Label='WinRM HTTP' }, @{ Port=5986; Label='WinRM HTTPS' })) {
            $listening = @(Get-NetTCPConnection -State Listen -LocalPort $portSpec.Port -ErrorAction SilentlyContinue)

            if ($listening.Count -gt 0) {
                $addresses = @($listening | ForEach-Object { $_.LocalAddress } | Select-Object -Unique)
                $anyScope  = @($addresses | Where-Object { $_ -eq '::' -or $_ -eq '0.0.0.0' }).Count -gt 0

                Write-Host "    ⚠️ $($portSpec.Label) listener on port $($portSpec.Port): $($addresses -join ', ')" -ForegroundColor Yellow
                $AuditResults["WinRM"] += [PSCustomObject]@{
                    RiskLevel = if ($anyScope) { "Medium" } else { "Low" }
                    Name      = "$($portSpec.Label) Listener ($($portSpec.Port))"
                    Detail    = "Listening on $(($addresses | Select-Object -First 4) -join ', ') - reachable from the network unless restricted by firewall rules"
                }
            } else {
                $AuditResults["WinRM"] += [PSCustomObject]@{
                    RiskLevel = "Pass"
                    Name      = "$($portSpec.Label) Listener ($($portSpec.Port))"
                    Detail    = "Not listening"
                }
            }
        }
    } catch {
        Write-AuditError -Context "WinRM Listeners" -ErrorMessage $_.Exception.Message
    }

    # ------------------------------------------------------------------
    # Service configuration from the WSMan: provider (Get-WinRMConfig does not exist).
    # Settings can only be read while the WinRM service is running, so absence is reported as unknown.
    # ------------------------------------------------------------------
    try {
        if (-not (Test-Path -LiteralPath 'WSMan:\localhost\Service')) {
            $AuditResults["WinRM"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "WinRM Configuration"
                Detail    = "The WSMan: provider is unavailable (start the WinRM service to inspect its configuration)"
            }
        } else {
            $unencryptedItem  = Get-Item -LiteralPath 'WSMan:\localhost\Service\AllowUnencrypted' -ErrorAction SilentlyContinue
            $allowUnencrypted = if ($null -ne $unencryptedItem) { [string]$unencryptedItem.Value } else { '' }

            if ([string]::IsNullOrWhiteSpace($allowUnencrypted)) {
                $AuditResults["WinRM"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "WinRM Unencrypted Traffic"
                    Detail    = "AllowUnencrypted could not be read; the WinRM service must be running to query its settings"
                }
            } elseif ($allowUnencrypted -eq 'true') {
                Write-Host "  🔴 WinRM AllowUnencrypted is enabled!" -ForegroundColor Red
                $AuditResults["WinRM"] += [PSCustomObject]@{
                    RiskLevel = "High"
                    Name      = "WinRM Unencrypted Traffic"
                    Detail    = "AllowUnencrypted=true (credentials and shell content can be sent in plaintext)"
                }
            } else {
                $AuditResults["WinRM"] += [PSCustomObject]@{
                    RiskLevel = "Pass"
                    Name      = "WinRM Unencrypted Traffic"
                    Detail    = "AllowUnencrypted=$allowUnencrypted (traffic is encrypted)"
                }
            }

            $authMethods = @(Get-ChildItem -LiteralPath 'WSMan:\localhost\Service\Auth' -ErrorAction SilentlyContinue)

            if ($authMethods.Count -eq 0) {
                $AuditResults["WinRM"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "WinRM Authentication Methods"
                    Detail    = "No authentication settings returned (WinRM service not running)"
                }
            } else {
                foreach ($auth in $authMethods) {
                    $enabled = [string]$auth.Value
                    $name    = [string]$auth.Name

                    if ($enabled -ne 'true') {
                        $risk = "Pass"
                    } elseif ($name -eq 'Basic') {
                        $risk = "High"
                    } elseif ($name -eq 'Anonymous') {
                        $risk = "Medium"
                    } else {
                        $risk = "Info"
                    }

                    if ($risk -eq 'High' -or $risk -eq 'Medium') {
                        Write-Host "    🔴 WinRM authentication method '$name' is enabled" -ForegroundColor Red
                    }

                    $note = ""
                    if ($name -eq 'Basic' -and $enabled -eq 'true') {
                        $note = " (basic authentication puts credentials on the wire; acceptable only over HTTPS with tight scoping)"
                    }

                    $AuditResults["WinRM"] += [PSCustomObject]@{
                        RiskLevel = $risk
                        Name      = "WinRM Auth: $name"
                        Detail    = "Enabled=$enabled$note"
                    }
                }
            }

            $listeners = @(Get-ChildItem -LiteralPath 'WSMan:\localhost\Listener' -ErrorAction SilentlyContinue)
            $AuditResults["WinRM"] += [PSCustomObject]@{
                RiskLevel = if ($listeners.Count -eq 0) { "Pass" } else { "Info" }
                Name      = "WinRM Listeners Configured"
                Detail    = "$($listeners.Count) WSMan listener(s) configured"
            }

            $maxShellsItem = Get-Item -LiteralPath 'WSMan:\localhost\Service\MaxShellsPerUser' -ErrorAction SilentlyContinue
            if ($null -ne $maxShellsItem -and -not [string]::IsNullOrWhiteSpace([string]$maxShellsItem.Value)) {
                $AuditResults["WinRM"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "WinRM MaxShellsPerUser"
                    Detail    = "$($maxShellsItem.Value) (limits concurrent remote shells per user)"
                }
            }
        }

    } catch {
        Write-AuditError -Context "WinRM Configuration" -ErrorMessage $_.Exception.Message
        $AuditResults["WinRM"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "WinRM Configuration"
            Detail    = "Unable to query WinRM configuration: $_"
        }
    }

    Write-ProgressOutput "WinRM audit complete." -Verbose:$false
}

function Audit-CredentialGuard {
    param($AuditResults)

    Write-ProgressOutput "Auditing Credential Guard / VBS..." -Verbose:$false

    # Win32_DeviceGuard exposes SecurityServicesConfigured / SecurityServicesRunning (int arrays) and
    # VirtualizationBasedSecurityStatus. The old code read $dg.SecurityRunning and compared it to $true,
    # which never matched and reported "not running" for every host.
    # Value meanings (Microsoft docs for Win32_DeviceGuard):
    #   1 Credential Guard | 2 Memory integrity (HVCI) | 3 System Guard Secure Launch
    #   4 SMM Firmware Measurement | 5 Kernel-mode HW-enforced Stack Protection | 6 same in audit mode
    #   7 Hypervisor-enforced page translation
    $serviceLabels = @{
        1 = 'Credential Guard'
        2 = 'Memory integrity (HVCI)'
        3 = 'System Guard Secure Launch'
        4 = 'SMM Firmware Measurement'
        5 = 'Kernel-mode Hardware-enforced Stack Protection'
        6 = 'Kernel-mode HW-enforced Stack Protection (audit mode)'
        7 = 'Hypervisor-enforced page translation'
    }

    $deviceGuard = @()
    try {
        $deviceGuard = @(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop)
    } catch {
        Write-AuditError -Context "Device Guard" -ErrorMessage $_.Exception.Message
    }

    if ($deviceGuard.Count -eq 0) {
        $AuditResults["CredentialGuard"] += [PSCustomObject]@{
            RiskLevel = "Info"
            Name      = "Device Guard / VBS"
            Detail    = "Win32_DeviceGuard is not available on this OS build (or the query failed)"
        }
    } else {
        foreach ($dg in $deviceGuard) {
            $configured = @(foreach ($v in @($dg.SecurityServicesConfigured)) { if ($serviceLabels.ContainsKey([int]$v)) { $serviceLabels[[int]$v] } })
            $running    = @(foreach ($v in @($dg.SecurityServicesRunning))    { if ($serviceLabels.ContainsKey([int]$v)) { $serviceLabels[[int]$v] } })

            $vbsStatus = [int]$dg.VirtualizationBasedSecurityStatus
            $vbsText   = switch ($vbsStatus) {
                0 { 'VBS is not enabled' }
                1 { 'VBS is enabled but not running (restart required)' }
                2 { 'VBS is enabled and running' }
                default { "VBS status code $vbsStatus" }
            }

            Write-Host "    ℹ️ $vbsText | configured: $(if ($configured.Count) { $configured -join ', ' } else { 'none' }) | running: $(if ($running.Count) { $running -join ', ' } else { 'none' })" -ForegroundColor Cyan

            $AuditResults["CredentialGuard"] += [PSCustomObject]@{
                RiskLevel = if ($vbsStatus -eq 2) { "Pass" } elseif ($vbsStatus -eq 1) { "Medium" } else { "Low" }
                Name      = "Virtualization-Based Security"
                Detail    = "$vbsText | configured: $(if ($configured.Count) { $configured -join ', ' } else { 'none' }) | running: $(if ($running.Count) { $running -join ', ' } else { 'none' })"
            }

            # Credential Guard specifically protects LSASS secrets.
            if (@($running | Where-Object { $_ -eq 'Credential Guard' }).Count -gt 0) {
                Write-Host "  ✅ Credential Guard is running." -ForegroundColor Green
                $AuditResults["CredentialGuard"] += [PSCustomObject]@{
                    RiskLevel = "Pass"
                    Name      = "Credential Guard"
                    Detail    = "Running (cached domain credentials and Kerberos tickets are isolated)"
                }
            } elseif (@($configured | Where-Object { $_ -eq 'Credential Guard' }).Count -gt 0) {
                Write-Host "    ⚠️ Credential Guard is configured but not running." -ForegroundColor Yellow
                $AuditResults["CredentialGuard"] += [PSCustomObject]@{
                    RiskLevel = "Medium"
                    Name      = "Credential Guard"
                    Detail    = "Configured but not running (a restart or prerequisite such as Secure Boot/TPM is usually missing)"
                }
            } else {
                Write-Host "    ℹ️ Credential Guard is not configured." -ForegroundColor Gray
                $AuditResults["CredentialGuard"] += [PSCustomObject]@{
                    RiskLevel = "Low"
                    Name      = "Credential Guard"
                    Detail    = "Not configured - NTLM hashes and Kerberos tickets in LSASS are readable from memory by local admin malware (optional on clients, recommended by baselines)"
                }
            }

            if (@($running | Where-Object { $_ -eq 'Memory integrity (HVCI)' }).Count -gt 0) {
                $AuditResults["CredentialGuard"] += [PSCustomObject]@{
                    RiskLevel = "Pass"
                    Name      = "Memory Integrity (HVCI)"
                    Detail    = "Running (kernel-mode drivers are validated before loading)"
                }
            } else {
                $AuditResults["CredentialGuard"] += [PSCustomObject]@{
                    RiskLevel = "Low"
                    Name      = "Memory Integrity (HVCI)"
                    Detail    = "Not running - vulnerable kernel drivers can be loaded (Core isolation > Memory integrity)"
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # Credential Guard policy value (readable without elevation).
    # ------------------------------------------------------------------
    try {
        $lsaConfig = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
        if ($null -ne $lsaConfig -and $null -ne $lsaConfig.LsaCfgFlags) {
            $flags = [int]$lsaConfig.LsaCfgFlags
            $flagText = switch ($flags) {
                0 { 'Credential Guard policy is disabled' }
                1 { 'Credential Guard enabled with UEFI lock' }
                2 { 'Credential Guard enabled without UEFI lock' }
                default { "LsaCfgFlags=$flags" }
            }

            $AuditResults["CredentialGuard"] += [PSCustomObject]@{
                RiskLevel = if ($flags -eq 0) { "Low" } else { "Pass" }
                Name      = "LSA Credential Guard Policy"
                Detail    = "$flagText (LsaCfgFlags=$flags)"
            }
        }
    } catch {
        # Non-fatal policy query
    }

    Write-ProgressOutput "Credential Guard / VBS audit complete." -Verbose:$false
}

function Audit-FileSystemACLs {
    param($AuditResults)

    Write-ProgressOutput "Auditing file system ACLs on critical paths..." -Verbose:$false

    $criticalPaths = @(
        @{ Path=$env:SystemRoot;                 Name='Windows Directory'; System=$true }
        @{ Path="$env:SystemRoot\System32";      Name='System32';          System=$true }
        @{ Path=$env:ProgramFiles;               Name='Program Files';     System=$true }
        @{ Path=[string]${env:ProgramFiles(x86)};Name='Program Files (x86)';System=$true }
        @{ Path=$env:ProgramData;                Name='ProgramData';       System=$false }
        @{ Path=$env:TEMP;                       Name='Temp Directory';    System=$false }
        @{ Path=$env:ALLUSERSPROFILE;            Name='All Users Profile'; System=$false }
    )

    # Broad identities that must not hold write access to system locations. Matching the trailing group
    # name fixes the previous regex, which required an exact whole-string match ('^NT AUTHORITY$') and so
    # classified every normal ACE as "non-standard".
    $broadIdentityPattern = '(?i)(^|\\)(Everyone|Authenticated Users|ANONYMOUS LOGON|Anonymous Logon|Network|Guests|Users|WORLD)$'
    $writeRightPattern    = '(?i)(FullControl|Modify|Write|FileAppendDown|GenericAll|ChangeOwner)'

    foreach ($pathSpec in $criticalPaths) {
        if ([string]::IsNullOrWhiteSpace($pathSpec.Path) -or -not (Test-Path -LiteralPath $pathSpec.Path)) {
            $AuditResults["FileSystemACLs"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "ACL: $($pathSpec.Name)"
                Detail    = "Path not present on this system: $($pathSpec.Path)"
            }
            continue
        }

        try {
            $acl   = Get-Acl -LiteralPath $pathSpec.Path -ErrorAction Stop
            $rules = @($acl.Access)
            $owner = [string]$acl.Owner

            Write-Host "    ℹ️ $($pathSpec.Name): owner $owner, $($rules.Count) access rules" -ForegroundColor Cyan

            $weak   = [System.Collections.Generic.List[object]]::new()
            $orphans = 0

            foreach ($rule in $rules) {
                $identity = [string]$rule.IdentityReference

                # Trustee no longer resolvable: the ACE survives a domain/machine change.
                if ($identity -match '^S-\d(-\d+)+$') {
                    $orphans++
                    continue
                }

                if ("$($rule.AccessControlType)" -ne 'Allow') { continue }
                if ($identity -notmatch $broadIdentityPattern) { continue }
                if ("$($rule.FileSystemRights)" -notmatch $writeRightPattern) { continue }

                $weak.Add([pscustomobject]@{
                    Identity  = $identity
                    Rights    = [string]$rule.FileSystemRights
                    Inherited = ([string]$rule.IsInherited -eq 'True')
                })
            }

            if ($orphans > 0) {
                $AuditResults["FileSystemACLs"] += [PSCustomObject]@{
                    RiskLevel = "Low"
                    Name      = "Unresolved ACEs: $($pathSpec.Name)"
                    Detail    = "$orphans access rule(s) reference a SID that no longer resolves (review after domain/machine changes)"
                }
            }

            if ($weak.Count -eq 0) {
                Write-Host "  ✅ $($pathSpec.Name): no broad identity has write access." -ForegroundColor Green
                $AuditResults["FileSystemACLs"] += [PSCustomObject]@{
                    RiskLevel = "Pass"
                    Name      = "ACL: $($pathSpec.Name)"
                    Detail    = "Owner: $owner | $($rules.Count) rules | no Everyone/Users/Authenticated Users write access"
                }
                continue
            }

            foreach ($entry in $weak) {
                $veryBroad = ($entry.Identity -match '(?i)(^|\\)(Everyone|ANONYMOUS LOGON|Anonymous Logon|WORLD)$')
                $riskLevel = if ($pathSpec.System -and $veryBroad) { "Critical" } elseif ($pathSpec.System) { "High" } else { "Medium" }

                Write-Host "    🔴 $($pathSpec.Name): $($entry.Identity) has $($entry.Rights)" -ForegroundColor Red
                $AuditResults["FileSystemACLs"] += [PSCustomObject]@{
                    RiskLevel = $riskLevel
                    Name      = "Broad Write Access: $($pathSpec.Name)"
                    Detail    = "$($entry.Identity) -> $($entry.Rights) (inherited=$($entry.Inherited)) on $($pathSpec.Path)"
                }
            }
        } catch {
            Write-AuditError -Context "ACL: $($pathSpec.Name)" -ErrorMessage $_.Exception.Message
            $AuditResults["FileSystemACLs"] += [PSCustomObject]@{
                RiskLevel = "Medium"
                Name      = "ACL: $($pathSpec.Name)"
                Detail    = "Unable to query ACL for $($pathSpec.Path): $_"
            }
        }
    }

    Write-ProgressOutput "File system ACL audit complete." -Verbose:$false
}

function Audit-DNSClient {
    param($AuditResults)

    Write-ProgressOutput "Auditing DNS client configuration..." -Verbose:$false

    # Get-DnsClient exposes ConnectionSpecificSuffix / ConnectionSpecificSuffixSearchList /
    # RegisterThisConnectionsAddress (there is no DhcpEnabled on it, and Get-DnsClientSearchOrder does not exist).
    try {
        $dnsClients = @(Get-DnsClient -ErrorAction Stop)

        if ($dnsClients.Count -eq 0) {
            $AuditResults["DNSClient"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "DNS Client"
                Detail    = "No DNS client interfaces returned"
            }
            Write-ProgressOutput "DNS client audit complete." -Verbose:$false
            return
        }

        # DHCP state comes from the network adapter configuration.
        $dhcpByIndex = @{}
        foreach ($nac in @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue)) {
            $dhcpByIndex[[int]$nac.InterfaceIndex] = [bool]$nac.DhcpEnabled
        }

        # Global suffix search list.
        try {
            $globalSetting = @(Get-DnsClientGlobalSetting -ErrorAction Stop)[0]
            if ($null -ne $globalSetting) {
                $suffixes = @($globalSetting.SuffixSearchList)
                $AuditResults["DNSClient"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "DNS Global Suffix Search List"
                    Detail    = "$(if ($suffixes.Count) { $suffixes -join ', ' } else { 'empty' }) | UseSuffixSearchList=$($globalSetting.UseSuffixSearchList) | AppendParent=$($globalSetting.AppendParentSuffixes)"
                }
            }
        } catch {
            Write-AuditError -Context "DNS Global Settings" -ErrorMessage $_.Exception.Message
        }

        foreach ($client in $dnsClients) {
            $alias   = [string]$client.InterfaceAlias
            $index   = [int]$client.InterfaceIndex
            $suffix  = [string]$client.ConnectionSpecificSuffix
            if ($dhcpByIndex.ContainsKey($index)) { $dhcp = $(if ($dhcpByIndex[$index]) { 'enabled' } else { 'disabled (static)' }) } else { $dhcp = 'unknown' }

            Write-Host "    ℹ️ $($alias): DHCP $dhcp | suffix '$suffix' | registers=$($client.RegisterThisConnectionsAddress)" -ForegroundColor Cyan

            $AuditResults["DNSClient"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "DNS Client: $alias"
                Detail    = "DHCP $dhcp | connection suffix: $(if ([string]::IsNullOrWhiteSpace($suffix)) { 'none' } else { $suffix }) | register this connection: $($client.RegisterThisConnectionsAddress) | use suffix when registering: $($client.UseSuffixWhenRegistering)"
            }

            # Static DNS on a client that is expected to be DHCP-managed usually means manual tampering.
            if ($dhcp -eq 'disabled (static)') {
                $AuditResults["DNSClient"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "Static IP Configuration: $alias"
                    Detail    = "IPv4 DHCP is disabled on this interface; verify the DNS servers are the intended ones (see Networking section)"
                }
            }
        }

    } catch {
        Write-AuditError -Context "DNS Client" -ErrorMessage $_.Exception.Message
        $AuditResults["DNSClient"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "DNS Client Configuration"
            Detail    = "Unable to query DNS client: $_"
        }
    }

    Write-ProgressOutput "DNS client audit complete." -Verbose:$false
}

function Audit-WindowsTime {
    param($AuditResults)

    Write-ProgressOutput "Auditing Windows Time Service..." -Verbose:$false

    try {
        $w32Time = Get-Service -Name W32Time -ErrorAction SilentlyContinue
        
        if ($null -ne $w32Time) {
            $AuditResults["WindowsTime"] += [PSCustomObject]@{
                RiskLevel = if ($w32Time.Status -eq "Running") { "Pass" } else { "Medium" }
                Name      = "Windows Time Service"
                Detail    = "Status: $($w32Time.Status) | Start Type: $($w32Time.StartType)"
            }
        }

        # Get time configuration via w32tm
        $timeConfig = w32tm /query /configuration 2>$null
        if ($null -ne $timeConfig) {
            $ntpServer = $timeConfig | Select-String "SpecialPollInterval|Type"
            if ($null -ne $ntpServer) {
                $AuditResults["WindowsTime"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "NTP Configuration"
                    Detail    = "$($timeConfig -join ' | ')"
                }
            }
        }

        # Get current time sync status
        $timeStatus = w32tm /query /status 2>$null
        if ($null -ne $timeStatus) {
            $source = $timeStatus | Select-String "Source:"
            if ($null -ne $source) {
                $AuditResults["WindowsTime"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "Time Sync Source"
                    Detail    = "$source"
                }
            }
        }

        # Check if time is synchronized (within acceptable drift)
        $localTime = Get-Date
        $utcTime = [System.TimeZoneInfo]::ConvertTime($localTime, [System.TimeZoneInfo]::Utc)
        
        $AuditResults["WindowsTime"] += [PSCustomObject]@{
            RiskLevel = "Info"
            Name      = "Current System Time"
            Detail    = "Local: $localTime | UTC: $utcTime"
        }

    } catch {
        Write-AuditError -Context "Windows Time" -ErrorMessage $_.Exception.Message
        $AuditResults["WindowsTime"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Windows Time Service"
            Detail    = "Unable to query time service: $_"
        }
    }

    Write-ProgressOutput "Windows Time audit complete." -Verbose:$false
}

function Audit-PrintSpooler {
    param($AuditResults)

    Write-ProgressOutput "Auditing Print Spooler..." -Verbose:$false

    try {
        $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        
        if ($null -ne $spooler) {
            $AuditResults["PrintSpooler"] += [PSCustomObject]@{
                RiskLevel = if ($spooler.Status -eq "Running") { "Medium" } else { "Pass" }
                Name      = "Print Spooler Service"
                Detail    = "Status: $($spooler.Status) | Start Type: $($spooler.StartType)"
            }

            if ($spooler.Status -eq "Running") {
                $AuditResults["PrintSpooler"] += [PSCustomObject]@{
                    RiskLevel = "Medium"
                    Name      = "PrintNightmare Relevance"
                    Detail    = "Print Spooler is running (CVE-2021-34527 relevance - ensure system is patched)"
                }
            } else {
                $AuditResults["PrintSpooler"] += [PSCustomObject]@{
                    RiskLevel = "Pass"
                    Name      = "PrintNightmare Mitigation"
                    Detail    = "Print Spooler is disabled (good mitigation)"
                }
            }
        }

        # Check for installed printers
        $printers = Get-CimInstance -ClassName Win32_Printer -ErrorAction SilentlyContinue
        if ($null -ne $printers) {
            $AuditResults["PrintSpooler"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Installed Printers"
                Detail    = "$($printers.Count) printer(s) installed"
            }
        }

    } catch {
        Write-AuditError -Context "Print Spooler" -ErrorMessage $_.Exception.Message
        $AuditResults["PrintSpooler"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Print Spooler"
            Detail    = "Unable to query print spooler: $_"
        }
    }

    Write-ProgressOutput "Print Spooler audit complete." -Verbose:$false
}

function Audit-GroupPolicy {
    param($AuditResults)

    Write-ProgressOutput "Auditing Group Policy results..." -Verbose:$false

    try {
        # Check if domain-joined
        $domainRole = Get-CimInstance -ClassName Win32_ComputerSystem -Property Domain -ErrorAction SilentlyContinue
        
        if ($null -ne $domainRole -and -not [string]::IsNullOrEmpty($domainRole.Domain)) {
            $AuditResults["GroupPolicy"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Domain Membership"
                Detail    = "Domain: $($domainRole.Domain)"
            }

            # Try gpresult for domain-joined machines
            try {
                $gpResult = gpresult /H "$env:TEMP\gpreport.html" /F 2>$null
                if ($LASTEXITCODE -eq 0) {
                    $AuditResults["GroupPolicy"] += [PSCustomObject]@{
                        RiskLevel = "Pass"
                        Name      = "Group Policy Report"
                        Detail    = "gpresult succeeded (report saved to $env:TEMP\gpreport.html)"
                    }
                } else {
                    $AuditResults["GroupPolicy"] += [PSCustomObject]@{
                        RiskLevel = "Medium"
                        Name      = "Group Policy Report"
                        Detail    = "gpresult failed with exit code $LASTEXITCODE"
                    }
                }
            } catch {
                $AuditResults["GroupPolicy"] += [PSCustomObject]@{
                    RiskLevel = "Medium"
                    Name      = "Group Policy Report"
                    Detail    = "Unable to run gpresult: $_"
                }
            }

            # Check for applied GPOs via registry
            try {
                $gpoLinks = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History" -ErrorAction SilentlyContinue
                if ($null -ne $gpoLinks) {
                    $AuditResults["GroupPolicy"] += [PSCustomObject]@{
                        RiskLevel = "Info"
                        Name      = "GPO History"
                        Detail    = "Group Policy history available"
                    }
                }
            } catch {
                # Skip GPO history failures
            }

        } else {
            $AuditResults["GroupPolicy"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Domain Membership"
                Detail    = "Not domain-joined (workgroup or standalone)"
            }

            # Check local GPO settings
            try {
                $localGPO = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
                if ($null -ne $localGPO) {
                    $AuditResults["GroupPolicy"] += [PSCustomObject]@{
                        RiskLevel = "Info"
                        Name      = "Local GPO"
                        Detail    = "Local Group Policy settings present"
                    }
                }
            } catch {
                # Skip local GPO failures
            }
        }

    } catch {
        Write-AuditError -Context "Group Policy" -ErrorMessage $_.Exception.Message
        $AuditResults["GroupPolicy"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Group Policy"
            Detail    = "Unable to query Group Policy: $_"
        }
    }

    Write-ProgressOutput "Group Policy audit complete." -Verbose:$false
}

function Audit-RegistryOptions {
    param($AuditResults)

    Write-ProgressOutput "Auditing registry security options..." -Verbose:$false

    # HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System
    $policiesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    
    try {
        $policies = Get-ItemProperty -Path $policiesPath -ErrorAction SilentlyContinue
        
        if ($null -ne $policies) {
            $securityOptions = @(
                @{Key="NoLockDown"; Name="No Lock Down"; RiskLevel="Medium"; Expected="0"},
                @{Key="FilterAdministratorToken"; Name="Filter Administrator Token"; RiskLevel="High"; Expected="1"},
                @{Key="ConsentPromptBehaviorAdmin"; Name="Admin Consent Prompt"; RiskLevel="High"; Expected="5"},
                @{Key="PromptOnSecureDesktop"; Name="Prompt on Secure Desktop"; RiskLevel="Medium"; Expected="1"},
                @{Key="EnableLUA"; Name="Enable UAC"; RiskLevel="Critical"; Expected="1"},
                @{Key="LocalAccountTokenFilterPolicy"; Name="Local Account Token Filter"; RiskLevel="High"; Expected="0"},
                @{Key="DisableCAD"; Name="Disable CAD"; RiskLevel="Medium"; Expected="0"},
                @{Key="ScForceOption"; Name="Force Smart Card"; RiskLevel="Low"; Expected="0"},
                @{Key="EnableVirtualization"; Name="Enable Virtualization"; RiskLevel="Low"; Expected="1"},
                @{Key="ValidateAdminCodeSignatures"; Name="Validate Admin Code Signatures"; RiskLevel="Medium"; Expected="0"},
                @{Key="DisableIPSecHardening"; Name="Disable IPSec Hardening"; RiskLevel="High"; Expected="0"},
                @{Key="NoAdminShare"; Name="No Admin Share"; RiskLevel="Low"; Expected="0"},
                @{Key="EnableSecureUIAPaths"; Name="Secure UIA Paths"; RiskLevel="Medium"; Expected="1"},
                @{Key="EnableInstallerDetection"; Name="Installer Detection"; RiskLevel="Low"; Expected="1"},
                @{Key="EnableUwpInstallerDetection"; Name="UWP Installer Detection"; RiskLevel="Low"; Expected="1"},
                @{Key="FilterAdministratorToken"; Name="Filter Admin Token"; RiskLevel="High"; Expected="1"},
                @{Key="ShutdownWithoutLogon"; Name="Shutdown Without Logon"; RiskLevel="Medium"; Expected="0"},
                @{Key="UndockWithoutLogon"; Name="Undock Without Logon"; RiskLevel="Medium"; Expected="0"},
                @{Key="MSIAlwaysInstallElevated"; Name="Always Install Elevated"; RiskLevel="High"; Expected="0"},
                @{Key="NoBackgroundPolicy"; Name="No Background Policy"; RiskLevel="Low"; Expected="0"},
                @{Key="NoGPOListChanges"; Name="No GPO List Changes"; RiskLevel="Medium"; Expected="0"},
                @{Key="WaitForRestart"; Name="Wait For Restart"; RiskLevel="Low"; Expected="0"},
                @{Key="EnableVirtualization"; Name="Enable Virtualization"; RiskLevel="Low"; Expected="1"},
                @{Key="ScreenSaverGracePeriod"; Name="Screen Saver Grace Period"; RiskLevel="Low"; Expected="5"},
                @{Key="ConnectedUserExperimentsDisabled"; Name="Connected User Experiments"; RiskLevel="Low"; Expected="1"},
                @{Key="DisableIPPolicyExtension"; Name="Disable IPSec Policy Extension"; RiskLevel="Medium"; Expected="0"},
                @{Key="NoTokenOnLogon"; Name="No Token on Logon"; RiskLevel="Medium"; Expected="0"},
                @{Key="SCENoApplyGPOList"; Name="No GPO List Cache"; RiskLevel="Low"; Expected="0"},
                @{Key="GPOFileSecurityMode"; Name="GPO File Security"; RiskLevel="Medium"; Expected="0"},
                @{Key="LsaCfgFlags"; Name="LSA Config Flags"; RiskLevel="High"; Expected="0"},
                @{Key="RunAsPPL"; Name="Run as PPL"; RiskLevel="High"; Expected="0"},
                @{Key="RunAsPPLAlias"; Name="Run as PPL Alias"; RiskLevel="High"; Expected="0"}
            )

            foreach ($opt in $securityOptions) {
                try {
                    $val = Get-ItemProperty -Path $policiesPath -Name $opt.Key -ErrorAction SilentlyContinue
                    if ($null -ne $val -and $null -ne $val.($opt.Key)) {
                        $actualVal = $val.($opt.Key)
                        $riskLevel = "Info"
                        
                        if ($opt.Expected -ne $null -and $actualVal -ne $opt.Expected) {
                            $riskLevel = $opt.RiskLevel
                        }

                        $AuditResults["RegistryOptions"] += [PSCustomObject]@{
                            RiskLevel = $riskLevel
                            Name      = "Registry Option: $($opt.Name)"
                            Detail    = "$($opt.Key) = $actualVal (expected: $($opt.Expected))"
                        }
                    }
                } catch {
                    # Skip inaccessible keys
                }
            }

        } else {
            $AuditResults["RegistryOptions"] += [PSCustomObject]@{
                RiskLevel = "Medium"
                Name      = "Registry Security Options"
                Detail    = "Unable to read policies registry"
            }
        }

    } catch {
        Write-AuditError -Context "Registry Security Options" -ErrorMessage $_.Exception.Message
        $AuditResults["RegistryOptions"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Registry Security Options"
            Detail    = "Unable to query registry security options: $_"
        }
    }

    Write-ProgressOutput "Registry security options audit complete." -Verbose:$false
}

function Audit-WifiProfiles {
    param($AuditResults)

    Write-ProgressOutput "Auditing saved Wi-Fi profiles..." -Verbose:$false

    # netsh output is localized; if the expected labels are absent we say so instead of reporting "none".
    # The key material itself is never copied into the report - only whether a profile stores one.
    try {
        $wifiOutput = @(netsh wlan show profiles 2>$null)

        if ($LASTEXITCODE -ne 0 -or $wifiOutput.Count -eq 0) {
            $AuditResults["WifiProfiles"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Saved Wi-Fi Profiles"
                Detail    = "netsh wlan returned no profiles (no wireless interface on this host)"
            }
            Write-ProgressOutput "Wi-Fi profiles audit complete." -Verbose:$false
            return
        }

        $profileNames = [System.Collections.Generic.List[string]]::new()
        foreach ($line in $wifiOutput) {
            if ("$line" -match '(?i)^\s*All User Profile\s*:\s*(.+)$') {
                $profileNames.Add($matches[1].Trim())
            }
        }

        if ($profileNames.Count -eq 0) {
            $AuditResults["WifiProfiles"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Saved Wi-Fi Profiles"
                Detail    = "netsh wlan returned output without recognisable profile labels (localized output?); review manually"
            }
            Write-ProgressOutput "Wi-Fi profiles audit complete." -Verbose:$false
            return
        }

        $withKeys = 0

        foreach ($profileName in $profileNames) {
            # Pass the profile as a single argument so names with spaces or quotes cannot break out.
            $profileArg    = "name=$profileName"
            $detail      = @(netsh wlan show profile $profileArg key=clear 2>$null)
            $authValue   = 'n/a'
            $cipherValue = 'n/a'
            $hasKey      = $false

            foreach ($line in $detail) {
                if ("$line" -match '(?i)^\s*Authentication\s*:\s*(.+)$') { $authValue = $matches[1].Trim() }
                elseif ("$line" -match '(?i)^\s*Cipher\s*:\s*(.+)$')            { $cipherValue = $matches[1].Trim() }
                elseif ("$line" -match '(?i)^\s*Key Content\s*:\s*(\S.*)$')     { $hasKey = $true }
            }

            if ($authValue -eq 'n/a' -and $cipherValue -eq 'n/a') {
                # Localized labels: fall back to reporting the profile without details.
                $AuditResults["WifiProfiles"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "Wi-Fi Profile: $profileName"
                    Detail    = "Profile stored on this host (authentication/cipher labels not recognised in localized netsh output)"
                }
                continue
            }

            # An open or WEP profile stores no usable credential protection at all.
            $weakSecurity = ($authValue -match '(?i)^(None|Any|Open)' -or $cipherValue -match '(?i)(WEP|^TKIP$)')
            if ($hasKey) { $withKeys++ }

            Write-Host "    ℹ️ Wi-Fi profile '$profileName': auth=$authValue cipher=$cipherValue keyStored=$hasKey" -ForegroundColor Cyan

            $AuditResults["WifiProfiles"] += [PSCustomObject]@{
                RiskLevel = if ($weakSecurity) { "Medium" } else { "Info" }
                Name      = "Wi-Fi Profile: $profileName"
                Detail    = "Authentication: $authValue | Cipher: $cipherValue | key stored in profile: $(if ($hasKey) { 'yes' } else { 'no' })$(if ($weakSecurity) { ' (open or weakly encrypted network)' } else { '' })"
            }

            if ($weakSecurity) {
                Write-Host "    ⚠️ Wi-Fi profile '$profileName' uses open/weak security ($authValue/$cipherValue)" -ForegroundColor Yellow
            }
        }

        $AuditResults["WifiProfiles"] += [PSCustomObject]@{
            RiskLevel = if ($withKeys -eq 0) { "Pass" } else { "Low" }
            Name      = "Saved Wi-Fi Profiles"
            Detail    = "$($profileNames.Count) profile(s); $withKeys store a key that any local administrator can read with netsh (no credentials were copied into this report)"
        }

    } catch {
        Write-AuditError -Context "Wi-Fi Profiles" -ErrorMessage $_.Exception.Message
        $AuditResults["WifiProfiles"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Saved Wi-Fi Profiles"
            Detail    = "Unable to query Wi-Fi profiles: $_"
        }
    }

    Write-ProgressOutput "Wi-Fi profiles audit complete." -Verbose:$false
}

function Audit-CredentialManager {
    param($AuditResults)

    Write-ProgressOutput "Auditing Credential Manager..." -Verbose:$false

    try {
        # List stored credentials (requires elevated privileges for some entries)
        $credOutput = cmdkey /list 2>$null
        
        if ($null -ne $credOutput) {
            $AuditResults["CredentialManager"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Credential Manager"
                Detail    = "Credential listing available"
            }

            # Parse and flag entries
            $targetEntries = @()
            foreach ($line in $credOutput) {
                if ($line -match 'Target:\s+(.+)') {
                    $targetEntries += $matches[1].Trim()
                }
            }

            if ($targetEntries.Count -gt 0) {
                $AuditResults["CredentialManager"] += [PSCustomObject]@{
                    RiskLevel = "Medium"
                    Name      = "Stored Credentials Count"
                    Detail    = "$($targetEntries.Count) credential(s) stored"
                }

                # Flag potentially risky entries
                $riskyPatterns = @(
                    @{Pattern='(?i)(domain|forest|dc|ad)\.'; Risk="High"},
                    @{Pattern='(?i)(sql|mysql|postgres|mssql)\.'; Risk="High"},
                    @{Pattern='(?i)(sharepoint|exchange|smtp|imap|pop3)\.'; Risk="Medium"},
                    @{Pattern='(?i)(ftp|sftp|scp)\.'; Risk="Medium"},
                    @{Pattern='(?i)(rdp|remote|desktop)\.'; Risk="Medium"},
                    @{Pattern='(?i)(admin|administrator|root)\.'; Risk="High"},
                    @{Pattern='(?i)(vault|key|token|cert)\.'; Risk="Medium"}
                )

                foreach ($target in $targetEntries) {
                    foreach ($pattern in $riskyPatterns) {
                        if ($target -match $pattern.Pattern) {
                            $AuditResults["CredentialManager"] += [PSCustomObject]@{
                                RiskLevel = $pattern.Risk
                                Name      = "Risky Credential Target"
                                Detail    = "Target: $target"
                            }
                            break
                        }
                    }
                }

                # List all targets
                foreach ($target in $targetEntries) {
                    $AuditResults["CredentialManager"] += [PSCustomObject]@{
                        RiskLevel = "Info"
                        Name      = "Credential Target"
                        Detail    = "Target: $target"
                    }
                }

            } else {
                $AuditResults["CredentialManager"] += [PSCustomObject]@{
                    RiskLevel = "Pass"
                    Name      = "Stored Credentials"
                    Detail    = "No stored credentials found"
                }
            }

        } else {
            $AuditResults["CredentialManager"] += [PSCustomObject]@{
                RiskLevel = "Medium"
                Name      = "Credential Manager"
                Detail    = "Unable to query Credential Manager"
            }
        }

    } catch {
        Write-AuditError -Context "Credential Manager" -ErrorMessage $_.Exception.Message
        $AuditResults["CredentialManager"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "Credential Manager"
            Detail    = "Unable to query Credential Manager: $_"
        }
    }

    Write-ProgressOutput "Credential Manager audit complete." -Verbose:$false
}

function Audit-SystemInfo {
    param($AuditResults)

    Write-ProgressOutput "Auditing system information..." -Verbose:$false

    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($null -ne $osInfo) {
            $AuditResults["SystemInfo"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "OS Name"
                Detail    = "$($osInfo.Caption)"
            }
            $AuditResults["SystemInfo"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "OS Version"
                Detail    = "Version: $($osInfo.Version) | Build: $($osInfo.BuildNumber)"
            }
            $AuditResults["SystemInfo"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "OS Architecture"
                Detail    = "$($osInfo.OSArchitecture)"
            }
            $AuditResults["SystemInfo"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "OS Install Date"
                Detail    = "$($osInfo.InstallDate.ToString('yyyy-MM-dd'))"
            }
            $AuditResults["SystemInfo"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Last Boot Up Time"
                Detail    = "$($osInfo.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))"
            }
            $AuditResults["SystemInfo"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "System Uptime"
                Detail    = "$((Get-Date) - $osInfo.LastBootUpTime)"
            }
        }

        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($null -ne $computerSystem) {
            $AuditResults["SystemInfo"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Computer Name"
                Detail    = "$($computerSystem.Name)"
            }
            $AuditResults["SystemInfo"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Manufacturer"
                Detail    = "$($computerSystem.Manufacturer)"
            }
            $AuditResults["SystemInfo"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Model"
                Detail    = "$($computerSystem.Model)"
            }
            $AuditResults["SystemInfo"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Total RAM"
                Detail    = "$([math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)) GB"
            }
            $AuditResults["SystemInfo"] += [PSCustomObject]@{
                RiskLevel = "Info"
                Name      = "Processor"
                Detail    = "$($computerSystem.ProcessorCount) CPU(s)"
            }
        }

        $cpuInfo = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue
        if ($null -ne $cpuInfo) {
            foreach ($cpu in $cpuInfo) {
                $AuditResults["SystemInfo"] += [PSCustomObject]@{
                    RiskLevel = "Info"
                    Name      = "CPU Details"
                    Detail    = "$($cpu.Name) | Max Clock Speed: $($cpu.MaxClockSpeed) MHz"
                }
            }
        }

        # Disk space
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
        if ($null -ne $disks) {
            foreach ($disk in $disks) {
                $sizeGB = [math]::Round($disk.Size / 1GB, 2)
                $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
                $usedPct = [math]::Round((($sizeGB - $freeGB) / $sizeGB) * 100, 1)
                
                $AuditResults["SystemInfo"] += [PSCustomObject]@{
                    RiskLevel = if ($usedPct -gt 90) { "High" } elseif ($usedPct -gt 80) { "Medium" } else { "Pass" }
                    Name      = "Disk: $($disk.DeviceID)"
                    Detail    = "Size: ${sizeGB}GB | Free: ${freeGB}GB | Used: ${usedPct}%"
                }
            }
        }

        $AuditResults["SystemInfo"] += [PSCustomObject]@{
            RiskLevel = "Info"
            Name      = "PowerShell Version"
            Detail    = "$($PSVersionTable.PSVersion.ToString())"
        }

        $AuditResults["SystemInfo"] += [PSCustomObject]@{
            RiskLevel = "Info"
            Name      = "PowerShell Edition"
            Detail    = "$($PSVersionTable.PSEdition)"
        }

    } catch {
        Write-AuditError -Context "System Information" -ErrorMessage $_.Exception.Message
        $AuditResults["SystemInfo"] += [PSCustomObject]@{
            RiskLevel = "Medium"
            Name      = "System Information"
            Detail    = "Unable to query system information: $_"
        }
    }

    Write-ProgressOutput "System information audit complete." -Verbose:$false
}

# --- MAIN EXECUTION ---

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                           ║" -ForegroundColor Cyan
Write-Host "║         🛡️  Windows Security Audit Tool v1.0            ║" -ForegroundColor White
Write-Host "║                                                           ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$startTime = Get-Date

$sysName = $env:COMPUTERNAME

if (-not $IsElevated) {
    Write-Host "  ⚠️ Running unelevated. Checks that need administrator rights (Defender threat history, BitLocker," -ForegroundColor Yellow
    Write-Host "     TPM/Secure Boot, the Security event log, share ACLs and other users' accounts) report 'unavailable'." -ForegroundColor Yellow
    Write-Host ""
}

Write-ProgressOutput "System: $sysName ($(Get-Date))" -Verbose:$false
Write-Host ""

# Run all audit functions sequentially (order matters for dependencies). Each entry names the
# $AuditResults key it populates so that an unexpected failure is still visible in the report.
$auditFunctions = @(
    @{ Name="Installed Programs";   Section="InstalledPrograms";   Script={ Audit-InstalledPrograms $AuditResults } },
    @{ Name="Windows Update";       Section="WindowsUpdate";       Script={ Audit-WindowsUpdate $AuditResults } },
    @{ Name="Networking";           Section="Networking";          Script={ Audit-Networking $AuditResults } },
    @{ Name="Hosts File";           Section="HostsFile";           Script={ Audit-HostsFile $AuditResults } },
    @{ Name="Windows Defender";     Section="WindowsDefender";     Script={ Audit-WindowsDefender $AuditResults } },
    @{ Name="Third-Party AV/EDR";   Section="ThirdPartyAV";        Script={ Audit-ThirdPartyAV $AuditResults } },
    @{ Name="Firewall";             Section="WindowsFirewall";     Script={ Audit-Firewall $AuditResults } },
    @{ Name="Network Shares";       Section="NetworkShares";       Script={ Audit-Shares $AuditResults } },
    @{ Name="Task Scheduler";       Section="TaskScheduler";       Script={ Audit-TaskScheduler $AuditResults } },
    @{ Name="Registry Security";    Section="RegistrySecurity";    Script={ Audit-RegistrySecurity $AuditResults } },
    @{ Name="User Accounts";        Section="UserAccounts";        Script={ Audit-UserAccounts $AuditResults } },
    @{ Name="Audit Policy";         Section="AuditPolicy";         Script={ Audit-AuditPolicy $AuditResults } },
    @{ Name="Local Security Policy";Section="LocalSecurityPolicy"; Script={ Audit-LocalSecurityPolicy $AuditResults } },
    @{ Name="Services";             Section="Services";            Script={ Audit-Services $AuditResults } },
    @{ Name="Startup Programs";     Section="StartupPrograms";     Script={ Audit-StartupPrograms $AuditResults } },
    @{ Name="BitLocker";            Section="BitLocker";           Script={ Audit-BitLocker $AuditResults } },
    @{ Name="PowerShell Config";    Section="PowerShellConfig";    Script={ Audit-PowerShellConfig $AuditResults } },
    @{ Name="TPM / Secure Boot";    Section="TPM_SecureBoot";      Script={ Audit-TPM_SecureBoot $AuditResults } },
    @{ Name="Event Log Config";     Section="EventLogConfig";      Script={ Audit-EventLogConfig $AuditResults } },
    @{ Name="WinRM";                Section="WinRM";               Script={ Audit-WinRM $AuditResults } },
    @{ Name="Credential Guard";     Section="CredentialGuard";     Script={ Audit-CredentialGuard $AuditResults } },
    @{ Name="File System ACLs";     Section="FileSystemACLs";      Script={ Audit-FileSystemACLs $AuditResults } },
    @{ Name="DNS Client";           Section="DNSClient";           Script={ Audit-DNSClient $AuditResults } },
    @{ Name="Windows Time";         Section="WindowsTime";         Script={ Audit-WindowsTime $AuditResults } },
    @{ Name="Print Spooler";        Section="PrintSpooler";        Script={ Audit-PrintSpooler $AuditResults } },
    @{ Name="Group Policy";         Section="GroupPolicy";         Script={ Audit-GroupPolicy $AuditResults } },
    @{ Name="Registry Options";     Section="RegistryOptions";     Script={ Audit-RegistryOptions $AuditResults } },
    @{ Name="Wi-Fi Profiles";       Section="WifiProfiles";        Script={ Audit-WifiProfiles $AuditResults } },
    @{ Name="Credential Manager";   Section="CredentialManager";   Script={ Audit-CredentialManager $AuditResults } },
    @{ Name="System Information";   Section="SystemInfo";          Script={ Audit-SystemInfo $AuditResults } }
)

$scriptErrorCountAtStart = $Error.Count

for ($i = 0; $i -lt $auditFunctions.Count; $i++) {
    $func = $auditFunctions[$i]
    Write-Progress -Activity "Windows Security Audit" -Status "Auditing: $($func.Name)" -PercentComplete (($i / $auditFunctions.Count) * 100)

    try {
        & $func.Script
    } catch {
        # A terminating error in one section must not skip the remaining sections.
        Write-Warning "  $($func.Name) audit stopped unexpectedly: $($_.Exception.Message)"
        if ($AuditResults.ContainsKey($func.Section)) {
            $AuditResults[$func.Section] += [PSCustomObject]@{
                RiskLevel = "ERROR"
                Name      = "Section Did Not Complete"
                Detail    = "$($func.Name): $($_.Exception.Message)"
            }
        }
    }
}
Write-Progress -Activity "Windows Security Audit" -Status "Complete" -PercentComplete 100 -Completed

$endTime       = Get-Date
$totalDuration = [Math]::Round(($endTime - $startTime).TotalSeconds, 2)

# --- Calculate Summary Statistics ---
$riskCounts = @{ Critical=0; High=0; Medium=0; Low=0; Pass=0; Info=0 }

foreach ($section in $AuditResults.Values) {
    foreach ($item in @($section)) {
        if ([string]::IsNullOrEmpty($item.RiskLevel)) { continue }

        if (-not $riskCounts.ContainsKey($item.RiskLevel)) {
            $riskCounts[$item.RiskLevel] = 1
        } else {
            $riskCounts[$item.RiskLevel]++
        }
    }
}

# --- Generate HTML Report ---
# Use the audit order rather than hashtable key order so the report is reproducible.
$ExportPath = [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($ExportPath))
$htmlReport = Generate-HTMLReport -Title "Windows Security Audit Report" -Sections $AuditSections -Results $AuditResults -RiskCounts:$riskCounts

# --- Save HTML Report (per html-template §10: UTF-8 with BOM for PS 5.1 compatibility) ---
try {
    $htmlReport | Out-File -LiteralPath $ExportPath -Encoding UTF8 -ErrorAction Stop
} catch {
    Write-Warning "Could not write the report to $ExportPath : $_"
}

# Optionally open in the default browser; non-fatal on headless systems (per html-template §10)
if (-not $NoLaunch -and (Test-Path -LiteralPath $ExportPath)) {
    try { Invoke-Item -LiteralPath $ExportPath } catch { Write-Verbose "Report could not be opened automatically: $_" }
}

# --- Write Summary Output ---
Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                 AUDIT SUMMARY                             ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Color-coded summary section
$levelColors = @{ Critical = 'Red'; High = 'Red'; Medium = 'Yellow'; Low = 'DarkCyan' }

foreach ($level in @("Critical", "High", "Medium", "Low")) {
    if ([int]$riskCounts[$level] -gt 0) {
        Write-Host ("  [{0,-8}] : {1}" -f $level, $riskCounts[$level]) -ForegroundColor $levelColors[$level]
    }
}

$passInfo = [int]$riskCounts.Pass + [int]$riskCounts.Info
if ($passInfo -gt 0) {
    Write-Host ("  [{0,-8}] : {1}" -f 'Pass/Info', $passInfo) -ForegroundColor Green
}

Write-Host ""
Write-Host "  Report saved to: $($ExportPath)" -ForegroundColor Green
Write-Host "  Total audit time: $($totalDuration) seconds" -ForegroundColor Cyan

$runtimeIssues = $Error.Count - $scriptErrorCountAtStart
if ($runtimeIssues -gt 0) {
    Write-Host "  Non-terminating errors recorded during the run: $runtimeIssues (see warnings above)" -ForegroundColor Yellow
}

Write-Host ""

return