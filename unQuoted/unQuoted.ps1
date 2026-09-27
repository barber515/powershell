#Requires -Version 5.1

<#
.SYNOPSIS
    Audits and remediates unquoted Windows service binary paths.

.DESCRIPTION
    An unquoted service path (a binary path that is not wrapped in double
    quotes yet contains a space) can be exploited for privilege escalation
    (CWE-426). This script finds all services on the local machine whose
    PathName is unquoted and truly exploitable.

    Two modes:
      -Audit   Generates a self-contained, styled HTML report of all unquoted service paths.
               The report always writes even when no vulnerabilities are found. It includes
               three sections: (1) truly vulnerable services, (2) scanned-but-not-vulnerable
               services with reasons why they were not flagged, and (3) scan summary.
               (read-only; nothing is modified).
      -FixAll  Interactively walks every truly vulnerable unquoted service path. For each
               service the script prints the details to the terminal and
               prompts Yes/No. "Yes" wraps the path in double quotes via
               Set-Service; "No" skips to the next service.

    Both modes require elevation (Run as Administrator).

    VULNERABILITY CRITERIA:
    For an unquoted service path to be truly exploitable, BOTH conditions must be met:
      1. The path contains a space in any folder name (not after .exe) and is unquoted
      2. A normal, unprivileged user has write access to one of the parent directories

.EXAMPLE
    PS> .\unQuoted.ps1 -Audit
    Queries the local machine and writes an HTML report of truly vulnerable paths.

.EXAMPLE
    PS> .\unQuoted.ps1 -Audit -OutputPath D:\Reports\unquoted.html -NoLaunch

.EXAMPLE
    PS> .\unQuoted.ps1 -FixAll
    Prompts Yes/No per truly vulnerable service and remediates the confirmed ones.
#>

[CmdletBinding()]
param(
    [Parameter(ParameterSetName = 'Audit', Mandatory = $true)]
    [switch]$Audit,

    [Parameter(ParameterSetName = 'FixAll', Mandatory = $true)]
    [switch]$FixAll,

    [Parameter(ParameterSetName = 'Audit')]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = ".\UnquotedServices_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(ParameterSetName = 'Audit')]
    [switch]$NoLaunch
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# =====================================================================
# Prerequisite: elevation
# =====================================================================
function Test-IsAdministrator {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    Write-Error "This script must be run as Administrator. Re-launch PowerShell with 'Run as administrator' and try again."
    exit 1
}

# =====================================================================
# Service discovery - Get all services
# =====================================================================

function Get-AllServices {
    [CmdletBinding()]
    param()
    Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
        Sort-Object Name
}

# =====================================================================
# Vulnerability assessment functions
# =====================================================================

<#
.SYNOPSIS
    Determines if a service path is unquoted and contains spaces in folder names.
.DESCRIPTION
    Returns $true if the path is not quoted AND contains at least one space
    in a directory component (not in the executable name or after .exe).
#>
function Test-ContainsSpaceInFolder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathName
    )

    if (-not $PathName) { return $false }

    $pathToCheck = $PathName.Trim()

    if ($pathToCheck.StartsWith('"')) {
        return $false
    }

    if (-not ($pathToCheck -match ' ')) {
        return $false
    }

    $parts = $pathToCheck -split '\\'
    $exeFound = $false

    foreach ($part in $parts) {
        if ([string]::IsNullOrWhiteSpace($part)) { continue }

        $lowerPart = $part.ToLower()

        if ($lowerPart.EndsWith('.exe')) {
            $exeFound = $true
            continue
        }

        if (-not $exeFound -and $part -match ' ') {
            return $true
        }
    }

    return $false
}

<#
.SYNOPSIS
    Determines if a normal user has write access to any parent directory in the path.
.DESCRIPTION
    Returns $true if the BUILTIN\Users group or similar unprivileged group has
    Write, Modify, or FullControl permissions on any parent directory.
#>
function Test-ParentDirectoryWritable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathName
    )

    try {
        if (-not $PathName) { return $false }

        $pathToCheck = $PathName.Trim()
        $parts = $pathToCheck -split '\\'

        for ($i = 0; $i -lt ($parts.Count - 1); $i++) {
            if ([string]::IsNullOrWhiteSpace($parts[$i])) { continue }

            $currentPath = $parts[0..$i] -join '\'
            if (-not [string]::IsNullOrEmpty([IO.Path]::GetExtension($currentPath))) {
                continue
            }

            if (-not (Test-Path $currentPath)) { continue }

            try {
                $acl = Get-Acl -LiteralPath $currentPath

                foreach ($access in $acl.Access) {
                    $identity = $access.IdentityReference.Value.ToUpper()

                    $isUnprivilegedGroup = (
                        $identity -eq 'BUILTIN\USERS' -or
                        $identity -eq 'NT AUTHORITY\Authenticated USERS' -or
                        $identity -eq 'EVERYONE'
                    )

                    if (-not $isUnprivilegedGroup) { continue }

                    $fileSystemRights = $access.FileSystemRights.ToString().ToUpper()
                    $hasWritePermission = (
                        $fileSystemRights -contains 'WRITE' -or
                        $fileSystemRights -contains 'MODIFY' -or
                        $fileSystemRights -contains 'FULLCONTROL'
                    )

                    if ($hasWritePermission) {
                        return $true
                    }
                }
            }
            catch [SecurityException], [UnauthorizedAccessException] {
                continue
            }
            catch { }
        }

        return $false
    }
    catch {
        Write-Verbose "Error checking path: $_"
        return $null
    }
}

<#
.SYNOPSIS
    Returns services with truly vulnerable unquoted paths.
.DESCRIPTION
    A truly vulnerable service has:
      1. An unquoted PathName that contains a space in a folder name (not after .exe)
      2. Write access to a parent directory by an unprivileged group
#>
function Get-TrulyVulnerableService {
    [CmdletBinding()]
    param()

    $allServices = Get-AllServices

    foreach ($service in $allServices) {
        if (-not $service.PathName) { continue }

        $isUnquotedWithSpace = Test-ContainsSpaceInFolder -PathName $service.PathName
        if (-not $isUnquotedWithSpace) { continue }

        $isParentWritable = Test-ParentDirectoryWritable -PathName $service.PathName

        if ($isParentWritable -eq $true) {
            [pscustomobject]@{
                ServiceName  = $service.Name
                DisplayName  = $service.DisplayName
                State        = if ($service.State -eq 'Running') { 'Running' } else { 'Stopped' }
                PathName     = $service.PathName
                QuotedPath   = '"' + $service.PathName + '"'
                Vulnerable   = $true
            }
        }
    }
}

<#
.SYNOPSIS
    Returns ALL unquoted-with-space services with their vulnerability assessment.
.DESCRIPTION
    For each service whose PathName is unquoted and contains a space in a folder name,
    this function returns an object indicating whether it is truly vulnerable or not,
    plus the reason when not vulnerable. This enables auditable reporting of every
    scanned service, not only the flagged ones.
.PARAMETER IncludeNotVulnerable
    When $true (default), also return services that are unquoted-with-space but NOT
    vulnerable (e.g., parent directory is not writable by an unprivileged group).
#>
function Get-UnquotedServiceAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [switch]$IncludeNotVulnerable
    )

    $allServices = Get-AllServices

    foreach ($service in $allServices) {
        if (-not $service.PathName) { continue }

        $isUnquotedWithSpace = Test-ContainsSpaceInFolder -PathName $service.PathName
        if (-not $isUnquotedWithSpace) { continue }

        # Service has unquoted path with space in folder name — assess parent writability
        $isParentWritable = Test-ParentDirectoryWritable -PathName $service.PathName

        if ($isParentWritable -eq $true) {
            [pscustomobject]@{
                ServiceName          = $service.Name
                DisplayName          = $service.DisplayName
                State                = if ($service.State -eq 'Running') { 'Running' } else { 'Stopped' }
                PathName             = $service.PathName
                QuotedPath           = '"' + $service.PathName + '"'
                Vulnerable           = $true
                ReasonNotVulnerable  = $null
            }
        }
        elseif ($IncludeNotVulnerable) {
            [pscustomobject]@{
                ServiceName          = $service.Name
                DisplayName          = $service.DisplayName
                State                = if ($service.State -eq 'Running') { 'Running' } else { 'Stopped' }
                PathName             = $service.PathName
                QuotedPath           = '"' + $service.PathName + '"'
                Vulnerable           = $false
                ReasonNotVulnerable  = switch ($isParentWritable) {
                    $null   { 'ACL check failed — manual review recommended' }
                    default { 'No unprivileged group has write access to parent directory' }
                }
            }
        }
    }
}

# =====================================================================
# HTML report helpers (per HTML report build standards)
# =====================================================================
function ConvertTo-HtmlEncoded {
    [CmdletBinding()]
    param([string]$Text)
    [System.Net.WebUtility]::HtmlEncode($Text)
}

function ConvertTo-HtmlTable {
    [CmdletBinding()]
    param(
        [object[]]$Rows
    )

    if (-not $Rows -or @($Rows).Count -eq 0) {
        return '<p class="empty">No results - nothing flagged for this check.</p>'
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

# =====================================================================
# Audit mode
# =====================================================================
function Invoke-Audit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [switch]$NoLaunch
    )

    Write-Host "[*] Querying local Windows service paths for vulnerable unquoted entries..." -ForegroundColor Cyan

    $totalServices = (Get-AllServices).Count
    $allAssessments  = @(Get-UnquotedServiceAssessment -IncludeNotVulnerable)
    $trulyVulnerable = @($allAssessments | Where-Object Vulnerable -eq $true)
    $notVulnerable   = @($allAssessments | Where-Object Vulnerable -eq $false)
    Write-Host ("[*] Scanned {0} services; {1} truly vulnerable, {2} unquoted-with-space but not vulnerable." -f $totalServices, $trulyVulnerable.Count, $notVulnerable.Count) -ForegroundColor Cyan

    $report    = [System.Collections.Generic.List[object]]::new()
    $sevColour = @{ Critical = '#c0392b'; High = '#e67e22'; Medium = '#f1c40f'; Info = '#3498db' }

    function Add-Section {
        param(
            [Parameter(Mandatory = $true)]
            [System.Collections.IList]$Report,
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

        $Report.Add([pscustomobject]$obj)
    }

    Add-Section -Report $report -Title 'Truly Vulnerable Unquoted Service Paths' -Severity 'High' `
        -Description 'Services whose binary path is unquoted, contains a space in a folder name (not after .exe), AND has write access to a parent directory by an unprivileged user group. An attacker can exploit this by placing a malicious executable in the writable parent directory (CWE-426). The QuotedPath column shows the remediated value.' `
        -Query { $trulyVulnerable }

    Add-Section -Report $report -Title 'Scan Summary' -Severity 'Info' `
        -Description 'Scope of this audit on the local machine.' `
        -Query {
            [pscustomobject]@{ Metric = 'Total services scanned';          Value = $totalServices }
            [pscustomobject]@{ Metric = 'Truly vulnerable paths';          Value = $trulyVulnerable.Count }
            [pscustomobject]@{ Metric = 'Unquoted-with-space, not vulnerable'; Value = $notVulnerable.Count }
            [pscustomobject]@{ Metric = 'Running and vulnerable';          Value = (@($trulyVulnerable | Where-Object State -eq 'Running')).Count }
        }

    Add-Section -Report $report -Title 'Scanned - Not Vulnerable' -Severity 'Info' `
        -Description 'Services whose binary path is unquoted and contains a space in a folder name, but NO parent directory was found writable by an unprivileged user group. Listed for audit completeness.' `
        -Query { $notVulnerable }

    # ---- Summary table ----
    $summaryRows = $report | ForEach-Object {
        New-Object psobject -Property @{
            Severity = $_.Severity
            Check    = $_.Title
            Findings = if ($_.Error) { 'ERROR' } else { $_.Count }
        }
    }
    $summaryTable = ConvertTo-HtmlTable -Rows $summaryRows

    # ---- Body ----
    $body = [System.Text.StringBuilder]::new()
    foreach ($sec in $report) {
        $colour = $sevColour[$sec.Severity]

        [void]$body.Append("<section><h2 style='border-left:6px solid $colour'>")
        [void]$body.Append("<span class='badge' style='background:$colour'>$($sec.Severity)</span> ")
        [void]$body.Append((ConvertTo-HtmlEncoded $sec.Title))
        $countLabel = if ($sec.Error) { 'error' } else { "$($sec.Count) result(s)" }
        [void]$body.Append("<span class='count'>$countLabel</span></h2>")
        [void]$body.Append("<p class='desc'>$(ConvertTo-HtmlEncoded $sec.Description)</p>")

        if ($sec.Error) {
            [void]$body.Append("<p class='error'>Query error: $(ConvertTo-HtmlEncoded $sec.Error)</p>")
        }
        else {
            [void]$body.Append((ConvertTo-HtmlTable -Rows $sec.Rows))
        }
        [void]$body.Append('</section>')
    }

    # ---- Header metadata ----
    $hTitle = ConvertTo-HtmlEncoded "Unquoted Service Paths Audit - $env:COMPUTERNAME"
    $hUser  = ConvertTo-HtmlEncoded "$env:USERDOMAIN\$env:USERNAME"

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
        background: #e67e22; color: #fff;
        font-size: 11px; font-weight: 600;
        padding: 3px 10px; border-radius: 3px;
        text-transform: uppercase; letter-spacing: .05em;
    }

    /* ---- Layout ---- */
    main { max-width: 1200px; margin: 24px auto; padding: 0 24px; }
    section {
        background: #fff; border-radius: 8px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
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
    th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #eaeef1; word-break: break-all; }
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
        Target: $env:COMPUTERNAME (local) &nbsp;|&nbsp;
        Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp;
        Run by: $hUser
    </div>
    <div class="classification">Restricted - contains host service enumeration</div>
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
    Read-only audit. No service configurations were modified.
    Paths flagged here are truly vulnerable: unquoted, contain spaces in folder names (not after .exe),
    and have writable parent directories by unprivileged users. Remediate by wrapping the entire PathName
    in double quotes (see QuotedPath column); review paths with complex arguments before changing them.
    Changes to a service's binary path take effect the next time the service is restarted.
</footer>

</body>
</html>
"@

    $resolvedPath = (Resolve-Path -LiteralPath (Split-Path -Parent $OutputPath) -ErrorAction SilentlyContinue).Path
    if ($resolvedPath) {
        $OutputPath = Join-Path $resolvedPath (Split-Path -Leaf $OutputPath)
    }

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Report written to: $OutputPath" -ForegroundColor Green

    if (-not $NoLaunch) {
        try { Invoke-Item $OutputPath } catch { }
    }
}

# =====================================================================
# FixAll mode
# =====================================================================
function Invoke-FixAll {
    [CmdletBinding()]
    param()

    Write-Host "[*] Querying local Windows service paths for truly vulnerable unquoted entries..." -ForegroundColor Cyan
    $trulyVulnerable = @(Get-TrulyVulnerableService)

    if ($trulyVulnerable.Count -eq 0) {
        Write-Host "[+] No truly vulnerable unquoted service paths found. Nothing to do." -ForegroundColor Green
        return
    }

    Write-Host ("[*] Found {0} truly vulnerable unquoted service path(s)." -f $trulyVulnerable.Count) -ForegroundColor Cyan
    Write-Host "Vulnerability requires: (1) space in folder name, (2) writable parent directory by unprivileged user." -ForegroundColor Yellow

    $fixed = 0
    $skipped = 0
    $failed = 0
    $index = 0

    foreach ($svc in $trulyVulnerable) {
        $index++
        Write-Host ""
        Write-Host ("[{0}/{1}] Service: {2} ({3}) - State: {4}" -f $index, $trulyVulnerable.Count, $svc.ServiceName, $svc.DisplayName, $svc.State) -ForegroundColor White
        Write-Host ("      Path: {0}" -f $svc.PathName) -ForegroundColor Yellow
        Write-Host ("      New : {0}" -f $svc.QuotedPath) -ForegroundColor DarkGray

        $answer = $null
        do {
            $answer = (Read-Host "      Fix this service path? (Yes/No)").Trim()
            if ($answer -notin @('Yes', 'No', 'Y', 'N')) {
                Write-Host "      Please answer Yes or No." -ForegroundColor DarkYellow
            }
        } while ($answer -notin @('Yes', 'No', 'Y', 'N'))

        if ($answer -in @('Yes', 'Y')) {
            try {
                Set-Service -Name $svc.ServiceName -BinaryPathName $svc.QuotedPath -ErrorAction Stop

                # Verify the change was applied
                $verify = (Get-CimInstance -ClassName Win32_Service -Filter "Name = '$($svc.ServiceName.Replace("'", "''"))'").PathName
                if ($verify -eq $svc.QuotedPath) {
                    Write-Host "      [FIXED]    Quoted and verified." -ForegroundColor Green
                    $fixed++
                }
                else {
                    Write-Warning "      [VERIFIED] Set-Service succeeded but path read back as: $verify"
                    $fixed++
                }
            }
            catch {
                Write-Warning "      [FAILED]   Could not update service: $_"
                $failed++
            }
        }
        else {
            Write-Host "      [SKIPPED]" -ForegroundColor DarkCyan
            $skipped++
        }
    }

    Write-Host ""
    Write-Host "==================== FIX SUMMARY ====================" -ForegroundColor Cyan
    Write-Host ("  Fixed   : {0}" -f $fixed)   -ForegroundColor Green
    Write-Host ("  Skipped : {0}" -f $skipped) -ForegroundColor DarkCyan
    Write-Host ("  Failed  : {0}" -f $failed)  -ForegroundColor $(if ($failed) { 'Red' } else { 'DarkGray' })
    Write-Host "====================================================" -ForegroundColor Cyan
    Write-Host "Note: binary-path changes take effect the next time each service is restarted." -ForegroundColor DarkGray
}

# =====================================================================
# Dispatch
# =====================================================================

switch ($PSCmdlet.ParameterSetName) {
    'Audit' { Invoke-Audit -OutputPath $OutputPath -NoLaunch:$NoLaunch }
    'FixAll' { Invoke-FixAll }
}