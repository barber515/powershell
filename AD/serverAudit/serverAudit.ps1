#Requires -Version 5.0

<#
.SYNOPSIS
    Server Audit Script
.DESCRIPTION
    Gathers comprehensive server inventory including OS, RAM, disk usage,
    Windows license status, currently logged-in users, and local administrators
    from all domain-joined Windows servers.
.EXAMPLE
    PS> .\serverAudit.ps1 -OutputPath "P:\powershell\AD\serverAudit\ServerAudit.html"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string] $OutputPath = ".\ServerAudit_$((Get-Date).ToString('yyyyMMdd_HHmmss')).html",
    [switch] $NoLaunch
)

$ErrorActionPreference = "Stop"

# Validate output directory exists or can be created
$outputDir = Split-Path -Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path -Path $outputDir)) {
    try {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    } catch {
        throw "Cannot create output directory '$outputDir': $_"
    }
}

function ConvertTo-HtmlEncoded {
    [CmdletBinding()]
    param([string]$Text)
    [System.Net.WebUtility]::HtmlEncode($Text)
}

function ConvertTo-HtmlTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Rows
    )

    if (-not $Rows -or @($Rows).Count -eq 0) {
        return "<p class=\"empty\">No results &mdash; nothing found.</p>"
    }
    $cols = ($Rows | Select-Object -First 1).PSObject.Properties.Name
    $sb   = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<table><thead><tr>")
    foreach ($c in $cols) { [void]$sb.Append("<th>$(ConvertTo-HtmlEncoded $c)</th>") }
    [void]$sb.Append("</tr></thead><tbody>")
    foreach ($r in $Rows) {
        [void]$sb.Append("<tr>")
        foreach ($c in $cols) {
            $val = if ($null -eq $r.$c) { "" } else { [string]$r.$c }
            [void]$sb.Append("<td>$(ConvertTo-HtmlEncoded $val)</td>")
        }
        [void]$sb.Append("</tr>")
    }
    [void]$sb.Append("</tbody></table>")
    return $sb.ToString()
}

$report = [System.Collections.Generic.List[object]]::new()
$sevColour = @{ Critical="#c0392b"; High="#e67e22"; Medium="#f1c40f"; Info="#3498db" }

function Add-Section {
    [CmdletBinding()]
    param(
        [string]$Title,
        [string]$Description,
        [ValidateSet("Critical","High","Medium","Info")][string]$Severity="Info",
        [scriptblock]$Query
    )

    Write-Verbose ("  - {0}" -f $Title)

    $obj = [ordered]@{ Title=$Title; Description=$Description; Severity=$Severity
                       Rows=@(); Count=0; Error=$null }
    try {
        $result = & $Query
        $obj.Rows = @($result)
        $obj.Count = @($result).Count
    } catch { $obj.Error = $_.Exception.Message }
    $report.Add([pscustomobject]$obj)
}

Add-Section -Title "Server Inventory" -Severity "Info" `
    -Description "Basic system information including OS version, installed RAM, and C-drive capacity." `
    -Query {
        $servers = Get-ADComputer -Filter { OperatingSystem -like "*Windows Server*" } `
            -Properties OperatingSystem, DnsHostname | Select-Object -ExpandProperty DnsHostname

        foreach ($server in $servers) {
            try {
                $os = Get-CimInstance -ComputerName $server -ClassName Win32_OperatingSystem -ErrorAction Stop
                $ram = Get-CimInstance -ComputerName $server -ClassName Win32_ComputerSystem -ErrorAction Stop | Select-Object -ExpandProperty TotalPhysicalMemory
                $cDrive = Get-CimInstance -ComputerName $server -Query "SELECT * FROM Win32_LogicalDisk WHERE DeviceID='C:'" -ErrorAction Stop

                [pscustomobject]@{
                    Servername   = ConvertTo-HtmlEncoded $server
                    OS           = ConvertTo-HtmlEncoded $os.Caption
                    RAM_GB       = [math]::Round($ram / 1GB, 2)
                    C_Total_GB   = if ($cDrive) { [math]::Round($cDrive.Size / 1GB, 2) } else { $null }
                    C_Free_GB    = if ($cDrive) { [math]::Round($cDrive.FreeSpace / 1GB, 2) } else { $null }
                }
            } catch {
                Write-Warning "Failed to query $server: $($_.Exception.Message)"
            }
        }
    }

Add-Section -Title "Currently Logged In User(s)" -Severity "Info" `
    -Description "Lists currently logged-in users on each server using Win32_LogonSession." `
    -Query {
        $servers = Get-ADComputer -Filter { OperatingSystem -like "*Windows Server*" } `
            -Properties OperatingSystem, DnsHostname | Select-Object -ExpandProperty DnsHostname

        foreach ($server in $servers) {
            try {
                $logons = Get-CimInstance -ComputerName $server -ClassName Win32_LogonSession `
                    -Property LogonId, StartTime -ErrorAction Stop |
                    Where-Object { $_.LogonType -eq 2 } | ForEach-Object {
                        $logonId = $_.LogonId
                        $user = Get-CimInstance -ComputerName $server -Query "ASSOCIATORS OF {Win32_LogonSession.LogonId=$logonId} WHERE ResultClass=Win32_UserAccount" -ErrorAction SilentlyContinue
                        if ($user) {
                            [pscustomobject]@{
                                Servername = ConvertTo-HtmlEncoded $server
                                Username   = ConvertTo-HtmlEncoded "$($user.Domain)\$($user.Name)"
                                LogonTime  = $_.StartTime
                            }
                        }
                    }

                if (-not $logons) {
                    [pscustomobject]@{
                        Servername = ConvertTo-HtmlEncoded $server
                        Username   = "No interactive user"
                        LogonTime  = $null
                    }
                } else {
                    $logons
                }
            } catch {
                Write-Warning "Failed to query logged-in users for $server: $($_.Exception.Message)"
            }
        }
    }

Add-Section -Title "Members of Local Administrators" -Severity "High" `
    -Description "Lists all members of the local Administrators group on each server." `
    -Query {
        $servers = Get-ADComputer -Filter { OperatingSystem -like "*Windows Server*" } `
            -Properties OperatingSystem, DnsHostname | Select-Object -ExpandProperty DnsHostname

        foreach ($server in $servers) {
            try {
                $adminGroup = Get-CimInstance -ComputerName $server -ClassName Win32_Group `
                    -Filter "Name='Administrators'" -ErrorAction Stop

                if (-not $adminGroup) {
                    Write-Warning "Failed to locate Administrators group on $server"
                    continue
                }

                $admins = Get-CimInstance -ComputerName $server -Query "
                    SELECT * FROM Win32_GroupUser WHERE GroupComponent=`"$(($adminGroup).Path)`"" `
                    -ErrorAction Stop | ForEach-Object {
                        $memberDomain = $_.PartComponent.Domain
                        $memberName   = $_.PartComponent.Name

                        [pscustomobject]@{
                            Servername    = ConvertTo-HtmlEncoded $server
                            MemberType    = if ($memberName -match '^S-1-5-21') { "Unknown SID" } else { "User/Group" }
                            MemberName    = ConvertTo-HtmlEncoded "$($memberDomain)\$($memberName)"
                        }
                    }

                if (-not $admins) {
                    [pscustomobject]@{
                        Servername = ConvertTo-HtmlEncoded $server
                        MemberType = "N/A"
                        MemberName = "No members found"
                    }
                } else {
                    $admins
                }
            } catch {
                Write-Warning "Failed to query local administrators for $server: $($_.Exception.Message)"
            }
        }
    }

Add-Section -Title "Windows License Status" -Severity "Info" `
    -Description "Activation status for Windows Server installations." `
    -Query {
        $servers = Get-ADComputer -Filter { OperatingSystem -like "*Windows Server*" } `
            -Properties OperatingSystem, DnsHostname | Select-Object -ExpandProperty DnsHostname

        foreach ($server in $servers) {
            try {
                $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $server -ErrorAction Stop
                $license = Get-WmiObject -Class SoftwareLicensingProduct -ComputerName $server -ErrorAction Stop |
                    Where-Object { $_.PartialProductKey } | Select-Object -First 1

                $statusText = switch ($license.LicenseStatus) {
                    0 { "Unlicensed" }
                    1 { "Licensed" }
                    2 { "Out-Of-Box Grace Period" }
                    3 { "Out-Of-Tolerance Grace Period" }
                    4 { "Non-Genuine Grace Period" }
                    5 { "Notification" }
                    6 { "Extended Grace" }
                    default { "Unknown" }
                }

                [pscustomobject]@{
                    Servername       = ConvertTo-HtmlEncoded $server
                    OS_Version       = ConvertTo-HtmlEncoded $os.Version
                    Activation_Status = ConvertTo-HtmlEncoded $statusText
                }
            } catch {
                Write-Warning "Failed to query license status for $server: $($_.Exception.Message)"
            }
        }
    }

$summaryRows = $report | ForEach-Object {
    [pscustomobject]@{ Severity=$_.Severity; Check=$_.Title; Findings=if($_.Error){"ERROR"}else{$_.Count} }
}
$summaryTable = ConvertTo-HtmlTable -Rows $summaryRows

$body = [System.Text.StringBuilder]::new()
foreach ($sec in $report) {
    $colour = $sevColour[$sec.Severity]
    [void]$body.Append("<section><h2 style='border-left:6px solid $colour'>")
    [void]$body.Append("<span class='badge' style='background:$colour'>$($sec.Severity)</span> ")
    [void]$body.Append((ConvertTo-HtmlEncoded $sec.Title))
    $label = if ($sec.Error) { "error" } else { "$($sec.Count) result(s)" }
    [void]$body.Append("<span class='count'>$label</span></h2>")
    [void]$body.Append("<p class='desc'>$(ConvertTo-HtmlEncoded $sec.Description)</p>")
    if ($sec.Error) {
        [void]$body.Append("<p class='error'>Query error: $(ConvertTo-HtmlEncoded $sec.Error)</p>")
    } else {
        [void]$body.Append((ConvertTo-HtmlTable -Rows $sec.Rows))
    }
    [void]$body.Append("</section>")
}

$hTitle = ConvertTo-HtmlEncoded "Server Audit Report"
$hUser = ConvertTo-HtmlEncoded "$env:USERDOMAIN\$env:USERNAME"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>$hTitle</title>
<style>
    :root { font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif; }
    body { margin:0; background:#f4f6f8; color:#222; }
    header { background:#1f2d3d; color:#fff; padding:24px 40px; }
    header h1 { margin:0 0 4px; font-size:22px; }
    header .meta { font-size:13px; color:#b8c4d0; }
    header .classification { display:inline-block;margin-top:12px;background:#c0392b;color:#fff;font-size:11px;font-weight:600;padding:3px 10px;border-radius:3px;text-transform:uppercase;letter-spacing:.05em; }
    main { max-width:1200px; margin:24px auto; padding:0 24px; }
    section { background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:20px;padding:16px 20px; }
    h2 { font-size:16px;padding-left:12px;display:flex;align-items:center;gap:10px; }
    .badge { color:#fff;font-size:11px;font-weight:600;padding:2px 8px;border-radius:10px;text-transform:uppercase;letter-spacing:.04em; }
    .count { margin-left:auto;font-size:12px;color:#888;font-weight:400; }
    .desc { font-size:13px;color:#555;margin:4px 0 12px; }
    table { border-collapse:collapse;width:100%;font-size:13px; }
    th,td { text-align:left;padding:6px 10px;border-bottom:1px solid #eaeef1; }
    th { background:#f0f3f6;font-weight:600; }
    tr:hover td { background:#fafbfc; }
    .empty { color:#27ae60;font-size:13px;font-style:italic; }
    .error { color:#c0392b;font-size:13px; }
    .summary th,.summary td { border-bottom:1px solid #ddd; }
    footer { max-width:1200px;margin:0 auto 40px;padding:0 24px;font-size:12px;color:#999; }
</style>
</head>
<body>
<header>
    <h1>$hTitle</h1>
    <div class="meta">
        Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp;
        Run by: $hUser
    </div>
    <div class="classification">Restricted</div>
</header>
<main>
    <section class="summary">
        <h2 style="border-left:6px solid #1f2d3d">Summary</h2>
        <p class="desc">Overview of all checks.</p>
        $summaryTable
    </section>
    $($body.ToString())
</main>
<footer>
    Read-only audit. No directory objects were modified.
</footer>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "Report written to: $OutputPath" -ForegroundColor Green

if (-not $NoLaunch) {
    try { Invoke-Item $OutputPath } catch { }
}
