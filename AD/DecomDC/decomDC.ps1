<#
=====================================================================
 DC-Decom-Discovery.ps1
 Read-only discovery for decommissioning on-prem domain controllers.

 Domain:   NTLife01.local
 Removing: DC1.ntlife01.local  (172.16.15.33)
           DC2.ntlife01.local  (172.16.15.34)
 Keeping:  ADC-01.ntlife01.local (10.10.128.10)
           ADC-02.ntlife01.local (10.10.144.10)

 This script ONLY READS. It transfers nothing, changes nothing.
 Run from a domain-joined host with RSAT (AD, DNS, DHCP, GPO modules)
 as an account with Domain Admin / DNS Admin read rights.

 Output: a timestamped folder of .txt/.csv reports, the HTML readiness
         report 99_decom_readiness_report.html, and a full transcript.
 Switches: -NoHtml skips the HTML report entirely; -NoLaunch stops the
           browser opening when the run finishes; -MaxPreLines caps raw
           tool output embedded per report section (0 embeds everything).
=====================================================================
#>

[CmdletBinding()]
param(
    # Suppress the HTML report entirely (fallback to CSV/TXT only behaviour).
    [switch]$NoHtml,
    # Do not open the report in the default browser when the run finishes.
    [switch]$NoLaunch,
    # Cap on lines of raw tool output embedded per section. 0 embeds everything.
    [int]$MaxPreLines = 400
)

#region ---- Parameters (edit if names/IPs ever change) ----
$OldDCs = @(
    [pscustomobject]@{ Name = 'DC1'    ; FQDN = 'DC1.ntlife01.local'    ; IP = '172.16.15.33' }
    [pscustomobject]@{ Name = 'DC2'    ; FQDN = 'DC2.ntlife01.local'    ; IP = '172.16.15.34' }
)
$NewDCs = @(
    [pscustomobject]@{ Name = 'ADC-01' ; FQDN = 'ADC-01.ntlife01.local' ; IP = '10.10.128.10' }
    [pscustomobject]@{ Name = 'ADC-02' ; FQDN = 'ADC-02.ntlife01.local' ; IP = '10.10.144.10' }
)
$OldIPs   = $OldDCs.IP
$OldNames = $OldDCs.Name + $OldDCs.FQDN
$Domain   = 'ntlife01.local'

# Accumulators for the HTML report. Declared here so they always exist, even when
# a whole block is skipped: an undefined variable and a genuinely empty result must
# not be distinguishable only by whether the section renders green.
$timeStatus         = @()   # per-DC w32tm status, with a '=== dc ===' header line
$dnsSrvRows         = @()   # forwarders and scavenging state per DNS server
$dhcpOptRows        = @()   # DHCP options read from every reachable server
$skippedDnsServers  = @()   # DCs skipped by Test-Connection in section 5
$dnsQueryFailures   = @()   # DNS queries that threw, with the server and message
$zoneFailures       = @()   # zones whose record scan failed in section 6
$dhcpServerFailures = @()   # per-server DHCP read failures in section 8
$NativeToolErrors   = @()   # stderr text from every native tool run, collected by Run-Tool
$gpoFilterError     = $null # set when the GroupPolicy block could not complete
$pkiError           = $null # set when the AD CS enrollment query could not run
$dhcpError          = $null # set when Get-DhcpServerInDC itself failed

$OutDir = Join-Path $env:USERPROFILE ("DC-Decom-Discovery_{0:yyyyMMdd_HHmmss}" -f (Get-Date))
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
Start-Transcript -Path (Join-Path $OutDir '00_transcript.log') -Append | Out-Null
#endregion

function Save($Name, $Data) {
    $path = Join-Path $OutDir $Name
    if ($Data -is [string]) { $Data | Out-File $path -Encoding UTF8 }
    elseif ($Name -like '*.csv') { $Data | Export-Csv $path -NoTypeInformation -Encoding UTF8 }
    else { $Data | Format-List * | Out-File $path -Encoding UTF8 }
    Write-Host ("  -> {0}" -f $Name) -ForegroundColor DarkGray
}
function Section($t) { Write-Host "`n==== $t ====" -ForegroundColor Cyan }

function Run-Tool {
    <#
        Runs a native tool once and returns its output as plain strings.
        The evidence file receives stdout only, exactly as before, so the CSV/TXT
        files stay byte identical to previous runs. The returned value additionally
        carries stderr text (normalised to the message alone) so tool errors reach
        the HTML report instead of only the console. Native stderr is never allowed
        to abort a read-only run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$Command,
        # Shown in the report's coverage section when the tool writes to stderr.
        [string]$Label,
        [string]$OutFile,
        # Some call sites already merged stderr into their evidence file (w32tm status).
        # Set this switch there so those files keep containing the error text; every
        # other site writes stdout only, exactly as before.
        [switch]$StdErrIntoFile
    )

    $stdout = New-Object System.Collections.Generic.List[string]
    $errors = New-Object System.Collections.Generic.List[string]
    $prevEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        foreach ($item in @(& $Command 2>&1)) {
            if ($null -eq $item) { continue }
            if ($item -is [System.Management.Automation.ErrorRecord]) {
                $errors.Add([string]$item.Exception.Message)
            } else {
                $stdout.Add([string]$item)
            }
        }
    } catch {
        # A caller running with ErrorActionPreference=Stop turns native stderr into a
        # terminating error; keep the discovery run alive and record the message.
        $errors.Add([string]$_.Exception.Message)
    } finally {
        $ErrorActionPreference = $prevEap
    }

    if ($OutFile) {
        $fileLines = if ($StdErrIntoFile) { @(@($stdout) + @($errors)) } else { @($stdout) }
        $fileLines | Out-File -FilePath $OutFile -Encoding UTF8
    }

    # Collected centrally so the coverage section cannot miss a tool. Without this, a
    # site that forgot to forward .Errors would hide its own failure.
    foreach ($e in $errors) {
        $script:NativeToolErrors += [pscustomobject]@{
            Tool    = $(if ($Label) { $Label } else { 'native command' })
            Message = [string]$e
        }
    }

    return [pscustomobject]@{
        Stdout   = @($stdout)
        Errors   = @($errors)
        Combined = @(@($stdout) + @($errors))
    }
}

function Get-DefinedRow {
    <#
        Wraps a collection for use in a foreach inside the report block. @($null) is an
        array with ONE null element, so an undefined or unset accumulator would mint a
        phantom row of empty cells - and a coverage row escalates the verdict. This drops
        nulls so 'nothing to report' stays 'nothing to report'.
    #>
    [CmdletBinding()]
    param([object]$Collection)

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($Collection)) {
        if ($null -ne $item) { $out.Add($item) }
    }
    return ,$out
}

function Test-MentionsOldDc {
    <#
        True when $Text contains the name or address of one of the DCs being removed.
        Short names are anchored so that 'DC1' does not match inside 'SDC1' or 'DC10';
        unanchored matching inflates findings on every table that reuses $OldNames.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }

    foreach ($n in @($script:OldNames)) {
        if ([string]::IsNullOrWhiteSpace($n)) { continue }
        if ($Text -match ('(?<![A-Za-z0-9\-])' + [regex]::Escape([string]$n) + '(?![A-Za-z0-9\-])')) { return $true }
    }
    foreach ($ip in @($script:OldIPs)) {
        if ([string]::IsNullOrWhiteSpace($ip)) { continue }
        if ($Text -match ('(?<![\d\.])' + [regex]::Escape([string]$ip) + '(?![\d\.])')) { return $true }
    }
    return $false
}

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# HTML helpers are loaded after the AD module so that nothing in this script calls
# an AD cmdlet before it is available. The report list is created here; sections are
# registered at the end of the run, in one place, once all data exists.
$ReportFile = $null
if (-not $NoHtml) {
    $helpers = Join-Path $PSScriptRoot 'DecomHtmlReport.ps1'
    if (-not (Test-Path -LiteralPath $helpers)) {
        Write-Error "HTML helpers not found at '$helpers'. Re-run with -NoHtml to skip the report."
        exit 1
    }
    . $helpers

    # Add-Section resolves $report from the caller's scope (html-template.md pattern).
    $report = [System.Collections.Generic.List[object]]::new()
}

# --------------------------------------------------------------------
Section '1. FSMO ROLE HOLDERS  (all 5 must be on ADC-01/ADC-02 before demote)'
# --------------------------------------------------------------------
$forest = Get-ADForest
$dom    = Get-ADDomain
$fsmo = [pscustomobject]@{
    SchemaMaster         = $forest.SchemaMaster
    DomainNamingMaster   = $forest.DomainNamingMaster
    PDCEmulator          = $dom.PDCEmulator
    RIDMaster            = $dom.RIDMaster
    InfrastructureMaster = $dom.InfrastructureMaster
}
$fsmo | Format-List
Save '01_fsmo_roles.txt' $fsmo
Run-Tool -Label 'netdom query fsmo' { netdom query fsmo } -OutFile (Join-Path $OutDir '01_fsmo_netdom.txt') | Out-Null
# Flag any role still on an old DC
$fsmo.PSObject.Properties | ForEach-Object {
    if ($OldNames | Where-Object { $_ -and $fsmo.$($_.Name) -match $_ }) { }
}
foreach ($p in $fsmo.PSObject.Properties) {
    foreach ($n in $OldDCs.FQDN) {
        if ($p.Value -match $n) { Write-Host ("  !! {0} still on {1}" -f $p.Name,$p.Value) -ForegroundColor Red }
    }
}

# --------------------------------------------------------------------
Section '2. DC INVENTORY  (GC status, OS, site, DNS/SYSVOL role)'
# --------------------------------------------------------------------
$dcs = Get-ADDomainController -Filter * |
    Select-Object Name, HostName, IPv4Address, Site, IsGlobalCatalog,
                  IsReadOnly, OperatingSystem, OperatingSystemVersion,
                  @{n='Roles';e={$_.OperationMasterRoles -join ','}}
$dcs | Format-Table -AutoSize
Save '02_dc_inventory.csv' $dcs

# --------------------------------------------------------------------
Section '3. REPLICATION HEALTH  (must be clean before AND after demote)'
# --------------------------------------------------------------------
$replSummaryTool = Run-Tool -Label 'repadmin /replsummary'     { repadmin /replsummary }   -OutFile (Join-Path $OutDir '03_replsummary.txt')
$showReplTool    = Run-Tool -Label 'repadmin /showrepl * /csv'  { repadmin /showrepl * /csv } -OutFile (Join-Path $OutDir '03_showrepl.csv')
$showBackupTool  = Run-Tool -Label 'repadmin /showbackup *'     { repadmin /showbackup * }    -OutFile (Join-Path $OutDir '03_showbackup.txt')
Write-Host '  Running dcdiag /e /v (this takes a minute)...' -ForegroundColor DarkGray
$dcdiagTool      = Run-Tool -Label 'dcdiag /e /v'              { dcdiag /e /v }             -OutFile (Join-Path $OutDir '03_dcdiag.txt')
# Raw text for the report: stdout plus any stderr, so a tool that errored shows it.
$replSummary = $replSummaryTool.Combined
$showReplCsv = @($showReplTool.Combined)
$showBackup  = @($showBackupTool.Combined)
$dcdiag      = $dcdiagTool.Combined
Get-Content (Join-Path $OutDir '03_replsummary.txt') | Select-Object -Last 20

# --------------------------------------------------------------------
Section '4. AD SITES & SERVICES  (subnets, links, connections, servers)'
# --------------------------------------------------------------------
Save '04_sites.csv'        (Get-ADReplicationSite -Filter * | Select Name, Description)
Save '04_subnets.csv'      (Get-ADReplicationSubnet -Filter * | Select Name, Site, Location)
Save '04_sitelinks.csv'    (Get-ADReplicationSiteLink -Filter * | Select Name, Cost, ReplicationFrequencyInMinutes, @{n='Sites';e={$_.SitesIncluded -join ';'}})
Save '04_connections.csv'  (Get-ADReplicationConnection -Filter * | Select Name, ReplicateFromDirectoryServer, ReplicateToDirectoryServer, AutoGenerated)
# Server objects still present under each site (old DCs must be gone post-demote)
$serverObjs = Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext `
    -Filter { objectClass -eq 'server' } -Properties dNSHostName |
    Select Name, dNSHostName, @{n='Site';e={($_.DistinguishedName -split ',')[2] -replace 'CN=',''}}
$serverObjs | Format-Table -AutoSize
Save '04_server_objects.csv' $serverObjs

# --------------------------------------------------------------------
Section '5. DNS SERVER CONFIG per DC  (forwarders, cond. forwarders, scavenging)'
# --------------------------------------------------------------------
foreach ($dc in ($NewDCs.FQDN + $OldDCs.FQDN)) {
    if (-not (Test-Connection $dc -Count 1 -Quiet)) {
        Write-Host "  (skip unreachable $dc)"
        # Recorded so the report can say what was NOT looked at: Test-Connection fails
        # for hosts that block ICMP but serve DNS perfectly well.
        $skippedDnsServers += [pscustomobject]@{
            Server = $dc
            Reason = 'Test-Connection failed (host down or ICMP blocked), DNS settings were not read'
        }
        continue
    }
    $safe = $dc -replace '\.','_'
    try {
        # Queried once and reused for the evidence file and the report row, so a slow
        # WAN link pays one round trip per server rather than two.
        $fwd = Get-DnsServerForwarder -ComputerName $dc -EA Stop
        $fwd | Out-File (Join-Path $OutDir "05_forwarders_$safe.txt") -Encoding UTF8
        Get-DnsServerZone -ComputerName $dc -EA Stop |
            Where-Object ZoneType -eq 'Forwarder' |
            Select ZoneName, @{n='Masters';e={$_.MasterServers -join ';'}} |
            Export-Csv (Join-Path $OutDir "05_condfwd_$safe.csv") -NoTypeInformation
        $scv = Get-DnsServerScavenging -ComputerName $dc -EA Stop
        $scv | Out-File (Join-Path $OutDir "05_scavenging_$safe.txt") -Encoding UTF8

        $dnsSrvRows += [pscustomobject]@{
            DnsServer       = $dc
            Forwarders      = ($fwd.Forwarders.IPAddress -join ';')
            ScavengeServers = [string]$scv.ScavengeServers
            AutoScavenge    = [string]$scv.AutoScavengePinnedRecords
            RefreshInterval = '{0}d {1}h {2}m' -f $scv.RefreshInterval.Days, $scv.RefreshInterval.Hours, $scv.RefreshInterval.Minutes
        }
    } catch {
        Write-Host "  DNS query failed on $dc : $_" -ForegroundColor Yellow
        # Without this the forwarder table can render short and read as complete.
        $dnsQueryFailures += [pscustomobject]@{ Server = $dc; Error = $_.Exception.Message }
    }
}

# --------------------------------------------------------------------
Section '6. DNS RECORDS REFERENCING OLD DCs  (A / PTR / NS / SRV / CNAME)'
#   The critical repointing checklist. Anything here needs a new target.
# --------------------------------------------------------------------
$dnsSrv = ($NewDCs.FQDN | Where-Object { Test-Connection $_ -Count 1 -Quiet } | Select-Object -First 1)
if ($dnsSrv) {
    $hits = New-Object System.Collections.Generic.List[object]
    $zones = Get-DnsServerZone -ComputerName $dnsSrv | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -ne 'Forwarder' }
    foreach ($z in $zones) {
        # A zone that fails to enumerate is recorded rather than skipped silently: a
        # repointing checklist with holes in it must not read as complete.
        try {
            $recs = Get-DnsServerResourceRecord -ComputerName $dnsSrv -ZoneName $z.ZoneName -EA Stop
        } catch {
            Write-Host ("  zone scan failed on {0} : {1}" -f $z.ZoneName, $_.Exception.Message) -ForegroundColor Yellow
            $zoneFailures += [pscustomobject]@{ Zone = $z.ZoneName; Error = $_.Exception.Message }
            continue
        }
        foreach ($r in $recs) {
            $blob = ($r.RecordData | Format-List | Out-String)
            $match = $false
            foreach ($ip in $OldIPs)   { if ($blob -match [regex]::Escape($ip)) { $match = $true } }
            foreach ($nm in $OldNames) { if ($nm -and $blob -match [regex]::Escape($nm)) { $match = $true } }
            if ($match) {
                $hits.Add([pscustomobject]@{
                    Zone = $z.ZoneName; Name = $r.HostName; Type = $r.RecordType
                    Data = ($blob -replace '\s+',' ').Trim()
                })
            }
        }
    }
    $hits | Format-Table -AutoSize
    Save '06_dns_records_referencing_old_dcs.csv' $hits
    Write-Host ("  Found {0} DNS record(s) still referencing an old DC." -f $hits.Count) -ForegroundColor Yellow
}

# --------------------------------------------------------------------
Section '7. TIME HIERARCHY  (PDC = authoritative source)'
# --------------------------------------------------------------------
Run-Tool -Label 'w32tm /query /configuration' { w32tm /query /configuration } -OutFile (Join-Path $OutDir '07_w32tm_config_local.txt') | Out-Null
Run-Tool -Label 'w32tm /query /status'         { w32tm /query /status }         -OutFile (Join-Path $OutDir '07_w32tm_status_local.txt')     | Out-Null
foreach ($dc in ($NewDCs.FQDN + $OldDCs.FQDN)) {
    $safe = $dc -replace '\.','_'
    # This site already redirected stderr into the file, so keep it there.
    $perDcTool = Run-Tool -Label ("w32tm /query /status /computer:{0}" -f $dc) { w32tm /query /status /computer:$dc } -OutFile (Join-Path $OutDir "07_w32tm_status_$safe.txt") -StdErrIntoFile
    # Tagged so the parser can attribute each Source line to a computer.
    $timeStatus += @("=== $dc ===") + @($perDcTool.Combined)
}
$w32tmMonitorTool = Run-Tool -Label 'w32tm /monitor /domain' { w32tm /monitor /domain:$Domain } -OutFile (Join-Path $OutDir '07_w32tm_monitor.txt')
$w32tmMonitor = $w32tmMonitorTool.Combined

# --------------------------------------------------------------------
Section '8. DHCP  (are scopes/authorization on the old DCs? option 006 = DNS)'
# --------------------------------------------------------------------
try {
    $authz = Get-DhcpServerInDC
    $authz | Format-Table -AutoSize
    Save '08_dhcp_authorized_servers.csv' ($authz | Select DnsName, IPAddress)
    foreach ($s in $authz) {
        $srv = $s.DnsName
        if (-not (Test-Connection $srv -Count 1 -Quiet)) { continue }
        $safe = $srv -replace '\.','_'
        try {
            $scopes = Get-DhcpServerv4Scope -ComputerName $srv
            $opts = foreach ($sc in $scopes) {
                Get-DhcpServerv4OptionValue -ComputerName $srv -ScopeId $sc.ScopeId -EA SilentlyContinue |
                    Where-Object OptionId -in 6,15,44 |
                    Select @{n='Scope';e={$sc.ScopeId}}, OptionId, Name, @{n='Value';e={$_.Value -join ';'}}
            }
            Get-DhcpServerv4OptionValue -ComputerName $srv -EA SilentlyContinue |
                Where-Object OptionId -in 6,15,44 |
                Select @{n='Scope';e={'SERVER'}}, OptionId, Name, @{n='Value';e={$_.Value -join ';'}} |
                ForEach-Object { $opts += $_ }
            $opts | Export-Csv (Join-Path $OutDir "08_dhcp_options_$safe.csv") -NoTypeInformation
            # Keep the rows for the report: $opts is rebuilt per server and would
            # otherwise never leave the loop.
            $dhcpOptRows += @($opts | ForEach-Object {
                [pscustomobject]@{
                    Server   = $srv
                    Scope    = $_.Scope
                    OptionId = $_.OptionId
                    Name     = $_.Name
                    Value    = $_.Value
                }
            })
        } catch {
            Write-Host "  DHCP read failed on $srv : $_" -ForegroundColor Yellow
            # Otherwise the options table renders empty and reads as 'nothing found'
            # when in fact nothing was read.
            $dhcpServerFailures += [pscustomobject]@{ Server = $srv; Error = $_.Exception.Message }
        }
    }
} catch {
    Write-Host '  No authorized DHCP servers found / DHCP module unavailable.' -ForegroundColor DarkGray
    # Reaching the report as an ERROR section, so "DHCP was never read" cannot render
    # as a clean empty table.
    $dhcpError = $_.Exception.Message
}

# --------------------------------------------------------------------
Section '9. SYSVOL REPLICATION STATE  (DFSR expected; flag legacy FRS)'
# --------------------------------------------------------------------
$dfsrmigGlobalTool    = Run-Tool -Label 'dfsrmig /getglobalstate'    { dfsrmig /getglobalstate }    -OutFile (Join-Path $OutDir '09_dfsr_globalstate.txt')
$dfsrmigMigrationTool = Run-Tool -Label 'dfsrmig /getmigrationstate' { dfsrmig /getmigrationstate } -OutFile (Join-Path $OutDir '09_dfsr_migrationstate.txt')
$dfsrmigState     = $dfsrmigGlobalTool.Combined
$dfsrmigMigration = $dfsrmigMigrationTool.Combined
Get-Content (Join-Path $OutDir '09_dfsr_globalstate.txt')

# --------------------------------------------------------------------
Section '10. NETLOGON / SRV LOCATOR RECORDS  (do new DCs advertise all services?)'
# --------------------------------------------------------------------
$srvQueries = @(
    "_ldap._tcp.dc._msdcs.$Domain",
    "_kerberos._tcp.dc._msdcs.$Domain",
    "_gc._tcp.$Domain",
    "_ldap._tcp.gc._msdcs.$Domain",
    "_ldap._tcp.pdc._msdcs.$Domain"
)
$srvOut = foreach ($q in $srvQueries) {
    Resolve-DnsName -Name $q -Type SRV -EA SilentlyContinue |
        Where-Object QueryType -eq 'SRV' |
        Select @{n='Query';e={$q}}, NameTarget, Port, Priority, Weight
}
$srvOut | Format-Table -AutoSize
Save '10_srv_locator_records.csv' $srvOut

# --------------------------------------------------------------------
Section '11. GPO WMI FILTERS & LINKS  (any that name a specific DC?)'
# --------------------------------------------------------------------
try {
    Import-Module GroupPolicy -EA Stop
    # Rows kept for the report so it does not re-query AD, and so a failure here is
    # visible instead of becoming an empty table.
    $wmiFilters = @(Get-ADObject -Filter { objectClass -eq 'msWMI-Som' } -Properties msWMI-Name, msWMI-Parm2)
    $wmiFilters |
        Select @{n='Filter';e={$_.'msWMI-Name'}}, @{n='Query';e={$_.'msWMI-Parm2'}} |
        Export-Csv (Join-Path $OutDir '11_gpo_wmi_filters.csv') -NoTypeInformation
    Get-GPO -All | Select DisplayName, Id, GpoStatus, ModificationTime |
        Export-Csv (Join-Path $OutDir '11_gpo_inventory.csv') -NoTypeInformation
} catch {
    Write-Host '  GroupPolicy module unavailable.' -ForegroundColor DarkGray
    $gpoFilterError = $_.Exception.Message
}

# --------------------------------------------------------------------
Section '12. PKI / CDP-AIA HINTS  (LDAP-based CRL/AIA can name DCs)'
#   Non-authoritative pointer — validate against your issuing CA (pkiview.msc).
# --------------------------------------------------------------------
try {
    $enrollBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services," + (Get-ADRootDSE).ConfigurationNamingContext
    $pkiRows = Get-ADObject -SearchBase $enrollBase -Filter * -Properties dNSHostName, cn |
        Select cn, dNSHostName
    $pkiRows | Export-Csv (Join-Path $OutDir '12_pki_enrollment_services.csv') -NoTypeInformation
    Write-Host '  Also review CDP/AIA extensions on the issuing CA (certutil -getreg CA\CRLPublicationURLs).' -ForegroundColor DarkGray
} catch {
    Write-Host '  No AD CS enrollment objects found (or no rights).' -ForegroundColor DarkGray
    # A rights or hierarchy failure must reach the report as ERROR, not as an empty
    # table that reads as 'no CDP/AIA pointer names a DC'.
    $pkiError = $_.Exception.Message
}

# --------------------------------------------------------------------
Section 'DONE'
# --------------------------------------------------------------------
Write-Host "`nAll reports written to:`n  $OutDir" -ForegroundColor Green
Write-Host @"

Manual / out-of-band items this script CANNOT see (verify by hand):
  - Client & member-server NIC DNS still set to 172.16.15.33/.34
  - FortiGate: DNS servers, LDAP/LDAPS auth servers, RADIUS
  - NPS/RADIUS, VPN, WSUS, backup jobs, monitoring targets
  - App LDAP bind strings (OnBase, PaperCut, Citrix, line-of-business)
  - Static host files / hardcoded IPs in scripts and appliances
"@ -ForegroundColor Yellow

# =====================================================================
# HTML readiness report. Registered in one place, after all discovery has
# run, so the diff stays reviewable and no section can read data that does not
# exist yet. The render happens exactly once, at the end of this block.
#
# Severity rules:
#   Critical = demoting now breaks authentication, locator or time service
#   High     = will break later, or leaves a stale reference to clean up
#   Medium   = needs a human decision, not necessarily before demotion
#   Info     = inventory; an Info section never blocks the verdict
# =====================================================================
if (-not $NoHtml) {

    # ---- 1. FSMO role holders -------------------------------------------------
    Add-Section -Title 'FSMO role holders' -Severity 'Info' `
        -Description 'All five operations master roles must sit on a retained DC before any demotion. A role still held by an old DC blocks the change.' `
        -EvidenceFile '01_fsmo_roles.txt','01_fsmo_netdom.txt' `
        -EscalateWhen { param($Rows) $Rows | Where-Object { $_.HolderOfOldDc } } `
        -Query {
            foreach ($p in $fsmo.PSObject.Properties) {
                [pscustomobject]@{
                    Role          = $p.Name
                    CurrentHolder = [string]$p.Value
                    HolderOfOldDc = (Test-MentionsOldDc -Text ([string]$p.Value))
                }
            }
        }

    # ---- 2. DC inventory ------------------------------------------------------
    Add-Section -Title 'DC inventory: retained versus decommission' -Severity 'Info' `
        -Description 'Every domain controller with its role in this change. A retained DC that is not a global catalog is a problem once the old GCs are gone.' `
        -EvidenceFile '02_dc_inventory.csv' `
        -EscalateTo 'High' `
        -EscalateWhen { param($Rows) $Rows | Where-Object { $_.Disposition -eq 'Retain' -and (-not [bool]$_.GlobalCatalog) } } `
        -Query {
            foreach ($d in $dcs) {
                $line  = '{0} {1}' -f $d.HostName, $d.IPv4Address
                [pscustomobject]@{
                    Name          = $d.Name
                    HostName      = $d.HostName
                    IP            = $d.IPv4Address
                    Site          = $d.Site
                    OS            = $d.OperatingSystem
                    GlobalCatalog = $d.IsGlobalCatalog
                    Roles         = [string]$d.Roles
                    Disposition   = $(if (Test-MentionsOldDc -Text $line) { 'Decommission' } else { 'Retain' })
                }
            }
        }

    # ---- 3. Surviving DC count ------------------------------------------------
    # Declared Critical and emits a row only when the rule is broken, so a clean run
    # renders green with no table. Avoids the double negative of escalating on empty.
    Add-Section -Title 'Retained domain controllers after removal' -Severity 'Critical' `
        -Description 'Two or more retained DCs are required for redundancy. A row here means fewer than two would survive.' `
        -EvidenceFile '02_dc_inventory.csv' `
        -EmptyText 'Two or more domain controllers remain after both removals.' `
        -Query {
            $retained = @($dcs | Where-Object { -not (Test-MentionsOldDc -Text ('{0} {1}' -f $_.HostName, $_.IPv4Address)) })
            if ($retained.Count -lt 2) {
                [pscustomobject]@{
                    RetainedCount = $retained.Count
                    Required      = 2
                    RetainedNames = ($retained.HostName -join ';')
                }
            }
        }

    # ---- 4. Replication summary (parsed) --------------------------------------
    Add-Section -Title 'Replication summary (repadmin /replsummary)' -Severity 'Info' `
        -Description 'Any non-zero failure count blocks the demotion window: demoting a DC with outstanding replication errors loses those changes.' `
        -EvidenceFile '03_replsummary.txt' `
        -EscalateWhen { param($Rows) $Rows | Where-Object { $_.HasFailures } } `
        -Query { Get-ReplSummaryRow -Output $replSummary }

    # ---- 5. repadmin raw output ----------------------------------------------
    # The parsed table above is a heuristic, so the authoritative text is always shown.
    Add-Section -Title 'repadmin raw output (replsummary, showrepl, showbackup)' -Severity 'Info' `
        -Description 'Unparsed tool output. Read this when the parsed summary disagrees with it.' `
        -EvidenceFile '03_replsummary.txt','03_showrepl.csv','03_showbackup.txt' `
        -Query { @($replSummary) + @('', '--- repadmin /showrepl * /csv ---') + $showReplCsv + @('', '--- repadmin /showbackup * ---') + @($showBackup) }

    # ---- 6. dcdiag findings ---------------------------------------------------
    Add-Section -Title 'dcdiag failures and warnings' -Severity 'Info' `
        -Description 'Failed tests are blockers. Warning lines are listed for triage; they do not block on their own.' `
        -EvidenceFile '03_dcdiag.txt' `
        -EscalateWhen { param($Rows) $Rows | Where-Object { $_.Result -eq 'FAIL' } } `
        -Query { Get-DcdiagFinding -Output $dcdiag }

    # ---- 7. dcdiag raw output -------------------------------------------------
    Add-Section -Title 'dcdiag raw output' -Severity 'Info' `
        -Description 'Full dcdiag /e /v text. Truncated in the browser only; the evidence file holds everything.' `
        -EvidenceFile '03_dcdiag.txt' `
        -Query { $dcdiag }

    # ---- 8. Server objects by site --------------------------------------------
    Add-Section -Title 'Server objects by AD site' -Severity 'Info' `
        -Description 'Verification table for AFTER the demotions: the old DC server objects must be gone from the sites container. Their presence before the change is expected and does not block.' `
        -EvidenceFile '04_server_objects.csv' `
        -Query {
            foreach ($s in $serverObjs) {
                [pscustomobject]@{
                    Server      = $s.Name
                    HostName    = [string]$s.dNSHostName
                    Site        = $s.Site
                    Disposition = $(if (Test-MentionsOldDc -Text ('{0} {1}' -f $s.Name, $s.dNSHostName)) { 'Decommission' } else { 'Retain' })
                }
            }
        }

    # ---- 9. DNS server configuration ------------------------------------------
    Add-Section -Title 'DNS server configuration per DC' -Severity 'Info' `
        -Description 'Forwarders and scavenging on every DNS server that was reachable. A forwarder list still containing an address being decommissioned must be fixed before the demotion.' `
        -EvidenceFile '05_forwarders_*.txt','05_scavenging_*.txt' `
        -EscalateWhen { param($Rows) $Rows | Where-Object { $_.NamesOldDc } } `
        -Query {
            foreach ($r in (Get-DefinedRow $dnsSrvRows)) {
                [pscustomobject]@{
                    DnsServer       = $r.DnsServer
                    Forwarders      = $r.Forwarders
                    ScavengeServers = $r.ScavengeServers
                    AutoScavenge    = $r.AutoScavenge
                    RefreshInterval = $r.RefreshInterval
                    NamesOldDc      = (Test-MentionsOldDc -Text $r.Forwarders)
                }
            }
        }

    # ---- 10. DNS records referencing the old DCs ------------------------------
    Add-Section -Title 'DNS records referencing old DCs' -Severity 'Critical' `
        -Description 'The repointing checklist. Every row must be deleted or retargeted before the old DCs are removed.' `
        -EvidenceFile '06_dns_records_referencing_old_dcs.csv' `
        -EmptyText 'No DNS record still points at an address being decommissioned.' `
        -Query {
            if (-not $dnsSrv) { throw 'No reachable DNS server, so the zone scan never ran. Treat this as unknown, not clean.' }
            @($hits)
        }

    # ---- 11. Time hierarchy (parsed sync sources) ------------------------------
    # Only actual sync-source lines count. Matching every line that merely names an
    # old DC made this fire on every single run, because w32tm /monitor lists every
    # DC in the domain.
    Add-Section -Title 'Time hierarchy: configured sync sources' -Severity 'Info' `
        -Description 'The PDC Emulator role holder is the authoritative time source. A retained DC still syncing from an old DC must be retargeted before demotion.' `
        -EvidenceFile '07_w32tm_monitor.txt','07_w32tm_status_*.txt' `
        -EscalateTo 'High' `
        -EscalateWhen { param($Rows) $Rows | Where-Object { $_.NamesOldDc } } `
        -Query {
            foreach ($r in @(Get-W32tmSourceRow -Output (@($w32tmMonitor) + @('') + @($timeStatus)))) {
                [pscustomobject]@{
                    Computer    = $r.Computer
                    SourceRaw   = $r.SourceRaw
                    NamesOldDc  = (Test-MentionsOldDc -Text $r.SourceRaw)
                }
            }
        }

    # ---- 12. w32tm raw output --------------------------------------------------
    Add-Section -Title 'w32tm raw output (/monitor and per-DC status)' -Severity 'Info' `
        -Description 'Unparsed time hierarchy output for the record.' `
        -EvidenceFile '07_w32tm_monitor.txt','07_w32tm_status_*.txt' `
        -Query { @($w32tmMonitor) + @('', '--- per-DC w32tm /query /status ---') + @($timeStatus) }

    # ---- 13. DHCP -------------------------------------------------------------
    Add-Section -Title 'DHCP references to old DCs' -Severity 'Info' `
        -Description 'Authorized DHCP servers and their options 006 (DNS), 015 (domain) and 044 (WINS). A value naming an address being decommissioned must be corrected before the demotion, otherwise clients lose their last working resolver.' `
        -EvidenceFile '08_dhcp_authorized_servers.csv','08_dhcp_options_*.csv' `
        -EscalateWhen { param($Rows) $Rows | Where-Object { $_.StaleReference } } `
        -Query {
            if ($dhcpError) { throw ("DHCP could not be read: {0}" -f $dhcpError) }
            foreach ($a in (Get-DefinedRow $authz)) {
                [pscustomobject]@{
                    Kind           = 'Authorized server'
                    Server         = [string]$a.DnsName
                    Setting        = 'DHCP authorization'
                    Value          = [string]$a.IPAddress
                    StaleReference = (Test-MentionsOldDc -Text ('{0} {1}' -f $a.DnsName, $a.IPAddress))
                }
            }
            foreach ($o in (Get-DefinedRow $dhcpOptRows)) {
                [pscustomobject]@{
                    Kind           = 'Scope option'
                    Server         = $o.Server
                    Setting        = ('option {0} ({1}) on scope {2}' -f $o.OptionId, $o.Name, $o.Scope)
                    Value          = [string]$o.Value
                    StaleReference = (Test-MentionsOldDc -Text ([string]$o.Value))
                }
            }
        }

    # ---- 14. SYSVOL replication state ------------------------------------------
    Add-Section -Title 'SYSVOL replication state (dfsrmig)' -Severity 'Info' `
        -Description 'DFSR must be in the FINAL state on every DC. Legacy FRS is a blocker: FRS has no clean way to remove a member and would leave SYSVOL broken.' `
        -EvidenceFile '09_dfsr_globalstate.txt','09_dfsr_migrationstate.txt' `
        -EscalateWhen { param($Rows) $Rows | Where-Object { $_ -match '(?i)(\bFRS\b|SOURCE state|INTERIM|PREPARED|unable to determine)' } } `
        -Query {
            $all = @(@($dfsrmigState) + @('') + @($dfsrmigMigration))
            if (@($all | Where-Object { $_ -match '\S' }).Count -eq 0) {
                throw 'dfsrmig produced no output, so the SYSVOL migration state is unknown. Check that dfsrmig ran and re-run.'
            }
            $all
        }

    # ---- 15. SRV locator records ------------------------------------------------
    Add-Section -Title 'SRV locator records for retained DCs' -Severity 'Info' `
        -Description 'Retained DCs must advertise every domain, GC and PDC locator record. Fewer rows than expected means clients will not find a DC after the old ones go.' `
        -EvidenceFile '10_srv_locator_records.csv' `
        -EscalateWhenEmpty -EscalateTo 'Critical' `
        -EmptyText 'No SRV records resolved at all. Verify the DnsClient resolution path and that retained DCs advertise their services.' `
        -Query { @($srvOut) }

    # ---- 16. GPO WMI filters ---------------------------------------------------
    # The predicate is required: declaring -EscalateTo without one leaves the section
    # unable to escalate, which is silent. Rows are flagged rather than filtered so
    # the full filter inventory stays visible while severity follows the real hits.
    Add-Section -Title 'GPO WMI filters naming a domain controller' -Severity 'Info' `
        -Description 'WMI filters and link queries that hard-code a DC name keep binding policy evaluation to a machine that is about to disappear. All filters are listed; only those naming an old DC raise the severity.' `
        -EvidenceFile '11_gpo_wmi_filters.csv','11_gpo_inventory.csv' `
        -EscalateTo 'High' `
        -EscalateWhen { param($Rows) $Rows | Where-Object { $_.NamesOldDc } } `
        -Query {
            if ($gpoFilterError) { throw ("Group Policy could not be read: {0}" -f $gpoFilterError) }
            foreach ($f in (Get-DefinedRow $wmiFilters)) {
                $name  = [string]$f.'msWMI-Name'
                $query = [string]$f.'msWMI-Parm2'
                [pscustomobject]@{
                    Filter     = $name
                    Query      = $query
                    NamesOldDc = (Test-MentionsOldDc -Text ('{0} {1}' -f $name, $query))
                }
            }
        }

    # ---- 17. PKI enrollment services -------------------------------------------
    Add-Section -Title 'PKI enrollment services (CDP and AIA pointers)' -Severity 'Medium' `
        -Description 'Non-authoritative pointer only: LDAP-based CRL and AIA extensions can name a DC. Validate against the issuing CA with pkiview.msc before treating any row as a finding.' `
        -EvidenceFile '12_pki_enrollment_services.csv' `
        -EscalateTo 'High' `
        -EscalateWhen { param($Rows) $Rows | Where-Object { $_.NamesOldDc } } `
        -Query {
            if ($pkiError) { throw ("AD CS enrollment objects could not be read: {0}" -f $pkiError) }
            foreach ($c in (Get-DefinedRow $pkiRows)) {
                [pscustomobject]@{
                    Service    = [string]$c.cn
                    HostName   = [string]$c.dNSHostName
                    NamesOldDc = (Test-MentionsOldDc -Text ('{0} {1}' -f $c.cn, $c.dNSHostName))
                }
            }
        }

    # ---- 18. Scan coverage -----------------------------------------------------
    # Everything the script intended to look at but could not. Without this section a
    # partial scan reads as a complete one.
    Add-Section -Title 'Scan coverage: what was NOT checked' -Severity 'Info' `
        -Description 'Hosts skipped, zones that failed to enumerate and per-server read failures. A short list here means the findings above are narrower than they look.' `
        -EscalateTo 'High' `
        -EscalateWhen { param($Rows) $Rows } `
        -EmptyText 'Every planned query completed against every target.' `
        -Query {
            foreach ($s in (Get-DefinedRow $skippedDnsServers)) {
                [pscustomobject]@{ Area='DNS server'; Target=$s.Server; Problem=$s.Reason }
            }
            foreach ($f in (Get-DefinedRow $dnsQueryFailures)) {
                [pscustomobject]@{ Area='DNS server'; Target=$f.Server; Problem=[string]$f.Error }
            }
            foreach ($z in (Get-DefinedRow $zoneFailures)) {
                [pscustomobject]@{ Area='DNS zone scan'; Target=$z.Zone; Problem=[string]$z.Error }
            }
            foreach ($d in (Get-DefinedRow $dhcpServerFailures)) {
                [pscustomobject]@{ Area='DHCP server options'; Target=$d.Server; Problem=[string]$d.Error }
            }
            foreach ($t in (Get-DefinedRow $NativeToolErrors)) {
                [pscustomobject]@{ Area='Native tool stderr'; Target=$t.Tool; Problem=[string]$t.Message }
            }
        }

    # ---- 19. Manual checklist ---------------------------------------------------
    Add-Section -Title 'Manual verification items (appendix)' -Severity 'Info' `
        -Description 'Out-of-band dependencies this script cannot see. These must be confirmed by hand regardless of the verdict above.' `
        -Query { @(
            ('Client and member-server NIC DNS still set to {0}' -f ($OldIPs -join ' / ')),
            'FortiGate: DNS servers, LDAP/LDAPS auth servers, RADIUS clients',
            'NPS/RADIUS, VPN concentrators, WSUS, backup jobs, monitoring targets',
            'Application LDAP bind strings (OnBase, PaperCut, Citrix, line-of-business)',
            'Static host files and hard-coded IPs in scripts and appliances'
        ) }

    # ---- Render once -----------------------------------------------------------
    New-DecomHtmlReport -Report $report -OutputPath $ReportFile `
        -Domain $Domain -Forest ([string]$forest.Name) `
        -Removing ($OldDCs.FQDN) -Retaining ($NewDCs.FQDN) `
        -EvidenceDir $OutDir -MaxPreLines $MaxPreLines -NoLaunch:$NoLaunch

    $verdict = Get-DemoteVerdict -Report $report
    Write-Host ("`nDEMOTE READINESS: {0}" -f $verdict.Label) -ForegroundColor $(if ($verdict.Ready) { 'Green' } else { 'Red' })
}

Stop-Transcript | Out-Null
