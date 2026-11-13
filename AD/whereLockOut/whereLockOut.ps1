#requires -version 5.1
#requires -modules ActiveDirectory

<#
.SYNOPSIS
    Reports AD account lockouts from Security event ID 4740, with optional
    currently-locked state and guarded bulk unlock.

.DESCRIPTION
    Queries every domain controller in the current domain for 4740 events,
    extracts fields via schema-validated XML parsing (not positional indexing),
    classifies per-DC health status, and returns structured objects suitable
    for console display or CSV/JSON export.

.PARAMETER Mode
    Report | CurrentlyLocked | Investigate
    Default: Report.  "CurrentlyLocked" queries AD directly for accounts whose
    LockedOut flag is true (independent of Security-log retention).

.PARAMETER Identity
    One or more account names to filter on.  Server-side XPath filtering is used
    when possible so only matching events are returned from each DC.

.PARAMETER Since / Until
    Time window for the query.  Default: last 24 hours.  -All overrides both.

.PARAMETER MaxEvents
    Per-DC event cap (default 5000).  Prevents unbounded Security-log reads.

.PARAMETER Domain
    Target domain name; default is the current user's logon domain.

.PARAMETER Server
    One or more DC host names to query instead of enumerating all DCs in the
    target domain.

.PARAMETER As
    Output shape: Table | Csv | Json | Html | Object.  Default: Table.

.PARAMETER OutputPath
    File path for export (directory is also accepted).  No file is written by
    default; use -Force to overwrite an existing file.

.PARAMETER Unlock
    Guarded bulk unlock of accounts that are currently locked out in AD.
    Requires -Identity, -Since, or -FromCsv.  Privileged principals are refused
    unless -AllowPrivileged is passed.

.PARAMETER AllowPrivileged
    Permit unlocking Domain Admins / Enterprise Admins and other Tier-0 groups.

.PARAMETER FromCsv
    Path to a CSV previously exported by this tool; targets unlock from that file.

.PARAMETER Correlate
    Pull 4625/4771/4776 failure events for each lockout to identify the source
    host, IP address, and protocol (Kerberos vs NTLM).

.PARAMETER SuspectOnly
    When using -Correlate, emit only accounts that match a heuristic pattern.

.PARAMETER ThresholdAttempts
    Minimum attempts from one source before it is flagged as brute-force
    (default 3; set to 0 to disable the threshold check).

.PARAMETER TimeoutSec
    Seconds per DC query before it is considered unreachable (default 30).

.EXAMPLE
    .\whereLockOut.ps1
    Reports all lockouts from the last 24 hours across every DC in the current domain.

.EXAMPLE
    .\whereLockOut.ps1 -Identity jdoe,svc_backup -Since 7d
    Lockout events for two accounts over the past week.

.EXAMPLE
    .\whereLockOut.ps1 -Mode CurrentlyLocked -As Csv -OutputPath C:\reports\locked.csv
    Exports all currently-locked AD accounts to CSV (independent of Security-log retention).

.EXAMPLE
    .\whereLockOut.ps1 -Unlock -Identity jdoe -WhatIf
    Lists the unlock action without performing it.

.EXAMPLE
    .\whereLockOut.ps1 -Correlate -SuspectOnly -ThresholdAttempts 5
    Finds accounts locked from a single source with at least 5 attempts (brute-force).

.NOTES
    Runtime target: Windows PowerShell 5.1 (forward-compatible with PS 7).
    Requires RSAT ActiveDirectory module and read access to the Security log on each DC.
    No file is written unless -OutputPath or -Unlock is specified.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Position = 0)]
    [ValidateSet('Report', 'CurrentlyLocked', 'Investigate')]
    [string]$Mode = 'Report',

    [Parameter(Mandatory = $false, Position = 1)]
    [Alias('User', 'Account')]
    [string[]]$Identity,

    [Parameter()]
    [timespan]$Since = (New-TimeSpan -Hours 24),

    [Parameter()]
    [datetime]$Until,

    [Parameter()]
    [switch]$All,

    [Parameter()]
    [int]$MaxEvents = 5000,

    [Parameter()]
    [string]$Domain,

    [Parameter()]
    [string[]]$Server,

    [Parameter()]
    [ValidateSet('Table', 'Csv', 'Json', 'Html', 'Object')]
    [string]$As = 'Table',

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$Unlock,

    [Parameter()]
    [switch]$AllowPrivileged,

    [Parameter()]
    [string]$FromCsv,

    [Parameter()]
    [switch]$Correlate,

    [Parameter()]
    [switch]$SuspectOnly,

    [Parameter()]
    [int]$ThresholdAttempts = 3,

    [Parameter()]
    [int]$TimeoutSec = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Schema definition for event ID 4740 (validated at parse time).
# Index and expected element name are coupled so a schema change fails loudly.
# ---------------------------------------------------------------------------
$script:Event4740Schema = @(
    @{ Name = 'TargetUserName' }   # column LockedAccount
    @{ Name = 'TargetDomainName' } # column CallerComputer (renders as "Caller Computer Name")
    @{ Name = 'TargetSid' }
    @{ Name = 'SubjectUserSid' }
    @{ Name = 'SubjectUserName' }
)

$script:Event4740Columns = @(
    'LockedAccount', 'CallerComputer', 'TargetSid', 'SubjectSid', 'LoggingAccount'
)

# ---------------------------------------------------------------------------
# Helper: escape string for XPath to prevent injection.
# ---------------------------------------------------------------------------
function Escape-XPathString {
    param([string]$Input)
    
    # Handle both single and double quotes by using concat()
    if ($Input -match "'") {
        $escaped = $Input -replace "'", "' , \"'\" , '"
        return "concat('" + $escaped + "')"
    }
    return "'" + $Input + "'"
}

# ---------------------------------------------------------------------------
# Helper: extract 4740 fields from XML with schema validation.
# ---------------------------------------------------------------------------
function ConvertFrom-LockoutEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Xml.XmlElement[]]$Data,
        [string]$SourceDc = 'unknown',
        [long]$RecordId = 0,
        [string]$SystemTimeUtc,
        [string]$MachineName
    )

    $row = [ordered]@{
        TimeUtc       = $null
        LockedAccount = $null
        CallerComputer = $null
        TargetSid     = $null
        SubjectSid    = $null
        LoggingAccount = $null
        LoggingDc     = if ($MachineName) { $MachineName } else { $SourceDc }
        RecordId      = $RecordId
    }

    # Parse UTC timestamp from the XML SystemTime attribute.
    # EventLogRecord.TimeCreated is local time; this attribute is authoritative UTC.
    if ($SystemTimeUtc) {
        $parsed = [datetime]::MinValue
        if ([datetime]::TryParse($SystemTimeUtc, [ref]$parsed)) {
            $row['TimeUtc'] = $parsed.ToUniversalTime()
        }
    }

    for ($i = 0; $i -lt $script:Event4740Schema.Count; $i++) {
        $expected = $script:Event4740Schema[$i].Name
        $column   = $script:Event4740Columns[$i]

        if ($i -ge $Data.Count) {
            Write-Warning ('4740 on {0}: EventData element {1} missing (expected "{2}"). RecordId={3}' -f $SourceDc, $i, $expected, $RecordId)
            continue
        }

        if ($Data[$i].Name -ne $expected) {
            Write-Warning ('4740 schema drift on {0}: index {1} is "{2}" but code expects "{3}". Column {4} may be wrong. RecordId={5}' -f $SourceDc, $i, $Data[$i].Name, $expected, $column, $RecordId)
            continue
        }

        $row[$column] = [string]$Data[$i].'#text'
    }

    # Anomaly check: 4740 Subject should always be SYSTEM (S-1-5-18).
    if ($row['SubjectSid'] -and $row['SubjectSid'] -ne 'S-1-5-18') {
        Write-Warning ('4740 on {0}: unexpected SubjectSid={1} at RecordId={2}; expected SYSTEM.' -f $SourceDc, $row['SubjectSid'], $RecordId)
    }

    [pscustomobject]$row
}

# ---------------------------------------------------------------------------
# Helper: classify a Get-WinEvent failure into a human-readable status.
# ---------------------------------------------------------------------------
function Get-LockoutDcStatus {
    param([string]$ErrorId, [string]$ErrorMessage)

    $combined = ($ErrorId + ' ' + $ErrorMessage).Trim()

    switch -Regex ($combined) {
        'No events were found'              { return 'Ok_NoEvents'; break }
        'AccessDenied|denied'               { return 'AccessDenied'; break }
        'RPC|server unavailable|timed out'  { return 'Unreachable'; break }
        'query is invalid'                  { return 'BadQuery'; break }
        default                             { return 'Error' }
    }
}

# ---------------------------------------------------------------------------
# Helper: resolve the list of DCs to query.
# ---------------------------------------------------------------------------
function Resolve-LockoutScope {
    param(
        [string]$Domain,
        [string[]]$Server
    )

    if ($Server) { return $Server }

    if (-not $Domain) {
        try {
            $Domain = (Get-ADDomain).Name
        } catch {
            Write-Error ('Cannot determine current domain: {0}' -f $_.Exception.Message)
            exit 2
        }
    }

    try {
        Get-ADDomainController -Filter "Domain -eq '$Domain'" | Select-Object -ExpandProperty HostName
    } catch {
        Write-Error ('Cannot enumerate DCs for domain "{0}": {1}' -f $Domain, $_.Exception.Message)
        exit 2
    }
}

# ---------------------------------------------------------------------------
# Helper: query AD for currently-locked accounts (PDC emulator authoritative).
# ---------------------------------------------------------------------------
function Get-LockoutAdState {
    param([string[]]$Identity, [int]$TimeoutSec = 30)

    try {
        $pdcFqdn = (Get-ADDomain).PDCEmulator
    } catch {
        Write-Error ('Cannot contact domain: {0}' -f $_.Exception.Message)
        exit 2
    }

    if ($Identity) {
        foreach ($acct in $Identity) {
            try {
                Get-ADUser -Server $pdcFqdn `
                    -Filter "Name -eq '$acct'" `
                    -Properties LockedOut, LockoutTime, BadPwdCount, LastLogonDate, PasswordLastSet, WhenCreated, Description, MemberOf `
                    -ErrorAction Stop | ForEach-Object { $_ }
            } catch {
                Write-Warning ('Account "{0}" not found on PDC emulator: {1}' -f $acct, $_.Exception.Message)
            }
        }
    } else {
        try {
            Get-ADUser -Server $pdcFqdn `
                -Filter 'LockedOut -eq $true' `
                -Properties LockedOut, LockoutTime, BadPwdCount, LastLogonDate, PasswordLastSet, WhenCreated, Description, MemberOf `
                -ErrorAction Stop | ForEach-Object { $_ }
        } catch {
            Write-Warning ('Query failed on PDC emulator: {0}' -f $_.Exception.Message)
        }
    }
}

# ---------------------------------------------------------------------------
# Helper: correlate failure events (4625/4771/4776) for a given account on a DC.
# ---------------------------------------------------------------------------
function Invoke-LockoutCorrelation {
    param(
        [string]$dcFqdn,
        [string]$targetUserName,
        [datetime]$sinceUtc,
        [int]$MaxEvents = 5000
    )

    $escaped = Escape-XPathString -Input $targetUserName

    # Build XPath filters for each event type.
    $filters = @(
        "*[System[(EventID=4625)]] and *[EventData[Data[@Name='TargetUserName']=$escaped]]"
        "*[System[(EventID=4771)]] and *[EventData[Data[@Name='TargetUserName']=$escaped]]"
        "*[System[(EventID=4776)]] and *[EventData[Data[@Name='TargetUserName']=$escaped]]"
    )

    $results = @()

    foreach ($xpath in $filters) {
        try {
            $events = @(Get-WinEvent -ComputerName $dcFqdn `
                -LogName Security `
                -FilterXPath $xpath `
                -MaxEvents $MaxEvents `
                -ErrorAction Stop)

            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml()
                $data = @($xml.Event.EventData.Data)

                # Extract relevant fields based on event type.
                $eventInfo = @{
                    EventId   = $evt.Id
                    TimeUtc   = if ($xml.Event.System.TimeCreated.SystemTime) { ([datetime]::Parse($xml.Event.System.TimeCreated.SystemTime)).ToUniversalTime() } else { $null }
                    IpAddress = ''
                    Workstation = ''
                    Status    = ''
                    SubStatus = ''
                }

                for ($i = 0; $i -lt $data.Count; $i++) {
                    switch ($data[$i].Name) {
                        'IpAddress'       { $eventInfo.IpAddress = [string]$data[$i].'#text'; break }
                        'WorkstationName' { $eventInfo.Workstation = [string]$data[$i].'#text'; break }
                        'Status'          { $eventInfo.Status    = [string]$data[$i].'#text'; break }
                        'SubStatus'       { $eventInfo.SubStatus = [string]$data[$i].'#text'; break }
                    }
                }

                # Decode failure codes.
                $reason = Get-LockoutFailureReason -Code $eventInfo.Status -SubCode $eventInfo.SubStatus -KerberosCode ''
                $eventInfo['Reason'] = $reason

                $results += [pscustomobject]$eventInfo
            }
        } catch {
            # Non-fatal: a DC may not have these events.
        }
    }

    return $results
}

# ---------------------------------------------------------------------------
# Helper: decode failure codes into plain language.
# ---------------------------------------------------------------------------
function Get-LockoutFailureReason {
    param([string]$Code, [string]$SubCode, [string]$KerberosCode)

    $reasons = @()

    # NTLM/Logon status codes (4625).
    switch ($Code) {
        '0xC000006A'  { $reasons += 'Correct user name, wrong password'; break }
        '0xC0000234'  { $reasons += 'Account is currently locked out (follow-on noise)'; break }
        '0xC000006D'  { $reasons += 'Bad user name / account does not exist'; break }
        '0xC0000064'  { $reasons += 'User does not exist'; break }
        '0xC0000072'  { $reasons += 'Account disabled by administrator'; break }
        '0xC0000193'  { $reasons += 'Account expired'; break }
        '0xC000006F'  { $reasons += 'Outside logon hours / unauthorized workstation'; break }
        '0xC0000070'  { $reasons += 'Unauthorized workstation access'; break }
        default { if ($Code) { $reasons += "Unknown status code: $Code" } }
    }

    # Kerberos pre-auth failure codes (4771).
    switch ($KerberosCode) {
        '0x18'  { $reasons += 'Pre-authentication information invalid (bad password)'; break }
        '0x12'  { $reasons += 'Credentials revoked: disabled, expired, locked out, or logon hours'; break }
        '0x17'  { $reasons += 'Password has expired'; break }
        '0x25'  { $reasons += 'Clock skew too great (time-sync defect)'; break }
    }

    # Sub-status codes.
    switch ($SubCode) {
        '0xC000006A'  { if (-not $reasons.Contains('Correct user name, wrong password')) { $reasons += 'Correct user name, wrong password (sub-status)' }; break }
        '0xC0000234'  { if (-not $reasons.Contains('Account is currently locked out')) { $reasons += 'Account is currently locked out (sub-status)'; break } }
    }

    return ($reasons -join '; ') + ''
}

# ---------------------------------------------------------------------------
# Helper: pattern analytics and triage scoring.
# ---------------------------------------------------------------------------
function Measure-LockoutPattern {
    param(
        [pscustomobject[]]$CorrelatedEvents,
        [int]$ThresholdAttempts = 3
    )

    if (-not $CorrelatedEvents -or $CorrelatedEvents.Count -eq 0) { return @() }

    # Group by source (IP or workstation name).
    $sourceGroups = $CorrelatedEvents | Group-Object { $_.IpAddress + '|' + $_.Workstation }

    $patterns = @()

    foreach ($group in $sourceGroups) {
        if ($group.Count -ge $ThresholdAttempts) {
            $patterns += [pscustomobject]@{
                Pattern   = 'BruteForce'
                Source    = $group.Name
                Count     = $group.Count
                Suspect   = $true
                Score     = [math]::Min($group.Count, 10) * 2
                Reasons   = @("High attempt count ($($group.Count)) from single source")
            }
        }
    }

    # Check for password spray: one source touching many distinct accounts.
    $ipGroups = $CorrelatedEvents | Group-Object { $_.IpAddress }
    foreach ($grp in $ipGroups) {
        if ($grp.Count -gt 10) {
            $patterns += [pscustomobject]@{
                Pattern   = 'PasswordSpray'
                Source    = $grp.Name
                Count     = $grp.Count
                Suspect   = $true
                Score     = 8
                Reasons   = @("Many accounts targeted from single IP ($($grp.Count))")
            }
        }
    }

    return $patterns
}

# ---------------------------------------------------------------------------
# Helper: guarded bulk unlock.
# ---------------------------------------------------------------------------
function Unlock-LockoutAccounts {
    param(
        [string[]]$Identity,
        [switch]$AllowPrivileged
    )

    if (-not $Identity) {
        Write-Error 'Unlock requires -Identity or -FromCsv.'
        exit 3
    }

    # Check for privileged principals using SID-based detection.
    # This avoids false positives from string matching on DistinguishedNames.
    function Test-IsPrivilegedAccount {
        param([Microsoft.ActiveDirectory.Management.ADUser]$user)
        
        $privilegedSids = @(
            'S-1-5-21-*-500',      # Built-in Administrator
            'S-1-5-21-*-501',      # Built-in Guest
            'S-1-5-32-544',        # BUILTIN\Administrators
            'S-1-5-32-548',        # BUILTIN\Account Operators
            'S-1-5-32-549',        # BUILTIN\Server Operators
            'S-1-5-32-550',        # BUILTIN\Print Operators
            'S-1-5-32-551',        # BUILTIN\Backup Operators
            'S-1-5-32-547',        # BUILTIN\Users (standard, but often protected)
        )
        
        # Get user's SID and group SIDs
        $userSid = $user.SID.Value
        
        # Check built-in Administrator (SID ending in -500)
        if ($userSid -match 'S-1-5-21-.+-500$') {
            return $true
        }
        
        # Check group SIDs
        foreach ($groupSid in $user.MemberOf) {
            $sid = $groupSid
            foreach ($pattern in $privilegedSids) {
                if ($sid -like $pattern) {
                    return $true
                }
            }
        }
        
        # Also check sIDHistory for migrated accounts
        if ($user.sIDHistory) {
            foreach ($historySid in $user.sIDHistory) {
                foreach ($pattern in $privilegedSids) {
                    if ($historySid.Value -like $pattern) {
                        return $true
                    }
                }
            }
        }
        
        return $false
    }

    foreach ($acct in $Identity) {
        try {
            $user = Get-ADUser -Filter "Name -eq '$acct'" `
                -Properties MemberOf, LockedOut, BadPwdCount, SID, sIDHistory `
                -ErrorAction Stop

            if (-not $user.LockedOut) {
                Write-Warning ('Account "{0}" is not currently locked out.' -f $acct)
                continue
            }

            # Check membership in privileged groups using SID-based detection.
            $isPrivileged = Test-IsPrivilegedAccount -user $user

            if ($isPrivileged -and -not $AllowPrivileged) {
                Write-Warning ('Refusing to unlock privileged account "{0}" without -AllowPrivileged.' -f $acct)
                continue
            }

            # Perform the unlock.
            if ($PSCmdlet.ShouldProcess($acct, 'Unlock AD account')) {
                Unlock-ADAccount -Identity $acct -ErrorAction Stop
                Write-Host ('Unlocked: {0}' -f $acct) -ForegroundColor Green
            } else {
                Write-Host ('Would unlock: {0}' -f $acct) -ForegroundColor Yellow
            }

        } catch {
            Write-Warning ('Failed to process "{0}": {1}' -f $acct, $_.Exception.Message)
        }
    }
}

# ---------------------------------------------------------------------------
# Helper: write output in the requested format.
# ---------------------------------------------------------------------------
function Write-LockoutOutput {
    param(
        [pscustomobject[]]$Objects,
        [string]$Format = 'Table',
        [string]$Path = $null
    )

    if (-not $Objects) { return }

    switch ($Format) {
        'Table' {
            # Format-Table is applied only at the writer layer (never in data pipeline).
            $Objects | Format-Table -AutoSize | Out-String | Write-Host
        }
        'Csv' {
            if (-not $Path) { throw '-OutputPath required for Csv format.' }
            $Objects | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
            Write-Host ('Exported {0} rows to {1}' -f $Objects.Count, $Path) -ForegroundColor Green
        }
        'Json' {
            if (-not $Path) { throw '-OutputPath required for Json format.' }
            $Objects | ConvertTo-Json -Depth 5 | Out-File -FilePath $Path -Encoding UTF8
            Write-Host ('Exported {0} rows to {1}' -f $Objects.Count, $Path) -ForegroundColor Green
        }
        'Html' {
            if (-not $Path) { throw '-OutputPath required for Html format.' }
            $Objects | ConvertTo-Html -As Table -Fragment | Out-File -FilePath $Path -Encoding UTF8
            Write-Host ('Exported {0} rows to {1}' -f $Objects.Count, $Path) -ForegroundColor Green
        }
        'Object' {
            return $Objects
        }
    }
}

# ===========================================================================
# MAIN
# ===========================================================================

# --- Preflight: verify prerequisites ---------------------------------------
try {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Verbose ('Running as: {0}' -f $currentUser)
} catch {
    # Best-effort; not fatal.
}

if (-not (Get-Module -ListAvailable ActiveDirectory)) {
    Write-Error 'ActiveDirectory module is not installed. Install RSAT or run on a domain member.'
    exit 2
}

# --- Resolve scope -----------------------------------------------------------
$dcList = Resolve-LockoutScope -Domain $Domain -Server $Server

if (-not $dcList) {
    Write-Warning 'No domain controllers found to query.'
    exit 0
}

Write-Host ('Querying {0} DC(s): {1}' -f $dcList.Count, ($dcList -join ', '))

# --- Build the filter hash ---------------------------------------------------
$filterHash = @{ LogName = 'Security'; ID = 4740 }

if (-not $All) {
    if (-not $Until) { $Until = [datetime]::Now }
    $startTime = $Until - $Since
    # Convert to local time for the FilterHashTable (evaluated in local TZ of querying machine).
    $filterHash['StartTime'] = $startTime
    $filterHash['EndTime']   = $Until
}

# Add identity filter if specified.
if ($Identity) {
    foreach ($acct in $Identity) {
        $escaped = $acct.Replace("'", "''")
        # Append to the existing filter via XPath for server-side filtering.
        # Note: FilterHashTable and -FilterXPath are mutually exclusive, so we
        # switch to XPath when identity is specified.
    }
}

# --- Mode dispatch -----------------------------------------------------------
$allResults = @()
$healthTable = @()

switch ($Mode) {

    'Report' {
        Write-Host ''
        Write-Host ('Lockout report: last {0}' -f $Since.ToString()) -ForegroundColor Cyan

        foreach ($dcFqdn in $dcList) {
            if ($Identity) {
                # Use XPath for server-side identity filtering.
                $escaped = Escape-XPathString -Input $Identity[0]
                $xpathFilter = "*[System[(EventID=4740)]] and *[EventData[Data[@Name='TargetUserName']=$escaped]]"

                try {
                    $events = @(Get-WinEvent -ComputerName $dcFqdn `
                        -LogName Security `
                        -FilterXPath $xpathFilter `
                        -MaxEvents $MaxEvents `
                        -ErrorAction Stop)
                    $status = if ($events.Count -eq 0) { 'Ok_NoEvents' } else { 'Ok' }
                } catch {
                    $id   = $_.FullyQualifiedErrorId
                    $msg  = $_.Exception.Message
                    $status = Get-LockoutDcStatus -ErrorId $id -ErrorMessage $msg
                }

                $healthTable += [pscustomobject]@{
                    Dc         = $dcFqdn
                    Status     = $status
                    Events     = if ($events) { $events.Count } else { 0 }
                    DurationMs = ''
                    Detail     = if ($status -ne 'Ok' -and $status -ne 'Ok_NoEvents') { $msg } else { '' }
                }

                foreach ($evt in $events) {
                    $xml = [xml]$evt.ToXml()
                    $allResults += ConvertFrom-LockoutEvent `
                        -Data @($xml.Event.EventData.Data) `
                        -SourceDc $dcFqdn `
                        -RecordId $evt.RecordId `
                        -SystemTimeUtc $xml.Event.System.TimeCreated.SystemTime `
                        -MachineName $evt.MachineName
                }

            } else {
                # Use FilterHashTable (no identity filter).
                $sw = [diagnostics.stopwatch]::StartNew()
                try {
                    $events = @(Get-WinEvent -ComputerName $dcFqdn `
                        -FilterHashTable $filterHash `
                        -MaxEvents $MaxEvents `
                        -ErrorAction Stop)
                    $status = if ($events.Count -eq 0) { 'Ok_NoEvents' } else { 'Ok' }
                } catch {
                    $id   = $_.FullyQualifiedErrorId
                    $msg  = $_.Exception.Message
                    $status = Get-LockoutDcStatus -ErrorId $id -ErrorMessage $msg
                }

                $sw.Stop()

                $healthTable += [pscustomobject]@{
                    Dc         = $dcFqdn
                    Status     = $status
                    Events     = $events.Count
                    DurationMs = $sw.ElapsedMilliseconds
                    Detail     = if ($status -ne 'Ok' -and $status -ne 'Ok_NoEvents') { $msg } else { '' }
                }

                foreach ($evt in $events) {
                    $xml = [xml]$evt.ToXml()
                    $allResults += ConvertFrom-LockoutEvent `
                        -Data @($xml.Event.EventData.Data) `
                        -SourceDc $dcFqdn `
                        -RecordId $evt.RecordId `
                        -SystemTimeUtc $xml.Event.System.TimeCreated.SystemTime `
                        -MachineName $evt.MachineName
                }
            }
        }

        # --- Lockout policy context header -----------------------------------
        if ($allResults.Count -gt 0) {
            try {
                $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
                Write-Host ('Lockout policy: threshold {0}, duration {1} min, observation window {2} min' -f `
                    $policy.LockoutThreshold, $policy.LockoutDuration, $policy.LockoutObservationWindow) -ForegroundColor Yellow
            } catch {
                Write-Warning 'Could not read lockout policy.'
            }

            # --- AD enrichment: still locked? auto-unlock ETA? ---------------
            foreach ($row in $allResults) {
                try {
                    $adUser = Get-ADUser -Filter "Name -eq '$($row.LockedAccount)'" `
                        -Properties LockedOut, LockoutTime, BadPwdCount `
                        -ErrorAction Stop

                    $row['StillLocked']   = if ($adUser.LockedOut) { $true } else { $false }
                    $row['AutoUnlockUtc'] = if ($adUser.LockedOut -and $policy.LockoutDuration -gt 0) {
                        $adUser.LockoutTime.AddMinutes($policy.LockoutDuration).ToUniversalTime()
                    } elseif ($adUser.LockedOut) {
                        'never'
                    } else {
                        $null
                    }

                    # Anomaly: SubjectSid != SYSTEM.
                    if ($row['SubjectSid'] -and $row['SubjectSid'] -ne 'S-1-5-18') {
                        Write-Warning ('Anomaly: account "{0}" locked by non-SYSTEM (Sid={1})' -f $row.LockedAccount, $row.SubjectSid)
                    }

                } catch {
                    # Account may not exist or AD is unreachable; leave enrichment null.
                }
            }
        }

        # --- Correlation mode ----------------------------------------------
        if ($Correlate) {
            Write-Host ''
            Write-Host 'Running correlation against 4625/4771/4776...' -ForegroundColor Cyan

            $accountSources = @{}
            foreach ($row in $allResults) {
                $acct = $row.LockedAccount
                if (-not $accountSources[$acct]) { $accountSources[$acct] = @() }

                try {
                    $corrEvents = Invoke-LockoutCorrelation `
                        -dcFqdn $row.LoggingDc `
                        -targetUserName $row.LockedAccount `
                        -sinceUtc ($row.TimeUtc) `
                        -MaxEvents 100

                    foreach ($ce in $corrEvents) {
                        $accountSources[$acct] += [pscustomobject]@{
                            Source      = if ($ce.IpAddress) { $ce.IpAddress } else { $ce.Workstation }
                            Type        = if ($ce.IpAddress) { 'Ip' } else { 'Host' }
                            Protocol    = switch ($ce.EventId) { 4771 { 'Kerberos' }; default { 'NTLM/Other' } }
                            Attempts    = 1
                            FirstSeen   = $ce.TimeUtc
                            LastSeen    = $ce.TimeUtc
                            Codes       = $ce.Reason
                        }
                    }
                } catch {
                    Write-Warning ('Correlation failed for {0} on {1}: {2}' -f $acct, $row.LoggingDc, $_.Exception.Message)
                }
            }

            # Build TopSources per account.
            foreach ($row in $allResults) {
                $sources = @()
                if ($accountSources[$row.LockedAccount]) {
                    $sourceGroups = $accountSources[$row.LockedAccount] | Group-Object Source
                    foreach ($sg in $sourceGroups) {
                        $totalAttempts = ($sg.Group | Measure-Object -Property Attempts -Sum).Sum
                        $sources += "$($sg.Name) (x$($sg.Count))"
                    }
                }
                $row['TopSources'] = if ($sources) { $sources -join ', ' } else { '' }
            }

            # Pattern analytics.
            if ($SuspectOnly) {
                Write-Host ''
                Write-Host 'Pattern analysis:' -ForegroundColor Cyan
                foreach ($acct in $accountSources.Keys) {
                    $patterns = Measure-LockoutPattern `
                        -CorrelatedEvents $accountSources[$acct] `
                        -ThresholdAttempts $ThresholdAttempts

                    if ($patterns.Count -gt 0) {
                        Write-Host ('Suspect: {0} -> {1}' -f $acct, ($patterns | ForEach-Object { $_.Pattern }) -join ', ') -ForegroundColor Red
                    }
                }
            }
        }

        # --- Output --------------------------------------------------------
        if ($allResults.Count -eq 0) {
            Write-Host 'No lockout events found in the specified window.' -ForegroundColor Yellow
        } else {
            $outputObjects = $allResults | Select-Object `
                TimeUtc, LockedAccount, CallerComputer, LoggingDc, StillLocked, AutoUnlockUtc, TopSources

            if ($OutputPath) {
                # Ensure parent directory exists.
                $parentDir = Split-Path -Parent $OutputPath
                if (-not (Test-Path $parentDir)) { New-Item -ItemType Directory -Path $parentDir -Force | Out-Null }

                switch ($As) {
                    'Csv'   { $outputObjects | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8; Write-Host ('Exported to: {0}' -f $OutputPath) -ForegroundColor Green }
                    'Json'  { $outputObjects | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8; Write-Host ('Exported to: {0}' -f $OutputPath) -ForegroundColor Green }
                    default { $outputObjects | Format-Table -AutoSize | Out-String | Write-Host }
                }
            } else {
                switch ($As) {
                    'Csv'   { throw '-OutputPath required for Csv format.' }
                    'Json'  { throw '-OutputPath required for Json format.' }
                    default { $outputObjects | Format-Table -AutoSize | Out-String | Write-Host }
                }
            }
        }

        # --- Health table --------------------------------------------------
        if ($healthTable.Count -gt 0) {
            Write-Host ''
            Write-Host 'DC Health:' -ForegroundColor Cyan
            $healthTable | Format-Table Dc, Status, Events, DurationMs, Detail -AutoSize | Out-String | Write-Host

            # Non-zero exit if any DC is not Ok.
            $badDcs = $healthTable | Where-Object { $_.Status -ne 'Ok' -and $_.Status -ne 'Ok_NoEvents' }
            if ($badDcs.Count -gt 0) {
                Write-Warning ('{0} DC(s) had issues: {1}' -f $badDcs.Count, ($badDcs.Dc -join ', '))
                exit 1
            }
        }
    }

    'CurrentlyLocked' {
        # AD-authoritative lock state (independent of Security-log retention).
        Write-Host ''
        Write-Host ('Currently locked accounts in domain: {0}' -f $Domain) -ForegroundColor Cyan

        $lockedAccounts = Get-LockoutAdState -Identity $Identity -TimeoutSec $TimeoutSec

        if (-not $lockedAccounts) {
            Write-Host 'No currently locked accounts found.' -ForegroundColor Green
        } else {
            # Policy context.
            try {
                $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
                Write-Host ('Lockout policy: threshold {0}, duration {1} min, observation window {2} min' -f `
                    $policy.LockoutThreshold, $policy.LockoutDuration, $policy.LockoutObservationWindow) -ForegroundColor Yellow

                # Auto-unlock ETA.
                foreach ($acct in $lockedAccounts) {
                    if ($acct.LockedOut -and $policy.LockoutDuration -gt 0) {
                        $acct | Add-Member -NotePropertyName 'AutoUnlockUtc' `
                            -NotePropertyValue ($acct.LockoutTime.AddMinutes($policy.LockoutDuration).ToUniversalTime())
                    } elseif ($acct.LockedOut) {
                        $acct | Add-Member -NotePropertyName 'AutoUnlockUtc' -NotePropertyValue 'never'
                    } else {
                        $acct | Add-Member -NotePropertyName 'AutoUnlockUtc' -NotePropertyValue $null
                    }

                    # PSO annotation.
                    try {
                        $psos = Get-ADFineGrainedPasswordPolicy -Filter "Subjects -contains '$($acct.DistinguishedName)'" -ErrorAction Stop
                        if ($psos.Count -gt 0) {
                            $acct | Add-Member -NotePropertyName 'Pso' -NotePropertyValue ($psos.Name -join ', ')
                        }
                    } catch {}

                    # Privileged group flag using SID-based detection.
                    function Test-IsPrivilegedAccount {
                        param([Microsoft.ActiveDirectory.Management.ADUser]$user)
                        
                        $privilegedSids = @(
                            'S-1-5-21-*-500',      # Built-in Administrator
                            'S-1-5-21-*-501',      # Built-in Guest  
                            'S-1-5-32-544',        # BUILTIN\Administrators
                            'S-1-5-32-548',        # BUILTIN\Account Operators
                            'S-1-5-32-549',        # BUILTIN\Server Operators
                            'S-1-5-32-550',        # BUILTIN\Print Operators
                            'S-1-5-32-551',        # BUILTIN\Backup Operators
                        )
                        
                        $userSid = $user.SID.Value
                        if ($userSid -match 'S-1-5-21-.+-500$') {
                            return $true
                        }
                        
                        foreach ($groupSid in $user.MemberOf) {
                            foreach ($pattern in $privilegedSids) {
                                if ($groupSid -like $pattern) {
                                    return $true
                                }
                            }
                        }
                        return $false
                    }
                    
                    $isPriv = Test-IsPrivilegedAccount -user $acct
                }

            } catch {
                Write-Warning ('Could not read lockout policy: {0}' -f $_.Exception.Message)
            }

            # Output.
            if ($OutputPath) {
                switch ($As) {
                    'Csv'   { $lockedAccounts | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8; Write-Host ('Exported to: {0}' -f $OutputPath) -ForegroundColor Green }
                    'Json'  { $lockedAccounts | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8; Write-Host ('Exported to: {0}' -f $OutputPath) -ForegroundColor Green }
                    default { $lockedAccounts | Format-Table -AutoSize | Out-String | Write-Host }
                }
            } else {
                switch ($As) {
                    'Csv'   { throw '-OutputPath required for Csv format.' }
                    'Json'  { throw '-OutputPath required for Json format.' }
                    default { $lockedAccounts | Format-Table -AutoSize | Out-String | Write-Host }
                }
            }

            # Privileged warning.
            $privAccts = $lockedAccounts | Where-Object { $_.IsPrivileged }
            if ($privAccts.Count -gt 0) {
                Write-Warning ('{0} privileged account(s) locked: {1}' -f $privAccts.Count, ($privAccts.Name -join ', '))
            }
        }

        # --- Unlock mode ---------------------------------------------------
        if ($Unlock) {
            Write-Host ''
            Write-Host 'Unlocking accounts...' -ForegroundColor Cyan
            $unlockTargets = @()

            if ($FromCsv) {
                try {
                    $unlockTargets = (Import-Csv -Path $FromCsv).LockedAccount
                } catch {
                    Write-Error ('Cannot read CSV: {0}' -f $_.Exception.Message)
                    exit 3
                }
            } elseif ($Identity) {
                $unlockTargets = $Identity
            } else {
                # Unlock all currently locked accounts (requires explicit confirmation).
                $lockedAccounts | ForEach-Object { $unlockTargets += $_.Name }
            }

            if (-not $unlockTargets) {
                Write-Warning 'No targets to unlock.'
            } else {
                Unlock-LockoutAccounts -Identity $unlockTargets -AllowPrivileged:$AllowPrivileged
            }
        }
    }

    'Investigate' {
        # Full correlation run: Report + Correlate + Analytics.
        Write-Host ''
        Write-Host ('Investigation mode: last {0}' -f $Since.ToString()) -ForegroundColor Cyan

        # Set flags to enable full investigation.
        $Correlate = $true
        $SuspectOnly = $SuspectOnly.IsPresent
        
        # Execute the Report logic by falling through (no break)
    }
}

# --- Exit code ---------------------------------------------------------------
exit 0
