<#
.SYNOPSIS
    Read-only Active Directory security audit that emits a styled HTML report.

.DESCRIPTION
    Runs a battery of read-only AD queries covering privileged access, DCSync
    rights, Kerberos delegation, roastable accounts, password hygiene, stale
    objects, trusts, LAPS coverage and ADCS certificate-template
    misconfigurations, then renders a single self-contained HTML report with a
    risk summary and per-section tables.

    Every query is READ-ONLY. The script makes no changes to the directory.

.PARAMETER OutputPath
    Full path for the HTML report. Defaults to the current directory with a
    timestamped filename. The report contains a target list (DCSync holders,
    unconstrained delegation hosts, roastable accounts, live ESC1 paths) --
    write it somewhere access-controlled and handle it as restricted.

.PARAMETER InactiveDays
    Threshold (days) for flagging stale users/computers. Default 90.

.PARAMETER Sections
    Which sections to run. Default 'All'. Valid values:
    Privileged, Delegation, DCSync, Roasting, Passwords, Stale, Trusts, LAPS, ADCS

.PARAMETER Server
    Optional target DC / domain. Defaults to the logon domain.

.PARAMETER NoLaunch
    Do not open the report in the default browser when the run completes.

.EXAMPLE
    .\Invoke-ADSecurityAudit.ps1

.EXAMPLE
    .\Invoke-ADSecurityAudit.ps1 -InactiveDays 60 -Sections Privileged,Delegation,ADCS

.EXAMPLE
    .\Invoke-ADSecurityAudit.ps1 -Server dc01.contoso.com -NoLaunch -OutputPath \\fs01\audit$\ad.html

.NOTES
    Requires the ActiveDirectory PowerShell module (RSAT).
    Run as a user with read access to the directory; no elevation needed for the
    read-only queries, though some attributes (e.g. LAPS) require delegated read.

    Changes in this revision
    ------------------------
    FIXED   Orphaned adminCount=1 used "-notmatch" against the memberOf array. That
            is a filter, not a boolean, so any admin holding at least one
            non-privileged group evaluated to $true and was reported as orphaned.
            Membership is now resolved by SID against the expanded privileged
            member set, with primaryGroupID considered as well.
    FIXED   Stale-object checks silently dropped accounts with a null
            lastLogonTimestamp -- i.e. accounts that have NEVER authenticated.
            These are now reported with a Status of NeverLoggedOn.
    FIXED   Enterprise Admins / Schema Admins were queried in the audited domain
            and the resulting error was swallowed, producing a clean-looking empty
            result in any child domain. They are now resolved by RID against the
            forest root, and any group that fails to enumerate is surfaced as a
            visible row instead of being silently skipped.
    FIXED   The Kerberoast "Privileged" column matched the substring 'Admins'
            against memberOf, so a member of e.g. "SQL Admins" was reported as
            privileged. It is now evaluated against the real privileged SID set.
    ADDED   ESC1 now checks msPKI-RA-Signature. A template requiring authorized
            signatures is not an ESC1 path and was previously a false positive.
            A single LikelyESC1 column combines all four conditions.
    CHANGED The DCSync ACL is read via Get-ADObject -Properties nTSecurityDescriptor,
            which honours -Server. The old Get-Acl AD:\ path ignored it.
    CHANGED DC exclusion in the unconstrained-delegation check now uses
            primaryGroupID 516/521 server-side rather than a hostname comparison.
    CHANGED Stale, LAPS, RBCD and password checks push their filters server-side
            instead of enumerating every enabled object and filtering in the pipeline.
    CHANGED Legacy-OS detection is anchored rather than matching bare year strings.
    CHANGED HTML encoding uses [System.Net.WebUtility], which needs no Add-Type and
            behaves identically on Windows PowerShell 5.1 and PowerShell 7. The
            report header is now encoded too.
    CHANGED Should-Run renamed to Test-SectionEnabled (approved verb).
    ADDED   -NoLaunch switch and a handling warning on the report and console.
#>

#Requires -Version 7.0

[CmdletBinding()]
param(
    [string]   $OutputPath = ".\AD-Security-Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [int]      $InactiveDays = 90,
    [ValidateSet('All','Privileged','Delegation','DCSync','Roasting','Passwords','Stale','Trusts','LAPS','ADCS')]
    [string[]] $Sections = 'All',
    [string]   $Server,
    [switch]   $NoLaunch
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    return
}
Import-Module ActiveDirectory -ErrorAction Stop

$adParams = @{}
if ($Server) { $adParams['Server'] = $Server }

$runAll = $Sections -contains 'All'
function Test-SectionEnabled([string]$Name) { $runAll -or ($Sections -contains $Name) }

$cutoff         = (Get-Date).AddDays(-$InactiveDays)
$cutoffFileTime = $cutoff.ToFileTime()
$report         = [System.Collections.Generic.List[object]]::new()

# UAC bit 2 = ACCOUNTDISABLE. Used to keep "enabled only" filters server-side.
$LDAP_NOT_DISABLED = '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'

try   { $domain = Get-ADDomain @adParams }
catch { Write-Error "Could not bind to the domain: $($_.Exception.Message)"; return }

$domainSid = $domain.DomainSID.Value

Write-Host "Auditing $($domain.DNSRoot) ..." -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Section helper
#   Wraps each check so a single failure is recorded, not fatal.
#   Severity drives the colour of the section header in the report.
# ---------------------------------------------------------------------------
function Add-Section {
    param(
        [string]$Title,
        [string]$Description,
        [ValidateSet('Critical','High','Medium','Info')] [string]$Severity = 'Info',
        [scriptblock]$Query
    )
    Write-Host ("  - {0}" -f $Title) -ForegroundColor DarkGray
    $obj = [ordered]@{
        Title       = $Title
        Description = $Description
        Severity    = $Severity
        Rows        = @()
        Count       = 0
        Error       = $null
    }
    try {
        $result = & $Query
        $obj.Rows  = @($result)
        $obj.Count = @($result).Count
    }
    catch {
        $obj.Error = $_.Exception.Message
    }
    $report.Add([pscustomobject]$obj)
}

# ---------------------------------------------------------------------------
# Privileged-group resolution
#
#   Groups are resolved by well-known RID/SID rather than by display name, so
#   the checks survive localised forests and, critically, so the forest-root
#   groups (Enterprise Admins RID 519, Schema Admins RID 518) are queried
#   against the forest root rather than against a child domain where they do
#   not exist.
#
#   All three helpers cache, so a run with -Sections Roasting still gets a
#   correct privileged set without the Privileged section having executed.
# ---------------------------------------------------------------------------
$script:PrivGroupCache  = $null
$script:PrivMemberCache = $null
$script:PrivSidCache    = $null

function Get-PrivilegedGroupTarget {
    if ($null -ne $script:PrivGroupCache) { return $script:PrivGroupCache }

    $list = [System.Collections.Generic.List[object]]::new()
    $add  = {
        param($GroupName,$Sid,$Srv)
        $list.Add([pscustomobject]@{ Name = $GroupName; SID = $Sid; Server = $Srv; Error = $null })
    }

    # BUILTIN aliases -- always local to the audited domain
    & $add 'Administrators'    'S-1-5-32-544' $Server
    & $add 'Account Operators' 'S-1-5-32-548' $Server
    & $add 'Server Operators'  'S-1-5-32-549' $Server
    & $add 'Print Operators'   'S-1-5-32-550' $Server
    & $add 'Backup Operators'  'S-1-5-32-551' $Server

    # Domain-local well-known RIDs
    & $add 'Domain Admins'               "$domainSid-512" $Server
    & $add 'Group Policy Creator Owners' "$domainSid-520" $Server

    # Forest-root-only groups
    try {
        $forest = Get-ADForest @adParams
        if ($forest.RootDomain -eq $domain.DNSRoot) {
            $rootSid    = $domainSid
            $rootServer = $Server
        }
        else {
            $rootDomain = Get-ADDomain -Identity $forest.RootDomain
            $rootSid    = $rootDomain.DomainSID.Value
            $rootServer = $forest.RootDomain
        }
        & $add 'Enterprise Admins' "$rootSid-519" $rootServer
        & $add 'Schema Admins'     "$rootSid-518" $rootServer
    }
    catch {
        # Surfaced as a visible row by Get-PrivilegedMember rather than swallowed.
        $list.Add([pscustomobject]@{
            Name   = 'Enterprise Admins / Schema Admins'
            SID    = $null
            Server = $null
            Error  = "Could not resolve the forest root: $($_.Exception.Message)"
        })
    }

    $script:PrivGroupCache = $list
    $list
}

function Get-PrivilegedMember {
    if ($null -ne $script:PrivMemberCache) { return $script:PrivMemberCache }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($g in Get-PrivilegedGroupTarget) {

        if (-not $g.SID) {
            $rows.Add([pscustomobject]@{
                Group = $g.Name; SamAccountName = '(NOT AUDITED)'
                ObjectClass = ''; Name = $g.Error; SID = ''
            })
            continue
        }

        $p = @{}; if ($g.Server) { $p['Server'] = $g.Server }
        try {
            Get-ADGroupMember -Identity $g.SID -Recursive @p -ErrorAction Stop |
              ForEach-Object {
                  $rows.Add([pscustomobject]@{
                      Group          = $g.Name
                      SamAccountName = $_.SamAccountName
                      ObjectClass    = $_.objectClass
                      Name           = $_.Name
                      SID            = $_.SID.Value
                  })
              }
        }
        catch {
            # Most commonly the >5000-member size limit, or foreign security
            # principals in BUILTIN groups. Never silently skipped.
            $rows.Add([pscustomobject]@{
                Group = $g.Name; SamAccountName = '(QUERY FAILED)'
                ObjectClass = ''; Name = $_.Exception.Message; SID = ''
            })
        }
    }

    $script:PrivMemberCache = $rows
    $rows
}

function Get-PrivilegedSidSet {
    if ($null -ne $script:PrivSidCache) { return $script:PrivSidCache }
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($m in Get-PrivilegedMember) { if ($m.SID) { [void]$set.Add($m.SID) } }
    $script:PrivSidCache = $set
    $set
}

# ---------------------------------------------------------------------------
# 1. Privileged accounts & group membership
# ---------------------------------------------------------------------------
if (Test-SectionEnabled 'Privileged') {

    Add-Section -Title 'Privileged Group Membership (recursive)' -Severity 'High' `
        -Description 'Effective members of high-value groups, expanded recursively and resolved by well-known SID rather than by display name. Enterprise Admins and Schema Admins are queried against the forest root. Any group that could not be enumerated appears as a QUERY FAILED / NOT AUDITED row -- treat those as unaudited, not as clean.' -Query {
        Get-PrivilegedMember
    }

    Add-Section -Title 'Orphaned adminCount=1 Objects' -Severity 'Medium' `
        -Description 'Users with adminCount=1 that are no longer an effective member of any protected group. SDProp stops maintaining their ACL but the flag and hardened inheritance remain -- a common source of stale, over-locked accounts. Membership is evaluated by SID against the recursively expanded privileged set, and primaryGroupID is checked as well, since a primary group does not appear in memberOf.' -Query {
        $privSids = Get-PrivilegedSidSet
        $privRids = 512,516,518,519,520,521

        Get-ADUser -LDAPFilter '(&(admincount=1)(!(isCriticalSystemObject=TRUE)))' `
          -Properties adminCount,memberOf,whenChanged,primaryGroupID @adParams |
          Where-Object {
              -not $privSids.Contains($_.SID.Value) -and
              ($_.primaryGroupID -notin $privRids)
          } |
          Select-Object SamAccountName,
                        Enabled,
                        @{n='WhenChanged';e={$_.whenChanged}},
                        @{n='GroupCount';e={@($_.memberOf).Count}} |
          Sort-Object WhenChanged
    }

    Add-Section -Title 'Privileged Accounts NOT in Protected Users' -Severity 'Medium' `
        -Description 'Domain Admins that are not members of the Protected Users group (RID 525). Where OS and functional level allow, privileged accounts should be enrolled to disable NTLM, unconstrained delegation and weak Kerberos crypto for those identities. Note that Protected Users breaks accounts relying on NTLM or delegation -- validate before enrolling any service identity.' -Query {
        $protected = @()
        try {
            $protected = @(Get-ADGroupMember -Identity "$domainSid-525" -Recursive @adParams -ErrorAction Stop |
                           ForEach-Object { $_.SID.Value })
        }
        catch {
            throw "Could not read Protected Users (RID 525): $($_.Exception.Message). The group is absent below DFL 2012 R2."
        }

        Get-ADGroupMember -Identity "$domainSid-512" -Recursive @adParams -ErrorAction Stop |
          Where-Object objectClass -eq 'user' |
          Where-Object { $_.SID.Value -notin $protected } |
          Select-Object SamAccountName, Name
    }
}

# ---------------------------------------------------------------------------
# 2. Kerberos delegation
# ---------------------------------------------------------------------------
if (Test-SectionEnabled 'Delegation') {

    Add-Section -Title 'Unconstrained Delegation' -Severity 'Critical' `
        -Description 'Accounts trusted for delegation to any service. Domain Controllers and RODCs legitimately hold this and are excluded server-side by primaryGroupID (516 / 521), which is harder to evade than a hostname comparison. Any other computer or user here can capture and reuse the TGTs of connecting users -- treat as a top-priority finding.' -Query {
        Get-ADObject -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516))(!(primaryGroupID=521)))' `
          -Properties samAccountName,userAccountControl,objectClass,primaryGroupID @adParams |
          Select-Object Name, samAccountName, objectClass,
                        @{n='Enabled';e={-not ($_.userAccountControl -band 2)}} |
          Sort-Object objectClass, Name
    }

    Add-Section -Title 'Constrained Delegation (to specific SPNs)' -Severity 'High' `
        -Description 'Accounts allowed to delegate to named services. Review the target SPNs -- delegation to sensitive services (a DC, the CA, a file server) widens the blast radius if the account is compromised. Protocol transition (any-authn, UAC bit 16777216) is higher risk than Kerberos-only and is sorted to the top.' -Query {
        Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' `
          -Properties msDS-AllowedToDelegateTo,samAccountName,userAccountControl @adParams |
          ForEach-Object {
              [pscustomobject]@{
                  Name                = $_.Name
                  SamAccountName      = $_.samAccountName
                  ProtocolTransition  = [bool]($_.userAccountControl -band 16777216)
                  AllowedToDelegateTo = ($_.'msDS-AllowedToDelegateTo' -join '; ')
              }
          } |
          Sort-Object ProtocolTransition -Descending
    }

    Add-Section -Title 'Resource-Based Constrained Delegation' -Severity 'High' `
        -Description 'Computers that name principals allowed to delegate to them (msDS-AllowedToActOnBehalfOfOtherIdentity), filtered server-side. Unexpected entries here are a classic privilege-escalation primitive -- an attacker with write access to a computer object can populate this attribute and then impersonate any user to that host.' -Query {
        Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
          -Properties PrincipalsAllowedToDelegateToAccount @adParams |
          Select-Object Name,
                        @{n='AllowedPrincipals';e={($_.PrincipalsAllowedToDelegateToAccount) -join '; '}} |
          Sort-Object Name
    }
}

# ---------------------------------------------------------------------------
# 2b. DCSync rights (replication extended rights on the domain head)
# ---------------------------------------------------------------------------
if (Test-SectionEnabled 'DCSync') {

    Add-Section -Title 'DCSync Rights on the Domain Head' -Severity 'Critical' `
        -Description 'Principals holding the DS-Replication-Get-Changes and -Get-Changes-All extended rights on the domain naming context. Held together, these permit a DCSync attack -- replicating any secret from the directory, up to and including the krbtgt hash. Domain Controllers, Enterprise Domain Controllers, SYSTEM and BUILTIN\Administrators hold these by design and are marked as expected defaults. Any OTHER principal that is FullDCSyncCapable is a critical finding. Expect Exchange (Exchange Trusted Subsystem / Exchange Windows Permissions) and Entra Connect sync accounts to appear -- confirm each is intentional, then add it to your own allowlist.' -Query {

        # Replication extended-right GUIDs
        $replRights = @{
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'Get-Changes'
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'Get-Changes-All'
            '89e95b76-444d-4c62-991a-0facbeda640c' = 'Get-Changes-In-Filtered-Set'
        }

        # Read the DACL via Get-ADObject so that -Server is honoured.
        $head = Get-ADObject -Identity $domain.DistinguishedName `
                    -Properties nTSecurityDescriptor @adParams
        $acl  = $head.nTSecurityDescriptor
        if (-not $acl) { throw 'Could not read nTSecurityDescriptor on the domain head.' }

        # Aggregate the replication rights granted to each identity
        $byId = @{}
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $ot = $ace.ObjectType.ToString()
            # A full-control / all-extended-rights ACE (null ObjectType) also confers replication
            $allExtended = ($ace.ActiveDirectoryRights -match 'GenericAll') -or
                           (($ace.ActiveDirectoryRights -match 'ExtendedRight') -and
                            $ot -eq '00000000-0000-0000-0000-000000000000')
            $granted = @()
            if ($replRights.ContainsKey($ot)) { $granted += $replRights[$ot] }
            elseif ($allExtended)             { $granted += 'Get-Changes','Get-Changes-All' }
            if (-not $granted) { continue }

            $id = $ace.IdentityReference.Value
            if (-not $byId.ContainsKey($id)) { $byId[$id] = [System.Collections.Generic.HashSet[string]]::new() }
            foreach ($g in $granted) { [void]$byId[$id].Add($g) }
        }

        $nb = $domain.NetBIOSName
        $expected = @(
            'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
            'NT AUTHORITY\SYSTEM',
            'BUILTIN\Administrators',
            "$nb\Domain Controllers",
            "$nb\Enterprise Read-only Domain Controllers"
        )

        $byId.GetEnumerator() | ForEach-Object {
            $full = ($_.Value.Contains('Get-Changes') -and $_.Value.Contains('Get-Changes-All'))
            [pscustomobject]@{
                Principal         = $_.Key
                Rights            = (($_.Value | Sort-Object) -join ', ')
                FullDCSyncCapable = $full
                ExpectedDefault   = ($_.Key -in $expected)
            }
        } | Sort-Object ExpectedDefault, @{Expression={$_.FullDCSyncCapable};Descending=$true}, Principal
    }
}

# ---------------------------------------------------------------------------
# 3. Roastable accounts
# ---------------------------------------------------------------------------
if (Test-SectionEnabled 'Roasting') {

    Add-Section -Title 'Kerberoastable Accounts (SPN on user)' -Severity 'High' `
        -Description 'User accounts carrying a Service Principal Name. Their service tickets are encrypted with the account password hash and can be cracked offline. Prioritise accounts with old passwords or privileged group membership; prefer gMSAs where possible. The Privileged column is evaluated against the resolved privileged SID set rather than a name match, so a member of e.g. "SQL Admins" is no longer wrongly flagged. krbtgt is excluded -- it carries an SPN by design and is not requestable.' -Query {
        $privSids = Get-PrivilegedSidSet

        Get-ADUser -LDAPFilter '(&(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))' `
          -Properties ServicePrincipalName,PasswordLastSet,Enabled @adParams |
          Select-Object SamAccountName, Enabled, PasswordLastSet,
                        @{n='PwdAgeDays';e={ if ($_.PasswordLastSet) { [int]((Get-Date) - $_.PasswordLastSet).TotalDays } else { $null } }},
                        @{n='Privileged';e={ $privSids.Contains($_.SID.Value) }},
                        @{n='SPNs';e={($_.ServicePrincipalName) -join '; '}} |
          Sort-Object @{Expression='Privileged';Descending=$true}, @{Expression='PwdAgeDays';Descending=$true}
    }

    Add-Section -Title 'AS-REP Roastable Accounts (no pre-auth)' -Severity 'High' `
        -Description 'Accounts with Kerberos pre-authentication disabled (UAC bit 4194304). An attacker can request an AS-REP and crack it offline without holding any credentials. There is rarely a good reason to leave pre-auth off.' -Query {
        $privSids = Get-PrivilegedSidSet

        Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' `
          -Properties userAccountControl,PasswordLastSet,Enabled @adParams |
          Select-Object SamAccountName, Enabled, PasswordLastSet,
                        @{n='Privileged';e={ $privSids.Contains($_.SID.Value) }} |
          Sort-Object Privileged -Descending
    }
}

# ---------------------------------------------------------------------------
# 4. Password hygiene
# ---------------------------------------------------------------------------
if (Test-SectionEnabled 'Passwords') {

    Add-Section -Title 'Password Never Expires (enabled accounts)' -Severity 'Medium' `
        -Description 'Enabled accounts whose password never expires (UAC bit 65536). Acceptable for some service accounts if compensated by length and rotation, but should be inventoried and justified.' -Query {
        Get-ADUser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=65536)$LDAP_NOT_DISABLED)" `
          -Properties PasswordLastSet @adParams |
          Select-Object SamAccountName,
                        PasswordLastSet,
                        @{n='PwdAgeDays';e={ if ($_.PasswordLastSet) { [int]((Get-Date) - $_.PasswordLastSet).TotalDays } else { $null } }} |
          Sort-Object PasswordLastSet
    }

    Add-Section -Title 'Password Not Required' -Severity 'High' `
        -Description 'Accounts flagged to permit an empty password (UAC bit 32). Should be empty; any result is a finding.' -Query {
        Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=32)' `
          -Properties userAccountControl,Enabled @adParams |
          Select-Object SamAccountName, Enabled |
          Sort-Object Enabled -Descending
    }

    Add-Section -Title 'Reversible Encryption Enabled' -Severity 'Critical' `
        -Description 'Accounts storing the password in a recoverable form (UAC bit 128). This should never be set; each result is effectively a cleartext-equivalent password at rest.' -Query {
        Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=128)' `
          -Properties userAccountControl,Enabled @adParams |
          Select-Object SamAccountName, Enabled
    }

    Add-Section -Title 'krbtgt Password Age' -Severity 'Medium' `
        -Description 'Age of the krbtgt account password. Rotate on a schedule (twice, spaced by at least one full replication cycle) and immediately after any suspected DC compromise, as it underpins all Kerberos ticket signing. In an RODC forest each RODC also has its own krbtgt_NNNNN account, not covered here.' -Query {
        Get-ADUser -Identity 'krbtgt' -Properties PasswordLastSet @adParams |
          Select-Object SamAccountName, PasswordLastSet,
                        @{n='AgeDays';e={ if ($_.PasswordLastSet) { [int]((Get-Date) - $_.PasswordLastSet).TotalDays } else { $null } }}
    }
}

# ---------------------------------------------------------------------------
# 5. Stale objects
# ---------------------------------------------------------------------------
if (Test-SectionEnabled 'Stale') {

    Add-Section -Title "Inactive / Never-Used Enabled Users (> $InactiveDays days)" -Severity 'Medium' `
        -Description "Enabled users with no logon inside the window, PLUS enabled users that have never authenticated at all (null lastLogonTimestamp). The latter were previously dropped from this check and are usually the more interesting finding: provisioned-and-forgotten service accounts and unclaimed joiners. NOTE: lastLogonTimestamp replicates lazily (up to ~14 days of skew) -- before disabling, confirm against the non-replicated lastLogon on each DC. WhenCreated is included so brand-new accounts can be told apart from long-dead ones." -Query {

        $inactive = Get-ADUser -LDAPFilter "(&$LDAP_NOT_DISABLED(lastLogonTimestamp<=$cutoffFileTime))" `
                      -Properties LastLogonTimestamp,whenCreated @adParams |
                    ForEach-Object {
                        [pscustomobject]@{
                            SamAccountName = $_.SamAccountName
                            Status         = 'Inactive'
                            LastLogon      = [datetime]::FromFileTime($_.LastLogonTimestamp)
                            WhenCreated    = $_.whenCreated
                        }
                    }

        $never = Get-ADUser -LDAPFilter "(&$LDAP_NOT_DISABLED(!(lastLogonTimestamp=*)))" `
                   -Properties LastLogonTimestamp,whenCreated @adParams |
                 ForEach-Object {
                     [pscustomobject]@{
                         SamAccountName = $_.SamAccountName
                         Status         = 'NeverLoggedOn'
                         LastLogon      = $null
                         WhenCreated    = $_.whenCreated
                     }
                 }

        @($inactive) + @($never) | Sort-Object Status, WhenCreated
    }

    Add-Section -Title "Inactive / Never-Used Enabled Computers (> $InactiveDays days)" -Severity 'Medium' `
        -Description 'Enabled computer accounts dormant beyond the window, plus computer objects that have never authenticated (pre-staged and abandoned, or failed builds). Candidates for review and disable; the same lastLogonTimestamp skew caveat applies.' -Query {

        $inactive = Get-ADComputer -LDAPFilter "(&$LDAP_NOT_DISABLED(lastLogonTimestamp<=$cutoffFileTime))" `
                      -Properties LastLogonTimestamp,OperatingSystem,whenCreated @adParams |
                    ForEach-Object {
                        [pscustomobject]@{
                            Name            = $_.Name
                            Status          = 'Inactive'
                            OperatingSystem = $_.OperatingSystem
                            LastLogon       = [datetime]::FromFileTime($_.LastLogonTimestamp)
                            WhenCreated     = $_.whenCreated
                        }
                    }

        $never = Get-ADComputer -LDAPFilter "(&$LDAP_NOT_DISABLED(!(lastLogonTimestamp=*)))" `
                   -Properties LastLogonTimestamp,OperatingSystem,whenCreated @adParams |
                 ForEach-Object {
                     [pscustomobject]@{
                         Name            = $_.Name
                         Status          = 'NeverLoggedOn'
                         OperatingSystem = $_.OperatingSystem
                         LastLogon       = $null
                         WhenCreated     = $_.whenCreated
                     }
                 }

        @($inactive) + @($never) | Sort-Object Status, WhenCreated
    }

    Add-Section -Title 'Legacy / Unsupported Operating Systems' -Severity 'High' `
        -Description 'Enabled computers running out-of-support OS versions. These lack current patches and often force weak protocol fallbacks (SMBv1, NTLMv1, RC4). The match is anchored to the start of the operatingSystem string rather than searching for bare year substrings, which previously risked false positives.' -Query {
        $legacy = '^Windows (Server )?(2000|2003|2008|2012|XP|Vista|7|8)(\b|$)'

        Get-ADComputer -LDAPFilter "(&$LDAP_NOT_DISABLED(operatingSystem=*))" `
          -Properties OperatingSystem,OperatingSystemVersion @adParams |
          Where-Object { $_.OperatingSystem -match $legacy } |
          Select-Object Name, OperatingSystem, OperatingSystemVersion |
          Sort-Object OperatingSystem, Name
    }
}

# ---------------------------------------------------------------------------
# 6. Trusts
# ---------------------------------------------------------------------------
if (Test-SectionEnabled 'Trusts') {

    Add-Section -Title 'Domain / Forest Trusts' -Severity 'Medium' `
        -Description 'Configured trusts with SID filtering and selective authentication state. Outbound and bidirectional trusts without SID filtering or selective auth broaden the trust boundary considerably -- a compromise on the far side becomes a compromise here.' -Query {
        Get-ADTrust -Filter * @adParams |
          Select-Object Name, Direction, TrustType, ForestTransitive,
                        SelectiveAuthentication, SIDFilteringForestAware, SIDFilteringQuarantined
    }
}

# ---------------------------------------------------------------------------
# 7. LAPS coverage
# ---------------------------------------------------------------------------
if (Test-SectionEnabled 'LAPS') {

    Add-Section -Title 'Computers Missing a Managed Local Admin Password' -Severity 'Medium' `
        -Description 'Enabled computers with no LAPS expiration attribute populated (Windows LAPS is checked first, then legacy Microsoft LAPS). Missing entries mean the local administrator password is likely unmanaged or shared. The absence test is applied server-side. Absence of both schemas is reported as an informational note rather than a finding. Reading the expiration attribute does not require the password-read delegation, so an empty result here reflects coverage, not permissions.' -Query {
        $rootDSE = Get-ADRootDSE @adParams

        $hasWinLaps = [bool](Get-ADObject -SearchBase $rootDSE.schemaNamingContext `
                                -LDAPFilter '(lDAPDisplayName=msLAPS-PasswordExpirationTime)' @adParams -ErrorAction SilentlyContinue)
        $hasLegacy  = [bool](Get-ADObject -SearchBase $rootDSE.schemaNamingContext `
                                -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)' @adParams -ErrorAction SilentlyContinue)

        if (-not $hasWinLaps -and -not $hasLegacy) {
            [pscustomobject]@{ Name = '(No LAPS schema detected in this forest)'
                               Note = 'Neither Windows LAPS nor legacy LAPS attributes are present in the schema.' }
            return
        }

        $prop = if ($hasWinLaps) { 'msLAPS-PasswordExpirationTime' } else { 'ms-Mcs-AdmPwdExpirationTime' }

        Get-ADComputer -LDAPFilter "(&$LDAP_NOT_DISABLED(!($prop=*)))" `
          -Properties OperatingSystem @adParams |
          Select-Object Name, OperatingSystem, @{n='MissingAttribute';e={$prop}} |
          Sort-Object Name
    }
}

# ---------------------------------------------------------------------------
# 8. ADCS certificate templates (ESC1 + enrollment-rights resolution)
# ---------------------------------------------------------------------------
if (Test-SectionEnabled 'ADCS') {

    Add-Section -Title 'ADCS Templates: ESC1 Indicator + Who Can Enroll' -Severity 'Critical' `
        -Description 'Templates where the enrollee supplies the subject (ENROLLEE_SUPPLIES_SUBJECT) AND client authentication is enabled -- then resolved to WHO holds enrollment rights on each. LikelyESC1 is true only when all four conditions hold: the template is published on a CA, needs no manager approval, requires NO authorized signatures (msPKI-RA-Signature = 0, newly checked here and a common source of false positives), and a broad principal (Domain Users, Authenticated Users, Domain Computers, Everyone) can enroll. Enrollment is counted from the Enroll and AutoEnroll extended rights and from GenericAll / all-extended-rights ACEs, the latter also implying ESC4 template hijack. Rows are ordered so LikelyESC1 surfaces first. Confirm with Certipy or Certify before acting.' -Query {
        $configNC = (Get-ADRootDSE @adParams).configurationNamingContext
        $pkiBase  = "CN=Public Key Services,CN=Services,$configNC"
        $tmplBase = "CN=Certificate Templates,$pkiBase"

        # If there is no PKI services container, report cleanly rather than erroring.
        if (-not (Get-ADObject -LDAPFilter '(cn=Certificate Templates)' -SearchBase $pkiBase @adParams -ErrorAction SilentlyContinue)) {
            [pscustomobject]@{ Template = '(No ADCS Certificate Templates container found)'
                               Note     = 'No enterprise CA or templates in this forest.' }
            return
        }

        # Templates actually published on an issuing CA -- only these are exploitable
        $published = @()
        try {
            $published = Get-ADObject -SearchBase "CN=Enrollment Services,$pkiBase" `
                            -LDAPFilter '(objectClass=pKIEnrollmentService)' `
                            -Properties certificateTemplates @adParams |
                         Select-Object -ExpandProperty certificateTemplates -ErrorAction SilentlyContinue |
                         Sort-Object -Unique
        } catch { }

        $clientAuthOids = @(
            '1.3.6.1.5.5.7.3.2',      # Client Authentication
            '1.3.6.1.5.2.3.4',        # PKINIT Client Authentication
            '1.3.6.1.4.1.311.20.2.2', # Smart Card Logon
            '2.5.29.37.0'             # Any Purpose
        )
        $enrollGuids = @{
            '0e10c968-78fb-11d2-90d4-00c04f79dc55' = 'Enroll'
            'a05b8cc2-17bc-4802-a710-e7c15ab866a2' = 'AutoEnroll'
        }
        # Broad principals whose enrollment turns a template into a real escalation path
        $broad = 'Everyone','Authenticated Users','Domain Users','Domain Computers','Users'

        Get-ADObject -SearchBase $tmplBase -LDAPFilter '(objectClass=pKICertificateTemplate)' `
          -Properties msPKI-Certificate-Name-Flag,pKIExtendedKeyUsage,msPKI-Enrollment-Flag,
                      msPKI-RA-Signature,displayName,name,nTSecurityDescriptor @adParams |
          Where-Object {
              ($_.'msPKI-Certificate-Name-Flag' -band 1) -and                        # ENROLLEE_SUPPLIES_SUBJECT
              ( ($_.pKIExtendedKeyUsage | Where-Object { $_ -in $clientAuthOids }) -or
                -not $_.pKIExtendedKeyUsage )                                        # client-auth capable (or no EKU = any purpose)
          } |
          ForEach-Object {
              $t = $_
              # Resolve principals who can enroll (or who fully control the template)
              $enrollers = foreach ($ace in $t.nTSecurityDescriptor.Access) {
                  if ($ace.AccessControlType -ne 'Allow') { continue }
                  $ot = $ace.ObjectType.ToString()
                  $isEnroll = ($ace.ActiveDirectoryRights -match 'ExtendedRight') -and $enrollGuids.ContainsKey($ot)
                  $isAllExt = ($ace.ActiveDirectoryRights -match 'ExtendedRight') -and
                              $ot -eq '00000000-0000-0000-0000-000000000000'
                  $isFull   = ($ace.ActiveDirectoryRights -match 'GenericAll')
                  if ($isEnroll -or $isAllExt -or $isFull) { $ace.IdentityReference.Value }
              }
              $enrollers   = @($enrollers | Sort-Object -Unique)
              $broadEnroll = @($enrollers | Where-Object { ($_ -split '\\')[-1] -in $broad })

              $isPublished = ($t.name -in $published)
              $noApproval  = -not ($t.'msPKI-Enrollment-Flag' -band 2)
              $noRaSig     = ([int]$t.'msPKI-RA-Signature' -le 0)
              $broadOk     = [bool]$broadEnroll.Count

              [pscustomobject]@{
                  Template             = $t.displayName
                  LikelyESC1           = ($isPublished -and $noApproval -and $noRaSig -and $broadOk)
                  Published            = $isPublished
                  NoManagerApproval    = $noApproval
                  NoAuthorizedSigs     = $noRaSig
                  BroadEnrollment      = $broadOk
                  EnrollmentPrincipals = ($enrollers -join '; ')
              }
          } |
          Sort-Object LikelyESC1, BroadEnrollment, Published, NoManagerApproval -Descending
    }
}

# ---------------------------------------------------------------------------
# Render HTML
#
#   [System.Net.WebUtility] is used instead of [System.Web.HttpUtility] so no
#   Add-Type is required and behaviour is identical on Windows PowerShell 5.1
#   and PowerShell 7.
# ---------------------------------------------------------------------------
function ConvertTo-HtmlEncoded { param([string]$Text) [System.Net.WebUtility]::HtmlEncode($Text) }

function ConvertTo-HtmlTable {
    param($Rows)
    if (-not $Rows -or @($Rows).Count -eq 0) { return '<p class="empty">No results &mdash; nothing flagged for this check.</p>' }
    $cols = ($Rows | Select-Object -First 1).PSObject.Properties.Name
    $sb = [System.Text.StringBuilder]::new()
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
    $sb.ToString()
}

$sevColour = @{ Critical = '#c0392b'; High = '#e67e22'; Medium = '#f1c40f'; Info = '#3498db' }

# Summary counts
$summaryRows = $report | ForEach-Object {
    [pscustomobject]@{
        Severity = $_.Severity
        Check    = $_.Title
        Findings = if ($_.Error) { 'ERROR' } else { $_.Count }
    }
}

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
    } else {
        [void]$body.Append((ConvertTo-HtmlTable -Rows $sec.Rows))
    }
    [void]$body.Append('</section>')
}

$summaryTable = ConvertTo-HtmlTable -Rows $summaryRows

$hDomain = ConvertTo-HtmlEncoded $domain.DNSRoot
$hForest = ConvertTo-HtmlEncoded $domain.Forest
$hRunBy  = ConvertTo-HtmlEncoded "$env:USERDOMAIN\$env:USERNAME"
$hTarget = ConvertTo-HtmlEncoded $(if ($Server) { $Server } else { '(auto-located DC)' })

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AD Security Audit - $hDomain</title>
<style>
    :root { font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
    body { margin: 0; background: #f4f6f8; color: #222; }
    header { background: #1f2d3d; color: #fff; padding: 24px 40px; }
    header h1 { margin: 0 0 4px; font-size: 22px; }
    header .meta { font-size: 13px; color: #b8c4d0; }
    header .classification { display: inline-block; margin-top: 12px; background: #c0392b; color: #fff;
              font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 3px;
              text-transform: uppercase; letter-spacing: .05em; }
    main { max-width: 1200px; margin: 24px auto; padding: 0 24px; }
    section { background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1);
              margin-bottom: 20px; padding: 16px 20px; }
    h2 { font-size: 16px; padding-left: 12px; display: flex; align-items: center; gap: 10px; }
    .badge { color: #fff; font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 10px;
             text-transform: uppercase; letter-spacing: .04em; }
    .count { margin-left: auto; font-size: 12px; color: #888; font-weight: 400; }
    .desc { font-size: 13px; color: #555; margin: 4px 0 12px; }
    table { border-collapse: collapse; width: 100%; font-size: 13px; }
    th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #eaeef1; }
    th { background: #f0f3f6; font-weight: 600; }
    tr:hover td { background: #fafbfc; }
    .empty { color: #27ae60; font-size: 13px; font-style: italic; }
    .error { color: #c0392b; font-size: 13px; }
    .summary th, .summary td { border-bottom: 1px solid #ddd; }
    footer { max-width: 1200px; margin: 0 auto 40px; padding: 0 24px; font-size: 12px; color: #999; }
</style>
</head>
<body>
<header>
    <h1>Active Directory Security Audit</h1>
    <div class="meta">
        Domain: $hDomain &nbsp;|&nbsp;
        Forest: $hForest &nbsp;|&nbsp;
        Target DC: $hTarget &nbsp;|&nbsp;
        Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp;
        Run by: $hRunBy &nbsp;|&nbsp;
        Inactive threshold: $InactiveDays days
    </div>
    <div class="classification">Restricted &mdash; contains privileged-account and attack-path detail</div>
</header>
<main>
    <section class="summary">
        <h2 style="border-left:6px solid #1f2d3d">Summary</h2>
        <p class="desc">Counts are objects flagged per check. A count of zero is generally good; investigate anything Critical or High with results, and treat ERROR rows as checks needing manual follow-up (usually a permissions or missing-feature issue). Rows reading QUERY FAILED or NOT AUDITED inside a section mean that portion was never evaluated &mdash; do not read them as clean.</p>
        $summaryTable
    </section>
    $($body.ToString())
</main>
<footer>
    Read-only audit. No directory objects were modified. LastLogonTimestamp-based checks may lag true activity by up to ~14 days &mdash; validate before acting.
    ADCS enrollment principals are resolved from template DACLs; confirm exploitability with Certipy or Certify before remediating.
    Privileged groups are resolved by well-known SID, with Enterprise Admins and Schema Admins read from the forest root.
    For scored, attack-path depth, pair this with PingCastle, BloodHound and Locksmith (ADCS).
</footer>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`nReport written to: $OutputPath" -ForegroundColor Green
Write-Warning "This report lists privileged accounts, DCSync holders, roastable service accounts and any live ESC1 paths. Store and transmit it as restricted material."

if (-not $NoLaunch) { try { Invoke-Item $OutputPath } catch { } }
