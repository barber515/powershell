#Requires -Version 5.1

<#
.SYNOPSIS
    Generate a PKCS#10 Certificate Signing Request (CSR) using SHA-256 and RSA-2048 via certreq.exe.
.DESCRIPTION
    Interactive PowerShell script that collects subject details and SAN entries,
    builds an INF template, and invokes certreq.exe to produce a CSR file.

    All input fields are validated against RFC 5280 constraints and INF-safe patterns.
.PARAMETER CN
    Common Name (e.g., server.example.com). Max 64 characters.
.PARAMETER O
    Organisation name.
.PARAMETER OU
    Organisational Unit.
.PARAMETER L
    Locality / City.
.PARAMETER S
    State / Province.
.PARAMETER C
    Two-letter Country Code (ISO 3166-1 alpha-2).
.PARAMETER SANs
    Subject Alternative Names as DNS entries. Supports wildcards (*.example.com) with a security warning.
    Each entry is validated against RFC 1123 hostname rules; bare wildcards (e.g., '*.') are rejected.
.PARAMETER MaxSanEntries
    Maximum number of SAN entries allowed. Default: 100. Range: 1-500.
.EXAMPLE
    .\poshreq.ps1
.EXAMPLE
    .\poshreq.ps1 -CN "web01.example.com" -O "Acme Corp" -C "US" -SANs @("www.example.com","mail.example.com")
#>

[CmdletBinding()]
param(
    # Common Name - RFC 5280 limits RDN to 64 chars; block INF-breaking characters.
    [Parameter(Mandatory = $true)]
    [ValidateLength(1, 64)]
    [ValidatePattern('^[^"\\\r\n]+$')]
    [string]$CN,

    # Organisation - block quotes, backslashes, newlines.
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[^"\\\r\n]+$')]
    [string]$O,

    # Organisational Unit - same constraints as O.
    [Parameter()]
    [ValidatePattern('^[^"\\\r\n]+$')]
    [string]$OU = '',

    # Locality / City - same constraints.
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[^"\\\r\n]+$')]
    [string]$L = '',

    # State - same constraints.
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[^"\\\r\n]+$')]
    [string]$S = '',

    # Country Code - enforce exactly 2 uppercase letters.
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[A-Z]{2}$')]
    [string]$C = '',

    # SANs - DNS name format; wildcards allowed but warned.
    # Wildcard entries must be properly formatted (e.g., *.example.com).
    # Duplicates are skipped. Max count enforced to prevent oversized CSRs.
    [Parameter()]
    [string[]]$SANs = @(),

    # Maximum number of SAN entries to prevent oversized CSRs.
    [Parameter()]
    [ValidateRange(1, 500)]
    [int]$MaxSanEntries = 100
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ── Helper: validate a single SAN entry ───────────────────────────────────
function Test-SanEntry {
    param(
        [string]$Entry,
        [int]$MaxEntries
    )
    $errors = @()

    # Strip INF-breaking characters.
    $sanCleaned = $Entry.Trim()
    if ($sanCleaned -match '["\r\n\\]') {
        Write-Host "    WARNING: Invalid characters stripped from SAN entry." -ForegroundColor Yellow
        $sanCleaned = ($sanCleaned -replace '["\r\n\\]', '')
    }

    # Basic DNS name format check.
    if ($sanCleaned -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]*$') {
        $errors += "'$Entry' does not look like a valid DNS name."
        return @{ Valid = $false; Cleaned = ''; Errors = $errors }
    }

    # Wildcard entries must be properly formatted: *.example.com (not just '*.' or '*').
    if ($sanCleaned -match '^\*\.') {
        if ($sanCleaned -eq '*.' -or $sanCleaned -match '^\*\.$') {
            $errors += "Wildcard SAN '$Entry' is invalid - must include a domain after the dot (e.g., *.example.com)."
        } elseif ($sanCleaned -notmatch '^\*\.[a-zA-Z0-9][a-zA-Z0-9.-]*$') {
            $errors += "Wildcard SAN '$Entry' has an invalid domain portion after '*.'"
        }
    }

    # Enforce RFC 1123 hostname rules via .NET.
    if (-not [System.Net.Dns]::TryGetHostName($sanCleaned)) {
        $errors += "'$sanCleaned' fails RFC 1123 hostname validation."
    }

    return @{ Valid = ($errors.Count -eq 0); Cleaned = $sanCleaned; Errors = $errors }
}

# ── Helper: warn about wildcard SAN entries ────────────────────────────────
function Write-SanWildcardWarning {
    param([string[]]$Entries)
    $wildcards = $Entries | Where-Object { $_ -match '^\*\.' }
    if ($wildcards.Count -gt 0) {
        Write-Host ""
        Write-Host "WARNING: The following SAN entries use wildcards and significantly expand the certificate's blast radius:" -ForegroundColor Yellow
        foreach ($wc in $wildcards) {
            Write-Host "  * $wc - a single compromised private key exposes all subdomains of its parent domain." -ForegroundColor DarkYellow
        }
        Write-Host "Ensure this is intentional before proceeding." -ForegroundColor Yellow
        Write-Host ""
    }
}

# ── Interactive input mode (when no parameters supplied) ───────────────────
if ($MyInvocation.BoundParameters.Count -eq 0) {
    # Prompt loop for CN with inline validation feedback.
    do {
        $cnInput = Read-Host "Common Name (CN) [max 64 chars]"
        if ([string]::IsNullOrWhiteSpace($cnInput)) {
            Write-Host "  ERROR: Common Name is required." -ForegroundColor Red
        } elseif ($cnInput.Length -gt 64) {
            Write-Host "  ERROR: Common Name exceeds 64 characters. Current length: $($cnInput.Length)." -ForegroundColor Red
        } elseif ($cnInput -match '[\"\r\n\\]') {
            Write-Host "  ERROR: Common Name contains invalid characters (quotes, backslashes, or newlines are not allowed)." -ForegroundColor Red
        } else {
            $CN = $cnInput.Trim()
        }
    } while ([string]::IsNullOrWhiteSpace($CN))

    # Organisation
    do {
        $oInput = Read-Host "Organisation (O)"
        if ([string]::IsNullOrWhiteSpace($oInput)) {
            Write-Host "  ERROR: Organisation is required." -ForegroundColor Red
        } elseif ($oInput -match '[\"\r\n\\]') {
            Write-Host "  ERROR: Organisation contains invalid characters (quotes, backslashes, or newlines are not allowed)." -ForegroundColor Red
        } else {
            $O = $oInput.Trim()
        }
    } while ([string]::IsNullOrWhiteSpace($O))

    # Organisational Unit (optional)
    $ouInput = Read-Host "Organisational Unit (OU) [optional]"
    if (-not [string]::IsNullOrWhiteSpace($ouInput)) {
        $ouCleaned = $ouInput.Trim()
        if ($ouCleaned -match '[\"\r\n\\]') {
            Write-Host "  WARNING: OU contains invalid characters - they have been stripped." -ForegroundColor Yellow
            $ouCleaned = ($ouCleaned -replace '[\"\r\n\\]', '')
        }
        $OU = $ouCleaned
    }

    # Locality / City (optional)
    $lInput = Read-Host "Locality / City (L) [optional]"
    if (-not [string]::IsNullOrWhiteSpace($lInput)) {
        $lCleaned = $lInput.Trim()
        if ($lCleaned -match '[\"\r\n\\]') {
            Write-Host "  WARNING: Locality contains invalid characters - they have been stripped." -ForegroundColor Yellow
            $lCleaned = ($lCleaned -replace '[\"\r\n\\]', '')
        }
        $L = $lCleaned
    }

    # State (optional)
    $sInput = Read-Host "State (S) [optional]"
    if (-not [string]::IsNullOrWhiteSpace($sInput)) {
        $sCleaned = $sInput.Trim()
        if ($sCleaned -match '[\"\r\n\\]') {
            Write-Host "  WARNING: State contains invalid characters - they have been stripped." -ForegroundColor Yellow
            $sCleaned = ($sCleaned -replace '[\"\r\n\\]', '')
        }
        $S = $sCleaned
    }

    # Country Code (optional)
    $cInput = Read-Host "Country Code (C) [e.g. US, GB, DE - optional]"
    if (-not [string]::IsNullOrWhiteSpace($cInput)) {
        $cCleaned = $cInput.Trim()
        if ($cCleaned.Length -ne 2 -or $cCleaned -notmatch '^[A-Z]{2}$') {
            Write-Host "  WARNING: Country Code must be exactly 2 uppercase letters (e.g. US). Leaving blank." -ForegroundColor Yellow
            $C = ''
        } else {
            $C = $cCleaned.ToUpper()
        }
    }

    # Subject Alternative Names - interactive loop with full validation + wildcard warning.
    Write-Host ""
    Write-Host "Enter Subject Alternative Names (DNS entries). Leave blank to finish." -ForegroundColor Yellow
    $sanList = @()
    $i = 1
    do {
        $sanInput = Read-Host "  SAN entry #$i"
        if ([string]::IsNullOrWhiteSpace($sanInput)) { break }

        # Enforce max SAN count before processing.
        if ($sanList.Count -ge $MaxSanEntries) {
            Write-Host "    ERROR: Maximum of $MaxSanEntries SAN entries reached." -ForegroundColor Red
            continue
        }

        $result = Test-SanEntry -Entry $sanInput -MaxEntries $MaxSanEntries
        if (-not $result.Valid) {
            foreach ($err in $result.Errors) {
                Write-Host "    ERROR: $err" -ForegroundColor Red
            }
            continue
        }

        # Check for duplicates.
        if ($sanList -contains $result.Cleaned) {
            Write-Host "    WARNING: '$($result.Cleaned)' is a duplicate - skipping." -ForegroundColor Yellow
            continue
        }

        $sanList += $result.Cleaned
        $i++
    } while ($true)

    if ($sanList.Count -gt 0) {
        Write-SanWildcardWarning($sanList)
        $SANs = $sanList
    }
} else {
    # --- Parameter mode - validate SANs and apply wildcard warning ---
    $validatedSanList = @()
    foreach ($sanItem in $SANs) {
        if ($validatedSanList.Count -ge $MaxSanEntries) {
            Write-Host "" -ForegroundColor Yellow
            Write-Host "WARNING: Only the first $MaxSanEntries SAN entries will be used (input contained $($SANs.Count))." -ForegroundColor DarkYellow
            break
        }

        # Skip duplicates.
        if ($validatedSanList -contains $sanItem) {
            continue
        }

        $result = Test-SanEntry -Entry $sanItem -MaxEntries $MaxSanEntries
        if (-not $result.Valid) {
            Write-Host "" -ForegroundColor Yellow
            Write-Host "ERROR: SAN validation failed for '$sanItem':" -ForegroundColor Red
            foreach ($err in $result.Errors) {
                Write-Host "  - $err" -ForegroundColor Red
            }
            exit 1
        }

        $validatedSanList += $result.Cleaned
    }

    if ($validatedSanList.Count -gt 0) {
        Write-SanWildcardWarning($validatedSanList)
        $SANs = $validatedSanList
    } else {
        $SANs = @()
    }
}

# ── Prerequisite: Administrator check ──────────────────────────────────────
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "Administrator privileges are required. Please restart this script with elevated rights." -ForegroundColor Red
    Start-Sleep -Seconds 5
    Throw "Administrator privileges are required. Please restart this script with elevated rights."
}

# ── Build INF template and generate CSR ────────────────────────────────────
$UID = [guid]::NewGuid()
$files = @{}
$files['settings'] = "$($env:TEMP)\$($UID)-settings.inf"
$files['csr']      = "$($env:TEMP)\$($UID)-csr.req"

# Build the Subject line - optional fields only included when provided.
$subjectLine = "CN=$CN"
if ($OU) { $subjectLine += ",OU=$OU" }
$subjectLine += ",O=$O"
if ($L)  { $subjectLine += ",L=$L" }
if ($S)  { $subjectLine += ",S=$S" }
if ($C)  { $subjectLine += ",C=$C" }

$settingsInf = @"
[Version]
Signature=`"$$Windows NT`"
[NewRequest]
KeyLength =  2048
Exportable = TRUE
FriendlyName = new_cert
MachineKeySet = TRUE
SMIME = FALSE
RequestType =  PKCS10
ProviderName = `"Microsoft RSA SChannel Cryptographic Provider`"
ProviderType =  12
HashAlgorithm = sha256
Subject = "$subjectLine"

;Certreq info
;http://technet.microsoft.com/en-us/library/dn296456.aspx
;CSR Decoder
;https://certlogik.com/decoder/
;https://ssltools.websecurity.symantec.com/checker/views/csrCheck.jsp
"@

# Build SAN extension block if entries exist.
if ($SANs.Count -gt 0) {
    $sanBlock = "2.5.29.17 = `"{text}`"`r`n"
    foreach ($sanItem in $SANs) {
        $sanBlock += "_continue_ = `"dns=$sanItem`"`r`n"
    }
    $settingsInf += "`r`n[Extensions]`r`n$sanBlock"
}

# Save INF (ASCII - UTF-8 BOM breaks certreq.exe).
$settingsInf | Set-Content -Path $files['settings'] -Encoding ASCII
Write-Host "INF file written: $($files['settings'])" -ForegroundColor Cyan

Clear-Host

# ── Display summary ────────────────────────────────────────────────────────
$sanDisplay = if ($SANs.Count -gt 0) { $SANs -join ", " } else { "(none)" }

Write-Host @"
Certificate information
Common name:      $CN
Organisation:     $O
Organisational unit: $(if ($OU) { $OU } else { "(not set)" })
City:             $(if ($L) { $L } else { "(not set)" })
State:            $(if ($S) { $S } else { "(not set)" })
Country:          $(if ($C) { $C } else { "(not set)" })

Subject alternative name(s): $sanDisplay

Signature algorithm: SHA256
Key algorithm:       RSA
Key size:            2048
"@ -ForegroundColor Yellow

# ── Run certreq.exe ────────────────────────────────────────────────────────
$certreqOutput = & certreq -new $files['settings'] $files['csr'] 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to generate CSR. Output: $($certreqOutput -join '`r`n')"
    exit 1
}

if (-not (Test-Path $files['csr'])) {
    Write-Error "Failed to generate CSR. certreq.exe did not produce a .req file."
    exit 1
}

# ── Output the CSR ─────────────────────────────────────────────────────────
$CSR = Get-Content $files['csr']
Write-Output $CSR
Write-Host ""

# Optional clipboard copy.
Write-Host "Copy CSR to clipboard? (y|n): " -ForegroundColor Yellow -NoNewline
if ((Read-Host) -ieq "y") {
    $CSR | clip
    Write-Host "Check your ctrl+v"
}

# ── Cleanup ────────────────────────────────────────────────────────────────
$files.Values | ForEach-Object {
    Remove-Item $_ -ErrorAction SilentlyContinue
}
