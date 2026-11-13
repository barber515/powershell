#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes all Veeam components from a Windows Server.

.DESCRIPTION
    Searches for and uninstalls all Veeam-related software found in the registry
    (Programs & Features), stops and removes Veeam services, and optionally cleans
    up leftover files and folders. Generates a transcript log.

    Every state-changing action is gated by ShouldProcess, so -WhatIf previews the
    full run without changing anything. Transcript logging itself is not gated.

    Exit codes:
      0 = success, nothing to remove, or user aborted at the prompt
      2 = non-interactive session without -Force; run aborted before changes
      3 = completed with failures or leftover components (re-run after a reboot)

.PARAMETER Force
    Skip the interactive confirmation prompt. Required for unattended runs.

.PARAMETER SkipFileCleanup
    Do not remove leftover Veeam program files/folders after uninstalling.

.PARAMETER RemoveRegistryKeys
    Also delete HKLM:\SOFTWARE\Veeam and its WOW6432Node counterpart at the end.
    Off by default because these keys can hold configuration and licensing data.

.PARAMETER LogPath
    Path for the transcript log file. Defaults to
    %SystemDrive%\VeeamRemovalLogs\VeeamRemoval_<timestamp>.log

.EXAMPLE
    .\VeeamCleaner.ps1 -WhatIf
    Preview every action without changing anything.

.EXAMPLE
    .\VeeamCleaner.ps1
    Interactive run with a confirmation prompt.

.EXAMPLE
    .\VeeamCleaner.ps1 -Force -LogPath "C:\Logs\VeeamRemoval.log"
    Unattended run, no prompt.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Force,
    [switch]$SkipFileCleanup,
    [switch]$RemoveRegistryKeys,
    [string]$LogPath
)

# ---------------------------------------------------------------------------
# HELPER: Get installed products from 64-bit, 32-bit, and current-user hives.
# HKCU reflects the user running this elevated session, not every console user.
# ---------------------------------------------------------------------------
function Get-InstalledVeeamProducts {
    $hivePaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($hivePath in $hivePaths) {
        if (-not (Test-Path -LiteralPath $hivePath)) { continue }
        Get-ItemProperty -Path (Join-Path $hivePath '*') -ErrorAction SilentlyContinue |
            Where-Object { ($_.DisplayName -match 'Veeam') -or ($_.Publisher -match 'Veeam') } |
            ForEach-Object {
                $found.Add([pscustomobject]@{
                    DisplayName          = $_.DisplayName
                    DisplayVersion       = $_.DisplayVersion
                    Publisher            = $_.Publisher
                    UninstallString      = $_.UninstallString
                    QuietUninstallString = $_.QuietUninstallString
                    PSChildName          = $_.PSChildName
                    SourcePath           = $hivePath
                })
            }
    }
    # Dedup by hive + key name so entries from different hives are never collapsed.
    $unique = @{}
    foreach ($item in $found) {
        $key = '{0}|{1}' -f $item.SourcePath, $item.PSChildName
        if (-not $unique.ContainsKey($key)) { $unique[$key] = $item }
    }
    return @($unique.Values | Sort-Object PSChildName)
}

# ---------------------------------------------------------------------------
# HELPER: Split an UninstallString into executable and arguments.
# Quote-aware; rejects ambiguous unquoted paths instead of guessing (H2).
# ---------------------------------------------------------------------------
function Split-UninstallString {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Raw)

    $trimmed = $Raw.Trim()
    if (-not $trimmed) { throw 'Empty uninstall string.' }

    $exe = ''
    $argLine = ''
    if ($trimmed.StartsWith('"')) {
        # Leading-quote case first so quoted non-.exe targets parse correctly.
        $endQuote = $trimmed.IndexOf('"', 1)
        if ($endQuote -lt 1) { throw "Unbalanced quote in uninstall string: $Raw" }
        $exe = $trimmed.Substring(1, $endQuote - 1)
        if ($trimmed.Length -gt $endQuote + 1) { $argLine = $trimmed.Substring($endQuote + 1).Trim() }
    }
    elseif (Test-Path -LiteralPath $trimmed) {
        # The whole string is an existing file path; no arguments.
        $exe = $trimmed
    }
    elseif ($trimmed -match '(?i)^(.+\.exe)(?:\s+(.*))?$') {
        # Unquoted path ending in .exe, with optional arguments.
        $exe = $Matches[1].Trim()
        if ($null -ne $Matches[2]) { $argLine = $Matches[2].Trim() }
    }
    elseif ($trimmed -match '^(\S+)\s+(.*)$') {
        # Unquoted executable token without spaces, plus arguments.
        $exe = $Matches[1]
        $argLine = $Matches[2]
        if (($exe.Contains('\')) -and (-not (Test-Path -LiteralPath $exe))) {
            throw "Cannot resolve uninstaller path; ambiguous quoting in: $Raw"
        }
    }
    else {
        $exe = $trimmed
    }

    # Resolve bare command names through PATH.
    if ($exe -and (-not ($exe.Contains('\'))) -and (-not (Test-Path -LiteralPath $exe))) {
        $app = Get-Command -Name $exe -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($app) { $exe = $app.Path }
    }
    if (-not $exe -or -not (Test-Path -LiteralPath $exe)) {
        throw "Uninstaller executable not found: $exe"
    }
    return [pscustomobject]@{ Exe = $exe; Args = $argLine }
}

# ---------------------------------------------------------------------------
# HELPER: True when any argument token is a recognized silent flag (H3).
# ---------------------------------------------------------------------------
function Test-SilentFlagPresent {
    [CmdletBinding()]
    param([string]$ArgumentLine)
    if ([string]::IsNullOrWhiteSpace($ArgumentLine)) { return $false }
    $silentFlags = @('/S','/VERYSILENT','/SILENT','/QUIET','/Q','/QN','/NORESTART','--SILENT','-S')
    foreach ($token in ($ArgumentLine -split '\s+')) {
        if (-not $token) { continue }
        $bare = ($token -split '=')[0]
        # -contains is case-insensitive for strings.
        if ($silentFlags -contains $bare) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------
# HELPER: Map an uninstaller exit code to a result category (M5).
# 1605/1614 mean the product is not installed; count them as already clean.
# ---------------------------------------------------------------------------
function Get-UninstallResultCategory {
    [CmdletBinding()]
    param($ExitCode)
    if ($null -eq $ExitCode) { return 'unknown' }
    switch ([int]$ExitCode) {
        0     { return 'success' }
        3010  { return 'reboot' }
        1605  { return 'already-clean' }
        1614  { return 'already-clean' }
        default { return 'failure' }
    }
}

# ---------------------------------------------------------------------------
# HELPER: Pending reboot check (L3); removal on a reboot-pending box often
# leaves components half-removed.
# ---------------------------------------------------------------------------
function Test-PendingReboot {
    $sessionMgmt = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $prop = Get-ItemProperty -Path $sessionMgmt -ErrorAction SilentlyContinue
    if ($prop -and ($prop.PSObject.Properties.Name -contains 'PendingFileRenameOperations')) {
        return $true
    }
    if (Test-Path -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion' +
            '\Component Based Servicing\RebootPending')) {
        return $true
    }
    return $false
}

# ---------------------------------------------------------------------------
# Logging setup (M7): dedicated log directory, transcript flag, single stop.
# ---------------------------------------------------------------------------
$msiLogDir = $null
if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $drive = 'C:'
    if (-not [string]::IsNullOrWhiteSpace($env:SystemDrive)) { $drive = $env:SystemDrive }
    $logDir = Join-Path $drive 'VeeamRemovalLogs'
    try {
        if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    } catch {
        Write-Warning ("Could not create {0}: {1}; falling back to %TEMP%." -f $logDir, $_.Exception.Message)
        $logDir = Join-Path $env:TEMP 'VeeamRemovalLogs'
        try { New-Item -ItemType Directory -Path $logDir -Force | Out-Null } catch { $logDir = $null }
    }
    if ($logDir) {
        $LogPath = Join-Path $logDir ('VeeamRemoval_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    } else {
        $LogPath = Join-Path $env:TEMP ('VeeamRemoval_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        $logDir  = Split-Path -Parent $LogPath
    }
} else {
    $logDir = Split-Path -Parent $LogPath
    if ($logDir -and (-not (Test-Path -LiteralPath $logDir))) {
        try { New-Item -ItemType Directory -Path $logDir -Force | Out-Null } catch { $logDir = $null }
    }
}
if ($logDir -and (Test-Path -LiteralPath $logDir)) { $msiLogDir = $logDir }

$transcriptStarted = $false
try {
    Start-Transcript -Path $LogPath -Append | Out-Null
    $transcriptStarted = $true
} catch {
    Write-Warning ("Could not start transcript at {0}: {1}" -f $LogPath, $_.Exception.Message)
}

# ---------------------------------------------------------------------------
# Body: every exit path runs the finally block, which stops the transcript.
# ---------------------------------------------------------------------------
try {
    Write-Host "`n=== Veeam Component Removal Script ===" -ForegroundColor Cyan
    Write-Host "Log: $LogPath"
    Write-Host "Started: $(Get-Date)`n"

    if (Test-PendingReboot) {
        Write-Warning 'A reboot is pending on this system. Consider rebooting first;'
        Write-Warning 'removing software while a reboot is pending can leave half-removed state.'
    }

    # -----------------------------------------------------------------------
    # STEP 1: Discover Veeam products
    # -----------------------------------------------------------------------
    Write-Host "--- Step 1: Discovering Veeam products ---" -ForegroundColor Yellow
    $veeamProducts = @(Get-InstalledVeeamProducts)

    if ($veeamProducts.Count -eq 0) {
        Write-Host "No Veeam products found in the registry. Nothing to uninstall." -ForegroundColor Green
    } else {
        Write-Host "Found $($veeamProducts.Count) Veeam product(s):" -ForegroundColor White
        $veeamProducts | ForEach-Object {
            Write-Host ("  [{0}] v{1} ({2})" -f $_.DisplayName, $_.DisplayVersion, $_.SourcePath)
        }
    }

    # -----------------------------------------------------------------------
    # STEP 2: Discover Veeam services
    # -----------------------------------------------------------------------
    Write-Host "`n--- Step 2: Discovering Veeam services ---" -ForegroundColor Yellow
    $veeamServices = @(Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Veeam' -or $_.Name -match 'Veeam' })

    if ($veeamServices.Count -eq 0) {
        Write-Host "No Veeam services found." -ForegroundColor Green
    } else {
        Write-Host "Found $($veeamServices.Count) Veeam service(s):" -ForegroundColor White
        $veeamServices | ForEach-Object {
            Write-Host ("  {0} ({1}) - {2}" -f $_.DisplayName, $_.Name, $_.Status)
        }
    }

    if ($veeamProducts.Count -eq 0 -and $veeamServices.Count -eq 0) {
        Write-Host "`nNothing to remove. Exiting." -ForegroundColor Green
        exit 0
    }

    # -----------------------------------------------------------------------
    # STEP 3: Confirm before proceeding (H4). Never block on input we cannot get.
    # -----------------------------------------------------------------------
    Write-Host "`n--- Step 3: Confirmation ---" -ForegroundColor Yellow
    if ($Force) {
        Write-Host "  -Force specified; skipping confirmation prompt."
    } elseif ($WhatIfPreference) {
        Write-Host "  WhatIf preview mode; no confirmation required and nothing will change."
    } elseif ([Environment]::UserInteractive -and (-not [Console]::IsInputRedirected)) {
        $proceed = $PSCmdlet.ShouldContinue(
            'This will uninstall all discovered Veeam components. Continue?',
            'Confirm Veeam removal')
        if (-not $proceed) {
            Write-Host "Aborted by user." -ForegroundColor Yellow
            exit 0
        }
    } else {
        Write-Warning 'Non-interactive session detected. Re-run with -Force to proceed unattended.'
        exit 2
    }

    # -----------------------------------------------------------------------
    # STEP 4: Stop Veeam services (H1: gated)
    # -----------------------------------------------------------------------
    Write-Host "`n--- Step 4: Stopping Veeam services ---" -ForegroundColor Yellow
    foreach ($svc in $veeamServices) {
        try {
            if ($svc.Status -ne 'Stopped') {
                if ($PSCmdlet.ShouldProcess($svc.DisplayName, 'Stop-Service')) {
                    Write-Host "  Stopping: $($svc.DisplayName)..."
                    Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                    Write-Host "  Stopped." -ForegroundColor Green
                }
            } else {
                Write-Host "  Already stopped: $($svc.DisplayName)" -ForegroundColor Gray
            }
        } catch {
            Write-Warning "  Could not stop $($svc.DisplayName): $_"
        }
    }

    # -----------------------------------------------------------------------
    # STEP 5: Uninstall Veeam products.
    # Preferred order: agents/plugins first, then backup components, core last.
    # Sort keys are rank, DisplayName, PSChildName so ordering is deterministic (M3).
    # -----------------------------------------------------------------------
    Write-Host "`n--- Step 5: Uninstalling Veeam products ---" -ForegroundColor Yellow

    $sortOrder = @('Agent','Plugin','Proxy','Tape','Gateway','Enterprise Manager','Backup & Replication')
    $sortedProducts = @($veeamProducts | Sort-Object {
        $rank = 99
        for ($i = 0; $i -lt $sortOrder.Count; $i++) {
            # Escape entries so regex metacharacters in names cannot throw (M4).
            if ($_.DisplayName -match [regex]::Escape($sortOrder[$i])) { $rank = $i; break }
        }
        $rank
    }, DisplayName, PSChildName)

    $successCount = 0
    $failCount    = 0

    foreach ($product in $sortedProducts) {
        Write-Host "`n  Uninstalling: $($product.DisplayName) v$($product.DisplayVersion)" -ForegroundColor White

        # Prefer QuietUninstallString, fall back to UninstallString.
        $uninstallCmd = if ($product.QuietUninstallString) {
            $product.QuietUninstallString
        } elseif ($product.UninstallString) {
            $product.UninstallString
        } else {
            $null
        }

        if (-not $uninstallCmd) {
            Write-Warning "  No uninstall string found for $($product.DisplayName). Skipping."
            $failCount++
            continue
        }

        try {
            $didRun = $false
            $proc   = $null

            if ($uninstallCmd -match '(?i)msiexec') {
                # MSI branch (M5): preserve vendor switches from QuietUninstallString.
                $parts    = Split-UninstallString -Raw $uninstallCmd
                $msiArgs  = $parts.Args
                if ($msiArgs -notmatch '\{[0-9A-Fa-f\-]{36}\}') {
                    # No usable product code in the string; rebuild from PSChildName.
                    if ($product.PSChildName -match '\{[0-9A-Fa-f\-]{36}\}') {
                        $msiArgs = '/x "{0}" /qn' -f $product.PSChildName
                    } else {
                        throw 'Could not extract MSI product GUID.'
                    }
                }
                if ($msiArgs -notmatch '(?i)/norestart') { $msiArgs += ' /norestart' }
                if ($msiLogDir) {
                    $safeName = ($product.PSChildName -replace '[^A-Za-z0-9._\-]', '_')
                    $msiLog   = Join-Path $msiLogDir ('msi_{0}_{1}.log' -f `
                        $safeName, (Get-Date -Format 'yyyyMMdd_HHmmss'))
                    $msiArgs += ' /L*V "{0}"' -f $msiLog
                }
                Write-Host "  Running: msiexec.exe $msiArgs"
                if ($PSCmdlet.ShouldProcess($product.DisplayName, 'Uninstall (MSI)')) {
                    $proc = Start-Process 'msiexec.exe' -ArgumentList $msiArgs `
                                -Wait -PassThru -ErrorAction Stop
                    $didRun = $true
                }
            } else {
                # EXE branch (H2/H3): native launch, quote-aware split, per-token
                # silent-flag detection, working directory set for relative paths.
                $parts   = Split-UninstallString -Raw $uninstallCmd
                $exePath = $parts.Exe
                $argLine = $parts.Args

                if (-not (Test-SilentFlagPresent -ArgumentLine $argLine)) {
                    $argLine = ($argLine + ' /S').Trim()
                    Write-Host "  No silent flag detected; appended /S."
                }

                Write-Host "  Running: $exePath $argLine"
                if ($PSCmdlet.ShouldProcess($product.DisplayName, 'Uninstall (EXE)')) {
                    $proc = Start-Process -FilePath $exePath -ArgumentList $argLine `
                                -WorkingDirectory (Split-Path -Parent $exePath) `
                                -Wait -PassThru -ErrorAction Stop
                    $didRun = $true
                }
            }

            if ($didRun) {
                switch (Get-UninstallResultCategory -ExitCode $proc.ExitCode) {
                    'success'       {
                        Write-Host ("  Success (exit code {0})" -f $proc.ExitCode) -ForegroundColor Green
                        $successCount++
                    }
                    'reboot'        {
                        $msg = "  Success (exit code {0}) - reboot required" -f $proc.ExitCode
                        Write-Host $msg -ForegroundColor Green
                        $successCount++
                    }
                    'already-clean' {
                        $msg = "  Not installed (exit code {0}); counted as clean." -f $proc.ExitCode
                        Write-Host $msg -ForegroundColor Gray
                        $successCount++
                    }
                    'unknown'       {
                        Write-Warning "  Uninstaller exit code unavailable; treating as failure."
                        $failCount++
                    }
                    default         {
                        Write-Warning ("  Exit code {0}; may not have uninstalled cleanly." -f $proc.ExitCode)
                        $failCount++
                    }
                }
            }
        } catch {
            Write-Warning "  ERROR uninstalling $($product.DisplayName): $_"
            $failCount++
        }
    }

    # -----------------------------------------------------------------------
    # STEP 6: Remove leftover Veeam services (M1). Runs after the uninstallers,
    # because successful uninstalls normally take their own services with them.
    # -----------------------------------------------------------------------
    Write-Host "`n--- Step 6: Removing leftover Veeam services ---" -ForegroundColor Yellow
    $leftoverServices = @(Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Veeam' -or $_.Name -match 'Veeam' })
    $servicesRemoved = 0
    if ($leftoverServices.Count -eq 0) {
        Write-Host "  No leftover Veeam services found." -ForegroundColor Green
    } else {
        foreach ($svc in $leftoverServices) {
            try {
                if ($svc.Status -ne 'Stopped') {
                    if ($PSCmdlet.ShouldProcess($svc.DisplayName, 'Stop-Service')) {
                        Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                    }
                }
                if ($PSCmdlet.ShouldProcess($svc.DisplayName, 'Remove leftover service (sc.exe delete)')) {
                    $scOut = & sc.exe delete $svc.Name 2>&1 | Out-String
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host ("  Removed service: {0}" -f $svc.DisplayName) -ForegroundColor Green
                        $servicesRemoved++
                    } else {
                        Write-Warning ("  Could not remove service {0} (sc.exe exit {1}): {2}" -f `
                            $svc.DisplayName, $LASTEXITCODE, $scOut.Trim())
                    }
                }
            } catch {
                Write-Warning "  Could not remove service $($svc.Name): $_"
            }
        }
    }

    # -----------------------------------------------------------------------
    # STEP 7: Remove leftover files / folders (M6 hardened).
    # Paths are built only from present env vars and must resolve under a known
    # root, so missing variables can never yield \Veeam or UNC-rooted targets.
    # -----------------------------------------------------------------------
    if (-not $SkipFileCleanup) {
        Write-Host "`n--- Step 7: Cleaning up leftover files ---" -ForegroundColor Yellow

        $envRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $allowedRoots = foreach ($r in $envRoots) {
            try { [System.IO.Path]::GetFullPath($r) } catch { $null }
        }

        $veeamPaths = @()
        if ($env:ProgramFiles) {
            $veeamPaths += (Join-Path $env:ProgramFiles 'Veeam')
            $veeamPaths += (Join-Path $env:ProgramFiles 'Common Files\Veeam')
        }
        if (${env:ProgramFiles(x86)}) {
            $veeamPaths += (Join-Path ${env:ProgramFiles(x86)} 'Veeam')
            $veeamPaths += (Join-Path ${env:ProgramFiles(x86)} 'Common Files\Veeam')
        }
        # ALLUSERSPROFILE\Veeam intentionally omitted; it resolves to ProgramData\Veeam.

        foreach ($path in $veeamPaths) {
            try {
                $full = [System.IO.Path]::GetFullPath($path)
            } catch {
                Write-Warning "  Skipping invalid path entry: $path"
                continue
            }

            $allowed = $false
            foreach ($root in $allowedRoots) {
                if (-not $root) { continue }
                if ($full.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $allowed = $true; break
                }
            }
            if (-not $allowed) {
                Write-Warning "  Refusing to delete path outside known roots: $full"
                continue
            }

            if ([System.IO.Directory]::Exists($full)) {
                # Never follow junctions/reparse points into unknown storage.
                $item = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
                if ($item -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                    Write-Warning "  Skipping reparse point: $full"
                    continue
                }

                if ($PSCmdlet.ShouldProcess($full, 'Remove-Item')) {
                    try {
                        Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
                        Write-Host "  Removed: $full" -ForegroundColor Green
                    } catch {
                        Write-Warning "  Could not remove $full : $_"
                    }
                }
            }
        }

        if ($RemoveRegistryKeys) {
            foreach ($regKey in 'HKLM:\SOFTWARE\Veeam', 'HKLM:\SOFTWARE\WOW6432Node\Veeam') {
                if (Test-Path -LiteralPath $regKey) {
                    if ($PSCmdlet.ShouldProcess($regKey, 'Remove registry key')) {
                        try {
                            Remove-Item -LiteralPath $regKey -Recurse -Force -ErrorAction Stop
                            Write-Host "  Removed: $regKey" -ForegroundColor Green
                        } catch {
                            Write-Warning "  Could not remove $regKey : $_"
                        }
                    }
                }
            }
        } else {
            Write-Host "  Registry keys under HKLM\SOFTWARE\Veeam left in place (use -RemoveRegistryKeys)." `
                -ForegroundColor Gray
        }
    } else {
        Write-Host "`n--- Step 7: Skipping file cleanup (SkipFileCleanup specified) ---" -ForegroundColor Gray
    }

    # -----------------------------------------------------------------------
    # STEP 8: Re-check registry and services to confirm removal (M1).
    # -----------------------------------------------------------------------
    Write-Host "`n--- Step 8: Verifying removal ---" -ForegroundColor Yellow
    $remaining = @(Get-InstalledVeeamProducts)
    if ($remaining.Count -eq 0) {
        Write-Host "  All Veeam products have been removed from the registry." -ForegroundColor Green
    } else {
        Write-Host "  The following Veeam products still appear in the registry:" -ForegroundColor Red
        $remaining | ForEach-Object { Write-Host ("    {0} v{1}" -f $_.DisplayName, $_.DisplayVersion) }
        Write-Host "  You may need to reboot and re-run, or remove these manually." -ForegroundColor Yellow
    }

    $remainingServices = @(Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Veeam' -or $_.Name -match 'Veeam' })
    if ($remainingServices.Count -eq 0) {
        Write-Host "  No Veeam services remain." -ForegroundColor Green
    } else {
        Write-Host ("  {0} Veeam service(s) still registered:" -f $remainingServices.Count) -ForegroundColor Red
        $remainingServices | ForEach-Object { Write-Host ("    {0} ({1})" -f $_.DisplayName, $_.Name) }
    }

    # -----------------------------------------------------------------------
    # Summary (L7): human-readable lines plus one returnable object.
    # -----------------------------------------------------------------------
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "  Products found     : $($veeamProducts.Count)"
    Write-Host "  Uninstalled OK     : $successCount" -ForegroundColor Green
    if ($failCount -gt 0) {
        Write-Host "  Failed / skipped   : $failCount" -ForegroundColor Red
    }
    Write-Host "  Services removed   : $servicesRemoved"
    Write-Host "  Remaining products : $($remaining.Count)"
    Write-Host "  Remaining services : $($remainingServices.Count)"
    Write-Host "  Log saved to       : $LogPath"

    $summary = [pscustomobject]@{
        ProductsFound     = $veeamProducts.Count
        UninstalledOk     = $successCount
        FailedOrSkipped   = $failCount
        ServicesRemoved   = $servicesRemoved
        RemainingProducts = $remaining.Count
        RemainingServices = $remainingServices.Count
        PendingReboot     = [bool](Test-PendingReboot)
        LogPath           = $LogPath
    }

    if ($WhatIfPreference) {
        Write-Host "`nDone. WhatIf preview only; nothing was changed.`n" -ForegroundColor Cyan
        Write-Output $summary
        exit 0
    }

    if ($remaining.Count -gt 0 -or $failCount -gt 0 -or $remainingServices.Count -gt 0) {
        Write-Host "`nDone. A reboot followed by a second run may be required.`n" -ForegroundColor Cyan
        Write-Output $summary
        exit 3
    }

    Write-Host "`nDone. A reboot is recommended to complete cleanup.`n" -ForegroundColor Cyan
    Write-Output $summary
    exit 0
}
finally {
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
}
