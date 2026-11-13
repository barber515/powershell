# =====================================================================
# DecomHtmlReport.ps1
# HTML report helpers for decomDC.ps1 (DC-Decom-Discovery).
#
# Implements the reporting pattern in html-template.md, extended with:
#   - raw text sections (repadmin / dcdiag / w32tm / dfsrmig output)
#   - data driven severity escalation (severity follows the findings)
#   - a demote readiness verdict banner and per section status column
#
# Dot source this file from decomDC.ps1. It produces no output on its own.
# Runs on Windows PowerShell 5.1 and PowerShell 7+. No external modules.
# =====================================================================

#region ---- html-template.md section 1: HTML encoding helper ----
function ConvertTo-HtmlEncoded {
    [CmdletBinding()]
    param([string]$Text)
    [System.Net.WebUtility]::HtmlEncode($Text)
}
#endregion

#region ---- html-template.md section 2: table renderer (+ -Class, -EmptyText) ----
function ConvertTo-HtmlTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Rows,
        # Extension: CSS class applied to the <table> element (for example 'summary').
        [string]$Class,
        # Extension: wording used when a section legitimately returns no rows.
        [string]$EmptyText = 'No results - nothing flagged for this check.'
    )

    if (-not $Rows -or @($Rows).Count -eq 0) {
        return "<p class='empty'>$(ConvertTo-HtmlEncoded $EmptyText)</p>"
    }

    # Normalise every row to the column set of the first row so ragged input
    # cannot produce malformed HTML.
    $cols = @((($Rows | Select-Object -First 1).PSObject.Properties.Name))
    if ($Class) { $tableTag = "<table class='$Class'>" } else { $tableTag = '<table>' }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append($tableTag)
    [void]$sb.Append('<thead><tr>')
    foreach ($c in $cols) {
        [void]$sb.Append("<th>$(ConvertTo-HtmlEncoded $c)</th>")
    }
    [void]$sb.Append('</tr></thead><tbody>')

    foreach ($r in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $cols) {
            $val = [string]$r.$c          # null becomes "" before encoding
            [void]$sb.Append("<td>$(ConvertTo-HtmlEncoded $val)</td>")
        }
        [void]$sb.Append('</tr>')
    }

    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}
#endregion

#region ---- Extension: raw text renderer (non tabular command output) ----
function ConvertTo-HtmlPre {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Lines = @(),
        # Long tool output is truncated in the HTML; the evidence file keeps it all.
        [int]$MaxLines = 400,
        [string]$EvidenceFile
    )

    $all = @($Lines | ForEach-Object { [string]$_ })
    if ($all.Count -eq 0) {
        return "<p class='empty'>Command produced no output.</p>"
    }

    $omitted = 0
    $shown   = $all
    if ($MaxLines -gt 0 -and $all.Count -gt $MaxLines) {
        $shown   = $all[0..($MaxLines - 1)]
        $omitted = $all.Count - $MaxLines
    }

    $text = ($shown | ForEach-Object { ConvertTo-HtmlEncoded $_ }) -join "`n"
    if ($omitted -gt 0) {
        $tail = "... output truncated: $omitted more line(s). Full output is in the evidence file."
        $text += "`n" + (ConvertTo-HtmlEncoded $tail)
    }

    $out = "<pre class='raw'>$text</pre>"
    if ($EvidenceFile) {
        $out += "<p class='evidence'>Full output: $(ConvertTo-HtmlEncoded $EvidenceFile)</p>"
    }
    return $out
}
#endregion

#region ---- html-template.md section 3: severity map + Add-Section (superset) ----
$DcSeverityColour = @{
    Critical = '#c0392b'   # dark red - blocks the demotion window
    High     = '#e67e22'   # orange   - must be remediated before cutover
    Medium   = '#f1c40f'   # yellow   - verify manually
    Info     = '#3498db'   # blue     - inventory / clean state
}

$DcStatusColour = @{
    BLOCKER = '#c0392b'
    REVIEW  = '#e67e22'
    CHECK   = '#f1c40f'
    OK      = '#27ae60'
    ERROR   = '#8e44ad'
}

function Add-Section {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title,
        [string]$Description,
        [ValidateSet('Critical','High','Medium','Info')]
        [string]$Severity = 'Info',
        [scriptblock]$Query,

        # --- Extensions -------------------------------------------------
        # Force the section body to render as <pre> even if rows are objects.
        [switch]$AsText,
        # Wording shown when zero rows is expected and acceptable.
        [string]$EmptyText = 'No results - nothing flagged for this check.',
        # Emits one object per blocking row; any output raises the severity.
        # Must start with param($Rows); Add-Section enforces this.
        [scriptblock]$EscalateWhen,
        [ValidateSet('Critical','High','Medium','Info')]
        [string]$EscalateTo = 'Critical',
        # Raise severity when an expected-to-have-content check came back empty
        # (for example "new DCs must advertise every SRV locator record").
        [switch]$EscalateWhenEmpty,
        # Evidence file names written by Save(), shown as a footnote.
        [string[]]$EvidenceFile
    )

    Write-Verbose ("  - {0}" -f $Title)

    # Note: an empty List[T] is falsy in PowerShell, so test for null explicitly.
    if ($null -eq $report) {
        throw 'Add-Section: the $report collection does not exist. Create it before calling Add-Section.'
    }

    # An escalation block receives the rows positionally, so it must name them.
    # Checked BEFORE the query runs: a missing param($Rows) silently disables an
    # escalation forever, which is worse than failing here at registration time.
    if ($EscalateTo -and $EscalateWhen -and -not $EscalateWhen.Ast.ParamBlock) {
        throw ("Add-Section '{0}': declares -EscalateTo '{1}' but its -EscalateWhen block has no param($Rows)." -f $Title, $EscalateTo)
    }
    # The mirror image of the same defect: a predicate that can raise severity but
    # nowhere to raise it to. Treated as a mistake rather than left implicit.
    if ($EscalateWhen -and -not $PSBoundParameters.ContainsKey('EscalateTo')) {
        Write-Verbose ("  note: '{0}' escalates via -EscalateWhen with the default target 'Critical'." -f $Title)
    }

    $rows = @()
    $err  = $null
    try {
        if ($Query) {
            $result = & $Query
            if ($null -ne $result) { $rows = @($result) }
        }
    }
    catch {
        $err = $_.Exception.Message
    }

    # Text sections: every row is a plain string or an ErrorRecord line.
    $nonText = @($rows | Where-Object { $_ -isnot [string] -and $_ -isnot [System.Management.Automation.ErrorRecord] })
    $isText  = ($AsText -or ($rows.Count -gt 0 -and $nonText.Count -eq 0))

    # Severity follows the findings, not just the author's assumption.
    $baseSeverity = $Severity
    $escalated    = $false
    if (-not $err) {
        $raise = $false
        if ($EscalateWhenEmpty -and $rows.Count -eq 0) { $raise = $true }
        if ($EscalateWhen) {
            $blockers = @(& $EscalateWhen $rows)
            if ($blockers.Count -gt 0) { $raise = $true }
        }
        if ($raise -and $Severity -ne $EscalateTo) {
            $Severity    = $EscalateTo
            $escalated   = $true
        }
    }

    $report.Add([pscustomobject]@{
        Title        = $Title
        Description  = $Description
        Severity     = $Severity
        BaseSeverity = $baseSeverity
        Escalated    = $escalated
        Rows         = $rows
        Count        = $rows.Count
        IsText       = [bool]$isText
        EmptyText    = $EmptyText
        EvidenceFile = @($EvidenceFile)
        Error        = $err
    })
}

function Get-SectionStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Section)

    if ($Section.Error) { return 'ERROR' }

    # An escalated section is a finding even when it produced zero rows:
    # that is exactly the escalate-on-empty case (missing SRV records, and so on).
    $hasFinding = ($Section.Count -gt 0) -or [bool]$Section.Escalated
    if (-not $hasFinding) { return 'OK' }

    switch ($Section.Severity) {
        'Critical' { 'BLOCKER' }
        'High'     { 'REVIEW' }
        'Medium'   { 'CHECK' }
        default    { 'INFO' }
    }
}

function Get-DemoteVerdict {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Report)

    $blockers = @()
    $review   = @()
    foreach ($sec in $Report) {
        switch (Get-SectionStatus -Section $sec) {
            'BLOCKER' { $blockers += $sec.Title }
            'ERROR'   { $blockers += ("{0} (query error)" -f $sec.Title) }
            'REVIEW'  { $review   += $sec.Title }
        }
    }

    if ($blockers.Count -gt 0) {
        $label = 'NOT READY TO DEMOTE'
        $class = 'blocked'
    }
    elseif ($review.Count -gt 0) {
        $label = 'CONDITIONAL - MANUAL REVIEW REQUIRED'
        $class = 'conditional'
    }
    else {
        $label = 'NO AUTOMATED BLOCKERS FOUND'
        $class = 'clear'
    }

    [pscustomobject]@{
        Ready       = ($blockers.Count -eq 0)
        Label       = $label
        CssClass    = $class
        BlockerList = $blockers
        ReviewList  = $review
    }
}
#endregion

#region ---- Extension: parsers for non tabular tool output --------------------
# Every parser in this region follows the same contract, because a check that
# silently parses nothing renders as a clean green section, which is the most
# dangerous possible misreading of a go/no-go report:
#   - accepts $null and blank lines (tool output always has blank lines);
#   - throws when the tool produced no output at all;
#   - throws when there was output but nothing matched, unless the parser can
#     positively prove it looked at the right kind of text.

function Get-ReplSummaryRow {
    [CmdletBinding()]
    param(
        # Mandatory string parameters gain an implicit 'not empty' check, which would
        # reject the blank lines that tool output always contains.
        [AllowNull()][AllowEmptyCollection()][AllowEmptyString()][string[]]$Output = @(),
        # Emit a row for every line under the Source/Destination tables that is not
        # recognised, so an unresponsive DC cannot disappear from the report.
        [switch]$Lenient
    )

    # Real 'repadmin /replsummary' layout (columns, not key/value):
    #   Source DSA          largest delta    fails/total   %% error
    #   ==================  ===============  ==========   ======
    #    DC1               52m:48s          0 / 5         0
    #    HQSVR01           41d.22h:53m:53s  5 / 5         100 (8524)
    # The delta column may itself contain spaces, so it is matched lazily up to the
    # distinctive "N / M" pair rather than assumed to be one token.
    $rxRow = [regex]'(?ix)^\s*(?<dc>[A-Za-z0-9][A-Za-z0-9\-_\.]*)\s+(?<delta>.+?)\s+(?<fails>\d+)\s*/\s*(?<total>\d+)\s+(?<pct>\d+%?)\s*(?:\((?<code>[^)]*)\))?\s*$'
    # A DC that repadmin could not read prints a placeholder instead of numbers.
    $rxPlaceholder = [regex]'(?ix)^\s*(?<dc>[A-Za-z0-9][A-Za-z0-9\-_\.]*)\s+(?<rest>.*?(?:unknow|unavail|\?\?|n/?a).*)$'
    # Trailing block: "Experienced the following operational errors ...":
    #   8341 - CRSVR01.foo.local
    $rxRetrievalErr = [regex]'(?ix)^\s*(?<code>\d{2,6})\s+-\s+(?<target>\S+)'

    $out       = New-Object System.Collections.Generic.List[object]
    $side      = ''
    $sawTable  = $false
    $content   = @($Output | ForEach-Object { [string]$_ })
    $nonBlank  = @($content | Where-Object { $_ -match '\S' })

    if ($nonBlank.Count -eq 0) {
        throw 'repadmin /replsummary produced no output, so replication health is unknown. Check that repadmin ran (RSAT) and re-run.'
    }

    foreach ($line in $content) {
        # Which table are we inside? Drives the Side column and the placeholder rule.
        if ($line -match '(?ix)^\s*(?<side>source|destination)\s+dsa\b') {
            $side = $Matches['side']
            $sawTable = $true
            continue
        }
        # Column underline rows (==== ...) and the progress dots carry no data.
        if ($line -match '^\s*[=\s]+$' -or $line -match '^\s*[.\s]*$') { continue }

        if ($line -match $rxRow) {
            # Rows are built into a variable first: a comma-formatted expression such as
            # "'{0} / {1}' -f $a, $b" inside a method-call argument list does not parse.
            $failed = [int]$Matches['fails']
            $pair   = ('{0} / {1}' -f $Matches['fails'], $Matches['total'])
            $row = [pscustomobject]@{
                Side         = $side
                Dc           = $Matches['dc']
                LargestDelta = $Matches['delta'].Trim()
                Failures     = $pair
                Percent      = $Matches['pct']
                ErrorCode    = [string]$Matches['code']
                HasFailures  = ($failed -gt 0)
            }
            $out.Add($row)
            continue
        }

        if ($line -match $rxRetrievalErr) {
            # repadmin could not even retrieve data for this DC: a finding, not a gap.
            $row = [pscustomobject]@{
                Side         = 'retrieval'
                Dc           = $Matches['target']
                LargestDelta = ''
                Failures     = 'not retrieved'
                Percent      = ''
                ErrorCode    = $Matches['code']
                HasFailures  = $true
            }
            $out.Add($row)
            continue
        }

        # Inside a known table, an unrecognised line that starts with a host name is
        # treated as a failure: it means repadmin could not summarise that DC.
        if ($sawTable -and $line -match $rxPlaceholder) {
            $row = [pscustomobject]@{
                Side         = $side
                Dc           = $Matches['dc']
                LargestDelta = ''
                Failures     = 'unknown'
                Percent      = ''
                ErrorCode    = ''
                HasFailures  = $true
            }
            $out.Add($row)
            continue
        }

        if ($Lenient) { continue }
    }

    if ($out.Count -eq 0) {
        throw ("repadmin /replsummary output was captured ({0} non-blank line(s)) but no rows matched the parser. The format may differ on this repadmin version or locale; read 03_replsummary.txt manually." -f $nonBlank.Count)
    }

    return $out
}

function Get-DcdiagFinding {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][AllowEmptyString()][string[]]$Output = @(),
        # dcdiag /v is verbose; cap the warning rows so the report stays readable.
        [int]$MaxWarnings = 200
    )

    # 'DC1 failed test Services' / '......................... DC1 passed test Services'
    $rxResult = [regex]'(?ix)^\s*(?:\.{2,}\s*)?(?<dc>[A-Za-z0-9\-_\.]+)\s+(?<result>passed|failed)\s+test\s+(?<test>[A-Za-z0-9_\-\.$]+)'
    # dcdiag marks problems with WARNING:, ERROR: or the !*W prefix.
    $rxWarn   = [regex]'(?i)(?:^|[\s])(WARNING:|ERROR:|!\*W)'

    $out       = New-Object System.Collections.Generic.List[object]
    $warnings  = 0
    $sawResult = $false          # proves the parser is looking at dcdiag output
    $content   = @($Output | ForEach-Object { [string]$_ })
    $nonBlank  = @($content | Where-Object { $_ -match '\S' })

    if ($nonBlank.Count -eq 0) {
        throw 'dcdiag produced no output, so directory health is unknown. Check that dcdiag ran (RSAT) and re-run.'
    }

    foreach ($line in $content) {
        if ($line -match $rxResult) {
            $sawResult = $true
            if ($Matches['result'] -eq 'failed') {
                $out.Add([pscustomobject]@{
                    Result = 'FAIL'
                    DC     = $Matches['dc']
                    Test   = $Matches['test']
                    Detail = $line.Trim()
                })
            }
            continue
        }
        if ($line -match $rxWarn) {
            $warnings++
            if ($warnings -le $MaxWarnings) {
                $out.Add([pscustomobject]@{
                    Result = 'WARN'
                    DC     = ''
                    Test   = ''
                    Detail = $line.Trim()
                })
            }
        }
    }

    if ($warnings -gt $MaxWarnings) {
        $out.Add([pscustomobject]@{
            Result = 'WARN'
            DC     = ''
            Test   = ''
            Detail = ('output truncated: {0} further warning line(s). See the evidence file.' -f ($warnings - $MaxWarnings))
        })
    }

    # A clean forest legitimately yields zero FAIL and zero WARN rows, but it always
    # yields "passed test" lines. Seeing none of those means the parser missed the
    # format (or dcdiag never ran), which must not read as a clean result.
    if (-not $sawResult) {
        throw ("dcdiag output was captured ({0} non-blank line(s)) but no test result lines matched the parser. The format may differ on this version or locale; read 03_dcdiag.txt manually." -f $nonBlank.Count)
    }

    return $out
}

function Get-WmiFilterRow {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Filters = @(),
        # Short names, FQDNs and addresses of the DCs being decommissioned.
        [AllowNull()][AllowEmptyCollection()][string[]]$OldNames = @()
    )

    # The section is titled "WMI filters naming a domain controller", so each row has
    # to say whether it actually names one of ours. Without this flag the escalation
    # predicate either floods (every filter) or never fires (no predicate at all).
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($f in @($Filters)) {
        if ($null -eq $f) { continue }
        $name  = [string]$f.'msWMI-Name'
        $query = [string]$f.'msWMI-Parm2'
        $hit   = @($OldNames | Where-Object { $_ -and (($name -match [regex]::Escape($_)) -or ($query -match [regex]::Escape($_))) })
        $out.Add([pscustomobject]@{
            Filter     = $name
            Query      = $query
            NamesOldDc = ($hit.Count -gt 0)
        })
    }
    return $out
}

function Get-W32tmSourceRow {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][AllowEmptyString()][string[]]$Output = @()
    )

    # Two shapes are handled:
    #   w32tm /monitor /domain:X  ->  =========================dc1.foo.local(10.0.0.1): (nptx5 ms, ...)
    #                                  Source ntp.foo.local,0x9 assumed reliable to sync time.
    #   per-DC status captures     ->  === dc1.foo.local ===
    #                                  Source: DC2.foo.local (172.16.15.34),0x8
    # Only the source/upstream lines become rows, so a DC merely being *listed* by
    # /monitor no longer counts as a finding. That was enough to make every run of
    # the report CONDITIONAL, because /monitor lists every DC in the domain.
    $rxMonitor = [regex]'(?ix)^\s*={3,}\s*(?<dc>[A-Za-z0-9\-_\.]+)\s*\(\s*(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s*\)'
    $rxMarker  = [regex]'^\s*===+\s*(?<dc>[^\s=]+?)\s*===+\s*$'
    $rxCompName= [regex]'(?i)^\s*Computer Name\s*:\s*(?<dc>\S+)'
    $rxSource  = [regex]'(?ix)^\s*(?:source|configured\s+source|upstream)\s*:?\s*(?<src>.*)$'

    $out      = New-Object System.Collections.Generic.List[object]
    $current  = ''
    foreach ($line in @($Output | ForEach-Object { [string]$_ })) {
        if ($line -match $rxMonitor)   { $current = $Matches['dc']; continue }
        if ($line -match $rxMarker)    { $current = $Matches['dc']; continue }
        if ($line -match $rxCompName)  { $current = $Matches['dc'].TrimEnd('.'); continue }
        if ($line -match $rxSource) {
            $src = $Matches['src'].Trim()
            if (-not $src) { continue }
            $out.Add([pscustomobject]@{
                Computer    = $current
                SourceRaw   = $src
                IsNtpServer = ($src -match '(?i)(ntp|pool|time\.)')
            })
        }
    }
    return $out
}
function Get-W32tmSourceRow {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][AllowEmptyString()][string[]]$Output = @()
    )

    # Two shapes are handled:
    #   w32tm /monitor /domain:X   ->  =========================dc1.foo.local(10.0.0.1): (nptx5 ms, ...)
    #                                   Source ntp.foo.local,0x9 assumed reliable to sync time.
    #   per-DC status captures     ->  === dc1.foo.local ===
    #                                   Source: DC2.foo.local (172.16.15.34),0x8
    # Only source/upstream lines become rows, so a DC merely being *listed* by /monitor
    # is no longer treated as a finding.
    $rxMonitor   = [regex]'(?ix)^\s*=+\s*(?<dc>[A-Za-z0-9\-_\.]+)\s*\(\s*\d{1,3}(?:\.\d{1,3}){3}\s*\)'
    $rxMarker    = [regex]'^\s*={3,}\s*(?<dc>[^\s=]+?)\s*=+\s*$'
    $rxCompName  = [regex]'(?i)^\s*Computer Name\s*:\s*(?<dc>\S+)'
    $rxSource    = [regex]'(?ix)^\s*(?:configured\s+source|upstream\s+time\s+source|source)\s*:?\s*(?<rest>.*)$'

    $out     = New-Object System.Collections.Generic.List[object]
    $current = ''
    foreach ($line in @($Output | ForEach-Object { [string]$_ })) {
        if ($line -match $rxMonitor)  { $current = $Matches['dc']; continue }
        if ($line -match $rxMarker)   { $current = $Matches['dc']; continue }
        if ($line -match $rxCompName) { $current = $Matches['dc'].TrimEnd('.'); continue }
        if ($line -match $rxSource) {
            $rest = $Matches['rest'].Trim()
            if (-not $rest) { continue }
            $out.Add([pscustomobject]@{
                Computer  = $current
                SourceRaw = $rest
            })
        }
    }
    return $out
}
#endregion

#region ---- Extension: summary table with severity badges ----
function ConvertTo-HtmlSummaryTable {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Report)

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<table class="summary"><thead><tr>')
    foreach ($c in 'Status','Severity','Check','Findings') {
        [void]$sb.Append("<th>$c</th>")
    }
    [void]$sb.Append('</tr></thead><tbody>')

    foreach ($sec in $Report) {
        $status   = Get-SectionStatus -Section $sec
        $sevColour = $DcSeverityColour[$sec.Severity]
        $staColour = $DcStatusColour[$status]
        if (-not $staColour) { $staColour = '#7f8c8d' }
        $findings = if ($sec.Error) { 'ERROR' } else { $sec.Count }

        [void]$sb.Append('<tr>')
        [void]$sb.Append("<td><span class='badge' style='background:$staColour'>$status</span></td>")
        [void]$sb.Append("<td><span class='badge' style='background:$sevColour'>$(ConvertTo-HtmlEncoded $sec.Severity)</span></td>")
        [void]$sb.Append("<td>$(ConvertTo-HtmlEncoded $sec.Title)</td>")
        [void]$sb.Append("<td>$(ConvertTo-HtmlEncoded ([string]$findings))</td>")
        [void]$sb.Append('</tr>')
    }

    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}
#endregion

#region ---- html-template.md sections 4 to 10: render, write, open ----
function New-DecomHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Report,
        [Parameter(Mandatory)]
        [string]$OutputPath,
        # Passed in by the caller so this file never depends on the AD module.
        [string]$Domain      = '',
        [string]$Forest      = '',
        [string[]]$Removing  = @(),
        [string[]]$Retaining = @(),
        [string]$EvidenceDir = '',
        [int]$MaxPreLines    = 400,
        [switch]$NoLaunch
    )

    # ---- Header metadata (html-template.md section 6): encode every dynamic value
    $titleText  = if ($Domain) { "Domain controller decommission readiness - $Domain" } else { 'Domain controller decommission readiness' }
    $hTitle     = ConvertTo-HtmlEncoded $titleText
    $hDomain    = if ($Domain) { ConvertTo-HtmlEncoded $Domain } else { '(not supplied)' }
    $hForest    = if ($Forest) { ConvertTo-HtmlEncoded $Forest } else { '(not supplied)' }
    $hRunBy     = ConvertTo-HtmlEncoded ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
    $hRunFrom   = ConvertTo-HtmlEncoded $env:COMPUTERNAME
    $hRemoving  = if ($Removing)  { ConvertTo-HtmlEncoded ($Removing  -join ', ') } else { '(none)' }
    $hRetaining = if ($Retaining) { ConvertTo-HtmlEncoded ($Retaining -join ', ') } else { '(none)' }
    $hEvidence  = ConvertTo-HtmlEncoded $EvidenceDir

    # ---- Summary roll-up (html-template.md section 4)
    $verdict      = Get-DemoteVerdict -Report $Report
    $summaryTable = ConvertTo-HtmlSummaryTable -Report $Report
    $vColour      = switch ($verdict.CssClass) { 'blocked' { '#c0392b' } 'conditional' { '#e67e22' } default { '#27ae60' } }
    $blockerList  = if ($verdict.BlockerList) { '<ul class="findings">' + (($verdict.BlockerList | ForEach-Object { "<li>$(ConvertTo-HtmlEncoded $_)</li>" }) -join '') + '</ul>' } else { '' }

    # ---- Section bodies (html-template.md section 5)
    $body = [System.Text.StringBuilder]::new()
    foreach ($sec in $Report) {
        $colour     = $DcSeverityColour[$sec.Severity]
        $status     = Get-SectionStatus -Section $sec
        $staColour  = if ($DcStatusColour[$status]) { $DcStatusColour[$status] } else { '#7f8c8d' }

        [void]$body.Append("<section><h2 style='border-left:6px solid $colour'>")
        [void]$body.Append("<span class='badge' style='background:$colour'>$($sec.Severity)</span> ")
        [void]$body.Append((ConvertTo-HtmlEncoded $sec.Title))
        $countLabel = if ($sec.Error) { 'error' } else { "$($sec.Count) result(s)" }
        [void]$body.Append("<span class='badge status' style='background:$staColour'>$status</span>")
        [void]$body.Append("<span class='count'>$countLabel</span></h2>")

        if ($sec.Description) {
            [void]$body.Append("<p class='desc'>$(ConvertTo-HtmlEncoded $sec.Description)</p>")
        }
        if ($sec.Escalated) {
            $note = "Severity raised from $($sec.BaseSeverity) because the findings are blocking for this decommission."
            [void]$body.Append("<p class='note'>$(ConvertTo-HtmlEncoded $note)</p>")
        }

        if ($sec.Error) {
            [void]$body.Append("<p class='error'>Query error: $(ConvertTo-HtmlEncoded $sec.Error)</p>")
        }
        elseif ($sec.IsText) {
            $lines = @($sec.Rows | ForEach-Object { [string]$_ })
            $ev    = if ($sec.EvidenceFile) { ($sec.EvidenceFile | Select-Object -First 1) } else { '' }
            [void]$body.Append((ConvertTo-HtmlPre -Lines $lines -MaxLines $MaxPreLines -EvidenceFile $ev))
        }
        elseif (@($sec.Rows).Count -eq 0) {
            [void]$body.Append("<p class='empty'>$(ConvertTo-HtmlEncoded $sec.EmptyText)</p>")
        }
        else {
            [void]$body.Append((ConvertTo-HtmlTable -Rows $sec.Rows))
        }

        if ($sec.EvidenceFile) {
            $joined = ConvertTo-HtmlEncoded ($sec.EvidenceFile -join ', ')
            [void]$body.Append("<p class='evidence'>Evidence: $joined</p>")
        }
        [void]$body.Append('</section>')
    }

    # ---- Footer disclaimers (html-template.md section 8)
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
    header .meta { font-size: 13px; color: #b8c4d0; line-height: 1.6; }
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
    .badge.status { background: #7f8c8d; }
    .count { margin-left: auto; font-size: 12px; color: #888; font-weight: 400; }
    .desc  { font-size: 13px; color: #555; margin: 4px 0 12px; }
    .note  { font-size: 12px; color: #7f8c8d; font-style: italic; margin: 4px 0 10px; }

    /* ---- Tables ---- */
    table { border-collapse: collapse; width: 100%; font-size: 13px; }
    th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #eaeef1; vertical-align: top; }
    th { background: #f0f3f6; font-weight: 600; }
    tr:hover td { background: #fafbfc; }

    /* ---- Status messages ---- */
    .empty { color: #27ae60; font-size: 13px; font-style: italic; }
    .error { color: #c0392b; font-size: 13px; }
    .evidence { font-size: 11px; color: #888; margin: 8px 0 0; }

    /* ---- Raw command output ---- */
    pre.raw {
        background: #f7f9fa; border: 1px solid #e2e6ea; border-radius: 4px;
        padding: 10px 12px; font-size: 12px; line-height: 1.45;
        white-space: pre-wrap; word-break: break-word; overflow-x: auto;
        max-height: 480px; overflow-y: auto; margin: 0;
    }

    /* ---- Verdict banner ---- */
    .verdict { border-left-width: 6px; border-left-style: solid; }
    .verdict .label { font-size: 20px; font-weight: 700; letter-spacing: .01em; }
    ul.findings { margin: 8px 0 0; padding-left: 22px; font-size: 13px; }

    /* ---- Summary overrides ---- */
    .summary th, .summary td { border-bottom: 1px solid #ddd; }

    /* ---- Footer ---- */
    footer { max-width: 1200px; margin: 0 auto 40px; padding: 0 24px; font-size: 12px; color: #999; }
    footer p { margin: 6px 0; }
</style>
</head>
<body>

<header>
    <h1>$hTitle</h1>
    <div class="meta">
        Domain: $hDomain &nbsp;|&nbsp; Forest: $hForest &nbsp;|&nbsp; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br>
        Removing DCs: $hRemoving<br>
        Retaining DCs: $hRetaining<br>
        Run by: $hRunBy &nbsp;|&nbsp; From: $hRunFrom &nbsp;|&nbsp; Evidence folder: $hEvidence
    </div>
    <div class="classification">Restricted - internal AD topology and domain controller inventory</div>
</header>

<main>
    <section class="verdict" style="border-left-color:$vColour">
        <h2 style="border-left:6px solid $vColour; padding-left:0">Demote readiness verdict</h2>
        <p class="label" style="color:$vColour">$($verdict.Label)</p>
        <p class="desc">Verdict is derived from the automated checks below only. It does not cover the manual items listed in the appendix section of this report.</p>
        $blockerList
    </section>

    <section class="summary">
        <h2 style="border-left:6px solid #1f2d3d">Summary</h2>
        <p class="desc">All checks with their severity and finding counts. Sections showing ERROR did not complete and may hide real findings, so review them first.</p>
        $summaryTable
    </section>

    $($body.ToString())
</main>

<footer>
    <p>Read-only discovery. No AD, DNS, DHCP or SYSVOL object was created, modified or deleted by this run.</p>
    <p>Evidence files (CSV/TXT) and the full transcript are stored in the evidence folder named in the header; this HTML file is a rendering of those files, not a replacement for them.</p>
    <p>repadmin, dcdiag, w32tm and dfsrmig output is parsed heuristically. A parser that matches nothing raises an error rather than reporting clean. Long raw output is truncated here and always complete in the matching evidence file.</p>
    <p>A clean verdict does not authorise demotion: client NIC DNS settings, appliance LDAP/RADIUS bind strings, firewall rules and monitoring targets must be confirmed manually.</p>
</footer>

</body>
</html>
"@

    $parent = Split-Path -Path $OutputPath -Parent
    if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }

    # UTF8 keeps a BOM on Windows PowerShell 5.1, which browsers handle fine.
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host ("HTML report written to: {0}" -f $OutputPath) -ForegroundColor Green

    if (-not $NoLaunch) {
        try { Invoke-Item $OutputPath } catch { }
    }
}
#endregion
