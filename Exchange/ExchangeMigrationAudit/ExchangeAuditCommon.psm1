#Requires -Version 5.0
<#
.SYNOPSIS
    Shared engine for the Exchange retirement audit scripts: HTML report rendering plus
    the helper functions those scripts use (step logging, size parsing, DNS/AD resolution,
    application classification and Microsoft 365 replacement-path advice).

.DESCRIPTION
    Implements the house HTML report pattern documented in html-template.md:
      - every value that originates from data is HTML-encoded before it reaches markup
      - each check becomes a severity-coloured section with its own error trap, so one
        failing query can never abort the audit
      - the finished document is one self-contained .html file (no external CSS/JS)

    Also exports:
      Invoke-AuditStep          - collect data for one check without killing the run
      Get-AuditSizeKB           - parse Exchange ByteObject / "1.23 GB (…)" strings to KB
      Resolve-AuditHostName     - cached PTR lookup
      Find-AuditComputerByIp    - AD computer object behind an IP (name, OS, description)
      Get-AuditAppCategory      - keyword classification of SMTP relay sources
      Get-AuditReplacementPath  - Microsoft 365 send-path recommendation per source
      Test-AuditExchangeShell   - verify the Exchange cmdlets are available in this session
      New-AuditOutputDirectory  - create the timestamped evidence folder
      Start/Stop-AuditTranscript- console transcript for the audit trail

.NOTES
    Target host: Windows PowerShell 5.1 (the Exchange Management Shell on Exchange 2019).
    Deliberately avoids ternary operators, null-coalescing and ForEach-Object -Parallel so
    everything runs inside the EMS runspace unchanged.

    READ-ONLY: no function in this module modifies AD, Exchange, DNS or file state outside
    the output folder you give it.

.EXAMPLE
    Import-Module .\ExchangeAuditCommon.psm1 -Force
#>

$script:AuditToolkitVersion = '1.0'
$script:AuditDnsCache   = @{}
$script:AuditAdComputerCache = @{}

# =====================================================================
# HTML helpers
# =====================================================================

function ConvertTo-HtmlEncoded {
    <#
    .SYNOPSIS
        HTML-encodes a string. Used for every data-derived value in the report.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Text
    )

    process {
        if ($null -eq $Text) { return '' }
        return [System.Net.WebUtility]::HtmlEncode($Text)
    }
}

function ConvertTo-AuditCellText {
    <#
    .SYNOPSIS
        Normalises any property value into display text before encoding.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value,
        [int]$MaxCellLength = 400
    )

    if ($null -eq $Value) { return '' }

    $text = $null

    if ($Value -is [datetime]) {
        $text = $Value.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    elseif ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $parts = @()
        foreach ($item in $Value) {
            if ($null -ne $item) { $parts += [string]$item }
        }
        $text = ($parts -join ', ')
    }
    else {
        $text = [string]$Value
    }

    if ($MaxCellLength -gt 0 -and $text.Length -gt $MaxCellLength) {
        $text = $text.Substring(0, $MaxCellLength) + ' …'
    }

    return $text
}

function ConvertTo-HtmlTable {
    <#
    .SYNOPSIS
        Renders a collection of objects as an HTML table.
    .DESCRIPTION
        Columns are auto-detected from the first row's PSObject.Properties, so column order
        and naming are controlled by Select-Object in the query. Every cell is encoded.
        Empty input renders the green "No results" message instead of a broken table.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]]$Rows,

        [string]$Caption,

        # 0 = no cap. Guards against multi-thousand-row sections making the file unusable.
        [int]$MaxRows = 0,

        [int]$MaxCellLength = 400
    )

    $all = @($Rows | Where-Object { $null -ne $_ })

    if ($all.Count -eq 0) {
        return '<p class="empty">No results &mdash; nothing flagged for this check.</p>'
    }

    # Bare strings / primitives still need to render.
    if ($all[0] -isnot [System.Management.Automation.PSCustomObject] -and
        $all[0] -isnot [System.Collections.IDictionary]) {
        $all = @($all | ForEach-Object { [pscustomobject]@{ Value = $_ } })
    }

    # Dictionary rows become objects so column detection works.
    $normalised = New-Object 'System.Collections.Generic.List[object]'
    foreach ($row in $all) {
        if ($row -is [System.Collections.IDictionary]) {
            $copy = [ordered]@{}
            foreach ($k in $row.Keys) { $copy[$k] = $row[$k] }
            $normalised.Add([pscustomobject]$copy) | Out-Null
        }
        else {
            $normalised.Add($row) | Out-Null
        }
    }

    $totalShown = $normalised.Count
    $truncated  = $false
    if ($MaxRows -gt 0 -and $normalised.Count -gt $MaxRows) {
        $totalShown = $MaxRows
        $truncated  = $true
    }

    $cols = @($normalised[0].PSObject.Properties.Name)
    $sb   = New-Object System.Text.StringBuilder

    if ($Caption) {
        [void]$sb.Append("<p class='caption'>$(ConvertTo-HtmlEncoded $Caption)</p>")
    }

    [void]$sb.Append('<table><thead><tr>')
    foreach ($c in $cols) {
        [void]$sb.Append("<th>$(ConvertTo-HtmlEncoded $c)</th>")
    }
    [void]$sb.Append('</tr></thead><tbody>')

    for ($i = 0; $i -lt $totalShown; $i++) {
        $r = $normalised[$i]
        [void]$sb.Append('<tr>')
        foreach ($c in $cols) {
            $raw = $null
            $prop = $r.PSObject.Properties[$c]
            if ($null -ne $prop) { $raw = $prop.Value }
            $text = ConvertTo-AuditCellText -Value $raw -MaxCellLength $MaxCellLength
            [void]$sb.Append("<td>$(ConvertTo-HtmlEncoded $text)</td>")
        }
        [void]$sb.Append('</tr>')
    }

    [void]$sb.Append('</tbody></table>')

    if ($truncated) {
        [void]$sb.Append(("<p class='caption'>Showing first {0} of {1} rows. Full data set is in the CSV export.</p>" -f $totalShown, $normalised.Count))
    }

    return $sb.ToString()
}

function Add-AuditHtmlBlock {
    <#
    .SYNOPSIS
        Appends free-form (already encoded) HTML between sections.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Report,
        [Parameter(Mandatory)][string]$Html
    )
    $Report.RawHtml.Add([pscustomobject]@{ AfterSectionCount = $Report.Sections.Count; Html = $Html }) | Out-Null
}

# =====================================================================
# Report model
# =====================================================================

function New-AuditReport {
    <#
    .SYNOPSIS
        Creates the report container used by Add-AuditSection.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [AllowNull()]
        [string]$Subtitle,

        # Ordered label/value pairs rendered in the header meta line (target, window, etc.)
        [System.Collections.IDictionary]$Meta = ([ordered]@{}),

        # Omit or pass an empty string to suppress the classification banner.
        [AllowEmptyString()]
        [string]$Classification = 'Internal &mdash; contains mail-flow and configuration detail',

        [AllowEmptyString()]
        [string]$SummaryDescription = 'Every check performed by this script, its severity and finding count.',

        # Optional extra paragraph under the summary table (e.g. how to read the severities).
        [AllowNull()]
        [string]$SummaryNote,

        [AllowEmptyString()]
        [string[]]$FooterNotes = @(),

        [hashtable]$SeverityColours
    )

    $defaults = @{
        Critical = '#c0392b'
        High     = '#e74c3c'
        Medium   = '#f1c40f'
        Low      = '#7f8c8d'
        Info     = '#3498db'
    }
    if ($SeverityColours) {
        foreach ($k in $SeverityColours.Keys) { $defaults[$k] = $SeverityColours[$k] }
    }

    return [pscustomobject]@{
        Title             = $Title
        Subtitle          = $Subtitle
        Meta              = $Meta
        Classification    = $Classification
        SummaryDescription= $SummaryDescription
        SummaryNote       = $SummaryNote
        FooterNotes       = $FooterNotes
        SeverityColours   = $defaults
        Sections          = [ordered]@{}
        RawHtml           = [System.Collections.Generic.List[object]]::new()
    }
}

function Add-AuditSection {
    <#
    .SYNOPSIS
        Adds one check to the report. A failing query is captured, never fatal.
    .PARAMETER Query
        Script block that returns rows. Executed inside try/catch.
    .PARAMETER Data / ErrorText
        Pre-collected alternative (used when data was gathered once and reused for several
        sections or for severity calculation). Populates Rows/Count/Error identically.
    .PARAMETER RawHtml
        Pre-rendered markup appended after the table - used for verdict cards and guidance
        blocks where a table is the wrong shape.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Report,

        [Parameter(Mandatory)]
        [string]$Title,

        [AllowEmptyString()]
        [string]$Description = '',

        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity = 'Info',

        [scriptblock]$Query,
        [object[]]$Data,
        [AllowNull()][string]$ErrorText,
        [AllowNull()][string]$Note,
        [AllowNull()][string]$RawHtml,
        [int]$MaxRows = 0
    )

    Write-Host ("      - {0}" -f $Title)

    $obj = [ordered]@{
        Title       = $Title
        Description = $Description
        Severity    = $Severity
        Rows        = @()
        Count       = 0
        Error       = $null
        Note        = $Note
        RawHtml     = $RawHtml
        MaxRows     = $MaxRows
    }

    if ($PSBoundParameters.ContainsKey('Data') -or $PSBoundParameters.ContainsKey('ErrorText')) {
        if ($null -ne $Data)   { $obj.Rows  = @($Data | Where-Object { $null -ne $_ }) }
        if ($ErrorText)        { $obj.Error = $ErrorText }
        $obj.Count = @($obj.Rows).Count
    }
    elseif ($Query) {
        try {
            $result   = & $Query
            $obj.Rows  = @($result | Where-Object { $null -ne $_ })
            $obj.Count = @($obj.Rows).Count
        }
        catch {
            $obj.Error = $_.Exception.Message
        }
    }

    if (-not $Report.Sections.Contains($Title)) {
        $Report.Sections.Add($Title, [pscustomobject]$obj)
    }
    else {
        # Duplicate titles would silently overwrite; disambiguate instead.
        $suffix = 2
        $candidate = "{0} ({1})" -f $Title, $suffix
        while ($Report.Sections.Contains($candidate)) {
            $suffix++
            $candidate = "{0} ({1})" -f $Title, $suffix
        }
        $Report.Sections.Add($candidate, [pscustomobject]$obj)
    }

    return $null
}

function Add-AuditHtmlBlock {
    <#
    .SYNOPSIS
        Appends free-form (already encoded) HTML between sections.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Report,
        [Parameter(Mandatory)][string]$Html
    )
    $Report.RawHtml.Add([pscustomobject]@{ AfterSectionCount = $Report.Sections.Count; Html = $Html }) | Out-Null
}

function New-AuditCard {
    <#
    .SYNOPSIS
        Renders one KPI card for a verdict/executive-summary block.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
        [AllowEmptyString()][string]$Detail = '',
        [ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity = 'Info',
        [hashtable]$SeverityColours
    )

    $colour = '#3498db'
    if ($SeverityColours -and $SeverityColours.ContainsKey($Severity)) { $colour = $SeverityColours[$Severity] }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<div class='card' style='border-top:3px solid $colour'>")
    [void]$sb.Append("<div class='kpi' style='color:$colour'>$(ConvertTo-HtmlEncoded $Value)</div>")
    [void]$sb.Append("<div class='klabel'>$(ConvertTo-HtmlEncoded $Label)</div>")
    if ($Detail) { [void]$sb.Append("<div class='kdetail'>$(ConvertTo-HtmlEncoded $Detail)</div>") }
    [void]$sb.Append('</div>')
    return $sb.ToString()
}

function New-AuditCallout {
    <#
    .SYNOPSIS
        Renders a highlighted recommendation / verdict paragraph.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity = 'Info',
        [AllowEmptyString()][string]$Heading = '',
        [hashtable]$SeverityColours
    )

    $colour = '#3498db'
    if ($SeverityColours -and $SeverityColours.ContainsKey($Severity)) { $colour = $SeverityColours[$Severity] }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<div class='callout' style='border-left:5px solid $colour'>")
    if ($Heading) { [void]$sb.Append("<strong>$(ConvertTo-HtmlEncoded $Heading)</strong><br />") }
    # Text is intentionally not encoded here so callers can embed <br/> and <ul>.
    [void]$sb.Append($Text)
    [void]$sb.Append('</div>')
    return $sb.ToString()
}

# =====================================================================
# Rendering
# =====================================================================

function Get-AuditReportHtml {
    <#
    .SYNOPSIS
        Builds the complete self-contained HTML document for a report object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Report,
        [string]$GeneratedBy = 'Exchange retirement audit scripts'
    )

    $sevColour = $Report.SeverityColours

    # ---- summary roll-up -------------------------------------------------
    $summaryRows = @($Report.Sections.Values | ForEach-Object {
        [pscustomobject]@{
            Severity = $_.Severity
            Check    = $_.Title
            Findings = if ($_.Error) { 'ERROR' } else { $_.Count }
        }
    })

    $tocSb = New-Object System.Text.StringBuilder
    [void]$tocSb.Append("<nav class='toc'>")
    $idx = 0
    foreach ($sec in $Report.Sections.Values) {
        $idx++
        $colour = $sevColour[$sec.Severity]
        $label  = if ($sec.Error) { 'error' } else { "$($sec.Count)" }
        [void]$tocSb.Append("<a href='#sec$idx'><span class='dot' style='background:$colour'></span>")
        [void]$tocSb.Append((ConvertTo-HtmlEncoded $sec.Title))
        [void]$tocSb.Append(" <em>($label)</em></a>")
    }
    [void]$tocSb.Append('</nav>')

    # ---- section bodies --------------------------------------------------
    $body = New-Object System.Text.StringBuilder
    $idx  = 0
    foreach ($sec in $Report.Sections.Values) {
        $idx++
        $colour = $sevColour[$sec.Severity]

        [void]$body.Append("<section id='sec$idx'><h2 style='border-left:6px solid $colour'>")
        [void]$body.Append("<span class='badge' style='background:$colour'>$(ConvertTo-HtmlEncoded $sec.Severity)</span> ")
        [void]$body.Append((ConvertTo-HtmlEncoded $sec.Title))

        $countLabel = if ($sec.Error) { 'error' } else { "$($sec.Count) result(s)" }
        [void]$body.Append("<span class='count'>$countLabel</span></h2>")

        if ($sec.Description) {
            [void]$body.Append("<p class='desc'>$(ConvertTo-HtmlEncoded $sec.Description)</p>")
        }

        if ($sec.Error) {
            [void]$body.Append("<p class='error'>Query error: $(ConvertTo-HtmlEncoded $sec.Error)</p>")
        }
        else {
            [void]$body.Append((ConvertTo-HtmlTable -Rows $sec.Rows -MaxRows $sec.MaxRows))
        }

        if ($sec.Note) {
            [void]$body.Append("<p class='note'>$(ConvertTo-HtmlEncoded $sec.Note)</p>")
        }
        if ($sec.RawHtml) {
            [void]$body.Append($sec.RawHtml)
        }

        [void]$body.Append('</section>')

        foreach ($block in @($Report.RawHtml | Where-Object { $_.AfterSectionCount -eq $idx })) {
            [void]$body.Append("<div class='block'>$($block.Html)</div>")
        }
    }

    # ---- header meta -----------------------------------------------------
    $metaSb = New-Object System.Text.StringBuilder
    $parts  = @()
    if (-not $Report.Meta) { $Report.Meta = [ordered]@{} }
    foreach ($key in $Report.Meta.Keys) {
        $val = [string]$Report.Meta[$key]
        if ([string]::IsNullOrWhiteSpace($val)) { continue }
        $parts += ("{0}: <strong>{1}</strong>" -f (ConvertTo-HtmlEncoded $key), (ConvertTo-HtmlEncoded $val))
    }
    $parts += ("Generated: <strong>{0}</strong>" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    $parts += ("Run by: <strong>{0}\{1}</strong>" -f (ConvertTo-HtmlEncoded $env:USERDOMAIN), (ConvertTo-HtmlEncoded $env:USERNAME))
    [void]$metaSb.Append(($parts -join ' &nbsp;|&nbsp; '))

    $subtitleHtml = ''
    if ($Report.Subtitle) {
        $subtitleHtml = "<div class='subtitle'>$(ConvertTo-HtmlEncoded $Report.Subtitle)</div>"
    }

    $classificationHtml = ''
    if ($Report.Classification) {
        # Classification text is authored by the script (static), not derived from data.
        $classificationHtml = "<div class='classification'>$($Report.Classification)</div>"
    }

    $summaryNoteHtml = ''
    if ($Report.SummaryNote) {
        $summaryNoteHtml = "<p class='note'>$(ConvertTo-HtmlEncoded $Report.SummaryNote)</p>"
    }

    $footerSb = New-Object System.Text.StringBuilder
    foreach ($line in @($Report.FooterNotes)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        [void]$footerSb.Append("<div>&bull; $(ConvertTo-HtmlEncoded $line)</div>")
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(ConvertTo-HtmlEncoded $Report.Title)</title>
<style>
    :root { font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
    body { margin: 0; background: #f4f6f8; color: #222; }

    header { background: #1f2d3d; color: #fff; padding: 24px 40px; }
    header h1 { margin: 0 0 4px; font-size: 22px; }
    header .subtitle { font-size: 14px; color: #cfd8e3; margin-bottom: 6px; }
    header .meta { font-size: 13px; color: #b8c4d0; line-height: 1.7; }
    header .classification {
        display: inline-block; margin-top: 12px;
        background: #c0392b; color: #fff;
        font-size: 11px; font-weight: 600;
        padding: 3px 10px; border-radius: 3px;
        text-transform: uppercase; letter-spacing: .05em;
    }

    main { max-width: 1280px; margin: 24px auto; padding: 0 24px; }
    section {
        background: #fff; border-radius: 8px;
        box-shadow: 0 1px 3px rgba(0,0,0,.1);
        margin-bottom: 20px; padding: 16px 20px;
    }

    h2 { font-size: 16px; padding-left: 12px; display: flex; align-items: center; gap: 10px; }
    .badge {
        color: #fff; font-size: 11px; font-weight: 600;
        padding: 2px 8px; border-radius: 10px;
        text-transform: uppercase; letter-spacing: .04em;
        flex: 0 0 auto;
    }
    .count { margin-left: auto; font-size: 12px; color: #888; font-weight: 400; white-space: nowrap; }
    .desc  { font-size: 13px; color: #555; margin: 4px 0 12px; }
    .note  { font-size: 12px; color: #666; background: #f7f9fa; border-left: 3px solid #cbd5dd;
             padding: 8px 10px; margin: 10px 0 0; }
    .caption { font-size: 12px; color: #777; margin: 10px 0 4px; font-weight: 600; }

    table { border-collapse: collapse; width: 100%; font-size: 13px; }
    th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #eaeef1; vertical-align: top; }
    th { background: #f0f3f6; font-weight: 600; position: sticky; top: 0; }
    tr:hover td { background: #fafbfc; }

    .empty { color: #27ae60; font-size: 13px; font-style: italic; }
    .error { color: #c0392b; font-size: 13px; }

    .summary th, .summary td { border-bottom: 1px solid #ddd; }

    .toc { display: flex; flex-wrap: wrap; gap: 6px 14px; margin-top: 12px; }
    .toc a { font-size: 12px; color: #34495e; text-decoration: none; display: inline-flex; align-items: center; gap: 5px; }
    .toc a:hover { text-decoration: underline; }
    .toc em { color: #888; font-style: normal; }
    .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex: 0 0 auto; }

    .cards { display: flex; flex-wrap: wrap; gap: 12px; margin: 6px 0 4px; }
    .card { background: #fbfcfd; border: 1px solid #e5eaee; border-radius: 6px;
            padding: 10px 14px; min-width: 170px; flex: 1 1 190px; }
    .card .kpi { font-size: 24px; font-weight: 700; line-height: 1.2; }
    .card .klabel { font-size: 12px; font-weight: 600; color: #34495e; margin-top: 2px; }
    .card .kdetail { font-size: 11px; color: #7f8c8d; margin-top: 4px; line-height: 1.4; }

    .callout { background: #fbfcfd; border-radius: 0 6px 6px 0; padding: 12px 14px;
               font-size: 13px; color: #333; margin: 12px 0; line-height: 1.55; }
    .callout ul { margin: 8px 0 0 18px; padding: 0; }
    .block { margin-bottom: 20px; }

    footer { max-width: 1280px; margin: 0 auto 40px; padding: 0 24px; font-size: 12px; color: #999; line-height: 1.7; }

    @media print {
        header { background: #1f2d3d !important; -webkit-print-color-adjust: exact; }
        th { position: static; }
        section { box-shadow: none; page-break-inside: avoid; }
        .toc { display: none; }
    }
</style>
</head>
<body>

<header>
    <h1>$(ConvertTo-HtmlEncoded $Report.Title)</h1>
    $subtitleHtml
    <div class="meta">$($metaSb.ToString())</div>
    $classificationHtml
</header>

<main>
    <section class="summary">
        <h2 style="border-left:6px solid #1f2d3d">Summary</h2>
        <p class="desc">$(ConvertTo-HtmlEncoded $Report.SummaryDescription)</p>
        $(ConvertTo-HtmlTable -Rows $summaryRows)
        $summaryNoteHtml
        $($tocSb.ToString())
    </section>

    $($body.ToString())
</main>

<footer>
    Generated by $(ConvertTo-HtmlEncoded $GeneratedBy).
    $($footerSb.ToString())
</footer>

</body>
</html>
"@

    return $html
}

function Write-AuditReport {
    <#
    .SYNOPSIS
        Writes the HTML document and (unless -NoLaunch) opens it in the default browser.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Report,
        [Parameter(Mandatory)][string]$Path,
        [switch]$NoLaunch,
        [string]$GeneratedBy = 'Exchange retirement audit scripts'
    )

    $html = Get-AuditReportHtml -Report $Report -GeneratedBy $GeneratedBy

    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    # Explicit UTF8: PS 5.1 defaults to UTF-16LE, which browsers render as mojibake.
    $html | Out-File -FilePath $Path -Encoding UTF8

    $sizeKB = [math]::Round(((Get-Item -LiteralPath $Path).Length / 1KB), 1)
    Write-Host ''
    Write-Host ("Report written to: {0} ({1} KB)" -f $Path, $sizeKB) -ForegroundColor Green

    if (-not $NoLaunch) {
        try { Invoke-Item -LiteralPath $Path } catch { }
    }
}

function Export-AuditCsv {
    <#
    .SYNOPSIS
        Exports every section's rows to CSV alongside the HTML (evidence / offline analysis).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Report,
        [Parameter(Mandatory)][string]$Directory
    )

    if (-not (Test-Path -LiteralPath $Directory)) {
        New-Item -Path $Directory -ItemType Directory -Force | Out-Null
    }

    $written = 0
    foreach ($sec in $Report.Sections.Values) {
        if (@($sec.Rows).Count -eq 0) { continue }

        $safe = ($sec.Title -replace '[^\w\-]+', '_').Trim('_')
        if ([string]::IsNullOrWhiteSpace($safe)) { $safe = 'section' }
        $file = Join-Path $Directory ("{0}.csv" -f $safe)

        try {
            @($sec.Rows) | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8
            $written++
        }
        catch {
            Write-Host ("      ! CSV export failed for '{0}': {1}" -f $sec.Title, $_.Exception.Message) -ForegroundColor Yellow
        }
    }

    Write-Host ("      CSV exports: {0} file(s) in {1}" -f $written, $Directory) -ForegroundColor DarkGray
}

# =====================================================================
# Collection / logging helpers
# =====================================================================

function Invoke-AuditStep {
    <#
    .SYNOPSIS
        Runs one data-collection step. Failures are captured, never fatal.
    .OUTPUTS
        [pscustomobject] with Name, Data (always an array) and Error ($null when clean).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Script
    )

    Write-Host ("  [*] {0}" -f $Name)

    $entry = [pscustomobject]@{
        Name       = $Name
        Data       = @()
        Error      = $null
        FailedItem = 0
    }

    try {
        $result = & $Script
        if ($null -ne $result) {
            $entry.Data = @($result | Where-Object { $null -ne $_ })
        }
    }
    catch {
        $entry.Error = $_.Exception.Message
        Write-Host ("      ! {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    }

    return $entry
}

function Start-AuditTranscript {
    <#
    .SYNOPSIS
        Starts a console transcript in the output folder (best effort).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AppendToExistingFile
    )

    try {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            Start-Transcript -Path $Path -Force | Out-Null
        }
        else {
            Start-Transcript -Path $Path | Out-Null
        }
        return $true
    }
    catch {
        Write-Host ("      Transcript not started: {0}" -f $_.Exception.Message) -ForegroundColor DarkGray
        return $false
    }
}

function Stop-AuditTranscript {
    [CmdletBinding()]
    param()
    try { Stop-Transcript | Out-Null } catch { }
}

function New-AuditOutputDirectory {
    <#
    .SYNOPSIS
        Creates the timestamped evidence folder used by all audit scripts.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$BasePath,
        [Parameter(Mandatory)][string]$Prefix
    )

    if ([string]::IsNullOrWhiteSpace($BasePath)) {
        $BasePath = Join-Path (Get-Location).Path ("{0}_{1}" -f $Prefix, (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
    }

    if (-not (Test-Path -LiteralPath $BasePath)) {
        New-Item -Path $BasePath -ItemType Directory -Force | Out-Null
    }

    return (Resolve-Path -LiteralPath $BasePath).Path
}

function Test-AuditExchangeShell {
    <#
    .SYNOPSIS
        Confirms the Exchange cmdlets are available; attempts to load EMS if they are not.
    #>
    [CmdletBinding()]
    param([switch]$AllowRemoteHint)

    if (Get-Command -Name 'Get-Mailbox' -ErrorAction SilentlyContinue) {
        return $true
    }

    Write-Host '  Exchange cmdlets not loaded in this session - attempting to load the EMS snap-in...' -ForegroundColor Yellow

    $emsLoader = $null
    if ($env:ExchangeInstallPath) {
        $candidate = Join-Path $env:ExchangeInstallPath 'bin\RemoteExchange.ps1'
        if (Test-Path -LiteralPath $candidate) { $emsLoader = $candidate }
    }

    if ($emsLoader) {
        try {
            . $emsLoader
            Start-Sleep -Seconds 2
            if (Get-Command -Name 'Get-Mailbox' -ErrorAction SilentlyContinue) { return $true }
        }
        catch {
            Write-Host ("      EMS loader failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        }
    }

    return $false
}

function Get-AuditExchangeBuildInfo {
    <#
    .SYNOPSIS
        Maps an Exchange AdminDisplayVersion string to a friendly product/CU label.
    .DESCRIPTION
        The CU table is informational and current as of November 2026. Unknown builds are
        reported as unmapped rather than guessed - verify against Microsoft's published
        "Exchange Server build numbers and release dates" article.
    #>
    [CmdletBinding()]
    param([string]$AdminDisplayVersion)

    $result = [pscustomobject]@{
        Product      = 'Unknown'
        MajorMinor   = ''
        Build        = 0
        CU           = 'Unmapped'
        SupportState = 'Unknown - verify against Microsoft lifecycle documentation'
    }

    if ([string]::IsNullOrWhiteSpace($AdminDisplayVersion)) { return $result }

    $match = [regex]::Match($AdminDisplayVersion, 'Version\s+(\d+)\.(\d+)\s+\(Build\s+(\d+)\.(\d+)\)')
    if (-not $match.Success) {
        $match = [regex]::Match($AdminDisplayVersion, '(\d+)\.(\d+)\.(\d+)\.(\d+)')
    }
    if (-not $match.Success) { return $result }

    $major  = [int]$match.Groups[1].Value
    $minor  = [int]$match.Groups[2].Value
    $build  = [int]$match.Groups[3].Value
    $rev    = [int]$match.Groups[4].Value

    $result.MajorMinor = "{0}.{1}" -f $major, $minor
    $result.Build      = $build

    switch ("{0}.{1}" -f $major, $minor) {
        '15.2' {
            $result.Product = 'Exchange Server 2019 / Subscription Edition'
            # Exchange 2019 CU base builds (Subscription Edition shares the 15.2.x namespace).
            if ($build -ge 2562)      { $result.CU = 'Subscription Edition (SE)' }
            elseif ($build -ge 1748)  { $result.CU = 'CU15' }
            elseif ($build -ge 1544)  { $result.CU = 'CU14' }
            elseif ($build -ge 1258)  { $result.CU = 'CU8 or earlier branch (see note)' }
            elseif ($build -ge 1118)  { $result.CU = 'CU7' }
            elseif ($build -ge 986)   { $result.CU = 'CU6' }
            elseif ($build -ge 858)   { $result.CU = 'CU5' }
            elseif ($build -ge 721)   { $result.CU = 'CU4' }
            elseif ($build -ge 595)   { $result.CU = 'CU3' }
            elseif ($build -ge 464)   { $result.CU = 'CU2' }
            elseif ($build -ge 330)   { $result.CU = 'CU1' }
            elseif ($build -ge 221)   { $result.CU = 'RTM' }

            if ($build -lt 2562) {
                $result.SupportState = 'Out of support since 14 Oct 2025 (security updates only via the ESU program)'
            }
            else {
                $result.SupportState = 'Supported (Subscription Edition servicing)'
            }
        }
        '15.1' {
            $result.Product      = 'Exchange Server 2016'
            $result.SupportState = 'Out of support since 14 Oct 2025 - migration required'
        }
        '15.0' { $result.Product = 'Exchange Server 2013'; $result.SupportState = 'Long out of support' }
        '14.x' { $result.Product = 'Exchange Server 2010'; $result.SupportState = 'Long out of support' }
    }

    return $result
}

# =====================================================================
# Size / value parsing
# =====================================================================

function Get-AuditSizeKB {
    <#
    .SYNOPSIS
        Converts an Exchange size (ByteObject or "1.234 GB (1,324 KB)" string) to total KB.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Size)

    if ($null -eq $Size) { return $null }

    # Native Exchange ByteObject / ByteQuantity
    try {
        if ($Size.PSObject.Properties.Name -contains 'Value' -and
            $Size.Value.PSObject.Methods.Name -contains 'ToKB') {
            return [int64]$Size.Value.ToKB()
        }
    }
    catch { }

    try {
        foreach ($method in @('ToKB', 'TotalKB')) {
            if ($Size.PSObject.Methods.Name -contains $method) {
                return [int64]$Size.$method()
            }
        }
    }
    catch { }

    # Numeric input already expressed in bytes or KB is ambiguous - treat as bytes only when > 1e9.
    if ($Size -is [int] -or $Size -is [long] -or $Size -is [double] -or $Size -is [decimal]) {
        return [int64]$Size
    }

    $text = [string]$Size
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    # Take the first "<number> <unit>" pair, e.g. "1.234 GB (1,324 KB)" -> 1.234 GB
    $m = [regex]::Match($text, '([\d\.,]+)\s*(GB|MB|KB|TB|PB|B)\b', 'IgnoreCase')
    if (-not $m.Success) { return $null }

    $numberText = $m.Groups[1].Value.Replace(',', '')
    $number = 0.0
    if (-not [double]::TryParse($numberText, [System.Globalization.NumberStyles]::Float,
                                [System.Globalization.CultureInfo]::InvariantCulture, [ref]$number)) {
        return $null
    }

    # Kilobytes per unit. Written as literals on purpose: "1024GB" is a terabyte in PowerShell,
    # which is exactly the kind of thing that silently corrupts size reporting.
    $kbPerUnit = @{
        'PB' = 1099511627776
        'TB' = 1073741824
        'GB' = 1048576
        'MB' = 1024
        'KB' = 1
        'B'  = 0.0009765625
    }

    $unit = $m.Groups[2].Value.ToUpperInvariant()
    if (-not $kbPerUnit.ContainsKey($unit)) { return $null }

    return [int64][math]::Round($number * $kbPerUnit[$unit], 0)
}

function Format-AuditSize {
    <#
    .SYNOPSIS
        Human-readable size from a KB value.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Kilobytes)

    if ($null -eq $Kilobytes) { return '' }
    $kb = 0.0
    if (-not [double]::TryParse(([string]$Kilobytes).Replace(',', '.'), [ref]$kb)) { return ([string]$Kilobytes) }

    # Thresholds expressed in KB (1 TB = 1,073,741,824 KB).
    if      ($kb -ge 1073741824) { return ('{0:N2} TB' -f ($kb / 1073741824)) }
    elseif  ($kb -ge 1048576)    { return ('{0:N2} GB' -f ($kb / 1048576)) }
    elseif  ($kb -ge 1024)       { return ('{0:N2} MB' -f ($kb / 1024)) }
    else                         { return ('{0:N0} KB' -f $kb) }
}

# =====================================================================
# Name resolution and relay-source classification
# =====================================================================

function Resolve-AuditHostName {
    <#
    .SYNOPSIS
        Cached reverse-DNS (PTR) lookup. Returns '' when nothing is found.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$IpAddress,
        [switch]$UseServer
    )

    if ([string]::IsNullOrWhiteSpace($IpAddress)) { return '' }
    if ($script:AuditDnsCache.ContainsKey($IpAddress)) { return $script:AuditDnsCache[$IpAddress] }

    $name = ''
    try {
        if (Get-Command -Name 'Resolve-DnsName' -ErrorAction SilentlyContinue) {
            $params = @{ Name = $IpAddress; Type = 'PTR'; DnsOnly = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
            if ($UseServer) { $params['DnsOnly'] = $true }
            $record = Resolve-DnsName @params | Where-Object { $_.Type -eq 'PTR' } | Select-Object -First 1
            if ($record -and $record.NameHost) { $name = $record.NameHost.TrimEnd('.') }
        }
        else {
            $entry = [System.Net.Dns]::GetHostEntry($IpAddress)
            if ($entry -and $entry.HostName) { $name = $entry.HostName }
        }
    }
    catch { $name = '' }

    $script:AuditDnsCache[$IpAddress] = $name
    return $name
}

function ConvertTo-AuditLdapFilterValue {
    <#
    .SYNOPSIS
        Escapes a value for use inside an LDAP filter string (RFC 4515).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return '' }

    $escaped = $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
    $escaped = $escaped.Replace([string][char]0, '\00')
    return $escaped
}

$script:AuditLastDnsError = $null

function Resolve-AuditDnsRecord {
    <#
    .SYNOPSIS
        Resolve-DnsName wrapper that degrades gracefully and returns a typed record array.
    .DESCRIPTION
        Returns an empty array when the name has no records of that type, and records the
        failure text in $script:AuditLastDnsError so callers can distinguish "no records"
        from "resolver broken". Falls back to the default resolver if the requested DNS
        server parameter is not supported by the installed DnsClient module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet('MX', 'TXT', 'A', 'AAAA', 'CNAME', 'NS', 'SRV')][string]$Type = 'MX',
        [AllowEmptyString()][string]$DnsServer
    )

    $script:AuditLastDnsError = $null

    if (-not (Get-Command -Name 'Resolve-DnsName' -ErrorAction SilentlyContinue)) {
        $script:AuditLastDnsError = 'Resolve-DnsName not available on this host'
        return @()
    }

    $attempts = New-Object 'System.Collections.Generic.List[object]'
    if ($DnsServer) {
        foreach ($serverParam in @('DnsServer', 'Server')) {
            $p = @{ Name = $Name; Type = $Type; ErrorAction = 'Stop' }
            $p[$serverParam] = $DnsServer
            $attempts.Add($p) | Out-Null
        }
    }
    $attempts.Add(@{ Name = $Name; Type = $Type; ErrorAction = 'Stop' }) | Out-Null

    foreach ($p in $attempts) {
        try {
            $records = @(Resolve-DnsName @p | Where-Object { $_.Type -eq $Type })
            return $records
        }
        catch {
            $script:AuditLastDnsError = $_.Exception.Message
        }
    }

    return @()
}

function Get-AuditMxHostName {
    <#
    .SYNOPSIS
        Extracts the target host name from a Resolve-DnsName MX record (property names vary).
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Record)

    if ($null -eq $Record) { return '' }
    foreach ($name in @('NameExchange', 'NameHost', 'Data', 'ExchangeServer')) {
        $prop = $Record.PSObject.Properties[$name]
        if ($null -ne $prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
            return ([string]$prop.Value).TrimEnd('.')
        }
    }
    return ''
}

function Find-AuditComputerByIp {
    <#
    .SYNOPSIS
        Best-effort Active Directory computer object lookup for a source IP or hostname.
    .DESCRIPTION
        Tries the ActiveDirectory module first (IPv4Address filter), then falls back to an
        ADSI search on dNSHostName / servicePrincipalName so it still works without RSAT.
        Returns Name, OperatingSystem and Description - device descriptions frequently name
        the owning application, which is what makes this worth doing.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$IpAddress,
        [AllowEmptyString()][string]$HostName
    )

    $cacheKey = "{0}|{1}" -f $IpAddress, $HostName
    if ($script:AuditAdComputerCache.ContainsKey($cacheKey)) { return $script:AuditAdComputerCache[$cacheKey] }

    $result = [pscustomobject]@{
        Name            = ''
        OperatingSystem = ''
        Description     = ''
        Source          = ''
    }

    if ([string]::IsNullOrWhiteSpace($IpAddress) -and [string]::IsNullOrWhiteSpace($HostName)) {
        $script:AuditAdComputerCache[$cacheKey] = $result
        return $result
    }

    $adModule = Get-Command -Name 'Get-ADComputer' -ErrorAction SilentlyContinue

    if ($adModule) {
        # IPv4Address is queryable on Windows Server 2012+ AD schemas.
        if (-not [string]::IsNullOrWhiteSpace($IpAddress)) {
            try {
                $computer = Get-ADComputer -Filter "IPv4Address -eq '$IpAddress'" `
                                -Properties OperatingSystem, Description, LastLogonDate -ErrorAction Stop |
                            Select-Object -First 1
                if ($computer) {
                    $result.Name            = [string]$computer.Name
                    $result.OperatingSystem = [string]$computer.OperatingSystem
                    $result.Description     = [string]$computer.Description
                    $result.Source          = 'AD (IPv4Address)'
                }
            }
            catch { }
        }

        if (-not $result.Name -and -not [string]::IsNullOrWhiteSpace($HostName)) {
            try {
                $escaped = ConvertTo-AuditLdapFilterValue -Value $HostName
                $computer = Get-ADComputer -LDAPFilter "(dNSHostName=$escaped)" `
                                -Properties OperatingSystem, Description -ErrorAction Stop |
                            Select-Object -First 1
                if (-not $computer) {
                    $computer = Get-ADComputer -LDAPFilter "(servicePrincipalName=HOST/$escaped)" `
                                    -Properties OperatingSystem, Description -ErrorAction Stop |
                                Select-Object -First 1
                }
                if ($computer) {
                    $result.Name            = [string]$computer.Name
                    $result.OperatingSystem = [string]$computer.OperatingSystem
                    $result.Description     = [string]$computer.Description
                    $result.Source          = 'AD (hostname)'
                }
            }
            catch { }
        }
    }

    if (-not $result.Name -and -not [string]::IsNullOrWhiteSpace($HostName)) {
        # ADSI fallback - no RSAT dependency.
        try {
            $escaped  = ConvertTo-AuditLdapFilterValue -Value ($HostName.Split('.')[0])
            $searcher = New-Object System.DirectoryServices.DirectorySearcher(
                "(objectCategory=computer)(|(name=$escaped)(dNSHostName=$($escaped)*))")
            $searcher.PropertiesToLoad.AddRange(@('name', 'operatingSystem', 'description')) | Out-Null
            $found = $searcher.FindOne()
            if ($found) {
                $result.Name            = [string]$found.Properties['name'][0]
                if ($found.Properties.Contains('operatingsystem')) {
                    $result.OperatingSystem = [string]$found.Properties['operatingsystem'][0]
                }
                if ($found.Properties.Contains('description')) {
                    $result.Description = [string]$found.Properties['description'][0]
                }
                $result.Source = 'AD (ADSI name match)'
            }
        }
        catch { }
    }

    $script:AuditAdComputerCache[$cacheKey] = $result
    return $result
}

$script:AuditCategoryRules = [ordered]@{
    'Printer / MFP'           = @('print', 'copier', 'printer', 'mfp', 'bizhub', 'toner', 'lexmark', 'epson', 'canon', 'sharp', 'tokai', 'ricoh', 'xerox', 'konica', 'develop', 'lp_', 'hpclj', 'phaser')
    'Scanner / imaging'       = @('scan', 'docu', 'kofax', 'capture', 'ocr', 'imaging', 'filenet', 'onbase')
    'Fax / unified comms'     = @('fax', 'hylafax', 'efax', 'ringcentral', 'mitel', 'avaya')
    'ERP / finance'           = @('erp', 'sap', 'navision', 'dynamicsgp', 'sage', 'jdedwards', 'infor', 'netsuite', 'acumatica', 'foodpro', 'alohapos', 'micromed', 'mas90', 'sage300', 'workday', 'financial', 'accounting', 'gl_', 'ap_')
    'CRM / marketing'         = @('crm', 'salesforce', 'dynamicscrm', 'hubspot', 'marketing', 'campaign', 'mailchimp', 'eloqua')
    'ITSM / ticketing'        = @('servicenow', 'cherwell', 'remedy', 'bmc', 'jira', 'itsm', 'helpdesk', 'ticket', 'request', 'sd_', 'helebot')
    'Monitoring / observability' = @('solarwinds', 'orion', 'nagios', 'zabbix', 'prtg', 'scom', 'operationsmanager', 'datadog', 'logicmonitor', 'newrelic', 'splunk', 'grafana', 'observium', 'paessler')
    'Backup / storage'        = @('veeam', 'commvault', 'netbackup', 'asigra', 'dpm', 'rubrik', 'cohesity', 'unitrends', 'backup', 'arcserve', 'catalog')
    'Security appliance'      = @('fortinet', 'fortigate', 'paloalto', 'panos', 'checkpoint', 'sophos', 'proofpoint', 'barracuda', 'tenable', 'qualys', 'rapid7', 'imperva', 'ironport', 'esa', 'wsa', 'trendmicro', 'mcafee', 'sentinelone', 'crowdstrike', 'fireeye', 'snort', 'alis')
    'SCCM / endpoint mgmt'    = @('sccm', 'mecm', 'configmgr', 'intune', 'endpoint', 'wsus', 'forefront')
    'Database server'         = @('sql', 'dbsrv', 'oracle', 'postgres', 'mongo', 'mysql', 'dbserver')
    'Web / application server'= @('web', 'iis', 'app', 'portal', 'intranet', 'tomcat', 'jboss', 'node', 'sharepoint', 'moss', 'nintex', 'k2', 'inforoma')
    'Build / CI'              = @('jenkins', 'bamboo', 'teamcity', 'gitlab', 'runner', 'vsts', 'azure-pipelines', 'build', 'deploy')
    'HR / payroll / workforce'= @('payroll', 'hris', 'kronos', 'dime', 'workforce', 'wfm', 'successfactors', 'adp', 'benefit')
    'Mail infrastructure'     = @('mail', 'smtp', 'relay', 'exchange', 'exch', 'transport', 'gateway', 'mx_', 'antivirus')
    'Directory / infrastructure' = @('dc0', 'dc1', 'addc', 'domaincontroller', 'hyperv', 'vcenter', 'esxi', 'nutanix', 'proxmox', 'host_', 'srv_')
}

function Get-AuditAppCategory {
    <#
    .SYNOPSIS
        Heuristic classification of an SMTP submission source from hostname, AD data,
        connector name and envelope sender addresses.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$HostName,
        [AllowEmptyString()][string]$ComputerName,
        [AllowEmptyString()][string]$Description,
        [AllowEmptyString()][string]$ConnectorId,
        [AllowEmptyString()][string]$Senders
    )

    $parts = @($HostName, $ComputerName, $Description, $ConnectorId, ($Senders -replace '@', ' ')) |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { ([string]$_).ToLowerInvariant() }
    $haystack = ($parts -join ' ')

    if ([string]::IsNullOrWhiteSpace($haystack)) { return 'Unknown' }

    foreach ($category in $script:AuditCategoryRules.Keys) {
        foreach ($keyword in $script:AuditCategoryRules[$category]) {
            if ($haystack.Contains($keyword)) { return $category }
        }
    }

    return 'Unknown - owner identification required'
}

function Get-AuditReplacementPath {
    <#
    .SYNOPSIS
        Recommends the Microsoft 365 send path for a discovered relay source.
    .DESCRIPTION
        Guidance is based on Microsoft's published options for applications and devices:
          - Client SMTP submission (SMTP AUTH, smtp.office365.com :587) - basic authentication
            for client submission is being retired; use OAuth or one of the alternatives.
          - SMTP relay via an OnPremises-type inbound connector (:25, IP- or cert-authenticated).
            Since 1 Nov 2023 the MAIL FROM domain must be an accepted domain in the tenant.
          - Direct Send (app acts as an MTA straight to the tenant MX) - cloud recipients only.
          - High Volume Email for Microsoft 365 (smtp.hve.mx.microsoft :587, TLS + HVE account)
            - internal recipients only, no throttling.
          - Azure Communication Services Email - internal and external, platform-managed.
        The recommendation is a starting point; confirm device TLS capability and egress IP.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('InternalOnly','Mixed','ExternalOnly','Unknown')][string]$RecipientScope = 'Unknown',
        [AllowEmptyString()][string]$Category = '',
        [switch]$HighVolume,
        [switch]$ThirdPartyHosted
    )

    if ($RecipientScope -eq 'InternalOnly') {
        if ($HighVolume) {
            return [pscustomobject]@{
                Path      = 'High Volume Email for Microsoft 365'
                Endpoint  = 'smtp.hve.mx.microsoft :587 (TLS + HVE account/OAuth)'
                Rationale = 'Internal recipients only and high volume - HVE has no recipient/day throttling and bypasses anti-spam for tenant mail.'
            }
        }
        return [pscustomobject]@{
            Path      = 'Direct Send or High Volume Email'
            Endpoint  = '<tenant>.mail.protection.outlook.com :25 (no auth) / smtp.hve.mx.microsoft :587'
            Rationale = 'Internal recipients only - Direct Send needs no tenant object; HVE if the device supports TLS and you want guaranteed delivery.'
        }
    }

    if ($RecipientScope -eq 'ExternalOnly' -or $RecipientScope -eq 'Mixed') {
        if ($ThirdPartyHosted) {
            return [pscustomobject]@{
                Path      = 'Azure Communication Services Email (or SMTP AUTH from a cloud mailbox)'
                Endpoint  = 'ACS Email resource / smtp.office365.com :587 with OAuth'
                Rationale = 'Source is hosted outside your network, so an IP-based OnPremises inbound connector cannot authenticate it.'
            }
        }
        return [pscustomobject]@{
            Path      = 'SMTP relay via OnPremises-type inbound connector'
            Endpoint  = '<tenant>.mail.protection.outlook.com :25 (IP- or cert-authenticated)'
            Rationale = 'Internal and external recipients. Needs a static egress IP dedicated to you, or a TLS certificate whose SAN matches an accepted domain (MAIL FROM must be an accepted domain since Nov 2023).'
        }
    }

    return [pscustomobject]@{
        Path      = 'Undetermined - owner identification required'
        Endpoint  = 'TBD'
        Rationale = 'Recipient scope unknown. Capture 30-90 days of message tracking (including quarterly batch jobs) before choosing a path.'
    }
}

function Get-AuditPrivateIpSet {
    <#
    .SYNOPSIS
        The IP addresses belonging to the local server and its network interfaces - used to
        tell "this server" apart from genuine external submission sources.
    #>
    [CmdletBinding()]
    param()

    $ips = New-Object 'System.Collections.Generic.HashSet[string]'

    try {
        foreach ($adapter in Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop) {
            if ($adapter.IPAddress) { [void]$ips.Add($adapter.IPAddress.ToString()) }
        }
    }
    catch {
        try {
            foreach ($host_ in [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName())) {
                if ($host_.AddressFamily -eq 'InterNetwork') { [void]$ips.Add($host_.ToString()) }
            }
        }
        catch { }
    }

    return $ips
}

function Format-AuditSize {
    <#
    .SYNOPSIS
        Human-readable size from a KB value.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Kilobytes)

    if ($null -eq $Kilobytes) { return '' }
    $kb = 0.0
    if (-not [double]::TryParse(([string]$Kilobytes).Replace(',', '.'), [ref]$kb)) { return ([string]$Kilobytes) }

    # Thresholds expressed in KB (1 TB = 1,073,741,824 KB).
    if      ($kb -ge 1073741824) { return ('{0:N2} TB' -f ($kb / 1073741824)) }
    elseif  ($kb -ge 1048576)    { return ('{0:N2} GB' -f ($kb / 1048576)) }
    elseif  ($kb -ge 1024)       { return ('{0:N2} MB' -f ($kb / 1024)) }
    else                         { return ('{0:N0} KB' -f $kb) }
}

function Get-AuditMxHostName {
    <#
    .SYNOPSIS
        Extracts the target host name from a Resolve-DnsName MX record (property names vary).
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Record)

    if ($null -eq $Record) { return '' }
    foreach ($name in @('NameExchange', 'NameHost', 'Data', 'ExchangeServer')) {
        $prop = $Record.PSObject.Properties[$name]
        if ($null -ne $prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
            return ([string]$prop.Value).TrimEnd('.')
        }
    }
    return ''
}

function Get-AuditExchangeBuildInfo {
    <#
    .SYNOPSIS
        Maps an Exchange AdminDisplayVersion string to a friendly product/CU label.
    #>
    [CmdletBinding()]
    param([string]$AdminDisplayVersion)

    $result = [pscustomobject]@{
        Product      = 'Unknown'
        MajorMinor   = ''
        Build        = 0
        CU           = 'Unmapped'
        SupportState = 'Unknown - verify against Microsoft lifecycle documentation'
    }

    if ([string]::IsNullOrWhiteSpace($AdminDisplayVersion)) { return $result }

    $match = [regex]::Match($AdminDisplayVersion, 'Version\s+(\d+)\.(\d+)\s+\(Build\s+(\d+)\.(\d+)\)')
    if (-not $match.Success) {
        $match = [regex]::Match($AdminDisplayVersion, '(\d+)\.(\d+)\.(\d+)\.(\d+)')
    }
    if (-not $match.Success) { return $result }

    $major  = [int]$match.Groups[1].Value
    $minor  = [int]$match.Groups[2].Value
    $build  = [int]$match.Groups[3].Value
    $rev    = [int]$match.Groups[4].Value

    $result.MajorMinor = "{0}.{1}" -f $major, $minor
    $result.Build      = $build

    switch ("{0}.{1}" -f $major, $minor) {
        '15.2' {
            $result.Product = 'Exchange Server 2019 / Subscription Edition'
            if ($build -ge 2562)      { $result.CU = 'Subscription Edition (SE)' }
            elseif ($build -ge 1748)  { $result.CU = 'CU15' }
            elseif ($build -ge 1544)  { $result.CU = 'CU14' }
            elseif ($build -ge 1258)  { $result.CU = 'CU8 or earlier branch (see note)' }
            elseif ($build -ge 1118)  { $result.CU = 'CU7' }
            elseif ($build -ge 986)   { $result.CU = 'CU6' }
            elseif ($build -ge 858)   { $result.CU = 'CU5' }
            elseif ($build -ge 721)   { $result.CU = 'CU4' }
            elseif ($build -ge 595)   { $result.CU = 'CU3' }
            elseif ($build -ge 464)   { $result.CU = 'CU2' }
            elseif ($build -ge 330)   { $result.CU = 'CU1' }
            elseif ($build -ge 221)   { $result.CU = 'RTM' }

            if ($build -lt 2562) {
                $result.SupportState = 'Out of support since 14 Oct 2025 (security updates only via the ESU program)'
            }
            else {
                $result.SupportState = 'Supported (Subscription Edition servicing)'
            }
        }
        '15.1' {
            $result.Product      = 'Exchange Server 2016'
            $result.SupportState = 'Out of support since 14 Oct 2025 - migration required'
        }
        '15.0' { $result.Product = 'Exchange Server 2013'; $result.SupportState = 'Long out of support' }
        '14.x' { $result.Product = 'Exchange Server 2010'; $result.SupportState = 'Long out of support' }
    }

    return $result
}

function Resolve-AuditDnsRecord {
    <#
    .SYNOPSIS
        Resolve-DnsName wrapper that degrades gracefully and returns a typed record array.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet('MX', 'TXT', 'A', 'AAAA', 'CNAME', 'NS', 'SRV')][string]$Type = 'MX',
        [AllowEmptyString()][string]$DnsServer
    )

    $script:AuditLastDnsError = $null

    if (-not (Get-Command -Name 'Resolve-DnsName' -ErrorAction SilentlyContinue)) {
        $script:AuditLastDnsError = 'Resolve-DnsName not available on this host'
        return @()
    }

    $attempts = New-Object 'System.Collections.Generic.List[object]'
    if ($DnsServer) {
        foreach ($serverParam in @('DnsServer', 'Server')) {
            $p = @{ Name = $Name; Type = $Type; ErrorAction = 'Stop' }
            $p[$serverParam] = $DnsServer
            $attempts.Add($p) | Out-Null
        }
    }
    $attempts.Add(@{ Name = $Name; Type = $Type; ErrorAction = 'Stop' }) | Out-Null

    foreach ($p in $attempts) {
        try {
            $records = @(Resolve-DnsName @p | Where-Object { $_.Type -eq $Type })
            return $records
        }
        catch {
            $script:AuditLastDnsError = $_.Exception.Message
        }
    }

    return @()
}

function Get-AuditPrivateIpSet {
    <#
    .SYNOPSIS
        The IP addresses belonging to the local server and its network interfaces.
    #>
    [CmdletBinding()]
    param()

    $ips = New-Object 'System.Collections.Generic.HashSet[string]'

    try {
        foreach ($adapter in Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue) {
            if ($adapter.IPAddress) { [void]$ips.Add($adapter.IPAddress.ToString()) }
        }
    }
    catch {
        try {
            foreach ($host_ in [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName())) {
                if ($host_.AddressFamily -eq 'InterNetwork') { [void]$ips.Add($host_.ToString()) }
            }
        }
        catch { }
    }

    return $ips
}

Export-ModuleMember -Function @(
    'ConvertTo-HtmlEncoded',
    'ConvertTo-AuditCellText',
    'ConvertTo-HtmlTable',
    'New-AuditReport',
    'Add-AuditSection',
    'Add-AuditHtmlBlock',
    'New-AuditCard',
    'New-AuditCallout',
    'Get-AuditReportHtml',
    'Write-AuditReport',
    'Export-AuditCsv',
    'Invoke-AuditStep',
    'Start-AuditTranscript',
    'Stop-AuditTranscript',
    'New-AuditOutputDirectory',
    'Test-AuditExchangeShell',
    'Get-AuditExchangeBuildInfo',
    'Get-AuditSizeKB',
    'Format-AuditSize',
    'Resolve-AuditHostName',
    'Resolve-AuditDnsRecord',
    'Get-AuditMxHostName',
    'ConvertTo-AuditLdapFilterValue',
    'Find-AuditComputerByIp',
    'Get-AuditAppCategory',
    'Get-AuditReplacementPath',
    'Get-AuditPrivateIpSet'
)
