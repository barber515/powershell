# PowerShell HTML Report Template

Universal HTML report generation pattern extracted from
`Invoke-ADSecurityAudit.ps1`. Drop these pieces into any script that needs to
render structured output as a self-contained, styled HTML file.

---

## 1. HTML Encoding Helper

Use `[System.Net.WebUtility]::HtmlEncode` — no `Add-Type`, identical behaviour
on Windows PowerShell 5.1 and PowerShell 7+.

```powershell
function ConvertTo-HtmlEncoded {
    [CmdletBinding()]
    param([string]$Text)
    [System.Net.WebUtility]::HtmlEncode($Text)
}
```

**Rule:** every value that originates from data (names, paths, error messages,
user input, domain names, group memberships) must pass through this function
before being interpolated into HTML. Never interpolate raw values directly.

**What to encode:**

| Source | Example | Encode? |
|--------|---------|---------|
| AD object properties (`Name`, `SamAccountName`) | `CN=Admins,CN=Users` | Yes |
| Error messages from queries | `"Could not bind: Access Denied"` | Yes |
| User identity (`$env:USERNAME`) | `andyb` | Yes (defensive) |
| Domain/forest names | `contoso.com` | Yes |
| Script-generated strings without special chars | `"No results"` | Optional but consistent |

---

## 2. Table Renderer

Converts a collection of objects into an HTML `<table>`. Auto-detects columns
from the first object's `PSObject.Properties`.

```powershell
function ConvertTo-HtmlTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Rows
    )

    if (-not $Rows -or @($Rows).Count -eq 0) {
        return '<p class="empty">No results &mdash; nothing flagged for this check.</p>'
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
            $val = [string]$r.$c          # null becomes "" before encoding
            [void]$sb.Append("<td>$(ConvertTo-HtmlEncoded $val)</td>")
        }
        [void]$sb.Append('</tr>')
    }

    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}
```

**Notes:**
- All cells are individually HTML-encoded.
- Empty input produces a green "No results" message (`.empty` class).
- Column order follows the property order of the first row. Control order and
  naming with `Select-Object` or calculated properties (`@{n='Label';e={...}}`)
  before calling this function.
- Null values are cast to empty strings via `[string]$null`. If you need a
  visible placeholder (e.g., "N/A"), handle it in the data pipeline, not here.

---

## 3. Section / Report Model

Collect results into a list of section objects. Each section carries a severity
level that drives its visual colour throughout the report.

### Data model

```powershell
$report = [System.Collections.Generic.List[object]]::new()
```

Each element is a `[pscustomobject]` built from an ordered dictionary with these
properties:

| Property | Type | Purpose |
|----------|------|---------|
| `Title` | string | Section heading shown in the report |
| `Description` | string | Context paragraph explaining what was checked and why |
| `Severity` | Critical / High / Medium / Info | Drives badge colour and header border |
| `Rows` | object[] | The data rows for this section's table |
| `Count` | int | Number of rows (set after query execution) |
| `Error` | string or $null | Populated only when the query throws; rendered as a red message |

### Severity colour map

```powershell
$sevColour = @{
    Critical = '#c0392b'   # dark red — immediate action required
    High     = '#e67e22'   # orange  — significant risk, review soon
    Medium   = '#f1c40f'   # yellow  — noteworthy, investigate when convenient
    Info     = '#3498db'   # blue    | informational / clean state
}
```

**Customization:** add new keys to the dictionary and extend the `ValidateSet`
in `Add-Section`. The colour is applied in two places: the severity badge and
the left border on the section heading. Keep colours WCAG-aware if the report
will be viewed by people with colour vision deficiency — always pair colour with
text labels.

### Section helper

```powershell
function Add-Section {
    [CmdletBinding()]
    param(
        [string]$Title,
        [string]$Description,
        [ValidateSet('Critical','High','Medium','Info')]
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

    $report.Add([pscustomobject]$obj)
}
```

**Key design points:**
- A failed query does not abort the run; the error is stored and rendered as a
  red message inside the section body. This means one misconfigured check cannot
  prevent the rest of the report from being generated.
- The `$()` array-subexpression around `$result` ensures that even a single-row
  result is always an array, so `.Count` works reliably.

**Usage:**

```powershell
Add-Section -Title 'Example Check' -Severity 'High' `
    -Description 'What this check looks for and why it matters.' `
    -Query {
        Get-Something -Filter * |
            Select-Object Name, Status, LastModified |
            Sort-Object LastModified
    }
```

---

## 4. Summary Table

A quick-glance roll-up of every section's severity and finding count. Place this
at the top of `<main>` so readers see the risk posture before drilling into
details.

```powershell
$summaryRows = $report | ForEach-Object {
    [pscustomobject]@{
        Severity = $_.Severity
        Check    = $_.Title
        Findings = if ($_.Error) { 'ERROR' } else { $_.Count }
    }
}
$summaryTable = ConvertTo-HtmlTable -Rows $summaryRows
```

The summary table uses the `.summary` CSS class for slightly different border
styling. Rows with `Findings = 'ERROR'` should be investigated first — they
indicate a check that could not complete, which may mask real findings.

---

## 5. Build the HTML Body

Iterate `$report` and concatenate each section's markup using `StringBuilder`.

```powershell
$body = [System.Text.StringBuilder]::new()

foreach ($sec in $report) {
    $colour = $sevColour[$sec.Severity]

    # Section heading with severity badge, title, and result count
    [void]$body.Append("<section><h2 style='border-left:6px solid $colour'>")
    [void]$body.Append("<span class='badge' style='background:$colour'>$($sec.Severity)</span> ")
    [void]$body.Append((ConvertTo-HtmlEncoded $sec.Title))

    $countLabel = if ($sec.Error) { 'error' } else { "$($sec.Count) result(s)" }
    [void]$body.Append("<span class='count'>$countLabel</span></h2>")

    # Description paragraph
    [void]$body.Append("<p class='desc'>$(ConvertTo-HtmlEncoded $sec.Description)</p>")

    # Body content: error message or data table
    if ($sec.Error) {
        [void]$body.Append("<p class='error'>Query error: $(ConvertTo-HtmlEncoded $sec.Error)</p>")
    }
    else {
        [void]$body.Append((ConvertTo-HtmlTable -Rows $sec.Rows))
    }

    [void]$body.Append('</section>')
}
```

**Multiple tables per section:** if a single check produces distinct data sets,
call `ConvertTo-HtmlTable` multiple times inside the body loop and append each
result. Insert a heading or separator between them as needed.

---

## 6. Header Metadata

Encode all dynamic values before interpolating into the HTML header. The header
conveys context: what was audited, when, by whom, and against which target.

```powershell
$hTitle   = ConvertTo-HtmlEncoded $domain.DNSRoot        # or any report title
$hForest  = ConvertTo-HtmlEncoded $domain.Forest         # optional
$hRunBy   = ConvertTo-HtmlEncoded "$env:USERDOMAIN\$env:USERNAME"
$hTarget  = ConvertTo-HtmlEncoded $(if ($Server) { $Server } else { '(auto-located DC)' })
```

**Header metadata checklist:**

| Field | Source | Encoded? | Notes |
|-------|--------|----------|-------|
| Report title / domain name | Script variable or AD query | Yes | Never raw from AD |
| Target system | Parameter or auto-discovery | Yes | Clarifies scope |
| Timestamp | `$(Get-Date -Format '...')` | No | Generated at render time, no user data |
| Run-by identity | `$env:USERDOMAIN\$env:USERNAME` | Yes | For audit trail |

---

## 7. Classification Banner

The classification banner signals that the report contains sensitive information.
Include it whenever the output lists privileged accounts, attack paths, secrets,
or other restricted data. Remove or edit it only when the report is safe for
unrestricted distribution.

```html
<div class="classification">Restricted &mdash; contains privileged-account and attack-path detail</div>
```

**Guidance:**
- Use this banner on any report that could aid an attacker if leaked (e.g.,
  enumeration of admin groups, delegation configurations, certificate templates).
- The text is static in the template but should match your organization's
  classification scheme. Replace "Restricted" with whatever label your policy uses.
- The banner is styled as a small red pill at the top of the page for visibility.

---

## 8. Footer Disclaimers

The footer is the place for methodology notes, data-limitation warnings, and
tooling caveats. Keep it factual and brief.

```html
<footer>
    Read-only audit. No directory objects were modified.
    LastLogonTimestamp-based checks may lag true activity by up to ~14 days &mdash; validate before acting.
    For scored, attack-path depth, pair this with [external tool reference].
</footer>
```

**Common disclaimer topics:**
- Data staleness (e.g., replication lag for `lastLogonTimestamp`)
- Read-only guarantee (confirms no modifications were made)
- Tooling limitations (what the script cannot detect and what to use instead)
- Remediation caveats (warnings about breaking changes if findings are acted on)

---

## 9. Full HTML Document Template

Replace the `{{ ... }}` placeholders with your encoded values. The `<style>`
block is self-contained — no external CSS or JavaScript dependencies.

```powershell
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ $hTitle }}</title>
<style>
    :root { font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
    body { margin: 0; background: #f4f6f8; color: #222; }

    /* ---- Header ---- */
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
    .count { margin-left: auto; font-size: 12px; color: #888; font-weight: 400; }
    .desc  { font-size: 13px; color: #555; margin: 4px 0 12px; }

    /* ---- Tables ---- */
    table { border-collapse: collapse; width: 100%; font-size: 13px; }
    th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #eaeef1; }
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
    <h1>{{ $hTitle }}</h1>
    <div class="meta">
        Target: {{ $hTarget }} &nbsp;|&nbsp;
        Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp;
        Run by: {{ $hUser }}
    </div>
    <!-- Remove or edit if the report does not contain sensitive data -->
    <div class="classification">Restricted &mdash; sensitive data</div>
</header>

<main>
    <section class="summary">
        <h2 style="border-left:6px solid #1f2d3d">Summary</h2>
        <p class="desc">Overview of all checks and their finding counts.</p>
        {{ $summaryTable }}
    </section>

    {{ $body.ToString() }}
</main>

<footer>
    {{ Optional disclaimer or methodology note }}
</footer>

</body>
</html>
"@
```

---

## 10. Write & Open

```powershell
# Write with UTF-8 encoding (includes BOM on Windows, which browsers handle fine)
$html | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "Report written to: $OutputPath" -ForegroundColor Green

# Optionally open in the default browser; non-fatal on headless systems
if (-not $NoLaunch) {
    try { Invoke-Item $OutputPath } catch { }
}
```

---

## 11. CSS Class Reference

All classes used by this template, with their purpose and styling:

| Class | Element | Purpose | Key Styles |
|-------|---------|---------|------------|
| `meta` | `<div>` inside header | Secondary metadata line (target, date, user) | 13px, muted grey |
| `classification` | `<div>` in header | Sensitive-data banner | Red pill badge, uppercase |
| `summary` | `<section>` wrapping summary table | Distinguishes summary from data sections | Custom border on cells |
| `badge` | `<span>` severity label | Coloured severity indicator | Rounded pill, white text |
| `count` | `<span>` result count | Right-aligned row count in section header | 12px, grey |
| `desc` | `<p>` description paragraph | Section explanation text | 13px, muted grey |
| `empty` | `<p>` inside table area | "No results" message for clean checks | Green italic |
| `error` | `<p>` query failure notice | Red error text when a check fails | Dark red |

**Theming:** all colours are defined as CSS properties in the `<style>` block.
To re-theme, change the hex values directly. For dark mode support, add a
`@media (prefers-color-scheme: dark)` block and override `body`, `section`,
`th`, and `td` background/text colours.

---

## 12. Minimal Integration Skeleton

A complete, copy-paste-ready script skeleton showing all pieces in context.

```powershell
#Requires -Version 7.0

<#
.SYNOPSIS
    Example script that produces a styled HTML report.
.EXAMPLE
    PS> .\Invoke-MyReport.ps1 -OutputPath .\report.html
#>

[CmdletBinding()]
param(
    [string] $OutputPath = ".\Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [switch] $NoLaunch
)

$ErrorActionPreference = 'Stop'

# =====================================================================
# HTML helpers  (Sections 1-2 of this template)
# =====================================================================
function ConvertTo-HtmlEncoded {
    param([string]$Text)
    [System.Net.WebUtility]::HtmlEncode($Text)
}

function ConvertTo-HtmlTable {
    param([object[]]$Rows)
    if (-not $Rows -or @($Rows).Count -eq 0) {
        return '<p class="empty">No results &mdash; nothing flagged.</p>'
    }
    $cols = ($Rows | Select-Object -First 1).PSObject.Properties.Name
    $sb   = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<table><thead><tr>')
    foreach ($c in $cols) { [void]$sb.Append("<th>$(ConvertTo-HtmlEncoded $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $cols) {
            [void]$sb.Append("<td>$(ConvertTo-HtmlEncoded ([string]$r.$c))</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    $sb.ToString()
}

# =====================================================================
# Report model  (Section 3 of this template)
# =====================================================================
$report    = [System.Collections.Generic.List[object]]::new()
$sevColour = @{ Critical='#c0392b'; High='#e67e22'; Medium='#f1c40f'; Info='#3498db' }

function Add-Section {
    param([string]$Title, [string]$Description,
          [ValidateSet('Critical','High','Medium','Info')][string]$Severity='Info',
          [scriptblock]$Query)
    $obj = [ordered]@{ Title=$Title; Description=$Description; Severity=$Severity
                       Rows=@(); Count=0; Error=$null }
    try {
        $result    = & $Query
        $obj.Rows  = @($result)
        $obj.Count = @($result).Count
    } catch { $obj.Error = $_.Exception.Message }
    $report.Add([pscustomobject]$obj)
}

# =====================================================================
# Main logic - add your sections here
# =====================================================================
Add-Section -Title 'Sample Check' -Severity 'Info' `
    -Description 'Demonstrates the section pattern.' `
    -Query {
        Get-Process | Select-Object -First 5 Name, Id, CPU
    }

# =====================================================================
# Render  (Sections 4-8 of this template)
# =====================================================================
$summaryRows  = $report | ForEach-Object {
    [pscustomobject]@{ Severity=$_.Severity; Check=$_.Title
                       Findings=if($_.Error){'ERROR'}else{$_.Count} }
}
$summaryTable = ConvertTo-HtmlTable -Rows $summaryRows

$body = [System.Text.StringBuilder]::new()
foreach ($sec in $report) {
    $colour = $sevColour[$sec.Severity]
    [void]$body.Append("<section><h2 style='border-left:6px solid $colour'>")
    [void]$body.Append("<span class='badge' style='background:$colour'>$($sec.Severity)</span> ")
    [void]$body.Append((ConvertTo-HtmlEncoded $sec.Title))
    $label = if($sec.Error){'error'}else{"$($sec.Count) result(s)"}
    [void]$body.Append("<span class='count'>$label</span></h2>")
    [void]$body.Append("<p class='desc'>$(ConvertTo-HtmlEncoded $sec.Description)</p>")
    if ($sec.Error) {
        [void]$body.Append("<p class='error'>Query error: $(ConvertTo-HtmlEncoded $sec.Error)</p>")
    } else {
        [void]$body.Append((ConvertTo-HtmlTable -Rows $sec.Rows))
    }
    [void]$body.Append('</section>')
}

$hTitle  = ConvertTo-HtmlEncoded 'My Report'
$hUser   = ConvertTo-HtmlEncoded "$env:USERDOMAIN\$env:USERNAME"

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
    header .classification { display:inline-block;margin-top:12px;background:#c0392b;color:#fff;
        font-size:11px;font-weight:600;padding:3px 10px;border-radius:3px;
        text-transform:uppercase;letter-spacing:.05em; }
    main { max-width:1200px; margin:24px auto; padding:0 24px; }
    section { background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1);
        margin-bottom:20px;padding:16px 20px; }
    h2 { font-size:16px;padding-left:12px;display:flex;align-items:center;gap:10px; }
    .badge { color:#fff;font-size:11px;font-weight:600;padding:2px 8px;
        border-radius:10px;text-transform:uppercase;letter-spacing:.04em; }
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
    Generated by PowerShell. All data is as-reported at generation time.
</footer>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "Report written to: $OutputPath" -ForegroundColor Green

if (-not $NoLaunch) {
    try { Invoke-Item $OutputPath } catch { }
}
```

---

## Design Decisions & Rationale

| Decision | Why |
|----------|-----|
| `[System.Net.WebUtility]::HtmlEncode` over `[System.Web.HttpUtility]` | No `Add-Type -AssemblyName System.Web` needed. Identical on PS 5.1 and 7+. Cross-platform compatible. |
| `StringBuilder` for assembly | Avoids thousands of string-concatenation allocations on large reports with many rows. |
| Section-level `try/catch` in `Add-Section` | One failed query must not abort the entire report. The error is surfaced as a visible red message so the operator knows something needs follow-up. |
| Severity colour map | Single source of truth for badge and border colour; easy to re-theme or extend with new levels. |
| Auto column detection from `PSObject.Properties` | No need to maintain a separate column list. Column order and naming are controlled by `Select-Object` before calling the table renderer. |
| `[string]$null` in cell rendering | Prevents `$null` from producing no `<td>` content; results in an empty cell instead of malformed HTML. |
| `Out-File -Encoding UTF8` | Explicit encoding avoids the PS 5.1 default (UTF-16LE) mismatch that produces garbled output in browsers. |
| Self-contained single file | No external CSS/JS dependencies. Report can be emailed, stored on a share, or opened from any browser without network access. |
| `Invoke-Item` with `try/catch` | Non-fatal on headless or restricted sessions where a browser cannot open. The report is still written successfully. |
| Classification banner | Signals to the reader that the document contains sensitive data and should be handled accordingly. |

---

## Adapting the Template

- **Different severity levels** — add keys to `$sevColour` and extend the
  `ValidateSet` in `Add-Section`.
- **Multiple tables per section** — call `ConvertTo-HtmlTable` multiple times
  inside the body loop and append each result. Insert a heading or separator
  between them as needed.
- **Dark mode** — add a `@media (prefers-color-scheme: dark)` block in the
  `<style>` section and override `body`, `section`, `th`, `td` colours.
- **Export to CSV alongside** — pipe the same `$report` rows to
  `Export-Csv` before rendering HTML; the data model is identical.
- **Remove classification banner** — delete the `<div class="classification">`
  line if the report does not contain sensitive data.
- **Custom header layout** — add or remove fields in the `.meta` div. All
  dynamic values must be HTML-encoded first.
- **Inline styles vs external CSS** — this template uses inline styles for
  simplicity and portability. For complex reports, consider extracting the
  `<style>` block into a separate `.css` file referenced via `<link>`.
