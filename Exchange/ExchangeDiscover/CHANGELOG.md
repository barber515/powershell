# Changelog

## 2026-11-13 — Runtime errors fixed: Subject not found, ServerRole (not ServerRoles), EmailAddressPolicy incomplete, Measure-Object property validation, Unlimited<ByteQuantifiedSize> wrapper

### `Invoke-ExchangeAudit.ps1`

| # | Fix | Rationale |
|---|-----|----------|
| **R-1** | Added `-IncludeMailboxSettingOnlyPolicy` to `Get-EmailAddressPolicy`. | Without it, email address policies that exist solely for mailbox settings (no SMTP addresses) are silently excluded from the report — a gap in audit coverage. |
| **R-2** | `ConvertTo-HtmlTable`: replaced `$val = [string]$r.$c` with property-existence guard (`$r.PSObject.Properties.Name -contains $c`). | When rows come from mixed sources (e.g., different cmdlet outputs merged into one table), some objects lack properties present in the first row. Direct `$r.$c` throws "The property 'X' cannot be found"; the guard returns `N/A` instead. |
| **R-3** | Replaced all `.ServerRoles` (plural, deprecated) with `.ServerRole` (singular, Exchange 2013+). Added `-and` null guard: `{ $_.ServerRole -and $_.ServerRole -match 'Mailbox' }`. | `Get-ExchangeServer` in Exchange 2013+ deprecated the plural `ServerRoles` property; it now returns `.ServerRole` (singular string like "Mailbox", "ClientAccess"). The script was written for pre-2013 Exchange where `ServerRoles` existed. All 6 occurrences across Server Configuration, Transport Queues, Mailbox Statistics, Server Health Status, DAG Health, and Client Access sections were updated. |
| **R-4** | Replaced `Measure-Object @{e={...}}` with explicit `foreach` loops for summing `.TotalItemSize.ToBytes()`. | In PowerShell 5.1, `Measure-Object` validates the "property" before evaluating a calculated-property expression. If any object in the pipeline lacks `.TotalItemSize`, it throws "cannot process argument because the value of argument 'property' is not valid." The explicit loop avoids property validation entirely. Applied to both the per-database size calculation and the total-storage sum in Mailbox Server Statistics. |
| **R-5** | Wrapped `.TotalItemSize.ToBytes()` calls in try/catch with fallback to `.Value.ToBytes()`. | `Get-MailboxStatistics` returns `$_.TotalItemSize` as `Unlimited<ByteQuantifiedSize>` (a generic wrapper type) rather than plain `ByteQuantifiedSize`. The wrapper lacks a `.ToBytes()` method; the underlying value is accessed via `.Value`. Try/catch first attempts direct call, then unwraps. Applied to both per-database and total-storage sums in Mailbox Server Statistics. |

### Behavioral changes
- Email Address Policies section now includes mailbox-setting-only policies (previously hidden).
- HTML report no longer shows "The property 'Subject' cannot be found" or "ServerRoles cannot be found" errors.
- Server Configuration table correctly reports `IsMailboxServer`/`IsEdgeServer` using the Exchange 2019 `.ServerRole` property.
- Transport Queues, Mailbox Statistics, Server Health Status, DAG Health, and Client Access sections now correctly filter to mailbox servers using the modern `.ServerRole` property.
- Mailbox Server Statistics no longer throws "cannot process argument because the value of argument 'property' is not valid" — uses explicit loops instead of `Measure-Object` with calculated properties.
- Mailbox Server Statistics no longer throws "method invocation failed... does not contain a method named 'ToBytes'" — handles `Unlimited<ByteQuantifiedSize>` wrapper via `.Value` fallback.

## 2026-11-13 — Syntax error fixes: unexpected token, missing expression, hash literal incomplete

### `Invoke-ExchangeAudit.ps1`

| # | Fix | Rationale |
|---|-----|----------|
| **S-1** | Replaced nested `@{ n='x'; e={...} }` calculated-property syntax inside `[pscustomobject]@{}` blocks with explicit `[ordered]@{} + property assignments`. | PowerShell 5.1's parser cannot reliably handle `@{n='x';e={...}}` as a value expression within another hashtable literal — it misidentifies the inner `{` as starting a new entry, producing "hash literal was incomplete" and "missing expression after ','" errors. The `[ordered]@{} + $obj.Prop = ...` pattern avoids nested hashtables entirely. |
| **S-2** | Replaced all double-encoded em-dash sequences (`â€"`, bytes `C3 A2 E2 82 AC E2 80 9D`) with ASCII `-` in string literals and here-string content. Also replaced double-encoded section sign (`Â§`, bytes `C3 82 C2 A7`) with plain text "section N" in comments. | The file contained UTF-8 em-dashes that had been re-encoded through Windows-1252 (a classic encoding corruption: original `—` → UTF-8 `E2 80 94` → Win-1252 interpretation → UTF-8 `C3 A2 E2 82 AC E2 80 9D`). PowerShell's parser treats these multi-byte sequences as individual characters inside string literals, confusing `$()` interpolation boundaries and producing "unexpected token '$('" errors that cascaded into breaking the entire HTML here-string. |

### Root cause summary
- **Unexpected token**: Double-encoded em-dash sequences (UTF-8 `E2 80 94` re-encoded through Windows-1252 → `C3 A2 E2 82 AC E2 80 9D`) inside string literals and here-string content confused PowerShell's parser about `$()` interpolation boundaries, producing cascading "unexpected token" errors.
- **Missing expression after ','**: The same encoding corruption caused the parser to treat multi-byte sequences as individual characters, breaking expression boundaries at commas within calculated-property definitions.
- **Hash literal was incomplete**: Nested `@{ n='x'; e={...} }` syntax inside `[pscustomobject]@{}` blocks — PowerShell 5.1's parser misidentifies the inner `{` as starting a new hashtable entry, leaving the outer literal unterminated.

### `Invoke-ExchangeAudit.ps1`

| # | Fix | Rationale |
|---|-----|-----------|
| **C-1** | Removed `#Requires -Modules ActiveDirectory`; domain info now falls back to `$env:USERDNSDOMAIN`, with optional AD module enrichment via `Get-Command Get-ADDomain` guard. | The RSAT AD module is not installed on Exchange 2019 servers by default — the script would abort before any audit work. |
| **C-2** | Changed mailbox database filter from `$_.Server` to `$_.ServerName`; added null guards on `.ToBytes()` for `DatabaseSize` and `AvailableNewMailboxSpace`. | `Get-MailboxDatabase` exposes hosting server as `ServerName`, not `Server`. The old filter dropped every row. Null sizes (unmounted DBs) would throw under StrictMode. |
| **C-3** | Certificates section now loops over `$exchangeServers`, calls `Get-ExchangeCertificate -Server $srv.Name`, and adds a `Server` column. | Without `-Server`, the cmdlet returns only local-server certs — half the inventory missing in a 2-member environment. |
| **C-4** | Restored `Get-MailboxDatabaseCopyStatus -Server $server.Name` in DAG Health (reverted E-04 regression). Fixed comment to reflect actual behavior. | The E-04 change (`Where-Object { $_.Server -eq $server.Name }`) was dead code: without `-Server`, the cmdlet defaults to local server, so the filter only matched when `$server.Name` happened to be the local server. |
| **C-5** | Multi-table renderer normalizes single-object results with `@($tableData.Data)` before checking count. Empty data renders as green "No results" instead of red "Error:". | PowerShell assigns a single object (not array) when a query returns exactly one row, so `-is [array]` was false — causing false errors for Email Address Policies and all four CAS sub-tables. |
| **H-1** | Mailbox size summation uses calculated property `@{e={if($null -ne $_.TotalItemSize){$_.TotalItemSize.ToBytes()}else{0}}}` instead of `Measure-Object -Property TotalItemSize -Sum`. | `TotalItemSize` is a `ByteQuantity*` object, not numeric; `Measure-Object -Sum` silently returns `$null`, producing `0 GB` for every server. |
| **H-2** | `$hRunBy = ConvertTo-HtmlEncoded "$env:USERDOMAIN\$env:USERNAME"` — single encoding before interpolation (template §6). | The F-1.1 fix removed double-encoding but left the value raw; a username with `&`, `<`, or `>` would break header markup. |
| **H-3** | `Add-Section` now scopes `$ErrorActionPreference = 'Stop'` around each query execution (saved/restored via `$oldEap`). | With global EAP=`Continue`, non-terminating errors inside a section's scriptblock were silently swallowed, producing false-clean green output instead of the intended red error. |
| **H-4** | Service health wraps remote `Get-Service` in per-server try/catch; reports all Exchange services with status (Running/Stopped) rather than only Stopped ones. Detects and reports query failures explicitly. | Remote service queries can fail silently (DCOM/WinRM blocked). Reporting only stopped services gave no positive evidence that healthy services were actually running. |
| **H-5** | `AddressSpaces` flattened to `SmtpAddress` strings; `TlsSettings` rendered as `"$TlsDomainSecure; $TlsRecipientSecure"`. | Without flattening, `ConvertTo-HtmlTable` cast these complex objects to their .NET type names (e.g., `System.Collections.Generic.List\`1[...]`). |
| **M-1** | Renamed "Update Rollups" → "Cumulative Update Levels"; reports full `AdminDisplayVersion.ToString()`, Major, Minor, BuildNumber, Revision. Dropped `ServicePack` and `LastUpgradePatchTime`. | Exchange 2019 ships monthly CUs identified by build number — not RUs. `ServicePack` is a non-existent property on `System.Version`; `Revision` is not the CU level. |
| **M-2** | CAS sub-headings include server name: e.g., "OWA Virtual Directories — EX01" instead of just "OWA Virtual Directories". | In a 2-member environment, two identical headings gave no indication of which server each table belonged to. |
| **M-3** | `$hComputer = ConvertTo-HtmlEncoded $env:COMPUTERNAME` used in footer; computer name is now encoded before interpolation. | Template §6 requires all dynamic values to be encoded. Same class of defect as H-2. |
| **M-4** | Queue sort changed from `Sort-Object Server, MessageCount -Descending` to `Sort-Object Server, @{ e = 'MessageCount'; d = $true }`. | `-Descending` applied to ALL listed properties; intent was Server ascending, MessageCount descending. |
| **M-5** | Removed dead `$dbCopy.Status -ne 'Healthy'` clause from DAG Health unhealthy check. | `Status` never equals `'Healthy'`; that is a `ContentIndexState` value. The condition was always true and misleading to maintainers. |
| **L-2** | Added `#endregion` matching the `#region Helper Functions`. | Unmatched region directive; minor housekeeping. |
| **L-3** | Added `h3 { font-size: 14px; margin: 16px 0 8px; padding-left: 8px; border-bottom: 1px solid #eaeef1; }` to `<style>` block. | The multi-table renderer uses `<h3>` for sub-headings but the template's CSS had no rule — rendered with browser defaults. |
| **L-5** | Transport Queues section filters to `MessageCount -gt 0 -or DeferredMessageCount -gt 0`. | Without filtering, the table is dominated by zero-message rows; stuck/deferred queues now stand out. |
| **L-7** | Added preflight check: `Get-Command Get-ExchangeServer` with friendly error message if running outside EMS. | Running outside Exchange Management Shell failed at `Get-ExchangeServer` with a raw, confusing error. |

### Behavioral changes
- Script now starts on any Exchange 2019 server regardless of RSAT AD module presence (C-1).
- Mailbox Databases section actually returns data instead of always being empty or throwing (C-2).
- Certificates section reports certs from ALL servers in the environment with a Server column (C-3).
- DAG Health Status correctly shows each server's database copies (C-4, reverts E-04 regression).
- Multi-table sections (Transport, Address, CAS) render single-row sub-tables as green "No results" instead of red "Error:" paragraphs (C-5).
- Mailbox Server Statistics reports actual storage sizes in GB instead of always 0 (H-1).
- Header Run-by identity is properly HTML-encoded (H-2); footer computer name encoded (M-3).
- Section failures now produce red error messages inside the section rather than false-clean green output (H-3).
- Server Health Status reports all Exchange services with status and detects remote query failures (H-4).
- Transport Configuration AddressSpaces/TlsSettings columns show readable values instead of .NET type names (H-5).
- Patch Levels renamed to Cumulative Update Levels with proper build-number reporting (M-1).
- CAS sub-headings distinguish servers in multi-server environments (M-2).
- Queue sort correctly applies descending only to MessageCount (M-4).

### Regression notes
- **E-04 reverted**: The prior fix that changed DAG Health from `-Server $server.Name` to `Where-Object { $_.Server -eq $server.Name }` was incorrect and has been restored. The original per-server query is the correct pattern.
- **F-1.1 superseded**: The previous double-encoding fix (raw `$hRunBy`) is replaced by single encoding via `ConvertTo-HtmlEncoded()` at assignment time.

## 2026-11-13 — Code review remediations: robustness, template compliance, and rendering fixes (F-1.1, F-1.2, F-1.3, F-1.4, F-2.1, F-2.2)

### `Invoke-ExchangeAudit.ps1`

| # | Fix | Rationale |
|---|-----|-----------|
| **F-2.2** | Added `#Requires -Modules ActiveDirectory` after `#Requires -Version 5.1`. | The script calls `Get-ADDomain` but did not declare the module requirement. Without it, a silent failure on servers lacking RSAT AD tools would produce incomplete domain metadata. |
| **F-2.1** | Changed `$ErrorActionPreference = "Stop"` to `"Continue"`; server-discovery block already uses `-ErrorAction Stop` locally and exits 1 on true fatal errors (no Exchange servers found). | The template explicitly states a failed query must not abort the entire run. A global `Stop` preference meant any unhandled error in *any* section would kill the script before generating the report. |
| **F-1.2** | Renamed `Component` → `Section` in Client Access Settings objects (OWA, ECP, MAPI, EWS vdirs). Also updated the catch-block object to use `Section`. | The body-loop multi-table renderer checks for a property named `'Section'` to detect nested tables. Using `Component` caused the check to fail, and arrays in the `Data` column rendered as `"System.Object[]"` — producing garbled output in the HTML report. |
| **F-1.4** | Added `$hDNSRoot = ConvertTo-HtmlEncoded $domainInfo.DNSRoot`; included both Forest and Domain in the `.meta` div alongside Target. | Template §6 checklist requires encoding and displaying the domain name for audit context. The previous version only showed server count with no AD forest/domain information. |
| **F-1.3** | `$hForest` is now actively used in the header `.meta` div (previously encoded but never interpolated). | Eliminated dead code; the variable serves its intended purpose of showing which AD forest was audited. |
| **F-1.1** | Removed double `ConvertTo-HtmlEncoded()` wrapping around `$hRunBy` in the `<header>` interpolation. `$hRunBy` is now assigned raw (`"$env:USERDOMAIN\$env:USERNAME"`) and interpolated directly. | The original code encoded `$hRunBy` at assignment, then passed it through `ConvertTo-HtmlEncoded()` again inside the here-string. This produced escaped entities like `&amp;` in the rendered HTML for usernames containing special characters (`<`, `>`, `&`). |

### Behavioral changes
- **Client Access Configuration** section now renders correctly as four sub-tables (OWA, ECP, MAPI, EWS) instead of garbled `System.Object[]` output.
- **Header metadata** now displays Forest and Domain alongside Target for full audit context.
- **Run-by identity** no longer double-encoded; special characters in usernames display correctly.
- **Error handling**: individual section failures (e.g., unreachable DC, missing AD module) no longer abort the entire report — they produce a red error message inside that section instead. The script still exits 1 only when Exchange servers cannot be discovered at all (truly fatal).

## 2026-11-13 — Template compliance + security & Exchange-specific fixes (T-01, T-02, T-03, S-04, E-01, E-04)

### `Invoke-ExchangeAudit.ps1`

| # | Fix | Rationale |
|---|-----|-----------|
| **T-01** | Wrapped `$hTitle`, `$hForest`, `$hRunBy`, and `$hTarget` in `ConvertTo-HtmlEncoded()` before here-string interpolation. | Template §6 mandates encoding all dynamic values to prevent XSS / HTML injection from AD domain names, usernames, or server lists. |
| **T-02** | Replaced `Start-Process -FilePath $OutputPath` with `Invoke-Item $OutputPath`. | Aligns with template §10 convention; functionally equivalent on Windows but consistent with the documented pattern. |
| **T-03** | Consolidated two identical multi-table rendering branches (one checking `'Section'`, one checking `'Data'`) into a single branch that checks for `'Section'` only. | Eliminates dead-code duplication; both branches produced identical output, so keeping both created maintenance risk if a future section added one property but not the other. |
| **S-04** | Removed `Where-Object { $_.PrivateKeyIsExportable -eq $true -or $_.Services -match 'SMTP\|IIS' }` filter from certificate query; now returns ALL Exchange certificates. | The original filter excluded self-signed/internal CA certs that are not exportable and lack SMTP/IIS services — the very certs critical for security posture documentation in a 2-server environment. |
| **E-01** | Removed `IsHubTransportServer` calculated column from Server Configuration section. | Hub Transport was deprecated in Exchange 2013; all Exchange 2019 servers are Mailbox or Edge role only. The column always returned `$false`, misleading operators about server capabilities. |
| **E-04** | Changed DAG Health query from `Get-MailboxDatabaseCopyStatus -Server $server.Name` (local copies) to `Get-MailboxDatabaseCopyStatus | Where-Object { $_.Server -eq $server.Name }` (copies hosted on the server). | The original only showed local replica status; the new query shows which databases are *hosted* by each server, giving a complete DAG topology view relevant for operational assessment of a 2-server environment. |

### Behavioral changes
- **Certificates section** now reports more rows (all certs instead of filtered subset). No false negatives on self-signed/internal CA certificates.
- **Server Configuration table** has one fewer column (`IsHubTransportServer` removed).
- **DAG Health Status** may show different rows depending on DAG topology; provides a more operationally relevant view for Exchange 2019 environments.
