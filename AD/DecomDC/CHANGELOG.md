# Changelog

## Unreleased - 2026-09-30: HTML readiness report for decomDC.ps1

Implements the plan in [htmlupdate.md](htmlupdate.md) with that plan's review findings applied. The
script now writes a self-contained `99_decom_readiness_report.html` into the evidence folder, following
the design guidelines in [html-template.md](html-template.md): encoded values throughout, severity-badged
sections, summary roll-up, classification banner, footer disclaimers, optional auto-launch.

Files:

| File | Change |
|---|---|
| [decomDC.ps1](decomDC.ps1) | Modified. 255 lines to 773. Discovery behaviour unchanged; report wiring added. |
| [DecomHtmlReport.ps1](DecomHtmlReport.ps1) | New. HTML render helpers plus the tool-output parsers. Dot-sourced by decomDC.ps1. |

No CSV or TXT evidence file changes its name, path, encoding or content (see "Evidence parity").

### Operator visible changes

- Three new switches: `-NoHtml` (skip the report entirely), `-NoLaunch` (do not open it in a browser),
  `-MaxPreLines <n>` (cap raw tool output embedded per section, default 400, `0` embeds everything).
- Console gains one final line: `DEMOTE READINESS: <verdict>`, green when no blockers were found.
- The report contains 19 sections and a verdict banner: NOT READY TO DEMOTE, CONDITIONAL - MANUAL
  REVIEW REQUIRED, or NO AUTOMATED BLOCKERS FOUND.
- A new section, "Scan coverage: what was NOT checked", lists hosts skipped, zones that failed to
  enumerate, per-server read failures and native tool stderr. Any row raises it to High (REVIEW).

### Fixes applied from review of the plan

| ID | Problem in the plan | What was done | Verified by |
|---|---|---|---|
| B1 | `Get-ReplSummaryRow` matched only an invented fixture, never real `repadmin /replsummary` output. Against genuine healthy and 5/5-failure captures it parsed **0 rows**, so the top blocker check rendered green. | Parser rewritten for the real column layout (`DC`, largest delta, `N / M`, `%% error`, `(code)`), with lazy delta matching, an unresponsive-DC placeholder rule and a retrieval-error rule that both count as failures. | Harness feeds two authentic captures: healthy parses 4 rows and is not a blocker; the broken one (5/5, code 8341) is a BLOCKER. |
| B2 | A parser matching nothing rendered green. | Parsers throw when output exists but nothing matched, which renders as ERROR and counts against the verdict. dcdiag distinguishes correctly: zero findings is legitimate only if `passed/failed test` lines were seen. | Harness asserts a no-match capture raises rather than reporting clean. |
| B3 | GPO section declared `-EscalateTo 'High'` with no predicate, so it could never escalate (the plan's own defect W1 recurring), while its title promised "naming a domain controller". | Rows now carry a `NamesOldDc` flag; the predicate escalates on that flag only. The full filter inventory stays visible and benign OS-version filters do not raise severity. | Harness: benign filter listed, no escalation; a filter naming DC1 raises Info to High (REVIEW). |
| B4 | Plan step 5.6 and Appendix C both specified the same render location, which would write the report twice and print the verdict twice. | One render call, at the end of the single registration block. | Static AST audit: exactly one `New-DecomHtmlReport` call site. |
| B5 | Plan loaded helpers with `Get-ADForest` inserted before `Import-Module ActiveDirectory`, producing a red CommandNotFoundException in every transcript and an empty forest name in the header. | Helpers load after the AD import; the existing `$forest` object is reused for the header instead of a second AD call. | Static check: helper dot-source line follows the import, inside the `-NoHtml` guard. |
| B6 | Plan's companion-file option said to dot-source the report block from step 5.2, which would run all sections before any data existed (mostly empty green, plus a false Critical SRV blocker). | Registration is inline in one contiguous block after discovery completes; no early dot-sourcing exists. | Harness registers exactly 19 sections against synthetic post-discovery state. |
| S1 | Adding `2>&1` to native captures injects PowerShell's multi-line error wrapper into evidence files and HTML, breaking the plan's byte-parity claim. | New `Run-Tool` writes stdout only to the evidence file (identical to before) and returns stderr text separately for the report. The one site that already merged stderr into its file (`w32tm /query /status`, per DC) keeps doing so via `-StdErrIntoFile`. | Harness: file contains stdout, not the stderr line, and never `CategoryInfo`/`NativeCommandError`; `.Errors` still carries the message. |
| S2 | Four swallowed failures still read clean: DHCP outer catch, per-server DHCP catch, DNS server-config catch, and `catch { continue }` inside the Critical zone scan. | Each now records into an accumulator that feeds the coverage section; GPO, PKI and DHCP-outer failures additionally re-throw inside their section so they render ERROR. | Harness covers the empty-versus-broken distinction; code paths reviewed line by line. |
| S3 | Time-hierarchy rule matched any line naming an old DC, but `w32tm /monitor` lists every DC in the domain, so it escalated to High on every single run. | New `Get-W32tmSourceRow` parses only source/upstream lines (attributed per computer); escalation requires an old DC actually being used as a sync source. | Harness: old DC merely listed does not escalate; retained DC syncing from DC1 does. |
| S4 | Passing `$null` to the parsers produced "Cannot bind argument ... because it is null". | Parsers accept `$null` and blank lines and raise an explicit message about missing tool output. | Harness asserts both messages. |

### Two further defects found while implementing (both fixed)

- A missing trailing backtick in section 18 parsed cleanly but silently split the `Add-Section` call,
  turning `-EmptyText ...` into its own statement at runtime. Static parsing cannot see this class of
  bug; it was caught by executing the extracted block. An AST audit for statements that begin with a
  parameter token is now part of the verification set and reports zero offenders.
- `@($null)` is an array with one element, so any undefined accumulator minted a phantom row of empty
  cells in the report tables, and a phantom coverage row escalated the verdict to REVIEW. Added
  `Get-DefinedRow`, applied to every object-table loop. Harness asserts zero coverage rows when
  nothing was skipped.

### Report sections (19)

FSMO role holders; DC inventory retained versus decommission; retained DC count after removal;
replication summary parsed; repadmin raw output; dcdiag failures and warnings; dcdiag raw output;
server objects by AD site; DNS server configuration per DC; DNS records referencing old DCs; time
hierarchy configured sync sources; w32tm raw output; DHCP references to old DCs; SYSVOL replication
state (dfsrmig); SRV locator records for retained DCs; GPO WMI filters naming a domain controller;
PKI enrollment services; scan coverage; manual verification items.

Severity convention: Critical blocks the demotion window, High must be remediated before cutover,
Medium needs a human decision, Info is inventory and never blocks. Severity is computed from rows, so
a section can rise above its declared base level; the report shows a note when that happens.

### Evidence parity

CSV and TXT files are written exactly as before: stdout only, same names, `-Encoding UTF8`. The single
exception is intentional and matches pre-existing behaviour: `07_w32tm_status_<dc>.txt` continues to
contain stderr text because the original line already redirected it into that file. If a tool writes to
stderr, that text now also appears in the report's coverage section rather than only on the console.

### Verification performed (Windows PowerShell 5.1, no domain required)

| Check | Result |
|---|---|
| Parse check, both files | `decomDC.ps1 parseErrors=0`, `DecomHtmlReport.ps1 parseErrors=0` |
| Behavioural harness against the shipped code (functions and report block extracted from decomDC.ps1 by AST, not duplicated) | 24 assertions, 0 failed |
| Static audits: single render call, 19 `Add-Section` sites, every `-EscalateTo` has a predicate, every `-EscalateWhen` declares `param($Rows)`, no broken line continuations, helper loaded after AD import and inside the `-NoHtml` guard | all pass |
| `-NoHtml` path executed | registers zero sections, writes no HTML |
| Encoding: DNS record name containing `<script>alert(1)</script>` | rendered as `&lt;script&gt;alert`, no executable script tag in output |

The harness and audit scripts were run from a scratch directory and are not tracked in the repo. Say the
word and they can be added alongside the change as a regression net.

### Not addressed here

- Live-forest validation (plan steps V5 to V7) still has to run on a domain-joined host with RSAT: open
  the report, confirm each section footer names an evidence file that exists, diff CSV/TXT against a
  baseline run of the previous version, and re-run after moving one FSMO role to watch severity drop.
- The parsers for `repadmin`, `dcdiag` and `w32tm` remain heuristic. They now fail loudly instead of
  silently when their input does not look like what they expect, and every parsed section has a raw-text
  twin plus an evidence-file pointer.
- Pre-existing discovery code still uses unanchored `-match` against `$OldNames` (plan observation O2).
  The report's own matching is anchored through `Test-MentionsOldDc`, so short names such as `DC1` no
  longer match inside `SDC1` or `DC10`; the older discovery blocks were left alone to keep the diff tight.
- One pre-existing em dash remains in a comment near section 12 (untouched, not introduced here).

### Rollback

Run with `-NoHtml` for today's behaviour, or delete the report block at the end of decomDC.ps1 and remove
DecomHtmlReport.ps1. Nothing else depends on either change, and no evidence file is affected.
