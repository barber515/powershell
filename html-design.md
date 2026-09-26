# HTML Design Specification: Invoke-ADSecurityAudit Report

## Overview
The `Invoke-ADSecurityAudit.ps1` script generates a self-contained, styled HTML report for security audits. The design is intended to be standalone (inline CSS) to ensure consistent formatting across different viewing environments.

## 1. Visual Framework
- **Self-Contained**: All styles are embedded in the `<head>` section of the document.
- **Theme**: A clean, professional look using a standard "System" font stack (`Segoe UI`, `Roboto`, etc.).
- **Layout**: 
    - **Header**: Contains metadata (Domain/Forest, Target DC, Generation Timestamp) and an urgent "RESTRICTED" classification banner.
    - **Summary Table**: A high-level overview of all findings at the top for rapid triage.
    - **Detail Sections**: Each check is wrapped in a distinct card with a color-coded header based on severity levels.

## 2. Style Attributes & Palette
The design uses specific colors to denote risk levels:
- **Critical** (Red): `#c0392b`
- **High** (Orange/Yellow): `#e67e22`
- **Medium** (Yellow): `#f1c40f`
- **Info** (Blue): `#3498sb`

## 3. Component Breakdown
### Header & Metadata
The top of the page provides context for the audit. The inclusion of a "Restricted" badge warns users that the content contains sensitive information regarding privileged accounts and attack vectors.

### Report Sections
Each assessment area (e.g., "DCSync", "Roasting") uses a consistent layout:
- **Header**: A large header with an accent border on the left side, matching the severity color. It includes a status badge and a count of findings.
- **Description**: A brief paragraph explaining the security implications of that specific check.
- **Data Tables**: Automatically generated tables using `ConvertTo-HtmlTable`. These use:
    - Fixed headers with background colors (`#f0f3f6`).
    - Hover effects on rows for better readability.
    - "No results" messaging styled in green.

## 4. Developer Template for New Sections
To maintain design consistency when adding new features:
1. Use **`ConvertTo-HtmlEncoded`** to sanitize all user/system input before outputting to the HTML string.
2. Define the result set as a collection of objects with clear property names (these become the table headers).
3. Wrap each section in the standard structure:
   ```html
   <section>
     <h2 style="border-left:6px solid [Color]">
       <span class="badge" style="background:[Color]">[Severity]</span> [Title]
       <span class="count">[Count] result(s)</span>
     </h2>
     <p class="desc">[Description]</p>
     [Table_Output]
   </section>
   ```
