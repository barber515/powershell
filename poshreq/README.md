# PoshReq — Certificate Request Generator

Interactive PowerShell script for generating PKCS#10 certificate signing requests (CSR) with RSA-2048 encryption on Windows systems.

## Features

- **Interactive prompts** for CN, SANs, and organizational details
- **Parameterized mode** — supply all fields via CLI arguments
- **RSA-2048** key generation
- **PKCS#10 CSR format** compatible with all major CAs
- **SHA-256WithRSA** signature algorithm
- **SAN support** — DNS names including wildcards (with security warning)
- **Input validation** — INF-safe patterns, RFC 5280 constraints, DNS name checks

## Requirements

- PowerShell 5.1+/7.0+
- Administrator privileges

## Usage

### Interactive Mode

```powershell
.\poshreq.ps1
```

Prompts you for:
- Common Name (CN) — max 64 characters
- Organisation, Organisational Unit (optional), Locality, State, Country Code
- DNS SAN entries (one per line; blank to finish)

### Parameterized Mode

```powershell
.\poshreq.ps1 -CN "web01.example.com" -O "Acme Corp" -L "London" -S "Greater London" -C "GB" -SANs @("www.example.com","mail.example.com")
```

All parameters are optional in parameterized mode except `CN`, `O`, `L`, `S`, and `C`. The script falls back to interactive prompts for any field not supplied.

### SAN Validation Rules

- Each SAN entry is validated against RFC 1123 hostname rules via `[System.Net.Dns]::TryGetHostName()`
- Wildcard entries must include a domain after the dot (e.g., `*.example.com`); bare `*.` or `*` are rejected
- Duplicate SANs are silently skipped in interactive mode; invalid entries cause exit in parameterized mode
- Default maximum of 100 SAN entries (adjust with `-MaxSanEntries <n>`, range 1–500)

## Input Validation

| Field | Constraint |
|-------|-----------|
| CN | 1–64 characters; no quotes, backslashes, or newlines |
| O, OU, L, S | No quotes, backslashes, or newlines |
| C | Exactly 2 uppercase ASCII letters (ISO 3166-1 alpha-2) |
| SANs | DNS name format (`^[a-zA-Z0-9][a-zA-Z0-9.-]*$`); RFC 1123 hostname validation; wildcards must be properly formatted (`*.example.com`, not bare `*.`); max 100 entries (configurable via `-MaxSanEntries`); duplicates are skipped |

Invalid characters in interactive input are either rejected with an error or stripped with a warning (OU, non-mandatory fields).

## Output

Generates a `csr` file in PEM format (base64-encoded DER) ready for submission to any Certificate Authority.

## Example Workflow

1. Run the script interactively or with parameters
2. Submit the generated CSR to your Issuing Certificate Authority
3. Receive and install the signed certificate on Windows via `certlm.msc` or PowerShell:

```powershell
Import-Certificate -FilePath "C:\certs\myserver.cer" -CertStoreLocation Cert:\LocalMachine\My
```
