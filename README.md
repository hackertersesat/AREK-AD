# AREK-AD — Auto Recon for Active Directory

Single-file PowerShell tool for **safe, read-only Active Directory enumeration** with optional, gated helpers for lab attack simulation.  
Designed for OSCP-style AD labs and post-compromise snapshots (works well in Evil-WinRM/WinRM shells).

---

## Table of Contents
- [Features](#features)  
- [Requirements](#requirements)  
- [Installation](#installation)  
- [Usage](#usage)  
- [Output files](#output-files)  
- [Safety & Ethics](#safety--ethics)  
- [Troubleshooting](#troubleshooting)  
- [Examples](#examples)  
- [Changelog](#changelog)  
- [License](#license)

---

## Features
- Colorized, linPEAS/winPEAS-style console sections for quick scanning.
- Comprehensive AD enumeration (read-only):
  - Domain / Forest / Domain Controllers / Trusts  
  - Users, Groups, Computers  
  - SPN (Kerberoast) candidates  
  - AS-REP roastable accounts  
  - KRBTGT metadata  
  - Group Policy Objects (GPO) and Organizational Units (OU) structure  
  - Domain password policy & fine-grained policy info (if available)  
  - Privileged group membership (Domain Admins, Enterprise Admins, Administrators, etc.)  
  - Domain Controller services and basic DC info  
  - DNS zones (if `DnsServer` module & privileges available)  
  - Local logged-on sessions and basic local context
- Output Modes: `Console`, `File`, `Both`.
- Single file: `AREK-AD.ps1` (no companion helper).
- Offensive helpers are **gated** — require both `-ExecuteUnsafe` and `-ConfirmUnsafe` to enable export of candidate lists for offline attack tooling.

---

## Requirements
- PowerShell 5.1 or later (works across constrained shells like Evil-WinRM).
- Recommended for full capability (install on host with RSAT/AD modules):
  - `ActiveDirectory` PowerShell module (RSAT)
  - `GroupPolicy` (for GPO enumeration)
  - `DnsServer` (for DNS zone enumeration; typically requires Domain Admin)
- Appropriate privileges: domain user returns useful info; domain admin returns complete data.

---

## Installation
Save the single file as `AREK-AD.ps1` on the target machine:
```powershell
# from attacker machine or downloaded into target
Save-Content .\AREK-AD.ps1   # (or copy/paste the file content)
```

To run ignoring execution policy for local testing:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\AREK-AD.ps1
```

---

## Usage

Show help:
```powershell
.\AREK-AD.ps1 -h
# or
.\AREK-AD.ps1 --help
```

Basic (default: console + files):
```powershell
.\AREK-AD.ps1
```

Console-only (linPEAS style):
```powershell
.\AREK-AD.ps1 -OutputMode Console
```

Save-only (writes CSV/JSON to OutFolder; quiet console):
```powershell
.\AREK-AD.ps1 -OutputMode File -OutFolder .\ad-output
```

Unsafe (lab-only — export attack candidates for offline use):
```powershell
.\AREK-AD.ps1 -ExecuteUnsafe -ConfirmUnsafe -OutFolder .\lab
```

Password-spray placeholder (note: script logs placeholder; do not abuse):
```powershell
.\AREK-AD.ps1 -ExecuteUnsafe -ConfirmUnsafe -SprayUserFile users.txt -SprayPassFile passwords.txt -SprayRate 30
# Script will place a placeholder/log; implement sprays manually and responsibly if authorized.
```

---

## Output files
When `-OutputMode` ≠ `Console`, results are saved in the `-OutFolder` directory (timestamped by default). Typical files:
- `domain.json` — domain/forest/DC info  
- `trusts.csv` — domain trusts (if any)  
- `users.csv` — user enumeration snapshot  
- `groups.csv` — groups snapshot  
- `computers.csv` — computer objects snapshot  
- `spn_accounts.csv` — Kerberoast candidates  
- `asrep_accounts.csv` — AS-REP roastable accounts  
- `krbtgt.json` — krbtgt metadata  
- `gpos.csv` — GPO list  
- `ou_list.csv` — Organizational Unit list  
- `password_policy.json` — domain password policy  
- `*_members.csv` — privileged group members (Domain_Admins_members.csv, etc.)  
- `domaincontrollers.csv` — DC service/basic info  
- `dns_zones.csv` — DNS zone listing (if available)  
- `arek-log.txt` — event log for this run

---

## Safety & Ethics
- **Only use in environments you own or are explicitly authorized to test.**
- Script is **read-only by default** — it will not attempt brute force or exploitation.
- Offensive helpers require both `-ExecuteUnsafe` and `-ConfirmUnsafe`; this is intentional to reduce accidental misuse.
- DO NOT run offensive actions (password spraying, Kerberoast cracking, exploitation) against production systems without written permission.

---

## Troubleshooting

**Parser / syntax errors**  
- If you see parse errors like `Missing closing '}'` or `The string is missing the terminator`, the file may be corrupted/truncated. Overwrite with the canonical single-file copy.

**`ActiveDirectory module missing`**  
- Limited enumeration will run using .NET/LDAP fallbacks. For full results, run on a host with RSAT/AD PowerShell modules installed.

**`Get-DnsServerZone` / DNS errors**  
- DNS zone enumeration requires the `DnsServer` module and usually Domain Admin permissions. If you get failures, it’s expected in non-privileged sessions.

**`query user` returns nothing**  
- Many remote WinRM sessions don’t show interactive console sessions. This is expected; local interactive sessions might not be visible from a non-interactive remote shell.

**Syntax check**  
```powershell
powershell -NoProfile -Command { [ScriptBlock]::Create((Get-Content .\AREK-AD.ps1 -Raw)) | Out-String }
```
If parser errors appear, re-download/overwrite the script.

---

## Examples

Quick console run:
```powershell
.\AREK-AD.ps1 -OutputMode Console
```

Full run with saved output:
```powershell
.\AREK-AD.ps1 -OutputMode Both -OutFolder .\ad-snapshot
```

Export Kerberoast/AS-REP candidates (lab only):
```powershell
.\AREK-AD.ps1 -ExecuteUnsafe -ConfirmUnsafe -OutFolder .\lab
```

---

## Changelog (high level)
- **v1.0** — Initial single-file release with colorized sections and core AD enumeration.  
- **v1.x** — Stability fixes: quoting/alias issues resolved; added gated unsafe helpers; `-h|--help` handling improved.  
- **current** — Balanced quoting/brace handling for Evil-WinRM/PowerShell 5.1 compatibility.

---

## License
Provided as-is for educational, lab, and authorized penetration testing use. Use responsibly. No warranty; the author is not liable for misuse.

---
