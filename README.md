# AREK-AD.ps1 — README.md update

> PowerShell helper for **safe Active Directory enumeration** plus optional **controlled attack-simulation helpers** (Kerberoast, AS-REP, password spraying) — intended **only** for labs and authorized pentesting (OSCP practice, training VMs, etc.).

---

## Table of contents
1. [Purpose](#purpose)  
2. [Important safety & legal notice](#important-safety--legal-notice)  
3. [Requirements](#requirements)  
4. [Files produced by the script](#files-produced-by-the-script)  
5. [Quick usage examples](#quick-usage-examples)  
6. [Parameters & flags](#parameters--flags)  
7. [Detailed behavior & notes](#detailed-behavior--notes)  
8. [Password spraying guidance](#password-spraying-guidance)  
9. [External tooling integration](#external-tooling-integration)  
10. [Troubleshooting](#troubleshooting)  
11. [Contributing / Attribution / License](#contributing--attribution--license)  

---

## Purpose
This repository contains a single PowerShell script (`AREK-AD.ps1`) that:

- Performs **read-only enumeration** of an Active Directory environment:
  - Domain, domain controllers, users, groups, computers
  - SPN (Kerberoast candidate) discovery
  - AS-REP (no-preauth) candidate discovery
  - KRBTGT account info
  - GPO listing & basic domain security policy extraction (if RSAT / GroupPolicy present)

- Optionally (only when explicitly enabled) provides **attack-simulation helpers**:
  - Export Kerberoast/AS-REP candidate lists
  - Optionally call external tools (Rubeus / Impacket) if provided
  - Controlled password-spraying routine with rate limiting and authorization prompts
  - Non-destructive Defender status checks (placeholders)

This is intended to speed up OSCP / lab prep while keeping offensive parts gated and explicit.

---

## Important safety & legal notice
**READ FIRST.**  
Do **NOT** run this script against production networks, third-party systems, or any environment where you **do not** have explicit written authorization. Offensive features are gated behind `-ExecuteUnsafe` **and** `-ConfirmUnsafe` switches — BOTH are required to run any potentially destructive or intrusive actions.

You are responsible for how you use this script. The author provides it for educational purposes only.

---

## Requirements
- Windows (domain-joined workstation recommended) or PowerShell 7+ with Windows compatibility
- PowerShell 5.1+ recommended
- Optional but recommended modules:
  - `ActiveDirectory` (RSAT: Active Directory module)
  - `GroupPolicy` (RSAT: Group Policy Management)
- Optional external tools for stronger offensive flows:
  - `Rubeus.exe` (Kerberos interactions) or Impacket `GetUserSPNs.py` / `GetNPUsers.py`
- Network connectivity to domain controllers / LDAP
- Run as Administrator for best results (some queries require elevated privileges)

---

## Files produced by the script
When you run the script it creates an output folder (default `.\AD-Enumeration-<timestamp>`). Typical files:

- `ad-enumeration.json` — master JSON with collected data  
- `domain.json` — domain name, forest, DC list  
- `users.csv` — user records (DisplayName, SamAccountName, UPN, SPNs, userAccountControl, etc.)  
- `groups.csv` — groups list  
- `computers.csv` — computer objects  
- `spn_accounts.csv` — SPN/Kerberoast candidates  
- `asrep_accounts.csv` — AS-REP (no preauth) candidates  
- `krbtgt.json` — KRBTGT account metadata (if found)  
- `gpos.csv` — GPO listing (if GroupPolicy module available)  
- `kerberoast_candidates.csv` (if unsafe kerberoast enumeration run)  
- `asrep_candidates.csv` (if unsafe AS-REP enumeration run)  
- `password_spray_results.csv` — results of password spray attempts (if run)  
- `*_tool_output.txt` — optional external tool logs

---

## Quick usage examples

**Enumeration only (safe, default):**
```powershell
.\AREK-AD.ps1 -OutFolder .\ad-output
```

**Enumerate + run attack helpers (DANGEROUS — lab only):**
```powershell
.\AREK-AD.ps1 -OutFolder .\ad-output -ExecuteUnsafe -ConfirmUnsafe `
  -KerberoastToolPath "C:\tools\Rubeus.exe" `
  -ASREPRoastToolPath "C:\tools\asreproast.exe"
```

**Run controlled password spray (lab only):**
```powershell
.\AREK-AD.ps1 -OutFolder .\ad-output -ExecuteUnsafe -ConfirmUnsafe `
  -SprayUserFile .\userlist.txt -SprayPassFile .\pwlist.txt -SprayRate 10
```

Notes:
- `-ExecuteUnsafe` **and** `-ConfirmUnsafe` are both required to enable attack helpers.
- For password spraying, prefer `-SprayRate 5`–`30` attempts/minute depending on lab lockout policies.

---

## Parameters & flags

| Parameter | Type | Description |
|---|---:|---|
| `-OutFolder` | string | Output directory (default `.\AD-Enumeration-<timestamp>`) |
| `-ExecuteUnsafe` | switch | Enables attack-simulation helpers (must be used with `-ConfirmUnsafe`) |
| `-ConfirmUnsafe` | switch | Explicit confirm to allow unsafe actions |
| `-SprayUserFile` | string | Path to newline user list for password spray |
| `-SprayPassFile` | string | Path to newline password list for password spray |
| `-SprayRate` | int | Attempts per minute for spray (default `30`) |
| `-SprayDelaySeconds` | int | Fallback delay between attempts (used if needed) |
| `-KerberoastToolPath` | string | Path to external Kerberoast tool (optional) |
| `-ASREPRoastToolPath` | string | Path to external AS-REP tool (optional) |

---

## Detailed behavior & notes
- **Enumeration** uses `ActiveDirectory` module when present; if not found, the script falls back to `System.DirectoryServices` LDAP queries (results may be more limited).
- **SPN enumeration** identifies accounts that have `servicePrincipalName` attributes set — these are potential Kerberoast targets.
- **AS-REP detection** looks for `userAccountControl` bits indicating `DONT_REQ_PREAUTH` (decimal `4194304` / hex `0x00400000`).
- **KRBTGT**: the script reads `krbtgt` metadata like `PasswordLastSet` if retrievable.
- **GPOs**: Requires `GroupPolicy` module (RSAT). The script will list GPOs; it does not automatically export full GPO XML/policies unless privileged and requested.
- **Attack helpers**:
  - Are gated and interactive. You will be prompted before any external tool is called.
  - Kerberoast/AS-REP functions **do not** perform cracking; they only extract candidate lists and optionally call external tools.
  - Password spray uses LDAP simple bind attempts — this is intrusive and may trigger lockouts or SIEM alerts.

---

## Password spraying guidance (IMPORTANT)
- **Only in lab/authorized environment.**
- Use very low `-SprayRate` (recommended `<= 10` attempts/min) in environments with unknown lockout thresholds.
- Keep password lists short and conservative (e.g., `Password123!`, `Welcome1` for lab).
- The script requests you type `I HAVE AUTH` before any password spraying to ensure you confirm authorization.
- Consider non-intrusive alternatives for OSCP practice: test `GetNPUsers.py` (Impacket) for AS-REP enumeration, or use Kerberoast candidates with offline cracking against a separate cracking VM (do not attempt online brute force).

---

## External tooling integration
This script can call external tools if the path is provided. Typical flows:
- **Kerberoast**: `Rubeus.exe kerberoast` or `GetUserSPNs.py` (Impacket). The script will export `kerberoast_candidates.csv` and can call the tool with a conservative wrapper if you confirm.
- **AS-REP**: `GetNPUsers.py` (Impacket) or Rubeus variants.
- The script does **not** include cracking logic — use Hashcat or John the Ripper offline against exported ticket hashes if you have permission.

---

## Troubleshooting
- **ActiveDirectory module not found**: Install RSAT (Remote Server Administration Tools) or run on a domain controller / management workstation.
- **LDAP bind issues during spray**: Verify network connectivity to DCs and correct domain context. The script uses the first DC found by DNS.
- **Permission errors**: Run PowerShell as Administrator. Some queries (GPO exports, secedit operations) require domain privileges.
- **Large AD environments**: LDAP fallback uses `PageSize = 1000`, but very large directories may still be slow — run on a VM with sufficient memory.

---

## Contributing / Attribution / License
- Use, modify, and adapt for authorized training and labs.
- If you improve the script (better error handling, RSAT detection, safer spray simulation modes), please keep changes documented.
- Suggested license: MIT (or choose your preferred permissive license), but **do not** remove the safety & legal notice.

---

## Example recommended OSCP workflow
1. Run enumeration only and collect CSV/JSON outputs:
   ```powershell
   .\AREK-AD.ps1 -OutFolder .\oscp-ad-output
   ```
2. Inspect `spn_accounts.csv` and `asrep_accounts.csv` for targets.
3. Export SPN hashes using Impacket / Rubeus in an isolated cracking VM; perform offline cracking there.
4. If practicing password sprays in lab VMs, set `-SprayRate 5` and very small wordlist.
5. Keep detailed notes of commands, timings, and results in your OSCP lab report.

---

## Contact / Author notes
This script and README were prepared to help streamline OSCP lab practice while enforcing strong safety guards. Please use wisely
