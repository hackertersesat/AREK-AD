<#
.SYNOPSIS
  AREK-AD.ps1 — Active Directory Enumeration & Risk Evaluation Kit
  For OSCP/AD labs. Safe, colorful, PEAS-style enumeration.

.DESCRIPTION
  Enumerates AD information including:
   - Domain / Forest / DCs / Trusts
   - Users / Groups / Computers
   - SPN & AS-REP roastable accounts
   - KRBTGT info / Password policies
   - OU / GPO / Privileged groups
   - DNS zones / DC services / Local sessions

  Output:
   - Console (no files)
   - File (quiet)
   - Both (default)

  Run with `--help` for usage.
#>

param(
  [Alias('h','help')]
  [switch]$Help,

  [ValidateSet("Console","File","Both")]
  [string]$OutputMode = "Both",

  [string]$OutFolder = ".\AREK-AD-$(Get-Date -Format yyyyMMdd-HHmmss)",
  [switch]$ExecuteUnsafe,
  [switch]$ConfirmUnsafe,
  [string]$SprayUserFile,
  [string]$SprayPassFile,
  [int]$SprayRate = 30
)

# ─────────────────────────────────────────────
# HELP MODE
# ─────────────────────────────────────────────
if ($Help -or ($args -contains '--help') -or ($args -contains '-h')) {
@"
AREK-AD.ps1 — Active Directory Enumeration & Risk Evaluation Kit

Usage:
  .\AREK-AD.ps1 [options]

Options:
  -OutputMode <Console|File|Both>    Output type (default Both)
  -OutFolder <path>                  Folder for results
  -ExecuteUnsafe -ConfirmUnsafe      Unlock Kerberoast/AS-REP export (LAB ONLY)
  -SprayUserFile <file>              User list for password spraying
  -SprayPassFile <file>              Password list for password spraying
  -SprayRate <n>                     Attempts/minute (default 30)
  -h | --help                        Show this help

Examples:
  .\AREK-AD.ps1 -OutputMode Console
  .\AREK-AD.ps1 -OutFolder .\results
  .\AREK-AD.ps1 -ExecuteUnsafe -ConfirmUnsafe
"@ | Write-Host -ForegroundColor Yellow
exit
}

# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────
function Section {
  param($Title)
  Write-Host "`n==================================================" -ForegroundColor Cyan
  Write-Host "== $Title" -ForegroundColor Green
  Write-Host "==================================================`n" -ForegroundColor Cyan
}

function Log {
  param(
    [string]$Msg,
    [ValidateSet('Info','Good','Warn','Err')]
    [string]$Lvl='Info'
  )
  $t = (Get-Date -Format HH:mm:ss)
  switch ($Lvl) {
    'Info' { Write-Host "[$t] [*] $Msg" -ForegroundColor Cyan }
    'Good' { Write-Host "[$t] [+] $Msg" -ForegroundColor Green }
    'Warn' { Write-Host "[$t] [!] $Msg" -ForegroundColor Yellow }
    'Err'  { Write-Host "[$t] [X] $Msg" -ForegroundColor Red }
  }
  if ($OutputMode -ne "Console" -and $Global:LogPath) {
    Add-Content -Path $Global:LogPath -Value "[$t][$Lvl] $Msg"
  }
}

function OutObj {
  param($Obj,$Name,$Fmt='csv')
  if ($OutputMode -ne 'Console') {
    $path = Join-Path $OutFolder $Name
    try {
      switch ($Fmt) {
        'csv'  { $Obj | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 }
        'json' { $Obj | ConvertTo-Json -Depth 4 | Out-File -FilePath $path -Encoding UTF8 }
      }
      Log ("Saved $Name") "Good"
    } catch {
      Log ("Failed to write $Name : $($_.Exception.Message)") "Err"
    }
  }
  if ($OutputMode -ne 'File') {
    Write-Host "`n>>> $Name preview:" -ForegroundColor Cyan
    try { $Obj | Select-Object -First 10 | Format-Table -AutoSize | Out-Host }
    catch { $Obj | Select-Object -First 10 | Out-Host }
  }
}

# ─────────────────────────────────────────────
# INIT
# ─────────────────────────────────────────────
if ($OutputMode -ne "Console") {
  if (-not (Test-Path $OutFolder)) {
    New-Item -ItemType Directory -Path $OutFolder | Out-Null
  }
  $Global:LogPath = Join-Path $OutFolder "arek-log.txt"
}
Section "INITIALIZATION"
Log "AREK-AD started | Mode=$OutputMode | Folder=$OutFolder"

# ─────────────────────────────────────────────
# ENUM: DOMAIN INFO
# ─────────────────────────────────────────────
Section "DOMAIN / FOREST / DC INFO"
try {
  $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
  $forest = $dom.Forest
  $dcs = $dom.DomainControllers | Select Name,IPv4Address
  $info = [PSCustomObject]@{
    Domain = $dom.Name
    Forest = $forest.Name
    DCs    = ($dcs.Name -join ',')
  }
  OutObj $info "domain.json" "json"
} catch {
  Log ("Domain discovery failed: $($_.Exception.Message)") "Err"
}

# ─────────────────────────────────────────────
# ENUM: TRUSTS
# ─────────────────────────────────────────────
Section "DOMAIN TRUSTS"
try {
  $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
  $trusts = $forest.GetAllTrustRelationships() | Select SourceName,TargetName,TrustType,Direction
  if ($trusts) { OutObj $trusts "trusts.csv" } else { Log "No trusts found." "Warn" }
} catch { Log "Trust enumeration failed." "Warn" }

# ─────────────────────────────────────────────
# ENUM: USERS / GROUPS / COMPUTERS
# ─────────────────────────────────────────────
Section "USERS / GROUPS / COMPUTERS"
$HaveAD = $false
if (Get-Module -ListAvailable -Name ActiveDirectory) {
  Import-Module ActiveDirectory -ErrorAction SilentlyContinue
  $HaveAD = $true
}
if ($HaveAD) {
  try {
    $users = Get-ADUser -Filter * -Properties SamAccountName,UserPrincipalName,DisplayName,ServicePrincipalName,userAccountControl,LastLogonDate |
             Select SamAccountName,DisplayName,UserPrincipalName,LastLogonDate,ServicePrincipalName,userAccountControl
    $groups = Get-ADGroup -Filter * -Properties GroupCategory,GroupScope | Select Name,GroupCategory,GroupScope
    $computers = Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate | Select Name,OperatingSystem,LastLogonDate
    OutObj $users "users.csv"
    OutObj $groups "groups.csv"
    OutObj $computers "computers.csv"
  } catch { Log "User/group/computer enumeration failed." "Err" }
} else {
  Log "ActiveDirectory module missing – limited enumeration only." "Warn"
}

# ─────────────────────────────────────────────
# ENUM: SPN / KERBEROAST
# ─────────────────────────────────────────────
Section "KERBEROAST CANDIDATES (SPN)"
try {
  $spn = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName |
         Select SamAccountName,ServicePrincipalName
  if ($spn) { OutObj $spn "spn_accounts.csv" } else { Log "No SPN accounts found." "Warn" }
} catch { Log "SPN enumeration failed." "Warn" }

# ─────────────────────────────────────────────
# ENUM: AS-REP ROAST
# ─────────────────────────────────────────────
Section "AS-REP ROASTABLE ACCOUNTS"
try {
  $flag = 0x00400000
  $asrep = Get-ADUser -Filter * -Properties userAccountControl |
           Where-Object { ($_.userAccountControl -band $flag) -ne 0 } |
           Select SamAccountName,DistinguishedName
  if ($asrep) { OutObj $asrep "asrep_accounts.csv" } else { Log "No AS-REP roastable users." "Warn" }
} catch { Log "AS-REP enumeration failed." "Warn" }

# ─────────────────────────────────────────────
# ENUM: KRBTGT
# ─────────────────────────────────────────────
Section "KRBTGT ACCOUNT INFO"
try {
  $krbtgt = Get-ADUser -Identity krbtgt -Properties Enabled,PasswordLastSet |
            Select SamAccountName,Enabled,PasswordLastSet
  OutObj $krbtgt "krbtgt.json" "json"
} catch { Log "KRBTGT query failed." "Warn" }

# ─────────────────────────────────────────────
# ENUM: GPO / OU
# ─────────────────────────────────────────────
Section "GROUP POLICY OBJECTS"
try {
  if (Get-Module -ListAvailable -Name GroupPolicy) {
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $gpo = Get-GPO -All | Select DisplayName,Id,Owner,ModificationTime
    OutObj $gpo "gpos.csv"
  } else { Log "GroupPolicy module not installed." "Warn" }
} catch { Log "GPO enumeration failed." "Warn" }

Section "ORGANIZATIONAL UNITS"
try {
  $ou = Get-ADOrganizationalUnit -Filter * | Select Name,DistinguishedName
  OutObj $ou "ou_list.csv"
} catch { Log "OU enumeration failed." "Warn" }

# ─────────────────────────────────────────────
# ENUM: PASSWORD POLICY
# ─────────────────────────────────────────────
Section "PASSWORD POLICY"
try {
  $policy = Get-ADDefaultDomainPasswordPolicy | 
            Select ComplexityEnabled,LockoutThreshold,MinPasswordLength,MaxPasswordAge
  OutObj $policy "password_policy.json" "json"
} catch { Log "Password policy enumeration failed." "Warn" }

# ─────────────────────────────────────────────
# ENUM: PRIVILEGED GROUPS
# ─────────────────────────────────────────────
Section "PRIVILEGED GROUP MEMBERS"
try {
  $priv = @("Domain Admins","Enterprise Admins","Administrators","Backup Operators","DnsAdmins")
  foreach ($p in $priv) {
    $m = Get-ADGroupMember $p -ErrorAction SilentlyContinue | Select Name,SamAccountName
    if ($m) { OutObj $m ("{0}_members.csv" -f ($p -replace ' ','_')) }
  }
} catch { Log "Privileged group enumeration failed." "Warn" }

# ─────────────────────────────────────────────
# ENUM: DOMAIN CONTROLLER SERVICES
# ─────────────────────────────────────────────
Section "DOMAIN CONTROLLER SERVICES"
try {
  $dcs = Get-ADDomainController -Filter * | Select Name,IPv4Address,Site,OperatingSystem
  OutObj $dcs "domaincontrollers.csv"
} catch { Log "DC enumeration failed." "Warn" }

# ─────────────────────────────────────────────
# ENUM: DNS ZONES
# ─────────────────────────────────────────────
Section "DNS ZONES"
try {
  $dns = Get-DnsServerZone -ErrorAction SilentlyContinue | Select ZoneName,ZoneType,ReplicationScope
  if ($dns) { OutObj $dns "dns_zones.csv" } else { Log "No DNS zones or insufficient rights." "Warn" }
} catch { Log "DNS zone query failed." "Warn" }

# ─────────────────────────────────────────────
# ENUM: LOCAL SESSIONS
# ─────────────────────────────────────────────
Section "LOGGED-ON USERS (LOCAL)"
try {
  $sessions = query user 2>$null
  if ($sessions) { Write-Host $sessions -ForegroundColor Gray }
  else { Log "No local sessions visible." "Warn" }
} catch { Log "Local session query failed." "Warn" }

# ─────────────────────────────────────────────
# ATTACK SIMULATIONS
# ─────────────────────────────────────────────
if ($ExecuteUnsafe -and $ConfirmUnsafe) {
  Section "ATTACK SIMULATION (LAB ONLY)"
  Log "Unsafe mode active – exporting roast candidates" "Warn"
  try { $spn | Export-Csv (Join-Path $OutFolder "kerberoast_candidates.csv") -NoTypeInformation } catch {}
  try { $asrep | Export-Csv (Join-Path $OutFolder "asrep_candidates.csv") -NoTypeInformation } catch {}
  if ($SprayUserFile -and $SprayPassFile) { Log "Password spray helper placeholder (manual step)" "Warn" }
} elseif ($ExecuteUnsafe) {
  Log "Add -ConfirmUnsafe to proceed with unsafe actions." "Warn"
} else {
  Log "Safe mode active – no attacks simulated." "Info"
}

# ─────────────────────────────────────────────
# FINISH
# ─────────────────────────────────────────────
Section "SUMMARY"
Log "AREK-AD completed. Results in $OutFolder" "Good"

