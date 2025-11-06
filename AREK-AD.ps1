<#
.SYNOPSIS
  AREK-AD.ps1 — Active Directory Enumeration & Risk Evaluation Kit
  Safe, colorized, PEAS-style AD enumeration for OSCP / lab use.
#>

param(
  [switch]$ShowHelp,

  [ValidateSet("Console","File","Both")]
  [string]$OutputMode = "Both",

  [string]$OutFolder = ".\AREK-AD-$(Get-Date -Format yyyyMMdd-HHmmss)",
  [switch]$ExecuteUnsafe,
  [switch]$ConfirmUnsafe,
  [string]$SprayUserFile,
  [string]$SprayPassFile,
  [int]$SprayRate = 30
)

# ---------------- HELP ----------------
if ($ShowHelp -or ($args -contains '--help') -or ($args -contains '-h')) {
@'
AREK-AD.ps1 — Active Directory Enumeration & Risk Evaluation Kit

Usage:
  .\AREK-AD.ps1 [options]

Options:
  -OutputMode <Console|File|Both>   Output type (default Both)
  -OutFolder <path>                 Folder for results
  -ExecuteUnsafe -ConfirmUnsafe     Unlock Kerberoast/AS-REP export (LAB ONLY)
  -SprayUserFile <file>             User list for password spraying
  -SprayPassFile <file>             Password list for password spraying
  -SprayRate <n>                    Attempts/minute (default 30)
  -h | --help                       Show this help

Examples:
  .\AREK-AD.ps1 -OutputMode Console
  .\AREK-AD.ps1 -OutFolder .\results
  .\AREK-AD.ps1 -ExecuteUnsafe -ConfirmUnsafe
'@ | Write-Host -ForegroundColor Yellow
  exit
}

# ---------------- UTILITIES ----------------
function Section {
  param([string]$Title)
  Write-Host "`n==================================================" -ForegroundColor Cyan
  Write-Host "== $Title" -ForegroundColor Green
  Write-Host "==================================================`n" -ForegroundColor Cyan
}

function Log {
  param(
    [Parameter(Mandatory = $true)][string]$Msg,
    [ValidateSet('Info','Good','Warn','Err')][string]$Lvl = 'Info'
  )
  $t = (Get-Date -Format HH:mm:ss)
  switch ($Lvl) {
    'Info' { Write-Host "[$t] [*] $Msg" -ForegroundColor Cyan }
    'Good' { Write-Host "[$t] [+] $Msg" -ForegroundColor Green }
    'Warn' { Write-Host "[$t] [!] $Msg" -ForegroundColor Yellow }
    'Err'  { Write-Host "[$t] [X] $Msg" -ForegroundColor Red }
  }
  if ($OutputMode -ne 'Console' -and $Global:LogPath) {
    Add-Content -Path $Global:LogPath -Value "[$t][$Lvl] $Msg"
  }
}

function OutObj {
  param(
    [Parameter(Mandatory = $true)][object]$Obj,
    [Parameter(Mandatory = $true)][string]$Name,
    [ValidateSet('csv','json')][string]$Fmt = 'csv'
  )
  if ($OutputMode -ne 'Console') {
    $path = Join-Path $OutFolder $Name
    try {
      switch ($Fmt) {
        'csv'  { $Obj | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 }
        'json' { $Obj | ConvertTo-Json -Depth 4 | Out-File -FilePath $path -Encoding UTF8 }
      }
      Log -Msg ("Saved " + $Name) -Lvl 'Good'
    } catch {
      Log -Msg ("Failed to write " + $Name + " : " + $_.Exception.Message) -Lvl 'Err'
    }
  }
  if ($OutputMode -ne 'File') {
    Write-Host "`n>>> " + $Name + " preview:" -ForegroundColor Cyan
    try {
      $Obj | Select-Object -First 10 | Format-Table -AutoSize | Out-Host
    } catch {
      $Obj | Select-Object -First 10 | Out-Host
    }
  }
}

# ---------------- INIT ----------------
if ($OutputMode -ne 'Console') {
  if (-not (Test-Path $OutFolder)) {
    New-Item -ItemType Directory -Path $OutFolder | Out-Null
  }
  $Global:LogPath = Join-Path $OutFolder 'arek-log.txt'
}

Section 'INITIALIZATION'
Log -Msg ('AREK-AD started | Mode=' + $OutputMode + ' | Folder=' + $OutFolder) -Lvl 'Info'

# ---------------- DOMAIN / FOREST / DC ----------------
Section 'DOMAIN / FOREST / DC INFO'
try {
  $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
  $forest = $dom.Forest
  $dcs = $dom.DomainControllers | Select-Object Name, IPv4Address
  $info = [PSCustomObject]@{
    Domain = $dom.Name
    Forest = $forest.Name
    DCs    = ($dcs.Name -join ',')
  }
  OutObj -Obj $info -Name 'domain.json' -Fmt 'json'
} catch {
  Log -Msg ('Domain discovery failed: ' + $_.Exception.Message) -Lvl 'Err'
}

# ---------------- TRUSTS ----------------
Section 'DOMAIN TRUSTS'
try {
  $forestObj = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
  $trusts = $forestObj.GetAllTrustRelationships() | Select-Object SourceName, TargetName, TrustType, Direction
  if ($trusts) { OutObj -Obj $trusts -Name 'trusts.csv' -Fmt 'csv' }
  else { Log -Msg 'No trusts found.' -Lvl 'Warn' }
} catch {
  Log -Msg 'Trust enumeration failed.' -Lvl 'Warn'
}

# ---------------- USERS / GROUPS / COMPUTERS ----------------
Section 'USERS / GROUPS / COMPUTERS'
$HaveAD = $false
if (Get-Module -ListAvailable -Name ActiveDirectory) {
  Import-Module ActiveDirectory -ErrorAction SilentlyContinue
  $HaveAD = $true
}

if ($HaveAD) {
  try {
    $users = Get-ADUser -Filter * -Properties SamAccountName, UserPrincipalName, DisplayName, ServicePrincipalName, userAccountControl, LastLogonDate |
             Select-Object SamAccountName, DisplayName, UserPrincipalName, LastLogonDate, ServicePrincipalName, userAccountControl
    $groups = Get-ADGroup -Filter * -Properties GroupCategory, GroupScope | Select-Object Name, GroupCategory, GroupScope
    $computers = Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate | Select-Object Name, OperatingSystem, LastLogonDate

    OutObj -Obj $users -Name 'users.csv' -Fmt 'csv'
    OutObj -Obj $groups -Name 'groups.csv' -Fmt 'csv'
    OutObj -Obj $computers -Name 'computers.csv' -Fmt 'csv'
  } catch {
    Log -Msg 'User/group/computer enumeration failed.' -Lvl 'Err'
  }
} else {
  Log -Msg 'ActiveDirectory module missing – limited enumeration only.' -Lvl 'Warn'
}

# ---------------- SPN / KERBEROAST ----------------
Section 'KERBEROAST CANDIDATES (SPN)'
try {
  $spn = Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties ServicePrincipalName |
         Select-Object SamAccountName, ServicePrincipalName
  if ($spn) { OutObj -Obj $spn -Name 'spn_accounts.csv' -Fmt 'csv' }
  else { Log -Msg 'No SPN accounts found.' -Lvl 'Warn' }
} catch {
  Log -Msg 'SPN enumeration failed.' -Lvl 'Warn'
}

# ---------------- AS-REP ----------------
Section 'AS-REP ROASTABLE ACCOUNTS'
try {
  $flag = 0x00400000
  $asrep = Get-ADUser -Filter * -Properties userAccountControl |
           Where-Object { ($_.userAccountControl -band $flag) -ne 0 } |
           Select-Object SamAccountName, DistinguishedName
  if ($asrep) { OutObj -Obj $asrep -Name 'asrep_accounts.csv' -Fmt 'csv' }
  else { Log -Msg 'No AS-REP roastable users.' -Lvl 'Warn' }
} catch {
  Log -Msg 'AS-REP enumeration failed.' -Lvl 'Warn'
}

# ---------------- KRBTGT ----------------
Section 'KRBTGT ACCOUNT INFO'
try {
  $krbtgt = Get-ADUser -Identity krbtgt -Properties Enabled, PasswordLastSet |
            Select-Object SamAccountName, Enabled, PasswordLastSet
  OutObj -Obj $krbtgt -Name 'krbtgt.json' -Fmt 'json'
} catch {
  Log -Msg 'KRBTGT query failed.' -Lvl 'Warn'
}

# ---------------- GPO / OU ----------------
Section 'GROUP POLICY OBJECTS'
try {
  if (Get-Module -ListAvailable -Name GroupPolicy) {
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $gpo = Get-GPO -All | Select-Object DisplayName, Id, Owner, ModificationTime
    OutObj -Obj $gpo -Name 'gpos.csv' -Fmt 'csv'
  } else {
    Log -Msg 'GroupPolicy module not installed.' -Lvl 'Warn'
  }
} catch {
  Log -Msg 'GPO enumeration failed.' -Lvl 'Warn'
}

Section 'ORGANIZATIONAL UNITS'
try {
  $ou = Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName
  OutObj -Obj $ou -Name 'ou_list.csv' -Fmt 'csv'
} catch {
  Log -Msg 'OU enumeration failed.' -Lvl 'Warn'
}

# ---------------- PASSWORD POLICY ----------------
Section 'PASSWORD POLICY'
try {
  $policy = Get-ADDefaultDomainPasswordPolicy | Select-Object ComplexityEnabled, LockoutThreshold, MinPasswordLength, MaxPasswordAge
  OutObj -Obj $policy -Name 'password_policy.json' -Fmt 'json'
} catch {
  Log -Msg 'Password policy enumeration failed.' -Lvl 'Warn'
}

# ---------------- PRIVILEGED GROUPS ----------------
Section 'PRIVILEGED GROUP MEMBERS'
try {
  $priv = @('Domain Admins','Enterprise Admins','Administrators','Backup Operators','DnsAdmins')
  foreach ($p in $priv) {
    $m = Get-ADGroupMember $p -ErrorAction SilentlyContinue | Select-Object Name, SamAccountName
    if ($m) { OutObj -Obj $m -Name ("{0}_members.csv" -f ($p -replace ' ', '_')) -Fmt 'csv' }
  }
} catch {
  Log -Msg 'Privileged group enumeration failed.' -Lvl 'Warn'
}

# ---------------- DC SERVICES ----------------
Section 'DOMAIN CONTROLLER SERVICES'
try {
  $dcs = Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, Site, OperatingSystem
  OutObj -Obj $dcs -Name 'domaincontrollers.csv' -Fmt 'csv'
} catch {
  Log -Msg 'DC enumeration failed.' -Lvl 'Warn'
}

# ---------------- DNS ----------------
Section 'DNS ZONES'
try {
  $dns = Get-DnsServerZone -ErrorAction SilentlyContinue | Select-Object ZoneName, ZoneType, ReplicationScope
  if ($dns) { OutObj -Obj $dns -Name 'dns_zones.csv' -Fmt 'csv' }
  else { Log -Msg 'No DNS zones or insufficient rights.' -Lvl 'Warn' }
} catch {
  Log -Msg 'DNS zone query failed.' -Lvl 'Warn'
}

# ---------------- LOCAL SESSIONS ----------------
Section 'LOGGED-ON USERS (LOCAL)'
try {
  $sessions = query user 2>$null
  if ($sessions) { Write-Host $sessions -ForegroundColor Gray }
  else { Log -Msg 'No local sessions visible.' -Lvl 'Warn' }
} catch {
  Log -Msg 'Local session query failed.' -Lvl 'Warn'
}

# ---------------- ATTACK SIMULATIONS (GATED) ----------------
if ($ExecuteUnsafe -and $ConfirmUnsafe) {
  Section 'ATTACK SIMULATION (LAB ONLY)'
  Log -Msg 'Unsafe mode active – exporting roast candidates' -Lvl 'Warn'
  try { $spn | Export-Csv -Path (Join-Path $OutFolder 'kerberoast_candidates.csv') -NoTypeInformation } catch {}
  try { $asrep | Export-Csv -Path (Join-Path $OutFolder 'asrep_candidates.csv') -NoTypeInformation } catch {}
  if ($SprayUserFile -and $SprayPassFile) {
    Log -Msg 'Password spray helper placeholder (manual step)' -Lvl 'Warn'
  }
} elseif ($ExecuteUnsafe) {
  Log -Msg 'Add -ConfirmUnsafe to proceed with unsafe actions.' -Lvl 'Warn'
} else {
  Log -Msg 'Safe mode active – no attacks simulated.' -Lvl 'Info'
}

# ---------------- SUMMARY ----------------
Section 'SUMMARY'
Log -Msg ('AREK-AD completed. Results in ' + $OutFolder) -Lvl 'Good'

# End of file

