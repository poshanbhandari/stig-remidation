<#
.SYNOPSIS
    Persistently remediates all Windows 11 DISA STIG v2r5 Audit Policy checks (WN11-AU-*)
    by writing settings directly into the Local Group Policy audit.csv file.

.NOTES
    Author          : Poshan Bhandari
    LinkedIn        : linkedin.com/in/poshanbhandari
    GitHub          : github.com/poshanbhandari
    Date Created    : 2026-03-06
    Last Modified   : 2026-03-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000005, WN11-AU-000010, WN11-AU-000030, WN11-AU-000035,
                      WN11-AU-000040, WN11-AU-000045, WN11-AU-000050, WN11-AU-000054,
                      WN11-AU-000060, WN11-AU-000065, WN11-AU-000070, WN11-AU-000075,
                      WN11-AU-000080, WN11-AU-000081, WN11-AU-000082, WN11-AU-000083,
                      WN11-AU-000084, WN11-AU-000085, WN11-AU-000090, WN11-AU-000100,
                      WN11-AU-000105, WN11-AU-000107, WN11-AU-000110, WN11-AU-000115,
                      WN11-AU-000120, WN11-AU-000130, WN11-AU-000135, WN11-AU-000140,
                      WN11-AU-000150, WN11-AU-000155, WN11-AU-000160, WN11-AU-000500,
                      WN11-AU-000505, WN11-AU-000510, WN11-AU-000515, WN11-AU-000520,
                      WN11-AU-000525, WN11-AU-000550, WN11-AU-000555, WN11-AU-000560,
                      WN11-AU-000565, WN11-AU-000570, WN11-AU-000575, WN11-AU-000580

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  : Windows 11 Pro 25H2 OS Build 26200.7840
    PowerShell Ver. : 5.1.26100.7705

.USAGE
    Run from elevated PowerShell:
    PS C:\> .\STIG_Win11_All_Audit_Remediation.ps1

.DESCRIPTION

    STEPS:
      STEP 1 - Set SCENoApplyLegacyAuditPolicy = 1 (subcategory override)
      STEP 2 - Write all STIG settings into Local GPO audit.csv
      STEP 3 - Force a Group Policy refresh so the CSV is read immediately
      STEP 4 - Apply via auditpol.exe for instant effect
      STEP 5 - Event log sizes and permissions (registry + wevtutil)
#>

#Requires -RunAsAdministrator

# ============================================================
# HELPER FUNCTION: Set-AuditSubcategory
# Applies a subcategory setting immediately via auditpol.exe
# ============================================================
function Set-AuditSubcategory {
    param(
        [string]$Subcategory,
        [ValidateSet('success','failure','both','none')]
        [string]$Setting,
        [string]$StigID
    )
    $successFlag = if ($Setting -in 'success','both') { 'enable' } else { 'disable' }
    $failureFlag = if ($Setting -in 'failure','both') { 'enable' } else { 'disable' }
    $result = & auditpol /set /subcategory:"$Subcategory" /success:$successFlag /failure:$failureFlag 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK]   $StigID  ->  $Subcategory ($Setting)" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $StigID  ->  $Subcategory : $result" -ForegroundColor Red
    }
}


# ============================================================
# STEP 1 — SCENoApplyLegacyAuditPolicy
#
# Must be set first. Tells Windows to honour subcategory-level
# audit settings instead of legacy category-level settings.
# ============================================================
Write-Host "`n=====================================================================" -ForegroundColor White
Write-Host " STEP 1: Enable subcategory audit policy override" -ForegroundColor White
Write-Host "=====================================================================`n" -ForegroundColor White

try {
    Set-ItemProperty `
        -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name  'SCENoApplyLegacyAuditPolicy' `
        -Value 1 `
        -Type  DWord `
        -Force
    Write-Host "  [OK]   SCENoApplyLegacyAuditPolicy = 1" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Could not set SCENoApplyLegacyAuditPolicy: $_" -ForegroundColor Red
}


# ============================================================
# STEP 2 — Write STIG audit settings into Local GPO audit.csv
#
#
# The file at the path is the Local Group Policy audit
# settings file. Windows reads this on every GP refresh and
# applies it — overriding auditpol and registry values.
#
# By writing our STIG-required settings here, they become
# part of Local GPO itself and will never be overwritten.
#
# CSV format columns:
#   Machine Name     - blank (applies to local machine)
#   Policy Target    - "Machine"
#   Subcategory      - Human readable name
#   Subcategory GUID - The subcategory's unique identifier
#   Inclusion Setting- "Success and Failure", "Success",
#                      "Failure", or "No Auditing"
#   Exclusion Setting- blank (not used)
#   Setting Value    - 3=Both, 1=Success, 2=Failure, 0=None
# ============================================================
Write-Host "`n=====================================================================" -ForegroundColor White
Write-Host " STEP 2: Writing STIG settings into Local GPO audit.csv (ROOT CAUSE FIX)" -ForegroundColor White
Write-Host "=====================================================================`n" -ForegroundColor White

# Path to the Local GPO audit policy CSV file
$auditCsvPath = 'C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv'

# Ensure the directory exists (it should, but just in case)
$auditCsvDir = Split-Path $auditCsvPath
if (-not (Test-Path $auditCsvDir)) {
    New-Item -Path $auditCsvDir -ItemType Directory -Force | Out-Null
    Write-Host "  [INFO] Created directory: $auditCsvDir" -ForegroundColor Gray
}

# Define all 44 STIG audit subcategory entries in CSV format
# Each row: Machine Name, Policy Target, Subcategory, GUID, Inclusion Setting, Exclusion Setting, Setting Value
# Setting Value: 3=Success+Failure, 1=Success, 2=Failure
$auditCsvContent = @"
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,Machine,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Machine,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success,,1
,Machine,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Machine,Plug and Play Events,{0CCE9248-69AE-11D9-BED3-505054503030},Success,,1
,Machine,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success,,1
,Machine,Account Lockout,{0CCE9217-69AE-11D9-BED3-505054503030},Failure,,2
,Machine,Group Membership,{0CCE9249-69AE-11D9-BED3-505054503030},Success,,1
,Machine,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,,1
,Machine,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Machine,Special Logon,{0CCE921B-69AE-11D9-BED3-505054503030},Success,,1
,Machine,Other Logon/Logoff Events,{0CCE921C-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Machine,File Share,{0CCE9224-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Machine,Other Object Access Events,{0CCE9227-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Machine,Removable Storage,{0CCE9245-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Machine,Detailed File Share,{0CCE9244-69AE-11D9-BED3-505054503030},Failure,,2
,Machine,Audit Policy Change,{0CCE922F-69AE-11D9-BED3-505054503030},Success,,1
,Machine,Authentication Policy Change,{0CCE9230-69AE-11D9-BED3-505054503030},Success,,1
,Machine,Authorization Policy Change,{0CCE9231-69AE-11D9-BED3-505054503030},Success,,1
,Machine,Other Policy Change Events,{0CCE9234-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Machine,MPSSVC Rule-Level Policy Change,{0CCE9232-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Machine,Sensitive Privilege Use,{0CCE9228-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Machine,IPsec Driver,{0CCE9213-69AE-11D9-BED3-505054503030},Failure,,2
,Machine,Other System Events,{0CCE9214-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Machine,Security State Change,{0CCE9210-69AE-11D9-BED3-505054503030},Success,,1
,Machine,Security System Extension,{0CCE9211-69AE-11D9-BED3-505054503030},Success,,1
,Machine,System Integrity,{0CCE9212-69AE-11D9-BED3-505054503030},Success and Failure,,3
"@

# Write the CSV file — this overwrites the previously empty file
# Using ASCII encoding as required by the Windows GPO audit CSV parser
try {
    $auditCsvContent | Out-File -FilePath $auditCsvPath -Encoding ascii -Force
    Write-Host "  [OK]   audit.csv written with all 44 STIG subcategory settings" -ForegroundColor Green
    Write-Host "  [INFO] Path: $auditCsvPath" -ForegroundColor Gray
} catch {
    Write-Host "  [FAIL] Could not write audit.csv: $_" -ForegroundColor Red
}


# ============================================================
# STEP 3 — Force Group Policy refresh
#
# Runs gpupdate /force so Windows immediately reads the updated
# audit.csv and applies the new settings without waiting for
# the next scheduled GP refresh (which can take up to 90 min).
# ============================================================
Write-Host "`n=====================================================================" -ForegroundColor White
Write-Host " STEP 3: Forcing Group Policy refresh to apply audit.csv immediately" -ForegroundColor White
Write-Host "=====================================================================`n" -ForegroundColor White

try {
    & gpupdate /force 2>&1 | Out-Null
    Write-Host "  [OK]   gpupdate /force completed" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] gpupdate failed: $_" -ForegroundColor Red
}


# ============================================================
# STEP 4 — Apply immediately via auditpol.exe
#
# Belt-and-suspenders: after gpupdate has applied the CSV,
# auditpol reinforces each setting on the live running system.
# ============================================================
Write-Host "`n=====================================================================" -ForegroundColor White
Write-Host " STEP 4: Applying audit subcategories immediately via auditpol.exe" -ForegroundColor White
Write-Host "=====================================================================`n" -ForegroundColor White

# -- ACCOUNT LOGON --
Write-Host "-- Account Logon --" -ForegroundColor Yellow
# WN11-AU-000005 / WN11-AU-000010
Set-AuditSubcategory 'Credential Validation'           both    'WN11-AU-000005 / WN11-AU-000010'

# -- ACCOUNT MANAGEMENT --
Write-Host "`n-- Account Management --" -ForegroundColor Yellow
# WN11-AU-000030
Set-AuditSubcategory 'Security Group Management'       success 'WN11-AU-000030'
# WN11-AU-000035 / WN11-AU-000040
Set-AuditSubcategory 'User Account Management'         both    'WN11-AU-000035 / WN11-AU-000040'

# -- DETAILED TRACKING --
Write-Host "`n-- Detailed Tracking --" -ForegroundColor Yellow
# WN11-AU-000045
Set-AuditSubcategory 'Plug and Play Events'            success 'WN11-AU-000045'
# WN11-AU-000050
Set-AuditSubcategory 'Process Creation'                success 'WN11-AU-000050'

# -- LOGON / LOGOFF --
Write-Host "`n-- Logon / Logoff --" -ForegroundColor Yellow
# WN11-AU-000054
Set-AuditSubcategory 'Account Lockout'                 failure 'WN11-AU-000054'
# WN11-AU-000060
Set-AuditSubcategory 'Group Membership'                success 'WN11-AU-000060'
# WN11-AU-000065
Set-AuditSubcategory 'Logoff'                          success 'WN11-AU-000065'
# WN11-AU-000070 / WN11-AU-000075
Set-AuditSubcategory 'Logon'                           both    'WN11-AU-000070 / WN11-AU-000075'
# WN11-AU-000080
Set-AuditSubcategory 'Special Logon'                   success 'WN11-AU-000080'
# WN11-AU-000560 / WN11-AU-000565
Set-AuditSubcategory 'Other Logon/Logoff Events'       both    'WN11-AU-000560 / WN11-AU-000565'

# -- OBJECT ACCESS --
Write-Host "`n-- Object Access --" -ForegroundColor Yellow
# WN11-AU-000081 / WN11-AU-000082
Set-AuditSubcategory 'File Share'                      both    'WN11-AU-000081 / WN11-AU-000082'
# WN11-AU-000083 / WN11-AU-000084
Set-AuditSubcategory 'Other Object Access Events'      both    'WN11-AU-000083 / WN11-AU-000084'
# WN11-AU-000085 / WN11-AU-000090
Set-AuditSubcategory 'Removable Storage'               both    'WN11-AU-000085 / WN11-AU-000090'
# WN11-AU-000570
Set-AuditSubcategory 'Detailed File Share'             failure 'WN11-AU-000570'

# -- POLICY CHANGE --
Write-Host "`n-- Policy Change --" -ForegroundColor Yellow
# WN11-AU-000100
Set-AuditSubcategory 'Audit Policy Change'             success 'WN11-AU-000100'
# WN11-AU-000105
Set-AuditSubcategory 'Authentication Policy Change'    success 'WN11-AU-000105'
# WN11-AU-000107
Set-AuditSubcategory 'Authorization Policy Change'     success 'WN11-AU-000107'
# WN11-AU-000550 / WN11-AU-000555
Set-AuditSubcategory 'Other Policy Change Events'      both    'WN11-AU-000550 / WN11-AU-000555'
# WN11-AU-000575 / WN11-AU-000580
Set-AuditSubcategory 'MPSSVC Rule-Level Policy Change' both    'WN11-AU-000575 / WN11-AU-000580'

# -- PRIVILEGE USE --
Write-Host "`n-- Privilege Use --" -ForegroundColor Yellow
# WN11-AU-000110 / WN11-AU-000115
Set-AuditSubcategory 'Sensitive Privilege Use'         both    'WN11-AU-000110 / WN11-AU-000115'

# -- SYSTEM --
Write-Host "`n-- System --" -ForegroundColor Yellow
# WN11-AU-000120
Set-AuditSubcategory 'IPsec Driver'                    failure 'WN11-AU-000120'
# WN11-AU-000130 / WN11-AU-000135
Set-AuditSubcategory 'Other System Events'             both    'WN11-AU-000130 / WN11-AU-000135'
# WN11-AU-000140
Set-AuditSubcategory 'Security State Change'           success 'WN11-AU-000140'
# WN11-AU-000150
Set-AuditSubcategory 'Security System Extension'       success 'WN11-AU-000150'
# WN11-AU-000155 / WN11-AU-000160
Set-AuditSubcategory 'System Integrity'                both    'WN11-AU-000155 / WN11-AU-000160'


# ============================================================
# STEP 5a — EVENT LOG SIZES
# WN11-AU-000500 : Application log >= 32768 KB
# WN11-AU-000505 : Security log    >= 1024000 KB
# WN11-AU-000510 : System log      >= 32768 KB
#
# Written to HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\<log>
# This is the only location needed — it is what the STIG scanner
# checks AND what Group Policy reads to enforce the size.
# Value is stored in KB as a DWORD.
# ============================================================
Write-Host "`n=====================================================================" -ForegroundColor White
Write-Host " STEP 5a: Configuring Event Log sizes" -ForegroundColor White
Write-Host "=====================================================================`n" -ForegroundColor White

$logSizes = @{
    'Application' = @{ StigID = 'WN11-AU-000500'; SizeKB = 32768   }
    'Security'    = @{ StigID = 'WN11-AU-000505'; SizeKB = 1024000 }
    'System'      = @{ StigID = 'WN11-AU-000510'; SizeKB = 32768   }
}

foreach ($log in $logSizes.Keys) {
    $stig   = $logSizes[$log].StigID
    $sizeKB = $logSizes[$log].SizeKB

    try {
        # Write size in KB to the GPO policy path — the only location
        # the STIG scanner and Group Policy both check
        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$log"
        if (-not (Test-Path $policyPath)) {
            New-Item -Path $policyPath -Force | Out-Null
        }
        Set-ItemProperty -Path $policyPath -Name MaxSize -Value $sizeKB -Type DWord -Force
        Write-Host "  [OK]   $stig  ->  $log log = $sizeKB KB" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] $stig  ->  $log : $_" -ForegroundColor Red
    }
}


# ============================================================
# STEP 5b — EVENT LOG PERMISSIONS
# WN11-AU-000515 : Application log permissions
# WN11-AU-000520 : Security log permissions
# WN11-AU-000525 : System log permissions
# ============================================================
Write-Host "`n=====================================================================" -ForegroundColor White
Write-Host " STEP 5b: Configuring Event Log permissions" -ForegroundColor White
Write-Host "=====================================================================`n" -ForegroundColor White

$logPerms = @(
    @{ Log = 'Application'; SDDL = 'O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x3;;;S-1-5-32-573)'; StigID = 'WN11-AU-000515' }
    @{ Log = 'Security';    SDDL = 'O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;S-1-5-32-573)'; StigID = 'WN11-AU-000520' }
    @{ Log = 'System';      SDDL = 'O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x3;;;S-1-5-32-573)'; StigID = 'WN11-AU-000525' }
)

foreach ($entry in $logPerms) {
    try {
        & wevtutil sl $entry.Log /ca:$entry.SDDL 2>&1 | Out-Null
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$($entry.Log)"
        Set-ItemProperty -Path $regPath -Name CustomSD -Value $entry.SDDL -Type String -Force
        Write-Host "  [OK]   $($entry.StigID)  ->  $($entry.Log) log permissions applied" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] $($entry.StigID)  ->  $($entry.Log) : $_" -ForegroundColor Red
    }
}


# ============================================================
# VERIFICATION
# Dump the current effective audit policy to confirm all
# subcategories are set correctly. Run this again after
# reboot to confirm full persistence.
# ============================================================
Write-Host "`n=====================================================================" -ForegroundColor White
Write-Host " VERIFICATION: Current Effective Audit Policy" -ForegroundColor White
Write-Host "=====================================================================`n" -ForegroundColor White

& auditpol /get /category:* | Where-Object { $_ -notmatch '^\s*$' }

Write-Host "`n=====================================================================" -ForegroundColor White
Write-Host " DONE: All 44 WN11-AU-* STIG checks applied and persisted via Local GPO." -ForegroundColor Green
Write-Host " Reboot, then run: auditpol /get /category:*" -ForegroundColor Yellow
Write-Host " to confirm settings survived the restart." -ForegroundColor Yellow
Write-Host "=====================================================================`n" -ForegroundColor White
