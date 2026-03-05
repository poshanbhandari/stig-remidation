 <#
.SYNOPSIS
    Checks status of "Always install with elevated privileges" policy, then disables it.

.NOTES
    Author          : Poshan Bhandari
    LinkedIn        : linkedin.com/in/poshanbhandari
    GitHub          : github.com/poshanbhandari
    Date Created    : 
    Last Modified   : 
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : 

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  :  Windows 11 pro 25H2 OS Build 26200.7840
    PowerShell Ver. :  5.1.26100.7705

.USAGE
    Run from elevated PowerShell:
    PS C:\> .\Check-Then-Disable-AlwaysInstallElevated.ps1
#>

# Define registry path and value for the policy
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$valueName = "AlwaysInstallElevated"

# Check current status first
Write-Host "Checking current status..." -ForegroundColor Cyan
$currentValue = (Get-ItemProperty -Path $path -Name $valueName -ErrorAction SilentlyContinue).$valueName

if ($null -eq $currentValue) {
    Write-Host "Status: NOT CONFIGURED (Safe default)" -ForegroundColor Yellow
}
elseif ($currentValue -eq 0) {
    Write-Host "Status: DISABLED (Already compliant)" -ForegroundColor Green
}
elseif ($currentValue -eq 1) {
    Write-Host "Status: ENABLED (Vulnerable - fixing now...)" -ForegroundColor Red
}
else {
    Write-Host "Status: UNKNOWN VALUE ($currentValue) - fixing..." -ForegroundColor Yellow
}

# Ensure registry key exists
if (-not (Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
    Write-Host "Created registry key: $path" -ForegroundColor Yellow
}

# Disable the setting (set to 0)
Set-ItemProperty -Path $path -Name $valueName -Value 0 -Type DWord -Force

# Final verification
Write-Host "`nFinal Status:" -ForegroundColor Cyan
$finalValue = (Get-ItemProperty -Path $path -Name $valueName -ErrorAction SilentlyContinue).$valueName
Write-Host "$path -> $valueName = $finalValue (0=Disabled, Compliant)" -ForegroundColor Green
