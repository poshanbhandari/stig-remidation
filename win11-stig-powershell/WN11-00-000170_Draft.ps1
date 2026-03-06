<#
.SYNOPSIS
    Checks and configures SMBv1 client driver to Disabled (Start=4).
    Disables legacy SMBv1 protocol to prevent exploits like EternalBlue.

.NOTES
    Author          : Poshan Bhandari
    LinkedIn        : linkedin.com/in/poshanbhandari
    GitHub          : github.com/poshanbhandari
    Date Created    : 
    Last Modified   : 
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000160

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  :  Windows 11 pro 25H2 OS Build 26200.7840
    PowerShell Ver. :  5.1.26100.7705

.USAGE
    Run from elevated PowerShell:
    PS C:\> .\Disable-SMBv1.ps1
    System restart required after changes.
#>

$path = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
$valueName = "Start"
$requiredValue = 4

Write-Host "Checking SMBv1 service..." -ForegroundColor Cyan

# CRITICAL: Check if service key exists FIRST
if (-not (Test-Path $path)) {
    Write-Host "SMBv1 service NOT FOUND (Compliant - feature uninstalled)" -ForegroundColor Green
    exit 0
}

# Service exists - check Start value
$current = (Get-ItemProperty -Path $path -Name $valueName -EA SilentlyContinue).$valueName
if ($current -eq 4) {
    Write-Host "SMBv1 already DISABLED ✓" -ForegroundColor Green
    exit 0
}

Write-Host "SMBv1 ACTIVE (Start=$current) → Disabling..." -ForegroundColor Yellow

# MODIFY EXISTING service key (never create)
Set-ItemProperty -Path $path -Name $valueName -Value $requiredValue -Type DWord -Force

Write-Host "SMBv1 DISABLED ✓ REBOOT REQUIRED!" -ForegroundColor Green
