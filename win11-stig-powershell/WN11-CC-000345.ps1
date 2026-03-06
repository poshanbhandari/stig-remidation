 <#
.SYNOPSIS
    Disables Basic authentication for WinRM Service (AllowBasic=0).
    Prevents insecure Basic auth over HTTP for remote management.

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
    PS C:\> .\Disable-WinRM-BasicAuth.ps1
#>

# Define registry path and value for disabling WinRM Basic authentication
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
$valueName = "AllowBasic"
$requiredValue = 0  # 0 = Disabled (Basic auth blocked)

# Check current status first
Write-Host "Checking WinRM Basic Authentication status..." -ForegroundColor Cyan

# Test if registry path exists
if (-not (Test-Path $path)) {
    Write-Host "Status: Registry path does not exist (Finding)" -ForegroundColor Red
}
else {
    # Get current value or null if it doesn't exist
    $currentValue = (Get-ItemProperty -Path $path -Name $valueName -ErrorAction SilentlyContinue).$valueName
    
    if ($null -eq $currentValue) {
        Write-Host "Status: Value does not exist (Finding)" -ForegroundColor Red
    }
    elseif ($currentValue -eq $requiredValue) {
        Write-Host "Status: BASIC AUTH DISABLED (Compliant)" -ForegroundColor Green
        exit 0  # Already compliant
    }
    else {
        Write-Host "Status: Basic auth ENABLED (Value=$currentValue, Fixing...)" -ForegroundColor Yellow
    }
}

# Create registry path if it doesn't exist
if (-not (Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
    Write-Host "Created registry path: $path" -ForegroundColor Yellow
}

# Set the value to disable Basic authentication (0=Disabled)
Set-ItemProperty -Path $path -Name $valueName -Value $requiredValue -Type DWord -Force
Write-Host "Set $valueName = $requiredValue (WinRM Basic auth disabled)" -ForegroundColor Green

# Refresh WinRM policy (optional but recommended)
Write-Host "Refreshing WinRM configuration..." -ForegroundColor Cyan
winrm set winrm/config/service/auth @{Basic="false"} 2>$null

# Final verification
Write-Host "`nFinal Status:" -ForegroundColor Cyan
$finalValue = (Get-ItemProperty -Path $path -Name $valueName).$valueName
Write-Host "$path -> $valueName = $finalValue (0=Compliant, Basic auth disabled)" -ForegroundColor Green

Write-Host "`nWinRM now requires Kerberos/NTLM - Basic auth over HTTP blocked." -ForegroundColor Cyan
 
