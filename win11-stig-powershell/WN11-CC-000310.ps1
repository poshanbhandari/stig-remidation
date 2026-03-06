<#
.SYNOPSIS
    Checks and configures "Allow user control over installs" policy to Disabled.
    Prevents users from controlling Windows Installer behavior.

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
    PS C:\> .\Disable-UserControlInstalls.ps1
#>

# Define registry path and value for disabling user control over installs
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$valueName = "EnableUserControl"
$requiredValue = 0  # 0 = Disabled (Users cannot control installs)

# Check current status first
Write-Host "Checking User Control over Installs status..." -ForegroundColor Cyan

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
        Write-Host "Status: USER CONTROL DISABLED (Compliant)" -ForegroundColor Green
        exit 0  # Already compliant
    }
    else {
        Write-Host "Status: User control ENABLED (Value=$currentValue, Fixing...)" -ForegroundColor Yellow
    }
}

# Create registry path if it doesn't exist
if (-not (Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
    Write-Host "Created registry path: $path" -ForegroundColor Yellow
}

# Set the value to disable user control over installs (0=Disabled)
Set-ItemProperty -Path $path -Name $valueName -Value $requiredValue -Type DWord -Force
Write-Host "Set $valueName = $requiredValue (User control over installs disabled)" -ForegroundColor Green

# Final verification
Write-Host "`nFinal Status:" -ForegroundColor Cyan
$finalValue = (Get-ItemProperty -Path $path -Name $valueName).$valueName
Write-Host "$path -> $valueName = $finalValue (0=Compliant, User control disabled)" -ForegroundColor Green
