<#
.SYNOPSIS
    Checks and configures "Turn off Microsoft consumer experiences" policy to Enabled.
    Disables Windows suggestions, tips, ads, and consumer features.

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
    PS C:\> .\Disable-WindowsConsumerFeatures.ps1
#>

# Define registry path and value for disabling Windows consumer features
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$valueName = "DisableWindowsConsumerFeatures"
$requiredValue = 1  # 1 = Enabled (Turn off consumer experiences)

# Check current status first
Write-Host "Checking Windows Consumer Features status..." -ForegroundColor Cyan

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
        Write-Host "Status: DISABLED (Compliant - Consumer features blocked)" -ForegroundColor Green
        exit 0  # Already compliant
    }
    else {
        Write-Host "Status: Consumer features ENABLED (Value=$currentValue, Fixing...)" -ForegroundColor Yellow
    }
}

# Create registry path if it doesn't exist
if (-not (Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
    Write-Host "Created registry path: $path" -ForegroundColor Yellow
}

# Set the value to disable Windows consumer features (1=Enabled policy)
Set-ItemProperty -Path $path -Name $valueName -Value $requiredValue -Type DWord -Force
Write-Host "Set $valueName = $requiredValue (Consumer features disabled)" -ForegroundColor Green

# Final verification
Write-Host "`nFinal Status:" -ForegroundColor Cyan
$finalValue = (Get-ItemProperty -Path $path -Name $valueName).$valueName
Write-Host "$path -> $valueName = $finalValue (1=Compliant, Consumer features disabled)" -ForegroundColor Green
