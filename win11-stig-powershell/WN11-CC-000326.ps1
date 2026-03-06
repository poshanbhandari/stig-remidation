<#
.SYNOPSIS
    Checks and configures PowerShell Script Block Logging to Enabled.
    Logs all PowerShell execution for security monitoring and forensics.

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
    PS C:\> .\Enable-PowerShellScriptBlockLogging.ps1
#>

# Define registry path and value for PowerShell Script Block Logging
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$valueName = "EnableScriptBlockLogging"
$requiredValue = 1  # 1 = Enabled (Log all PowerShell execution)

# Check current status first
Write-Host "Checking PowerShell Script Block Logging status..." -ForegroundColor Cyan

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
        Write-Host "Status: SCRIPT BLOCK LOGGING ENABLED (Compliant)" -ForegroundColor Green
        exit 0  # Already compliant
    }
    else {
        Write-Host "Status: Logging DISABLED (Value=$currentValue, Fixing...)" -ForegroundColor Yellow
    }
}

# Create registry path if it doesn't exist
if (-not (Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
    Write-Host "Created registry path: $path" -ForegroundColor Yellow
}

# Set the value to enable PowerShell Script Block Logging (1=Enabled)
Set-ItemProperty -Path $path -Name $valueName -Value $requiredValue -Type DWord -Force
Write-Host "Set $valueName = $requiredValue (Script Block Logging enabled)" -ForegroundColor Green

# Final verification
Write-Host "`nFinal Status:" -ForegroundColor Cyan
$finalValue = (Get-ItemProperty -Path $path -Name $valueName).$valueName
Write-Host "$path -> $valueName = $finalValue (1=Compliant, Logging Enabled)" -ForegroundColor Green

Write-Host "`nPowerShell will now log ALL script execution to Event ID 4104 (Microsoft-Windows-PowerShell/Operational)." -ForegroundColor Cyan
