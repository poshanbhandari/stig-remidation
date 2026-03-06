 <#
.SYNOPSIS
    Configures "Audit Process Creation" policy to audit Success events
    (Computer Configuration >> Security Settings >> Advanced Audit Policy >> Detailed Tracking).

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
    PS C:\> .\Enable-AuditProcessCreation-Success.ps1
#>

# Path for  Audit Policies
$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$valueName = "Process_Creation"
$successValue = 0x1  # Success only

# Check current status
$current = (Get-ItemProperty -Path $path -Name $valueName -EA 0).$valueName
if ($current -band 1) { Write-Host "Already auditing Success ✓" -F Green }
else { Write-Host "Enabling Success auditing..." -F Yellow }

# Set policy and refresh
if (-not (Test-Path $path)) { New-Item $path -Force | Out-Null }
Set-ItemProperty -Path $path -Name $valueName -Value $successValue -Type DWord -Force
auditpol /set /subcategory:"Process Creation" /success:enable

# Verify
"Final Value: $((Get-ItemProperty $path -Name $valueName -EA 0).$valueName) ✓"
 
