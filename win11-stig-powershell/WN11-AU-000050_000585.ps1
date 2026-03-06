<#
.SYNOPSIS
    Fixes WN11-AU-000050 (Process Creation Success) AND WN11-AU-000585 (Command Line Process Auditing Failure)
    Enables Process Creation auditing for BOTH Success and Failure events.
    Fixes both STIG requirements simultaneously

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
    PS C:\> .\Enable-AuditProcessCreation-Success&Failures.ps1
#>

# Enable Process Creation auditing for SUCCESS (WN11-AU-000050)
auditpol /set /subcategory:"Process Creation" /success:enable

# Enable Process Creation auditing for FAILURE (WN11-AU-000585) 
auditpol /set /subcategory:"Process Creation" /failure:enable

# Enable Command Line Auditing in Process Creation events (required for WN11-AU-000585)
reg add "HKLM\Software\Microsoft\Windows CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

Write-Host "✅ WN11-AU-000050 & WN11-AU-000585 FIXED" -ForegroundColor Green
Write-Host "   - Process Creation Success: ENABLED" -ForegroundColor Green
Write-Host "   - Process Creation Failure: ENABLED" -ForegroundColor Green  
Write-Host "   - Command Line Auditing: ENABLED" -ForegroundColor Green

# Verify the settings
Write-Host "`nVerification:" -ForegroundColor Yellow
auditpol /get /subcategory:"Process Creation"
"Final: $((Get-ItemProperty $path -Name $valueName -EA 0).$valueName) ✓"
