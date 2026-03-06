<#
.SYNOPSIS
    Configures "Audit Process Creation" to audit Failure events (Fixed verification).

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
    PS C:\> .\Set-AuditProcessCreation-Failure.ps1
#>

Write-Host "Configuring 'Audit Process Creation' to audit Failure events..." -ForegroundColor Cyan

# Configure audit policy for Process Creation - Failure events
$auditResult = auditpol /set /subcategory:"Process Creation" /failure:enable

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ auditpol command succeeded" -ForegroundColor Green
} else {
    Write-Host "✗ auditpol failed: $auditResult" -ForegroundColor Red
    exit 1
}

# Verify configuration
Write-Host "`nVerification:" -ForegroundColor Cyan
$auditStatus = auditpol /get /subcategory:"Process Creation"
Write-Host $auditStatus

# Fixed verification logic - checks for "Failure" in output (means Enabled)
if ($auditStatus -match "Process Creation\s+Failure") {
    Write-Host "`n✓ STATUS: Audit Process Creation (Failure) ENABLED (Compliant)" -ForegroundColor Green
    Write-Host "Event ID 4688 (Security log) will capture failed process creations." -ForegroundColor Cyan
} else {
    Write-Host "`n✗ STATUS: Verification failed - review auditpol output above" -ForegroundColor Red
}

Write-Host "`nAudit logs viewable in:" -ForegroundColor Yellow
Write-Host "Event Viewer >> Windows Logs >> Security >> Event ID 4688" -ForegroundColor Yellow
