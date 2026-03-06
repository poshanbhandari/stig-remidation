 <#
.SYNOPSIS
    Configures audit policy override (WN11-SO-000030) and enables "Audit Credential Validation - Success".

.NOTES
    Author          : Poshan Bhandari
    LinkedIn        : linkedin.com/in/poshanbhandari
    GitHub          : github.com/poshanbhandari
    Date Created    : 
    Last Modified   : 
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000030

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  :  Windows 11 pro 25H2 OS Build 26200.7840
    PowerShell Ver. :  5.1.26100.7705

.USAGE
    Run from elevated PowerShell:
    PS C:\> .\Enable-AuditPolicyOverride-CredentialValidation.ps1
#>

# Part 1: Enable Audit Policy Subcategory Override (WN11-SO-000030)
Write-Host "=== Part 1: Configuring Audit Policy Override (WN11-SO-000030) ===" -ForegroundColor Cyan

$path1 = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$valueName1 = "SCENoApplyLegacyAuditPolicy"
$requiredValue1 = 1

if (-not (Test-Path $path1)) {
    Write-Host "LSA path missing (unlikely), creating..." -ForegroundColor Yellow
}

Set-ItemProperty -Path $path1 -Name $valueName1 -Value $requiredValue1 -Type DWord -Force
Write-Host "Set SCENoApplyLegacyAuditPolicy = 1 (Subcategories override categories)" -ForegroundColor Green

# Part 2: Enable Audit Credential Validation - Success
Write-Host "`n=== Part 2: Enabling Audit Credential Validation (Success) ===" -ForegroundColor Cyan

# Set advanced audit policy using auditpol
auditpol /set /subcategory:"Credential Validation" /success:enable

# Verify both settings
Write-Host "`n=== Verification ===" -ForegroundColor Cyan

# Verify registry setting
$lsaValue = (Get-ItemProperty -Path $path1 -Name $valueName1 -ErrorAction SilentlyContinue).$valueName1
Write-Host "WN11-SO-000030: SCENoApplyLegacyAuditPolicy = $lsaValue (1=Compliant)" -ForegroundColor $(if($lsaValue -eq 1){"Green"}else{"Red"})

# Verify audit policy
Write-Host "`nAudit Credential Validation:" -ForegroundColor Cyan
auditpol /get /subcategory:"Credential Validation"

Write-Host "`nSUCCESS: Audit policy override enabled + Credential Validation auditing active." -ForegroundColor Green
Write-Host "Logs will appear in Event Viewer >> Security >> Event ID 4776 (Success)." -ForegroundColor Cyan
 
