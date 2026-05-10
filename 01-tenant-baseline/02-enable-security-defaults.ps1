# ============================================
# Script: enable-security-defaults.ps1
# Purpose: Check and document security defaults status
# Author: Uzma Shabbir
# Date: May 2026
# ============================================

# 1. Ensure the required modules are loaded
Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop

Write-Host "Initiating connection to Microsoft Graph..." -ForegroundColor Cyan

# 2. Connect to Graph (Added Policy.ReadWrite.SecurityDefaults so you have permission to change it)
Connect-MgGraph -Scopes `
    "Policy.Read.All", `
    "Policy.ReadWrite.ConditionalAccess", `
    "Policy.ReadWrite.SecurityDefaults"

# 3. Get current security defaults status
$securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy

Write-Host "`n=== SECURITY DEFAULTS STATUS ===" -ForegroundColor Cyan
Write-Host "Is Enabled: $($securityDefaults.IsEnabled)" -ForegroundColor White

# 4. Evaluate and update
if ($securityDefaults.IsEnabled) {
    Write-Host "`n⚠️  Security Defaults is ENABLED" -ForegroundColor Yellow
    Write-Host "We need to DISABLE it to use Conditional Access" -ForegroundColor Yellow
    Write-Host "Conditional Access = MORE granular and powerful" -ForegroundColor Green
    
    # Disable security defaults to use Conditional Access instead
    $params = @{
        IsEnabled = $false
    }
    
    Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $params
    
    Write-Host "`n✅ Security Defaults DISABLED" -ForegroundColor Green
    Write-Host "✅ Ready for Conditional Access Policies" -ForegroundColor Green

} else {
    Write-Host "`n✅ Security Defaults already disabled" -ForegroundColor Green
    Write-Host "✅ Ready for Conditional Access setup" -ForegroundColor Green
}

