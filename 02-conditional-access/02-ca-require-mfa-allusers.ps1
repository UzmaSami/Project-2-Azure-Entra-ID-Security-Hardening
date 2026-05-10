# ============================================
# Script: ca-require-mfa-allusers.ps1
# Purpose: Create Conditional Access policy requiring MFA for all users
# Author: Uzma Shabbir
# Date: May 2026
# ============================================

# Added User.Read.All scope to ensure we can look up your break glass account
Connect-MgGraph -Scopes 'Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'User.Read.All'

Write-Host '[STATUS] Creating CA Policy: MFA for All Users...' -ForegroundColor Cyan

# 1. Look up your specific Break Glass account UPN
$breakGlassUpn = 'xxusk@nazshkhanxxxgmail.onmicrosoft.com'
$breakGlassUser = Get-MgUser -UserId $breakGlassUpn -ErrorAction SilentlyContinue

if ($breakGlassUser) {
    $excludedUsers = @($breakGlassUser.Id)
    Write-Host '[SUCCESS] Break glass account found and will be safely excluded.' -ForegroundColor Green
} else {
    Write-Host '[ERROR] Break glass account not found! Aborting to prevent tenant lockout.' -ForegroundColor Red
    exit
}

# 2. Define the Conditional Access policy parameters
$params = @{
    DisplayName = 'CA002 - Require MFA for All Users'
    State       = 'enabledForReportingButNotEnforced'
    Conditions  = @{
        Users = @{
            IncludeUsers = @('All')
            ExcludeUsers = $excludedUsers
        }
        Applications = @{
            IncludeApplications = @('All')
        }
        ClientAppTypes = @('all')
    }
    GrantControls = @{
        Operator        = 'OR'
        BuiltInControls = @('mfa')
    }
}

# 3. Create the policy
$policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $params

Write-Host '[SUCCESS] CA Policy created successfully!' -ForegroundColor Green
Write-Host 'Policy ID:   ' $policy.Id -ForegroundColor Cyan
Write-Host 'Policy Name: ' $policy.DisplayName -ForegroundColor Cyan
Write-Host 'State:       ' $policy.State -ForegroundColor Yellow
Write-Host '[WARNING] Policy is in REPORT MODE - monitor before enforcing' -ForegroundColor Yellow

# 4. Save policy ID for reference using the safe file write method
$logText = 'CA002 Policy ID: ' + $policy.Id
Add-Content -Path '.\ca-policy-ids.txt' -Value $logText

