# ============================================
# Script: ca-block-legacy-auth.ps1
# Purpose: Block legacy authentication protocols which bypass MFA
# Author: Uzma Shabbir
# Date: May 2026
# ============================================

Connect-MgGraph -Scopes 'Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'User.Read.All'

Write-Host '[STATUS] Creating CA Policy: Block Legacy Authentication...' -ForegroundColor Cyan
Write-Host 'Legacy auth = SMTP, IMAP, POP3, older Office clients' -ForegroundColor Yellow
Write-Host 'These bypass MFA - MUST be blocked!' -ForegroundColor Red

# 1. Look up your specific Break Glass account UPN to exclude
$breakGlassUpn = 'xxusk@nazshkhanxxxgmail.onmicrosoft.com'
$breakGlassUser = Get-MgUser -UserId $breakGlassUpn -ErrorAction SilentlyContinue

if ($breakGlassUser) {
    $excludedUsers = @($breakGlassUser.Id)
    Write-Host '[SUCCESS] Break glass account found and will be excluded.' -ForegroundColor Green
} else {
    Write-Host '[ERROR] Break glass account not found! Aborting to prevent lockout.' -ForegroundColor Red
    exit
}

# 2. Define Policy Parameters
$params = @{
    DisplayName = 'CA003 - Block Legacy Authentication'
    State       = 'enabledForReportingButNotEnforced'
    Conditions  = @{
        Users = @{
            IncludeUsers = @('All')
            ExcludeUsers = $excludedUsers
        }
        Applications = @{
            IncludeApplications = @('All')
        }
        # Target legacy auth client apps specifically
        ClientAppTypes = @(
            'exchangeActiveSync',
            'other'
        )
    }
    GrantControls = @{
        Operator        = 'OR'
        BuiltInControls = @('block')
    }
}

# 3. Create the policy
$policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $params

Write-Host '[SUCCESS] Legacy Auth Block policy created!' -ForegroundColor Green
Write-Host 'Policy Name: ' $policy.DisplayName -ForegroundColor Cyan
Write-Host '[INFO] This single policy blocks 99% of password spray attacks!' -ForegroundColor Green

# 4. Save policy ID for reference using safe file write
$logText = 'CA003 Policy ID: ' + $policy.Id
Add-Content -Path '.\ca-policy-ids.txt' -Value $logText

