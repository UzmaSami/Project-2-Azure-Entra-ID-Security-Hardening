# ============================================
# Script: check-mfa-status.ps1
# Purpose: Audit MFA registration status for all users
# Author: Uzma Shabbir
# Date: May 2026
# ============================================

# Using single quotes and clean scopes
Connect-MgGraph -Scopes 'UserAuthenticationMethod.Read.All', 'Directory.Read.All', 'User.Read.All'

Write-Host '[STATUS] Checking MFA status for all users...' -ForegroundColor Cyan

# Get all users
$allUsers = Get-MgUser -All -Property 'Id,DisplayName,UserPrincipalName,AccountEnabled'

$mfaReport = @()

foreach ($user in $allUsers) {
    # Get authentication methods for each user
    $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue

    # Check for MFA methods
    $hasMFA = $false
    $mfaMethods = @()

    foreach ($method in $authMethods) {
        $methodType = $method.AdditionalProperties['@odata.type']
        
        switch ($methodType) {
            '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' {
                $hasMFA = $true
                $mfaMethods += 'Authenticator App'
            }
            '#microsoft.graph.phoneAuthenticationMethod' {
                $hasMFA = $true
                $mfaMethods += 'Phone/SMS'
            }
            '#microsoft.graph.fido2AuthenticationMethod' {
                $hasMFA = $true
                $mfaMethods += 'FIDO2 Key'
            }
            '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' {
                $hasMFA = $true
                $mfaMethods += 'Windows Hello'
            }
        }
    }

    # Build the report object
    $mfaReport += [PSCustomObject]@{
        DisplayName       = $user.DisplayName
        UserPrincipalName = $user.UserPrincipalName
        AccountEnabled    = $user.AccountEnabled
        MFARegistered     = $hasMFA
        MFAMethods        = ($mfaMethods -join ', ')
        Status            = if ($hasMFA) {'Protected'} else {'At Risk'}
    }
}

# Calculate summary data
$protected  = ($mfaReport | Where-Object { $_.MFARegistered }).Count
$atRisk     = ($mfaReport | Where-Object { -not $_.MFARegistered -and $_.AccountEnabled }).Count
$totalUsers = $mfaReport.Count

# Handle potential division by zero if tenant is empty
$coverage = 0
if ($totalUsers -gt 0) {
    $coverage = [math]::Round(($protected / $totalUsers) * 100, 2)
}

Write-Host '========================================' -ForegroundColor Cyan
Write-Host 'MFA REGISTRATION SUMMARY' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host "Total Users:    $totalUsers" -ForegroundColor White
Write-Host "MFA Registered: $protected" -ForegroundColor Green
Write-Host "At Risk:        $atRisk" -ForegroundColor Red
Write-Host "Coverage:       $coverage%" -ForegroundColor Yellow
Write-Host '========================================' -ForegroundColor Cyan

# Show at risk users (using clean single-line Select-Object)
Write-Host '[INFO] USERS WITHOUT MFA:' -ForegroundColor Red
$mfaReport | Where-Object { -not $_.MFARegistered -and $_.AccountEnabled } | Select-Object DisplayName, UserPrincipalName, Status | Format-Table -AutoSize

# Export full report to CSV
$mfaReport | Export-Csv -Path '.\mfa-status-report.csv' -NoTypeInformation

Write-Host '[SUCCESS] Full MFA report exported to mfa-status-report.csv' -ForegroundColor Green

