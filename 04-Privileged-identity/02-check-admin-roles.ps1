# ============================================
# Script: check-admin-roles.ps1
# Purpose: Security check on admin roles (Simplified v1.0 version)
# Author: Uzma Shabbir
# ============================================

# AuditLog.Read.All is the key scope for sign-in data
Connect-MgGraph -Scopes 'Directory.Read.All', 'User.Read.All', 'AuditLog.Read.All'

Write-Host '[STATUS] Running Admin Role Security Check...' -ForegroundColor Cyan

$findings = @()
$breakGlassUpn = 'xxusk@nazshkhanxxxgmail.onmicrosoft.com'

# 1. Get Global Admin Role and Members
$globalAdminRole = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq 'Global Administrator' }
$globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id

Write-Host ' '
Write-Host '[CHECK 1] Global Administrator Count' -ForegroundColor Yellow
Write-Host "Found: $($globalAdmins.Count) Global Administrators" -ForegroundColor White

if ($globalAdmins.Count -gt 3) {
    $findings += '[FAIL] Too many Global Admins (' + $globalAdmins.Count + '). Recommended: 2-3 maximum.'
} else {
    $findings += '[PASS] Global Admin count is acceptable (' + $globalAdmins.Count + ').'
}

# 2. Check for Guest users with admin roles
Write-Host ' '
Write-Host '[CHECK 2] Guest Users with Admin Roles' -ForegroundColor Yellow
$guestCount = 0

foreach ($admin in $globalAdmins) {
    $user = Get-MgUser -UserId $admin.Id -Property 'Id,UserType,UserPrincipalName' -ErrorAction SilentlyContinue
    if ($user -and $user.UserType -eq 'Guest') {
        $guestCount++
        Write-Host '[ALERT] Guest Admin: ' $user.UserPrincipalName -ForegroundColor Red
    }
}

if ($guestCount -gt 0) {
    $findings += '[CRITICAL] ' + $guestCount + ' GUEST users have Global Admin role!'
} else {
    $findings += '[PASS] No guest users have admin roles.'
}

# 3. Check for Stale admin accounts (90 days)
Write-Host ' '
Write-Host '[CHECK 3] Stale Admin Accounts' -ForegroundColor Yellow
$ninetyDaysAgo = (Get-Date).AddDays(-90)
$staleCount = 0

foreach ($admin in $globalAdmins) {
    # Requesting SignInActivity explicitly in v1.0
    $user = Get-MgUser -UserId $admin.Id -Property 'DisplayName,UserPrincipalName,SignInActivity' -ErrorAction SilentlyContinue
    
    # Skip the break glass account
    if ($user.UserPrincipalName -eq $breakGlassUpn) { continue }

    if ($user.SignInActivity.LastSignInDateTime) {
        $lastSignIn = [DateTime]$user.SignInActivity.LastSignInDateTime
        if ($lastSignIn -lt $ninetyDaysAgo) {
            $staleCount++
            Write-Host '[STALE] ' $user.UserPrincipalName ' (Last seen: ' $lastSignIn.ToShortDateString() ')' -ForegroundColor Yellow
        }
    } else {
        # No sign-in data found usually means the account is very old or never used
        $staleCount++
        Write-Host '[STALE] ' $user.UserPrincipalName ' (Never signed in)' -ForegroundColor Yellow
    }
}

if ($staleCount -gt 0) {
    $findings += '[WARNING] ' + $staleCount + ' admin accounts inactive for 90+ days.'
} else {
    $findings += '[PASS] All active admin accounts show recent activity.'
}

# Display Summary
Write-Host ' '
Write-Host '========================================' -ForegroundColor Cyan
Write-Host 'ADMIN ROLE SECURITY FINDINGS' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
foreach ($finding in $findings) {
    if ($finding -like '*[FAIL]*' -or $finding -like '*[CRITICAL]*') {
        Write-Host $finding -ForegroundColor Red
    } elseif ($finding -like '*[WARNING]*') {
        Write-Host $finding -ForegroundColor Yellow
    } else {
        Write-Host $finding -ForegroundColor Green
    }
}
Write-Host '========================================' -ForegroundColor Cyan

# Export findings
$findings | Out-File -FilePath '.\admin-role-security-findings.txt' -Encoding UTF8
Write-Host ' '
Write-Host '[SUCCESS] Findings exported to admin-role-security-findings.txt' -ForegroundColor Green

