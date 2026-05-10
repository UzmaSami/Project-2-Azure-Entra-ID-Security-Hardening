# ============================================
# Script: signin-logs-analysis.ps1
# Purpose: Analyze sign-in logs for suspicious patterns
# Author: Uzma Shabbir
# Date: May 2026
# ============================================

Connect-MgGraph -Scopes 'AuditLog.Read.All'

Write-Host '[STATUS] Analyzing sign-in logs...' -ForegroundColor Cyan

# 1. Get sign-in logs from last 7 days (ISO 8601 format)
$7daysAgo = (Get-Date).AddDays(-7).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

# Using a filter to only get relevant recent logs
$signInLogs = Get-MgAuditLogSignIn -Filter "createdDateTime ge $7daysAgo" -Top 500

Write-Host ('Retrieved ' + $signInLogs.Count + ' sign-in events') -ForegroundColor White

# 2. Analyze failures
$failures = $signInLogs | Where-Object { $_.Status.ErrorCode -ne 0 }

# 3. Analyze by location
$locationGroups = $signInLogs | Group-Object { $_.Location.CountryOrRegion } | Sort-Object Count -Descending

# 4. Failed sign-ins analysis
Write-Host ' '
Write-Host '=== FAILED SIGN-IN ANALYSIS ===' -ForegroundColor Red
Write-Host ('Total Failures: ' + $failures.Count) -ForegroundColor Red

$failures | Group-Object UserPrincipalName | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
    Write-Host ('User: ' + $_.Name + ' -- Failures: ' + $_.Count) -ForegroundColor Yellow
}

# 5. Sign-ins by country
Write-Host ' '
Write-Host '=== SIGN-INS BY COUNTRY ===' -ForegroundColor Cyan
$locationGroups | Select-Object @{N='Country';E={$_.Name}}, Count | Select-Object -First 10 | Format-Table -AutoSize

# 6. Suspicious patterns (Brute Force Detection)
Write-Host ' '
Write-Host '=== SUSPICIOUS PATTERN DETECTION ===' -ForegroundColor Yellow

$suspiciousUsers = $failures | Group-Object UserPrincipalName | Where-Object { $_.Count -gt 5 }

if ($suspiciousUsers) {
    Write-Host '[WARNING] Potential brute force attempts detected!' -ForegroundColor Red
    $suspiciousUsers | ForEach-Object {
        Write-Host ('User: ' + $_.Name + ' -- ' + $_.Count + ' failures in the last 7 days') -ForegroundColor Red
    }
} else {
    Write-Host '[INFO] No suspicious brute-force patterns detected.' -ForegroundColor Green
}

# 7. Export analysis to CSV
$signInLogs | Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName, `
    @{N='Country';E={$_.Location.CountryOrRegion}}, `
    @{N='ErrorCode';E={$_.Status.ErrorCode}}, `
    @{N='FailureReason';E={$_.Status.FailureReason}} |
    Export-Csv -Path '.\signin-analysis.csv' -NoTypeInformation

Write-Host ' '
Write-Host '[SUCCESS] Sign-in analysis exported to signin-analysis.csv' -ForegroundColor Green

