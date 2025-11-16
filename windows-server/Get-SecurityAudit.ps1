<#
.SYNOPSIS
    Comprehensive Windows Server Security Audit Script

.DESCRIPTION
    Performs a thorough security audit of Windows Server including:
    - Security policies
    - User accounts and permissions
    - Firewall configuration
    - Windows Defender status
    - Installed updates
    - Security event logs
    - Network configurations

.PARAMETER ExportPath
    Path where the audit report will be saved (default: C:\SecurityAudits)

.EXAMPLE
    .\Get-SecurityAudit.ps1 -ExportPath "C:\Reports"

.NOTES
    Author: Infrastructure Security Team
    Requires: Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "C:\SecurityAudits"
)

# Ensure running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

# Create export directory if it doesn't exist
if (-not (Test-Path $ExportPath)) {
    New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $ExportPath "SecurityAudit_$timestamp.html"

Write-Host "Starting Security Audit..." -ForegroundColor Green

# Initialize HTML report
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows Server Security Audit - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 5px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th { background-color: #3498db; color: white; padding: 10px; text-align: left; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .warning { color: #e74c3c; font-weight: bold; }
        .success { color: #27ae60; font-weight: bold; }
        .info { background-color: #ecf0f1; padding: 10px; margin: 10px 0; border-left: 4px solid #3498db; }
    </style>
</head>
<body>
    <h1>Windows Server Security Audit Report</h1>
    <div class="info">
        <strong>Server:</strong> $env:COMPUTERNAME<br>
        <strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
        <strong>OS:</strong> $(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
    </div>
"@

# Function to add section to HTML
function Add-HTMLSection {
    param([string]$Title, [string]$Content)
    return "<h2>$Title</h2>$Content"
}

# 1. Security Policy Audit
Write-Host "Auditing Security Policies..." -ForegroundColor Cyan
$secpolContent = & secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet
$secpol = Get-Content "$env:TEMP\secpol.cfg"

$passwordPolicy = @"
<table>
    <tr><th>Policy</th><th>Setting</th></tr>
"@

# Parse key security policies
$policies = @{
    'MinimumPasswordLength' = 'Minimum Password Length'
    'PasswordComplexity' = 'Password Complexity'
    'MaximumPasswordAge' = 'Maximum Password Age'
    'MinimumPasswordAge' = 'Minimum Password Age'
    'LockoutBadCount' = 'Account Lockout Threshold'
}

foreach ($key in $policies.Keys) {
    $value = ($secpol | Select-String $key | ForEach-Object { ($_ -split '=')[1].Trim() })
    if ($value) {
        $passwordPolicy += "<tr><td>$($policies[$key])</td><td>$value</td></tr>"
    }
}

$passwordPolicy += "</table>"
$htmlReport += Add-HTMLSection "Password Policy" $passwordPolicy

# 2. Local Administrators
Write-Host "Checking Local Administrators..." -ForegroundColor Cyan
$admins = Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass, PrincipalSource
$adminTable = "<table><tr><th>Name</th><th>Type</th><th>Source</th></tr>"
foreach ($admin in $admins) {
    $adminTable += "<tr><td>$($admin.Name)</td><td>$($admin.ObjectClass)</td><td>$($admin.PrincipalSource)</td></tr>"
}
$adminTable += "</table>"
$htmlReport += Add-HTMLSection "Local Administrators" $adminTable

# 3. Windows Firewall Status
Write-Host "Checking Windows Firewall..." -ForegroundColor Cyan
$fwProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
$fwTable = "<table><tr><th>Profile</th><th>Enabled</th><th>Inbound Default</th><th>Outbound Default</th></tr>"
foreach ($profile in $fwProfiles) {
    $enabled = if ($profile.Enabled) { "<span class='success'>Yes</span>" } else { "<span class='warning'>No</span>" }
    $fwTable += "<tr><td>$($profile.Name)</td><td>$enabled</td><td>$($profile.DefaultInboundAction)</td><td>$($profile.DefaultOutboundAction)</td></tr>"
}
$fwTable += "</table>"
$htmlReport += Add-HTMLSection "Windows Firewall Status" $fwTable

# 4. Windows Defender Status
Write-Host "Checking Windows Defender..." -ForegroundColor Cyan
try {
    $defender = Get-MpComputerStatus
    $defenderTable = @"
    <table>
        <tr><th>Component</th><th>Status</th></tr>
        <tr><td>Antivirus Enabled</td><td>$(if ($defender.AntivirusEnabled) { "<span class='success'>Yes</span>" } else { "<span class='warning'>No</span>" })</td></tr>
        <tr><td>Real-time Protection</td><td>$(if ($defender.RealTimeProtectionEnabled) { "<span class='success'>Yes</span>" } else { "<span class='warning'>No</span>" })</td></tr>
        <tr><td>Antivirus Signature Age</td><td>$($defender.AntivirusSignatureAge) days</td></tr>
        <tr><td>Last Quick Scan</td><td>$($defender.QuickScanAge) days ago</td></tr>
        <tr><td>Last Full Scan</td><td>$($defender.FullScanAge) days ago</td></tr>
    </table>
"@
    $htmlReport += Add-HTMLSection "Windows Defender Status" $defenderTable
} catch {
    $htmlReport += Add-HTMLSection "Windows Defender Status" "<p class='warning'>Unable to retrieve Windows Defender status</p>"
}

# 5. Installed Updates
Write-Host "Checking Windows Updates..." -ForegroundColor Cyan
$updates = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20
$updateTable = "<table><tr><th>KB Article</th><th>Description</th><th>Installed On</th></tr>"
foreach ($update in $updates) {
    $updateTable += "<tr><td>$($update.HotFixID)</td><td>$($update.Description)</td><td>$($update.InstalledOn)</td></tr>"
}
$updateTable += "</table>"
$htmlReport += Add-HTMLSection "Recent Windows Updates (Last 20)" $updateTable

# 6. Security Event Log Analysis
Write-Host "Analyzing Security Event Logs..." -ForegroundColor Cyan
$logonFailures = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count
$logonSuccess = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count

$eventTable = @"
<table>
    <tr><th>Event Type</th><th>Count (Last 7 Days)</th></tr>
    <tr><td>Successful Logons (4624)</td><td>$logonSuccess</td></tr>
    <tr><td>Failed Logons (4625)</td><td>$(if ($logonFailures -gt 100) { "<span class='warning'>$logonFailures</span>" } else { $logonFailures })</td></tr>
</table>
"@
$htmlReport += Add-HTMLSection "Security Events Summary" $eventTable

# 7. Network Configuration
Write-Host "Checking Network Configuration..." -ForegroundColor Cyan
$networkAdapters = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object Name, InterfaceDescription, MacAddress, Status
$netTable = "<table><tr><th>Name</th><th>Description</th><th>MAC Address</th><th>Status</th></tr>"
foreach ($adapter in $networkAdapters) {
    $netTable += "<tr><td>$($adapter.Name)</td><td>$($adapter.InterfaceDescription)</td><td>$($adapter.MacAddress)</td><td>$($adapter.Status)</td></tr>"
}
$netTable += "</table>"
$htmlReport += Add-HTMLSection "Active Network Adapters" $netTable

# 8. Services Running as SYSTEM or with High Privileges
Write-Host "Checking High-Privilege Services..." -ForegroundColor Cyan
$services = Get-WmiObject Win32_Service | Where-Object {$_.StartName -like "*SYSTEM*" -and $_.State -eq "Running"} | Select-Object Name, DisplayName, StartName, PathName -First 30
$servicesTable = "<table><tr><th>Name</th><th>Display Name</th><th>Run As</th></tr>"
foreach ($service in $services) {
    $servicesTable += "<tr><td>$($service.Name)</td><td>$($service.DisplayName)</td><td>$($service.StartName)</td></tr>"
}
$servicesTable += "</table>"
$htmlReport += Add-HTMLSection "Services Running as SYSTEM (Sample)" $servicesTable

# 9. SMB Security Settings
Write-Host "Checking SMB Security..." -ForegroundColor Cyan
try {
    $smbConfig = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, EncryptData, RequireSecuritySignature
    $smbTable = @"
    <table>
        <tr><th>Setting</th><th>Value</th></tr>
        <tr><td>SMB1 Protocol</td><td>$(if ($smbConfig.EnableSMB1Protocol) { "<span class='warning'>Enabled</span>" } else { "<span class='success'>Disabled</span>" })</td></tr>
        <tr><td>SMB2 Protocol</td><td>$(if ($smbConfig.EnableSMB2Protocol) { "<span class='success'>Enabled</span>" } else { "<span class='warning'>Disabled</span>" })</td></tr>
        <tr><td>Encrypt Data</td><td>$(if ($smbConfig.EncryptData) { "<span class='success'>Yes</span>" } else { "<span class='warning'>No</span>" })</td></tr>
        <tr><td>Require Security Signature</td><td>$(if ($smbConfig.RequireSecuritySignature) { "<span class='success'>Yes</span>" } else { "<span class='warning'>No</span>" })</td></tr>
    </table>
"@
    $htmlReport += Add-HTMLSection "SMB Security Configuration" $smbTable
} catch {
    $htmlReport += Add-HTMLSection "SMB Security Configuration" "<p class='warning'>Unable to retrieve SMB configuration</p>"
}

# Close HTML
$htmlReport += @"
    <hr>
    <p><em>Report generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</em></p>
</body>
</html>
"@

# Save report
$htmlReport | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "`nSecurity Audit Complete!" -ForegroundColor Green
Write-Host "Report saved to: $reportFile" -ForegroundColor Yellow

# Clean up temp file
Remove-Item "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue

# Open report (optional)
# Start-Process $reportFile
