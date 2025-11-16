<#
.SYNOPSIS
    Sophos XG/XGS Firewall Configuration Backup and Security Audit

.DESCRIPTION
    Connects to Sophos XG/XGS Firewall via XML API to:
    - Backup firewall rules and configurations
    - Audit security policies
    - Review web filtering policies
    - Analyze IPS configurations
    - Export detailed security reports

.PARAMETER SophosIP
    IP address or FQDN of Sophos Firewall

.PARAMETER Username
    Admin username for Sophos Firewall

.PARAMETER Password
    Admin password for Sophos Firewall

.PARAMETER ExportPath
    Path where backups and reports will be saved (default: current directory)

.PARAMETER SkipCertificateCheck
    Skip SSL certificate validation

.EXAMPLE
    .\Get-SophosFirewallConfig.ps1 -SophosIP "192.168.1.1" -Username "admin" -Password "password"

.EXAMPLE
    .\Get-SophosFirewallConfig.ps1 -SophosIP "firewall.company.com" -Username "admin" -Password "pass" -ExportPath "C:\SophosBackups" -SkipCertificateCheck

.NOTES
    Author: Infrastructure Security Team
    Requires: Sophos XG/XGS Firewall with XML API enabled
    API Access: Enable in System > Administration > Device Access > API
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$SophosIP,

    [Parameter(Mandatory=$true)]
    [string]$Username,

    [Parameter(Mandatory=$true)]
    [string]$Password,

    [Parameter(Mandatory=$false)]
    [string]$ExportPath = ".",

    [Parameter(Mandatory=$false)]
    [switch]$SkipCertificateCheck
)

# Skip certificate validation if requested
if ($SkipCertificateCheck) {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
        $PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
    } else {
        add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    }
}

$apiUrl = "https://${SophosIP}:4444/webconsole/APIController"

Write-Host "Sophos XG/XGS Firewall Configuration Backup & Security Audit" -ForegroundColor Cyan
Write-Host "Sophos Firewall: $SophosIP" -ForegroundColor Green
Write-Host "=" * 70 -ForegroundColor Cyan

# Create export directory
if (-not (Test-Path $ExportPath)) {
    New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = Join-Path $ExportPath "Sophos_Backup_$timestamp"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

$findings = @{
    Critical = @()
    High = @()
    Medium = @()
    Low = @()
    Info = @()
}

function Add-Finding {
    param(
        [string]$Severity,
        [string]$Category,
        [string]$Finding,
        [string]$Recommendation
    )

    $findings[$Severity] += [PSCustomObject]@{
        Category = $Category
        Finding = $Finding
        Recommendation = $Recommendation
    }
}

# Function to invoke Sophos API
function Invoke-SophosAPI {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Entity,

        [Parameter(Mandatory=$false)]
        [string]$Action = "get"
    )

    $xmlRequest = @"
<Request APIVersion='1800.1'>
    <Login>
        <Username>$Username</Username>
        <Password>$Password</Password>
    </Login>
    <$Action>
        <$Entity/>
    </$Action>
</Request>
"@

    try {
        $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Body $xmlRequest -ContentType "application/xml"
        return $response
    } catch {
        Write-Host "API Error ($Entity): $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# 1. Get System Information
Write-Host "`n[1/9] Retrieving system information..." -ForegroundColor Cyan
$systemInfo = Invoke-SophosAPI -Entity "System"

if ($systemInfo) {
    $deviceName = $systemInfo.Response.System.DeviceName
    $serialNo = $systemInfo.Response.System.SerialNumber
    $firmwareVersion = $systemInfo.Response.System.FirmwareVersion

    $sysInfoText = @"
Sophos Firewall System Information
===================================
Device Name: $deviceName
Serial Number: $serialNo
Firmware Version: $firmwareVersion
"@

    Write-Host $sysInfoText -ForegroundColor Green
    $systemInfo | Export-Clixml -Path (Join-Path $backupDir "system_info.xml")
    $sysInfoText | Out-File -FilePath (Join-Path $backupDir "system_info.txt")
}

# 2. Get Firewall Rules
Write-Host "`n[2/9] Analyzing firewall rules..." -ForegroundColor Cyan
$firewallRules = Invoke-SophosAPI -Entity "FirewallRule"

if ($firewallRules -and $firewallRules.Response.FirewallRule) {
    $rules = $firewallRules.Response.FirewallRule
    $firewallRules | Export-Clixml -Path (Join-Path $backupDir "firewall_rules.xml")

    Write-Host "  Total rules: $(@($rules).Count)" -ForegroundColor Yellow

    # Analyze rules for security issues
    foreach ($rule in $rules) {
        # Check for disabled rules
        if ($rule.Status -eq "Disable") {
            Add-Finding -Severity "Low" -Category "Firewall Rule" `
                -Finding "Rule '$($rule.RuleName)' is disabled" `
                -Recommendation "Remove if no longer needed to reduce complexity"
        }

        # Check for rules without logging
        if ($rule.LogTraffic -ne "Enable") {
            Add-Finding -Severity "Medium" -Category "Firewall Rule" `
                -Finding "Rule '$($rule.RuleName)' has logging disabled" `
                -Recommendation "Enable logging for security monitoring and compliance"
        }

        # Check for ANY source/destination
        if ($rule.SourceZones -contains "ANY" -or $rule.SourceNetworks -contains "Any") {
            Add-Finding -Severity "Medium" -Category "Firewall Rule" `
                -Finding "Rule '$($rule.RuleName)' allows traffic from ANY source" `
                -Recommendation "Restrict to specific source networks"
        }

        if ($rule.DestinationZones -contains "ANY" -or $rule.DestinationNetworks -contains "Any") {
            Add-Finding -Severity "Medium" -Category "Firewall Rule" `
                -Finding "Rule '$($rule.RuleName)' allows traffic to ANY destination" `
                -Recommendation "Restrict to specific destination networks"
        }

        # Check for rules allowing all services
        if ($rule.Services -contains "Any") {
            Add-Finding -Severity "High" -Category "Firewall Rule" `
                -Finding "Rule '$($rule.RuleName)' allows ALL services/ports" `
                -Recommendation "Limit to specific required services only"
        }
    }
}

# 3. Get Web Filter Policies
Write-Host "`n[3/9] Analyzing web filter policies..." -ForegroundColor Cyan
$webPolicies = Invoke-SophosAPI -Entity "WebFilterPolicy"

if ($webPolicies) {
    $webPolicies | Export-Clixml -Path (Join-Path $backupDir "web_filter_policies.xml")

    if ($webPolicies.Response.WebFilterPolicy) {
        $policies = $webPolicies.Response.WebFilterPolicy
        Write-Host "  Web filter policies: $(@($policies).Count)" -ForegroundColor Green

        foreach ($policy in $policies) {
            # Check if policies are too permissive
            if ($policy.PolicyType -eq "Open") {
                Add-Finding -Severity "Medium" -Category "Web Filtering" `
                    -Finding "Web filter policy '$($policy.Name)' is set to Open (unrestricted)" `
                    -Recommendation "Review and apply appropriate content filtering"
            }

            # Check for HTTPS scanning
            if ($policy.HTTPSScanning -ne "Enable") {
                Add-Finding -Severity "High" -Category "Web Filtering" `
                    -Finding "Policy '$($policy.Name)' does not scan HTTPS traffic" `
                    -Recommendation "Enable HTTPS scanning to inspect encrypted traffic"
            }
        }
    }
}

# 4. Get IPS Policies
Write-Host "`n[4/9] Analyzing IPS policies..." -ForegroundColor Cyan
$ipsPolicies = Invoke-SophosAPI -Entity "IPSPolicy"

if ($ipsPolicies) {
    $ipsPolicies | Export-Clixml -Path (Join-Path $backupDir "ips_policies.xml")

    if ($ipsPolicies.Response.IPSPolicy) {
        Write-Host "  IPS policies configured" -ForegroundColor Green
    } else {
        Add-Finding -Severity "High" -Category "IPS" `
            -Finding "No IPS policies configured" `
            -Recommendation "Enable IPS protection to detect and prevent intrusions"
    }
}

# 5. Get VPN Configurations
Write-Host "`n[5/9] Analyzing VPN configurations..." -ForegroundColor Cyan
$vpnConfig = Invoke-SophosAPI -Entity "IPSecConnection"

if ($vpnConfig) {
    $vpnConfig | Export-Clixml -Path (Join-Path $backupDir "vpn_ipsec.xml")

    if ($vpnConfig.Response.IPSecConnection) {
        $vpnConnections = $vpnConfig.Response.IPSecConnection
        Write-Host "  IPsec VPN connections: $(@($vpnConnections).Count)" -ForegroundColor Yellow

        foreach ($vpn in $vpnConnections) {
            # Check for weak encryption
            if ($vpn.Encryption -match "DES|3DES") {
                Add-Finding -Severity "High" -Category "VPN Security" `
                    -Finding "VPN '$($vpn.Name)' uses weak encryption: $($vpn.Encryption)" `
                    -Recommendation "Use AES-256 encryption"
            }

            # Check authentication method
            if ($vpn.AuthenticationType -eq "PSK") {
                Add-Finding -Severity "Medium" -Category "VPN Security" `
                    -Finding "VPN '$($vpn.Name)' uses Pre-Shared Key authentication" `
                    -Recommendation "Consider using certificate-based authentication for better security"
            }
        }
    }
}

# 6. Get Admin Users
Write-Host "`n[6/9] Auditing administrator accounts..." -ForegroundColor Cyan
$adminUsers = Invoke-SophosAPI -Entity "User" -Action "Get"

if ($adminUsers) {
    $adminUsers | Export-Clixml -Path (Join-Path $backupDir "admin_users.xml")

    if ($adminUsers.Response.User) {
        $users = $adminUsers.Response.User
        $adminCount = @($users | Where-Object { $_.UserType -eq "Administrator" }).Count
        Write-Host "  Administrator accounts: $adminCount" -ForegroundColor Yellow

        foreach ($user in $users) {
            if ($user.UserType -eq "Administrator") {
                # Check for default admin account
                if ($user.Username -eq "admin") {
                    Add-Finding -Severity "Medium" -Category "Administrative Access" `
                        -Finding "Default 'admin' account is in use" `
                        -Recommendation "Create named admin accounts and disable default 'admin' account"
                }

                # Check for accounts without two-factor authentication
                if ($user.TwoFactorAuth -ne "Enable") {
                    Add-Finding -Severity "High" -Category "Administrative Access" `
                        -Finding "Administrator '$($user.Username)' does not have two-factor authentication enabled" `
                        -Recommendation "Enable two-factor authentication for all administrator accounts"
                }
            }
        }
    }
}

# 7. Get Network Interfaces
Write-Host "`n[7/9] Reviewing network interfaces..." -ForegroundColor Cyan
$interfaces = Invoke-SophosAPI -Entity "Interface"

if ($interfaces) {
    $interfaces | Export-Clixml -Path (Join-Path $backupDir "interfaces.xml")

    if ($interfaces.Response.Interface) {
        Write-Host "  Network interfaces: $(@($interfaces.Response.Interface).Count)" -ForegroundColor Green
    }
}

# 8. Get Zone Configuration
Write-Host "`n[8/9] Analyzing zone configuration..." -ForegroundColor Cyan
$zones = Invoke-SophosAPI -Entity "Zone"

if ($zones) {
    $zones | Export-Clixml -Path (Join-Path $backupDir "zones.xml")

    if ($zones.Response.Zone) {
        Write-Host "  Security zones: $(@($zones.Response.Zone).Count)" -ForegroundColor Green
    }
}

# 9. Get Services Configuration
Write-Host "`n[9/9] Exporting services configuration..." -ForegroundColor Cyan
$services = Invoke-SophosAPI -Entity "Services"

if ($services) {
    $services | Export-Clixml -Path (Join-Path $backupDir "services.xml")
    Write-Host "  Services configuration exported" -ForegroundColor Green
}

# Generate HTML Report
Write-Host "`nGenerating security audit report..." -ForegroundColor Cyan

$totalFindings = $findings.Critical.Count + $findings.High.Count +
                 $findings.Medium.Count + $findings.Low.Count

$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Sophos Firewall Security Audit - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; }
        h1 { color: #00B5E2; border-bottom: 3px solid #00B5E2; padding-bottom: 10px; }
        h2 { color: #333; margin-top: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { padding: 15px; border-radius: 5px; text-align: center; color: white; }
        .critical { background-color: #d32f2f; }
        .high { background-color: #f57c00; }
        .medium { background-color: #fbc02d; }
        .low { background-color: #388e3c; }
        .summary-card h3 { margin: 0; font-size: 32px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th { background-color: #00B5E2; color: white; padding: 10px; text-align: left; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .info-box { background-color: #e1f5fe; padding: 15px; margin: 15px 0; border-left: 4px solid #00B5E2; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Sophos XG/XGS Firewall Security Audit Report</h1>
        <div class="info-box">
            <strong>Firewall:</strong> $SophosIP<br>
            <strong>Device Name:</strong> $deviceName<br>
            <strong>Firmware:</strong> $firmwareVersion<br>
            <strong>Report Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        </div>

        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="summary-card critical">
                <h3>$($findings.Critical.Count)</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card high">
                <h3>$($findings.High.Count)</h3>
                <p>High</p>
            </div>
            <div class="summary-card medium">
                <h3>$($findings.Medium.Count)</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card low">
                <h3>$($findings.Low.Count)</h3>
                <p>Low</p>
            </div>
        </div>
"@

# Add findings by severity
foreach ($severity in @('Critical', 'High', 'Medium', 'Low')) {
    if ($findings[$severity].Count -gt 0) {
        $htmlReport += "<h2>$severity Findings</h2>"
        $htmlReport += "<table><tr><th>Category</th><th>Finding</th><th>Recommendation</th></tr>"

        foreach ($finding in $findings[$severity]) {
            $htmlReport += "<tr><td>$($finding.Category)</td><td>$($finding.Finding)</td><td>$($finding.Recommendation)</td></tr>"
        }

        $htmlReport += "</table>"
    }
}

$htmlReport += @"
        <h2>Best Practices Recommendations</h2>
        <ul>
            <li>Enable two-factor authentication for all administrator accounts</li>
            <li>Configure IPS protection on critical network segments</li>
            <li>Enable HTTPS scanning for web traffic inspection</li>
            <li>Use certificate-based VPN authentication instead of PSK</li>
            <li>Enable logging on all firewall rules</li>
            <li>Regular firmware updates and security patches</li>
            <li>Implement network segmentation using security zones</li>
            <li>Regular review and cleanup of disabled/unused rules</li>
        </ul>

        <hr>
        <p><em>Report generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</em></p>
    </div>
</body>
</html>
"@

$reportFile = Join-Path $backupDir "Security_Audit_Report.html"
$htmlReport | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "`nBackup and Audit Complete!" -ForegroundColor Green
Write-Host "=" * 70 -ForegroundColor Green
Write-Host "Backup Location: $backupDir" -ForegroundColor Yellow
Write-Host "Security Findings: $totalFindings" -ForegroundColor $(if($totalFindings -gt 0){'Red'}else{'Green'})
Write-Host "  Critical: $($findings.Critical.Count)" -ForegroundColor Red
Write-Host "  High: $($findings.High.Count)" -ForegroundColor DarkRed
Write-Host "  Medium: $($findings.Medium.Count)" -ForegroundColor Yellow
Write-Host "  Low: $($findings.Low.Count)" -ForegroundColor Green
Write-Host "`nDetailed Report: $reportFile" -ForegroundColor Cyan
