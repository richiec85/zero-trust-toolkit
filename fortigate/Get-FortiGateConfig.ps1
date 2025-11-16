<#
.SYNOPSIS
    FortiGate Configuration Backup and Security Audit

.DESCRIPTION
    Connects to FortiGate firewall via REST API to:
    - Backup configuration
    - Audit security policies
    - Review firewall rules
    - Analyze NAT configurations
    - Check administrative access
    - Export detailed reports

.PARAMETER FortiGateIP
    IP address or FQDN of FortiGate firewall

.PARAMETER ApiKey
    FortiGate API key (generate in System > Administrators)

.PARAMETER ExportPath
    Path where backups and reports will be saved (default: current directory)

.PARAMETER SkipCertificateCheck
    Skip SSL certificate validation (use for self-signed certs)

.EXAMPLE
    .\Get-FortiGateConfig.ps1 -FortiGateIP "192.168.1.99" -ApiKey "your-api-key"

.EXAMPLE
    .\Get-FortiGateConfig.ps1 -FortiGateIP "firewall.company.com" -ApiKey "your-api-key" -ExportPath "C:\FortiGateBackups" -SkipCertificateCheck

.NOTES
    Author: Infrastructure Security Team
    Requires: FortiGate API access (REST API enabled)
    API Key: Create in FortiGate GUI > System > Administrators > Create New > REST API Admin
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$FortiGateIP,

    [Parameter(Mandatory=$true)]
    [string]$ApiKey,

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
        # PowerShell 5.1 workaround
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

$baseUri = "https://$FortiGateIP/api/v2"
$headers = @{
    "Authorization" = "Bearer $ApiKey"
}

Write-Host "FortiGate Configuration Backup & Security Audit" -ForegroundColor Cyan
Write-Host "FortiGate: $FortiGateIP" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Cyan

# Create export directory
if (-not (Test-Path $ExportPath)) {
    New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = Join-Path $ExportPath "FortiGate_Backup_$timestamp"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# Function to make FortiGate API calls
function Invoke-FortiGateAPI {
    param(
        [string]$Endpoint,
        [string]$Method = "GET"
    )

    try {
        $uri = "$baseUri/$Endpoint"
        $response = Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers
        return $response
    } catch {
        Write-Host "API Error: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

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

# 1. Get System Information
Write-Host "`n[1/8] Retrieving system information..." -ForegroundColor Cyan
$systemInfo = Invoke-FortiGateAPI -Endpoint "monitor/system/status"

if ($systemInfo) {
    $systemData = @"
FortiGate System Information
============================
Hostname: $($systemInfo.results.hostname)
Version: $($systemInfo.results.version)
Serial: $($systemInfo.results.serial)
Model: $($systemInfo.results.platform_type)
"@
    Write-Host $systemData -ForegroundColor Green
    $systemData | Out-File -FilePath (Join-Path $backupDir "system_info.txt")
}

# 2. Get Firewall Policies
Write-Host "`n[2/8] Analyzing firewall policies..." -ForegroundColor Cyan
$policies = Invoke-FortiGateAPI -Endpoint "cmdb/firewall/policy"

if ($policies -and $policies.results) {
    $policies.results | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $backupDir "firewall_policies.json")

    Write-Host "  Total policies: $($policies.results.Count)" -ForegroundColor Yellow

    # Analyze policies for security issues
    foreach ($policy in $policies.results) {
        # Check for "any" source/destination
        if ($policy.srcaddr.name -contains "all") {
            Add-Finding -Severity "Medium" -Category "Firewall Policy" `
                -Finding "Policy '$($policy.name)' (ID: $($policy.policyid)) allows traffic from ANY source" `
                -Recommendation "Restrict source to specific address objects"
        }

        if ($policy.dstaddr.name -contains "all") {
            Add-Finding -Severity "Medium" -Category "Firewall Policy" `
                -Finding "Policy '$($policy.name)' (ID: $($policy.policyid)) allows traffic to ANY destination" `
                -Recommendation "Restrict destination to specific address objects"
        }

        # Check for "any" service
        if ($policy.service.name -contains "ALL") {
            Add-Finding -Severity "High" -Category "Firewall Policy" `
                -Finding "Policy '$($policy.name)' (ID: $($policy.policyid)) allows ALL services" `
                -Recommendation "Limit to specific required services only"
        }

        # Check for disabled policies (potential unused rules)
        if ($policy.status -eq "disable") {
            Add-Finding -Severity "Low" -Category "Firewall Policy" `
                -Finding "Policy '$($policy.name)' (ID: $($policy.policyid)) is disabled" `
                -Recommendation "Remove if no longer needed"
        }

        # Check for policies without logging
        if ($policy.logtraffic -eq "disable") {
            Add-Finding -Severity "Medium" -Category "Firewall Policy" `
                -Finding "Policy '$($policy.name)' (ID: $($policy.policyid)) has logging disabled" `
                -Recommendation "Enable logging for security monitoring"
        }

        # Check for policies without UTM profiles
        if ($policy.action -eq "accept" -and
            -not $policy.av-profile -and
            -not $policy.webfilter-profile -and
            -not $policy.ips-sensor) {
            Add-Finding -Severity "High" -Category "Firewall Policy" `
                -Finding "Policy '$($policy.name)' (ID: $($policy.policyid)) allows traffic without UTM inspection" `
                -Recommendation "Apply AV, Web Filter, and IPS profiles"
        }
    }
}

# 3. Get Address Objects
Write-Host "`n[3/8] Exporting address objects..." -ForegroundColor Cyan
$addresses = Invoke-FortiGateAPI -Endpoint "cmdb/firewall/address"
if ($addresses -and $addresses.results) {
    $addresses.results | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $backupDir "address_objects.json")
    Write-Host "  Exported: $($addresses.results.Count) address objects" -ForegroundColor Green
}

# 4. Get Service Objects
Write-Host "`n[4/8] Exporting service objects..." -ForegroundColor Cyan
$services = Invoke-FortiGateAPI -Endpoint "cmdb/firewall.service/custom"
if ($services -and $services.results) {
    $services.results | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $backupDir "service_objects.json")
    Write-Host "  Exported: $($services.results.Count) service objects" -ForegroundColor Green
}

# 5. Get NAT Policies
Write-Host "`n[5/8] Analyzing NAT policies..." -ForegroundColor Cyan
$natPolicies = Invoke-FortiGateAPI -Endpoint "cmdb/firewall/policy"
if ($natPolicies -and $natPolicies.results) {
    $natEnabled = $natPolicies.results | Where-Object { $_.nat -eq "enable" }
    $natEnabled | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $backupDir "nat_policies.json")
    Write-Host "  NAT-enabled policies: $($natEnabled.Count)" -ForegroundColor Yellow
}

# 6. Get Administrators
Write-Host "`n[6/8] Auditing administrators..." -ForegroundColor Cyan
$admins = Invoke-FortiGateAPI -Endpoint "cmdb/system/admin"
if ($admins -and $admins.results) {
    $admins.results | Select-Object name, trusthost*, accprofile, vdom | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $backupDir "administrators.json")

    foreach ($admin in $admins.results) {
        # Check for unrestricted admin access
        if ($admin.trusthost1 -eq "0.0.0.0/0" -or -not $admin.trusthost1) {
            Add-Finding -Severity "High" -Category "Administrative Access" `
                -Finding "Administrator '$($admin.name)' has no trusted host restrictions" `
                -Recommendation "Configure trusted host IP restrictions"
        }

        # Check for accounts with super_admin profile
        if ($admin.accprofile -eq "super_admin") {
            Add-Finding -Severity "Info" -Category "Administrative Access" `
                -Finding "Account '$($admin.name)' has super_admin privileges" `
                -Recommendation "Review if full admin access is required"
        }
    }

    Write-Host "  Total administrators: $($admins.results.Count)" -ForegroundColor Yellow
}

# 7. Get Interfaces
Write-Host "`n[7/8] Exporting interface configuration..." -ForegroundColor Cyan
$interfaces = Invoke-FortiGateAPI -Endpoint "cmdb/system/interface"
if ($interfaces -and $interfaces.results) {
    $interfaces.results | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $backupDir "interfaces.json")

    foreach ($interface in $interfaces.results) {
        # Check for interfaces without management restrictions
        if ($interface.allowaccess -contains "http") {
            Add-Finding -Severity "High" -Category "Interface Security" `
                -Finding "Interface '$($interface.name)' allows HTTP management access" `
                -Recommendation "Use HTTPS only for management"
        }

        if ($interface.allowaccess -contains "telnet") {
            Add-Finding -Severity "Critical" -Category "Interface Security" `
                -Finding "Interface '$($interface.name)' allows Telnet access" `
                -Recommendation "Disable Telnet, use SSH only"
        }
    }

    Write-Host "  Total interfaces: $($interfaces.results.Count)" -ForegroundColor Green
}

# 8. Get VPN Configuration
Write-Host "`n[8/8] Exporting VPN configuration..." -ForegroundColor Cyan
$vpnIpsec = Invoke-FortiGateAPI -Endpoint "cmdb/vpn.ipsec/phase1-interface"
if ($vpnIpsec -and $vpnIpsec.results) {
    $vpnIpsec.results | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $backupDir "vpn_ipsec.json")
    Write-Host "  IPsec VPN tunnels: $($vpnIpsec.results.Count)" -ForegroundColor Green

    foreach ($vpn in $vpnIpsec.results) {
        # Check for weak encryption
        if ($vpn.proposal -match "des|3des") {
            Add-Finding -Severity "High" -Category "VPN Security" `
                -Finding "VPN '$($vpn.name)' uses weak encryption (DES/3DES)" `
                -Recommendation "Use AES encryption"
        }
    }
}

# Generate HTML Report
Write-Host "`nGenerating security audit report..." -ForegroundColor Cyan

$totalFindings = $findings.Critical.Count + $findings.High.Count + $findings.Medium.Count + $findings.Low.Count

$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>FortiGate Security Audit - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; }
        h1 { color: #d13438; border-bottom: 3px solid #d13438; padding-bottom: 10px; }
        h2 { color: #333; margin-top: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { padding: 15px; border-radius: 5px; text-align: center; color: white; }
        .critical { background-color: #d13438; }
        .high { background-color: #ff6b35; }
        .medium { background-color: #f7931e; }
        .low { background-color: #5cb85c; }
        .summary-card h3 { margin: 0; font-size: 32px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th { background-color: #d13438; color: white; padding: 10px; text-align: left; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .info-box { background-color: #e7f3ff; padding: 15px; margin: 15px 0; border-left: 4px solid #0078d4; }
    </style>
</head>
<body>
    <div class="container">
        <h1>FortiGate Security Audit Report</h1>
        <div class="info-box">
            <strong>FortiGate:</strong> $FortiGateIP<br>
            <strong>Hostname:</strong> $($systemInfo.results.hostname)<br>
            <strong>Version:</strong> $($systemInfo.results.version)<br>
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
        <hr>
        <p><em>Report generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</em></p>
    </div>
</body>
</html>
"@

$reportFile = Join-Path $backupDir "Security_Audit_Report.html"
$htmlReport | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "`nBackup and Audit Complete!" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Green
Write-Host "Backup Location: $backupDir" -ForegroundColor Yellow
Write-Host "Security Findings: $totalFindings" -ForegroundColor $(if($totalFindings -gt 0){'Red'}else{'Green'})
Write-Host "  Critical: $($findings.Critical.Count)" -ForegroundColor Red
Write-Host "  High: $($findings.High.Count)" -ForegroundColor DarkRed
Write-Host "  Medium: $($findings.Medium.Count)" -ForegroundColor Yellow
Write-Host "  Low: $($findings.Low.Count)" -ForegroundColor Green
Write-Host "`nDetailed Report: $reportFile" -ForegroundColor Cyan
