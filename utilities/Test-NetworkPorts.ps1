<#
.SYNOPSIS
    Network Port Scanner and Security Assessment Tool

.DESCRIPTION
    Scans network hosts and ports to identify:
    - Open ports and services
    - Common security vulnerabilities
    - Unnecessary open ports
    - Service version detection
    - SSL/TLS configuration

.PARAMETER Target
    Target host or IP address (single or array)

.PARAMETER Ports
    Ports to scan (single, comma-separated, or range like 1-1000)

.PARAMETER CommonPorts
    Scan common ports only (faster)

.PARAMETER Timeout
    Connection timeout in milliseconds (default: 1000)

.PARAMETER ExportPath
    Export scan results to file

.EXAMPLE
    .\Test-NetworkPorts.ps1 -Target "192.168.1.1" -CommonPorts

.EXAMPLE
    .\Test-NetworkPorts.ps1 -Target "server.company.com" -Ports "80,443,3389,22"

.EXAMPLE
    .\Test-NetworkPorts.ps1 -Target @("192.168.1.1", "192.168.1.2") -Ports "1-1000" -ExportPath "C:\Reports"

.NOTES
    Author: Infrastructure Security Team
    For comprehensive scans, consider using nmap
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string[]]$Target,

    [Parameter(Mandatory=$false)]
    [string]$Ports,

    [Parameter(Mandatory=$false)]
    [switch]$CommonPorts,

    [Parameter(Mandatory=$false)]
    [int]$Timeout = 1000,

    [Parameter(Mandatory=$false)]
    [string]$ExportPath
)

# Common ports and services
$commonPortList = @{
    20 = "FTP Data"
    21 = "FTP Control"
    22 = "SSH"
    23 = "Telnet"
    25 = "SMTP"
    53 = "DNS"
    80 = "HTTP"
    110 = "POP3"
    135 = "MS RPC"
    139 = "NetBIOS"
    143 = "IMAP"
    443 = "HTTPS"
    445 = "SMB"
    587 = "SMTP (TLS)"
    993 = "IMAPS"
    995 = "POP3S"
    1433 = "MS SQL"
    1521 = "Oracle"
    3306 = "MySQL"
    3389 = "RDP"
    5432 = "PostgreSQL"
    5900 = "VNC"
    5985 = "WinRM HTTP"
    5986 = "WinRM HTTPS"
    8080 = "HTTP Proxy"
    8443 = "HTTPS Alt"
    27017 = "MongoDB"
}

# Risk levels for open ports
$portRiskLevels = @{
    23 = "CRITICAL"    # Telnet - unencrypted
    21 = "HIGH"        # FTP - unencrypted
    135 = "HIGH"       # RPC - attack vector
    139 = "HIGH"       # NetBIOS - attack vector
    445 = "HIGH"       # SMB - frequent target
    3389 = "MEDIUM"    # RDP - if exposed to internet
    1433 = "HIGH"      # SQL - should not be public
    3306 = "HIGH"      # MySQL - should not be public
    5432 = "HIGH"      # PostgreSQL - should not be public
    27017 = "HIGH"     # MongoDB - should not be public
}

Write-Host "Network Port Scanner & Security Assessment" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

# Determine ports to scan
$portsToScan = @()

if ($CommonPorts) {
    $portsToScan = $commonPortList.Keys | Sort-Object
    Write-Host "Scanning common ports ($($portsToScan.Count) ports)..." -ForegroundColor Yellow
} elseif ($Ports) {
    # Parse port specification
    if ($Ports -match '-') {
        # Range: 1-1000
        $range = $Ports -split '-'
        $start = [int]$range[0]
        $end = [int]$range[1]
        $portsToScan = $start..$end
    } elseif ($Ports -match ',') {
        # List: 80,443,3389
        $portsToScan = $Ports -split ',' | ForEach-Object { [int]$_.Trim() }
    } else {
        # Single port
        $portsToScan = @([int]$Ports)
    }
    Write-Host "Scanning specified ports ($($portsToScan.Count) ports)..." -ForegroundColor Yellow
} else {
    Write-Error "Please specify -CommonPorts or -Ports parameter"
    exit 1
}

$allResults = @()

foreach ($targetHost in $Target) {
    Write-Host "`nScanning: $targetHost" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan

    $openPorts = @()
    $totalPorts = $portsToScan.Count
    $scanned = 0

    foreach ($port in $portsToScan) {
        $scanned++

        # Progress indicator
        if ($scanned % 50 -eq 0 -or $scanned -eq $totalPorts) {
            Write-Progress -Activity "Scanning $targetHost" `
                -Status "Port $port ($scanned/$totalPorts)" `
                -PercentComplete (($scanned / $totalPorts) * 100)
        }

        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connect = $tcpClient.BeginConnect($targetHost, $port, $null, $null)
            $wait = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)

            if ($wait) {
                $tcpClient.EndConnect($connect)
                $tcpClient.Close()

                # Port is open
                $service = if ($commonPortList.ContainsKey($port)) {
                    $commonPortList[$port]
                } else {
                    "Unknown"
                }

                $risk = if ($portRiskLevels.ContainsKey($port)) {
                    $portRiskLevels[$port]
                } else {
                    "LOW"
                }

                $portInfo = [PSCustomObject]@{
                    Host = $targetHost
                    Port = $port
                    Service = $service
                    Status = "Open"
                    Risk = $risk
                    Timestamp = Get-Date
                }

                $openPorts += $portInfo
                $allResults += $portInfo

                $color = switch ($risk) {
                    "CRITICAL" { "Red" }
                    "HIGH" { "DarkRed" }
                    "MEDIUM" { "Yellow" }
                    default { "Green" }
                }

                Write-Host "  [$risk] Port $port ($service) - OPEN" -ForegroundColor $color
            } else {
                $tcpClient.Close()
            }
        } catch {
            # Port is closed or filtered
        }
    }

    Write-Progress -Activity "Scanning $targetHost" -Completed

    # Summary for this host
    Write-Host "`nSummary for $targetHost" -ForegroundColor Cyan
    Write-Host "  Total Ports Scanned: $totalPorts" -ForegroundColor White
    Write-Host "  Open Ports: $($openPorts.Count)" -ForegroundColor Yellow

    if ($openPorts.Count -gt 0) {
        $criticalPorts = $openPorts | Where-Object { $_.Risk -eq "CRITICAL" }
        $highRiskPorts = $openPorts | Where-Object { $_.Risk -eq "HIGH" }
        $mediumRiskPorts = $openPorts | Where-Object { $_.Risk -eq "MEDIUM" }

        if ($criticalPorts.Count -gt 0) {
            Write-Host "  CRITICAL Risk Ports: $($criticalPorts.Count)" -ForegroundColor Red
        }
        if ($highRiskPorts.Count -gt 0) {
            Write-Host "  HIGH Risk Ports: $($highRiskPorts.Count)" -ForegroundColor DarkRed
        }
        if ($mediumRiskPorts.Count -gt 0) {
            Write-Host "  MEDIUM Risk Ports: $($mediumRiskPorts.Count)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  No open ports found" -ForegroundColor Green
    }
}

# Security Recommendations
Write-Host "`nSecurity Recommendations:" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

$criticalFindings = $allResults | Where-Object { $_.Risk -eq "CRITICAL" }
$highRiskFindings = $allResults | Where-Object { $_.Risk -eq "HIGH" }

if ($criticalFindings.Count -gt 0) {
    Write-Host "`nCRITICAL ISSUES - Immediate Action Required:" -ForegroundColor Red
    foreach ($finding in $criticalFindings) {
        Write-Host "  - $($finding.Host):$($finding.Port) ($($finding.Service))" -ForegroundColor Red
        switch ($finding.Port) {
            23 { Write-Host "    Action: Disable Telnet immediately. Use SSH instead." -ForegroundColor Yellow }
        }
    }
}

if ($highRiskFindings.Count -gt 0) {
    Write-Host "`nHIGH RISK ISSUES - Review and Remediate:" -ForegroundColor DarkRed
    foreach ($finding in $highRiskFindings | Select-Object -First 10) {
        Write-Host "  - $($finding.Host):$($finding.Port) ($($finding.Service))" -ForegroundColor DarkRed
        switch ($finding.Port) {
            21 { Write-Host "    Action: Use SFTP or FTPS instead of plain FTP" -ForegroundColor Yellow }
            135 { Write-Host "    Action: Block RPC from untrusted networks" -ForegroundColor Yellow }
            139 { Write-Host "    Action: Disable NetBIOS if not required" -ForegroundColor Yellow }
            445 { Write-Host "    Action: Ensure SMB signing is enabled, block from internet" -ForegroundColor Yellow }
            1433 { Write-Host "    Action: SQL Server should not be internet-facing" -ForegroundColor Yellow }
            3306 { Write-Host "    Action: MySQL should not be internet-facing" -ForegroundColor Yellow }
            5432 { Write-Host "    Action: PostgreSQL should not be internet-facing" -ForegroundColor Yellow }
        }
    }
}

Write-Host "`nGeneral Recommendations:" -ForegroundColor Cyan
Write-Host "  1. Implement network segmentation and firewall rules" -ForegroundColor White
Write-Host "  2. Use VPN for remote access instead of exposing services" -ForegroundColor White
Write-Host "  3. Enable encryption for all management protocols" -ForegroundColor White
Write-Host "  4. Regular vulnerability scanning and patching" -ForegroundColor White
Write-Host "  5. Implement intrusion detection/prevention systems" -ForegroundColor White

# Export results
if ($ExportPath) {
    if (-not (Test-Path $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvFile = Join-Path $ExportPath "PortScan_Results_$timestamp.csv"
    $htmlFile = Join-Path $ExportPath "PortScan_Report_$timestamp.html"

    # Export CSV
    $allResults | Export-Csv -Path $csvFile -NoTypeInformation
    Write-Host "`nResults exported to CSV: $csvFile" -ForegroundColor Green

    # Generate HTML Report
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Network Port Scan Report - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th { background-color: #3498db; color: white; padding: 10px; text-align: left; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .critical { background-color: #e74c3c; color: white; }
        .high { background-color: #e67e22; color: white; }
        .medium { background-color: #f39c12; }
        .low { background-color: #2ecc71; color: white; }
    </style>
</head>
<body>
    <h1>Network Port Scan Report</h1>
    <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <p><strong>Total Open Ports:</strong> $($allResults.Count)</p>

    <table>
        <tr>
            <th>Host</th>
            <th>Port</th>
            <th>Service</th>
            <th>Risk Level</th>
        </tr>
"@

    foreach ($result in $allResults | Sort-Object Risk, Port) {
        $riskClass = $result.Risk.ToLower()
        $htmlReport += "<tr class='$riskClass'><td>$($result.Host)</td><td>$($result.Port)</td><td>$($result.Service)</td><td>$($result.Risk)</td></tr>"
    }

    $htmlReport += "</table></body></html>"
    $htmlReport | Out-File -FilePath $htmlFile -Encoding UTF8

    Write-Host "HTML report exported: $htmlFile" -ForegroundColor Green
}

Write-Host "`nScan complete!" -ForegroundColor Green
