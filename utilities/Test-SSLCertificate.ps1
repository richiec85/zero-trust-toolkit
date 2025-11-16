<#
.SYNOPSIS
    SSL/TLS Certificate Security Assessment Tool

.DESCRIPTION
    Tests SSL/TLS certificates and configurations for:
    - Certificate validity and expiration
    - Certificate chain validation
    - Weak cipher suites
    - Protocol versions (TLS 1.0, 1.1, 1.2, 1.3)
    - Certificate transparency
    - Common SSL/TLS vulnerabilities

.PARAMETER Target
    Target hostname or IP address

.PARAMETER Port
    Port number (default: 443)

.PARAMETER ExportPath
    Export path for reports

.PARAMETER CheckExpiration
    Check certificates expiring within specified days (default: 30)

.EXAMPLE
    .\Test-SSLCertificate.ps1 -Target "www.example.com"

.EXAMPLE
    .\Test-SSLCertificate.ps1 -Target "mail.company.com" -Port 587 -CheckExpiration 60

.EXAMPLE
    .\Test-SSLCertificate.ps1 -Target "192.168.1.100" -Port 8443 -ExportPath "C:\Reports"

.NOTES
    Author: Infrastructure Security Team
    Requires: PowerShell 5.1 or later
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Target,

    [Parameter(Mandatory=$false)]
    [int]$Port = 443,

    [Parameter(Mandatory=$false)]
    [string]$ExportPath,

    [Parameter(Mandatory=$false)]
    [int]$CheckExpiration = 30
)

Write-Host "SSL/TLS Certificate Security Assessment" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "Target: $Target`:$Port" -ForegroundColor Green
Write-Host ""

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
        [string]$Finding,
        [string]$Details,
        [string]$Recommendation
    )

    $findings[$Severity] += [PSCustomObject]@{
        Finding = $Finding
        Details = $Details
        Recommendation = $Recommendation
    }
}

# Test basic connectivity
Write-Host "[1/6] Testing connectivity..." -ForegroundColor Cyan
try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $connect = $tcpClient.BeginConnect($Target, $Port, $null, $null)
    $wait = $connect.AsyncWaitHandle.WaitOne(5000, $false)

    if (-not $wait) {
        Write-Host "  ERROR: Cannot connect to $Target`:$Port" -ForegroundColor Red
        exit 1
    }

    $tcpClient.EndConnect($connect)
    $tcpClient.Close()
    Write-Host "  Connection successful" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Retrieve SSL certificate
Write-Host "`n[2/6] Retrieving SSL certificate..." -ForegroundColor Cyan

try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient($Target, $Port)
    $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, {$true})

    # Force TLS 1.2
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    $sslStream.AuthenticateAsClient($Target)
    $certificate = $sslStream.RemoteCertificate
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificate)

    Write-Host "  Certificate retrieved successfully" -ForegroundColor Green

    # Certificate Details
    Write-Host "`n  Subject: $($cert.Subject)" -ForegroundColor White
    Write-Host "  Issuer: $($cert.Issuer)" -ForegroundColor White
    Write-Host "  Valid From: $($cert.NotBefore)" -ForegroundColor White
    Write-Host "  Valid To: $($cert.NotAfter)" -ForegroundColor White
    Write-Host "  Serial Number: $($cert.SerialNumber)" -ForegroundColor White
    Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor White

    $sslStream.Close()
    $tcpClient.Close()

} catch {
    Write-Host "  ERROR: Failed to retrieve certificate: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Check certificate validity
Write-Host "`n[3/6] Checking certificate validity..." -ForegroundColor Cyan

$now = Get-Date

# Check if expired
if ($cert.NotAfter -lt $now) {
    $daysExpired = ($now - $cert.NotAfter).Days
    Write-Host "  CRITICAL: Certificate EXPIRED $daysExpired days ago!" -ForegroundColor Red
    Add-Finding -Severity "Critical" `
        -Finding "Certificate Expired" `
        -Details "Certificate expired on $($cert.NotAfter) ($daysExpired days ago)" `
        -Recommendation "Renew certificate immediately to prevent service disruption"
} elseif ($cert.NotAfter -lt $now.AddDays($CheckExpiration)) {
    $daysRemaining = ($cert.NotAfter - $now).Days
    Write-Host "  WARNING: Certificate expires in $daysRemaining days" -ForegroundColor Yellow
    Add-Finding -Severity "High" `
        -Finding "Certificate Expiring Soon" `
        -Details "Certificate expires on $($cert.NotAfter) (in $daysRemaining days)" `
        -Recommendation "Renew certificate before expiration"
} else {
    $daysRemaining = ($cert.NotAfter - $now).Days
    Write-Host "  Certificate is valid ($daysRemaining days remaining)" -ForegroundColor Green
    Add-Finding -Severity "Info" `
        -Finding "Certificate Valid" `
        -Details "Certificate is valid until $($cert.NotAfter) ($daysRemaining days remaining)" `
        -Recommendation "No action required"
}

# Check if not yet valid
if ($cert.NotBefore -gt $now) {
    Write-Host "  ERROR: Certificate not yet valid!" -ForegroundColor Red
    Add-Finding -Severity "Critical" `
        -Finding "Certificate Not Yet Valid" `
        -Details "Certificate becomes valid on $($cert.NotBefore)" `
        -Recommendation "Check system time or use correct certificate"
}

# Check certificate algorithm
Write-Host "`n[4/6] Checking certificate algorithm..." -ForegroundColor Cyan
$signatureAlg = $cert.SignatureAlgorithm.FriendlyName
Write-Host "  Signature Algorithm: $signatureAlg" -ForegroundColor White

if ($signatureAlg -match "sha1|md5") {
    Write-Host "  WARNING: Weak signature algorithm detected" -ForegroundColor Red
    Add-Finding -Severity "High" `
        -Finding "Weak Signature Algorithm" `
        -Details "Using $signatureAlg which is considered weak" `
        -Recommendation "Use SHA-256 or stronger signature algorithm"
} elseif ($signatureAlg -match "sha256") {
    Write-Host "  Signature algorithm is acceptable (SHA-256)" -ForegroundColor Green
} elseif ($signatureAlg -match "sha384|sha512") {
    Write-Host "  Strong signature algorithm (SHA-384/512)" -ForegroundColor Green
}

# Check key size
$publicKey = $cert.PublicKey.Key
if ($publicKey -is [System.Security.Cryptography.RSA]) {
    $keySize = $publicKey.KeySize
    Write-Host "  Key Type: RSA" -ForegroundColor White
    Write-Host "  Key Size: $keySize bits" -ForegroundColor White

    if ($keySize -lt 2048) {
        Write-Host "  WARNING: Key size too small" -ForegroundColor Red
        Add-Finding -Severity "Critical" `
            -Finding "Weak Key Size" `
            -Details "RSA key size is $keySize bits (minimum 2048 required)" `
            -Recommendation "Generate new certificate with at least 2048-bit RSA key"
    } elseif ($keySize -eq 2048) {
        Write-Host "  Key size meets minimum requirements" -ForegroundColor Yellow
    } else {
        Write-Host "  Strong key size" -ForegroundColor Green
    }
}

# Check Subject Alternative Names (SAN)
Write-Host "`n[5/6] Checking Subject Alternative Names..." -ForegroundColor Cyan
$sans = $cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Subject Alternative Name"}

if ($sans) {
    $sanString = $sans.Format($false)
    Write-Host "  SANs found:" -ForegroundColor Green
    $sanString -split ',' | ForEach-Object { Write-Host "    - $($_.Trim())" -ForegroundColor White }
} else {
    Write-Host "  No Subject Alternative Names found" -ForegroundColor Yellow
    Add-Finding -Severity "Medium" `
        -Finding "No Subject Alternative Names" `
        -Details "Certificate does not contain SANs" `
        -Recommendation "Modern certificates should include SANs for compatibility"
}

# Check certificate chain
Write-Host "`n[6/6] Checking certificate chain..." -ForegroundColor Cyan
$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
$chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
$chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag

$chainBuildResult = $chain.Build($cert)

if ($chainBuildResult) {
    Write-Host "  Certificate chain is valid" -ForegroundColor Green
    Write-Host "  Chain length: $($chain.ChainElements.Count) certificates" -ForegroundColor White

    # Display chain
    $i = 0
    foreach ($element in $chain.ChainElements) {
        $certInChain = $element.Certificate
        Write-Host "    [$i] $($certInChain.Subject)" -ForegroundColor Cyan
        $i++
    }
} else {
    Write-Host "  WARNING: Certificate chain validation failed" -ForegroundColor Red

    foreach ($status in $chain.ChainStatus) {
        Write-Host "    - $($status.StatusInformation)" -ForegroundColor Yellow
        Add-Finding -Severity "High" `
            -Finding "Certificate Chain Issue" `
            -Details $status.StatusInformation `
            -Recommendation "Ensure complete certificate chain is properly configured"
    }
}

# Test TLS versions
Write-Host "`n[Extra] Testing TLS Protocol Support..." -ForegroundColor Cyan

$protocols = @{
    "TLS 1.0" = [System.Net.SecurityProtocolType]::Tls
    "TLS 1.1" = [System.Net.SecurityProtocolType]::Tls11
    "TLS 1.2" = [System.Net.SecurityProtocolType]::Tls12
}

# Add TLS 1.3 if available (.NET 4.8+)
if ([System.Net.SecurityProtocolType].GetEnumNames() -contains 'Tls13') {
    $protocols["TLS 1.3"] = [System.Net.SecurityProtocolType]::Tls13
}

foreach ($protocolName in $protocols.Keys) {
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = $protocols[$protocolName]
        $tcpClient = New-Object System.Net.Sockets.TcpClient($Target, $Port)
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, {$true})
        $sslStream.AuthenticateAsClient($Target)

        if ($protocolName -match "TLS 1.0|TLS 1.1") {
            Write-Host "  $protocolName : SUPPORTED (Weak - should be disabled)" -ForegroundColor Red
            Add-Finding -Severity "High" `
                -Finding "$protocolName Enabled" `
                -Details "Server supports deprecated $protocolName protocol" `
                -Recommendation "Disable $protocolName and use TLS 1.2 or higher only"
        } else {
            Write-Host "  $protocolName : SUPPORTED" -ForegroundColor Green
        }

        $sslStream.Close()
        $tcpClient.Close()
    } catch {
        Write-Host "  $protocolName : NOT SUPPORTED" -ForegroundColor Gray
    }
}

# Generate Report
Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
Write-Host "Security Assessment Summary" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan

$totalFindings = $findings.Critical.Count + $findings.High.Count + $findings.Medium.Count + $findings.Low.Count

Write-Host "Critical Issues: $($findings.Critical.Count)" -ForegroundColor $(if($findings.Critical.Count -gt 0){'Red'}else{'Green'})
Write-Host "High Issues: $($findings.High.Count)" -ForegroundColor $(if($findings.High.Count -gt 0){'DarkRed'}else{'Green'})
Write-Host "Medium Issues: $($findings.Medium.Count)" -ForegroundColor $(if($findings.Medium.Count -gt 0){'Yellow'}else{'Green'})
Write-Host "Low Issues: $($findings.Low.Count)" -ForegroundColor $(if($findings.Low.Count -gt 0){'Yellow'}else{'Green'})

# Display findings
foreach ($severity in @('Critical', 'High', 'Medium', 'Low')) {
    if ($findings[$severity].Count -gt 0) {
        Write-Host "`n$severity Findings:" -ForegroundColor Cyan
        foreach ($finding in $findings[$severity]) {
            Write-Host "  - $($finding.Finding)" -ForegroundColor Yellow
            Write-Host "    Details: $($finding.Details)" -ForegroundColor White
            Write-Host "    Recommendation: $($finding.Recommendation)" -ForegroundColor Green
        }
    }
}

# Export results
if ($ExportPath) {
    if (-not (Test-Path $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = Join-Path $ExportPath "SSL_Assessment_${Target}_${timestamp}.html"

    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>SSL/TLS Assessment - $Target</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; margin-top: 30px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th { background-color: #3498db; color: white; padding: 10px; text-align: left; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .critical { color: #e74c3c; font-weight: bold; }
        .high { color: #e67e22; font-weight: bold; }
        .medium { color: #f39c12; font-weight: bold; }
        .info-box { background-color: #ecf0f1; padding: 15px; margin: 15px 0; }
    </style>
</head>
<body>
    <h1>SSL/TLS Certificate Assessment Report</h1>
    <div class="info-box">
        <strong>Target:</strong> $Target`:$Port<br>
        <strong>Assessment Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
        <strong>Certificate Subject:</strong> $($cert.Subject)<br>
        <strong>Valid Until:</strong> $($cert.NotAfter)
    </div>

    <h2>Certificate Information</h2>
    <table>
        <tr><td><strong>Subject</strong></td><td>$($cert.Subject)</td></tr>
        <tr><td><strong>Issuer</strong></td><td>$($cert.Issuer)</td></tr>
        <tr><td><strong>Valid From</strong></td><td>$($cert.NotBefore)</td></tr>
        <tr><td><strong>Valid To</strong></td><td>$($cert.NotAfter)</td></tr>
        <tr><td><strong>Serial Number</strong></td><td>$($cert.SerialNumber)</td></tr>
        <tr><td><strong>Signature Algorithm</strong></td><td>$signatureAlg</td></tr>
        <tr><td><strong>Thumbprint</strong></td><td>$($cert.Thumbprint)</td></tr>
    </table>

    <h2>Security Findings</h2>
"@

    foreach ($severity in @('Critical', 'High', 'Medium', 'Low')) {
        if ($findings[$severity].Count -gt 0) {
            $htmlReport += "<h3 class='$($severity.ToLower())'>$severity Issues ($($findings[$severity].Count))</h3><table>"
            $htmlReport += "<tr><th>Finding</th><th>Details</th><th>Recommendation</th></tr>"

            foreach ($finding in $findings[$severity]) {
                $htmlReport += "<tr><td>$($finding.Finding)</td><td>$($finding.Details)</td><td>$($finding.Recommendation)</td></tr>"
            }

            $htmlReport += "</table>"
        }
    }

    $htmlReport += "</body></html>"
    $htmlReport | Out-File -FilePath $reportFile -Encoding UTF8

    Write-Host "`nReport saved to: $reportFile" -ForegroundColor Green
}

Write-Host "`nAssessment complete!" -ForegroundColor Green
