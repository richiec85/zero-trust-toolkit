# Security Utilities

Cross-platform utility scripts for infrastructure security assessment and testing.

## Scripts

### Test-NetworkPorts.ps1
Network port scanner and security assessment tool.

**Features:**
- Port scanning with customizable ranges
- Common port identification
- Service detection
- Risk level assessment
- Security recommendations
- HTML and CSV export

**Usage:**
```powershell
# Scan common ports
.\Test-NetworkPorts.ps1 -Target "192.168.1.1" -CommonPorts

# Scan specific ports
.\Test-NetworkPorts.ps1 -Target "server.company.com" -Ports "80,443,3389,22"

# Scan port range
.\Test-NetworkPorts.ps1 -Target "192.168.1.1" -Ports "1-1000"

# Multiple targets with export
.\Test-NetworkPorts.ps1 -Target @("192.168.1.1", "192.168.1.2", "192.168.1.3") -CommonPorts -ExportPath "C:\Reports"

# Custom timeout (faster scanning)
.\Test-NetworkPorts.ps1 -Target "10.0.0.1" -Ports "1-65535" -Timeout 500
```

**Common Ports Scanned:**
- 21 (FTP)
- 22 (SSH)
- 23 (Telnet)
- 25 (SMTP)
- 80 (HTTP)
- 443 (HTTPS)
- 445 (SMB)
- 1433 (MS SQL)
- 3306 (MySQL)
- 3389 (RDP)
- 5432 (PostgreSQL)
- And more...

**Risk Levels:**
- **CRITICAL**: Severe security risk (e.g., Telnet)
- **HIGH**: Significant risk (e.g., exposed databases, SMB)
- **MEDIUM**: Moderate risk (e.g., RDP on public networks)
- **LOW**: Minimal risk

**Output:**
- Console output with color-coded risk levels
- CSV file with scan results
- HTML report with findings

---

### Test-SSLCertificate.ps1
SSL/TLS certificate security assessment tool.

**Features:**
- Certificate validity checking
- Expiration warnings
- Certificate chain validation
- Signature algorithm analysis
- Key size verification
- Subject Alternative Names (SAN) review
- TLS protocol version testing
- Weak cipher detection
- HTML report generation

**Usage:**
```powershell
# Basic certificate check
.\Test-SSLCertificate.ps1 -Target "www.example.com"

# Check mail server on non-standard port
.\Test-SSLCertificate.ps1 -Target "mail.company.com" -Port 587

# Check with custom expiration warning (60 days)
.\Test-SSLCertificate.ps1 -Target "api.company.com" -CheckExpiration 60

# Internal server with report export
.\Test-SSLCertificate.ps1 -Target "192.168.1.100" -Port 8443 -ExportPath "C:\Reports"

# Check multiple servers
$servers = @("web1.company.com", "web2.company.com", "api.company.com")
foreach ($server in $servers) {
    .\Test-SSLCertificate.ps1 -Target $server -ExportPath "C:\SSL_Reports"
}
```

**Security Checks:**
1. **Certificate Validity**
   - Expiration date
   - Valid date range
   - Days until expiration warning

2. **Signature Algorithm**
   - Weak algorithms (MD5, SHA-1)
   - Recommended: SHA-256 or higher

3. **Key Size**
   - Minimum 2048-bit RSA
   - Recommended: 2048-bit or higher

4. **Certificate Chain**
   - Chain completeness
   - Trust validation
   - Intermediate certificates

5. **Subject Alternative Names**
   - SAN presence
   - Hostname coverage

6. **TLS Protocol Support**
   - TLS 1.0 (deprecated, should be disabled)
   - TLS 1.1 (deprecated, should be disabled)
   - TLS 1.2 (current standard)
   - TLS 1.3 (recommended)

**Output:**
- Detailed console output
- Certificate information
- Security findings by severity
- HTML assessment report

---

## Use Cases

### Regular Security Scanning

```powershell
# Weekly external perimeter scan
$externalHosts = @(
    "firewall.company.com",
    "vpn.company.com",
    "mail.company.com",
    "www.company.com"
)

foreach ($host in $externalHosts) {
    Write-Host "`nScanning $host..." -ForegroundColor Cyan
    .\Test-NetworkPorts.ps1 -Target $host -CommonPorts -ExportPath "C:\WeeklyScans"
}
```

### SSL Certificate Monitoring

```powershell
# Monthly SSL certificate audit
$sslHosts = @(
    @{Host="www.company.com"; Port=443},
    @{Host="api.company.com"; Port=443},
    @{Host="mail.company.com"; Port=587},
    @{Host="vpn.company.com"; Port=443}
)

$reportPath = "C:\SSL_Audits\$(Get-Date -Format 'yyyyMM')"

foreach ($target in $sslHosts) {
    .\Test-SSLCertificate.ps1 -Target $target.Host -Port $target.Port -CheckExpiration 45 -ExportPath $reportPath
}

# Send email summary
# (Add email logic here)
```

### Pre-Deployment Security Validation

```powershell
# New server deployment checklist
param(
    [string]$ServerIP = "10.0.1.50"
)

Write-Host "Pre-Deployment Security Validation" -ForegroundColor Cyan

# 1. Port scan to ensure only required ports are open
Write-Host "`n1. Scanning for open ports..." -ForegroundColor Yellow
.\Test-NetworkPorts.ps1 -Target $ServerIP -Ports "1-10000" -ExportPath "C:\Deployments"

# 2. If HTTPS is enabled, check SSL configuration
Write-Host "`n2. Checking SSL certificate (if applicable)..." -ForegroundColor Yellow
.\Test-SSLCertificate.ps1 -Target $ServerIP -ExportPath "C:\Deployments"

Write-Host "`nValidation complete! Review reports in C:\Deployments" -ForegroundColor Green
```

### Compliance Scanning

```powershell
# PCI DSS Compliance checks
function Test-PCIDSSCompliance {
    param([string]$Target)

    Write-Host "PCI DSS Compliance Scan: $Target" -ForegroundColor Cyan

    # Check for insecure protocols
    $results = .\Test-NetworkPorts.ps1 -Target $Target -Ports "21,23,80" -CommonPorts

    # Check SSL/TLS configuration
    .\Test-SSLCertificate.ps1 -Target $Target -CheckExpiration 30

    # Review findings and generate compliance report
}

# Scan all payment processing servers
$paymentServers = @("payment1.company.com", "payment2.company.com")
foreach ($server in $paymentServers) {
    Test-PCIDSSCompliance -Target $server
}
```

---

## Best Practices

### Scanning Ethics and Authorization

**IMPORTANT:** Only scan systems you own or have explicit permission to scan.

1. **Authorization**: Get written permission before scanning
2. **Scope**: Define clear scan boundaries
3. **Timing**: Schedule scans during maintenance windows
4. **Notification**: Inform relevant teams before scanning
5. **Documentation**: Maintain scan records and findings

### Performance Considerations

```powershell
# For large scans, adjust timeout for faster results
.\Test-NetworkPorts.ps1 -Target "192.168.1.1" -Ports "1-65535" -Timeout 500

# Use -CommonPorts for quick security checks
.\Test-NetworkPorts.ps1 -Target "server.local" -CommonPorts

# Parallel scanning of multiple hosts (PowerShell 7+)
$targets = @("host1", "host2", "host3")
$targets | ForEach-Object -Parallel {
    & .\Test-NetworkPorts.ps1 -Target $_ -CommonPorts
} -ThrottleLimit 5
```

### Automated Reporting

```powershell
# Automated weekly security scan with email
$scanResults = @()

# Scan all production servers
$servers = Get-Content "production-servers.txt"

foreach ($server in $servers) {
    $result = .\Test-NetworkPorts.ps1 -Target $server -CommonPorts -ExportPath "C:\WeeklyScan"
    $scanResults += $result
}

# Generate summary email
$emailBody = @"
Weekly Security Scan Summary

Servers Scanned: $($servers.Count)
Critical Issues: $(($scanResults | Where-Object {$_.Risk -eq 'CRITICAL'}).Count)
High Risk Issues: $(($scanResults | Where-Object {$_.Risk -eq 'HIGH'}).Count)

Full reports available in C:\WeeklyScan
"@

Send-MailMessage -From "security@company.com" -To "it-team@company.com" `
    -Subject "Weekly Security Scan Results" -Body $emailBody -SmtpServer "smtp.company.com"
```

### Integration with Other Tools

```powershell
# Export to SIEM or ticketing system
$scanResults = .\Test-NetworkPorts.ps1 -Target "192.168.1.1" -CommonPorts -ExportPath "."

# Parse results and create tickets for high-risk findings
$criticalFindings = Import-Csv "PortScan_Results_*.csv" | Where-Object {$_.Risk -eq "CRITICAL"}

foreach ($finding in $criticalFindings) {
    # Create ticket in your system
    # Example: New-Ticket -Title "Critical Port Open: $($finding.Port)" -Description "..."
}
```

---

## Scheduled Automation

### Windows Task Scheduler

```powershell
# Create daily port scan task
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\Test-NetworkPorts.ps1 -Target 'gateway.company.com' -CommonPorts -ExportPath 'C:\DailyScans'"

$trigger = New-ScheduledTaskTrigger -Daily -At 3am

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "Daily Security Port Scan" `
    -Action $action -Trigger $trigger -Principal $principal
```

```powershell
# Create weekly SSL check task
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\Check-AllSSL.ps1"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am

Register-ScheduledTask -TaskName "Weekly SSL Certificate Check" `
    -Action $action -Trigger $trigger -Principal $principal
```

---

## Troubleshooting

### Port Scanning Issues

**Issue**: Slow scanning
```powershell
# Reduce timeout for faster scanning
.\Test-NetworkPorts.ps1 -Target "host" -Ports "1-1000" -Timeout 500
```

**Issue**: Connection refused errors
- Verify network connectivity: `Test-Connection -ComputerName $target`
- Check firewall rules
- Ensure target host is online

**Issue**: False positives
- Some services may respond slowly
- Increase timeout: `-Timeout 2000`
- Verify with manual testing

### SSL Certificate Issues

**Issue**: Certificate validation errors on internal servers
- Internal CAs may not be in trusted store
- Install root CA certificate
- Or verify manually

**Issue**: TLS handshake failures
- Check TLS version support
- Verify cipher suite compatibility
- Review server TLS configuration

**Issue**: "Unable to connect" errors
- Verify port is correct (443, 8443, etc.)
- Check if SSL/TLS is enabled on that port
- Test with: `Test-NetConnection -ComputerName $target -Port $port`

---

## Security Recommendations

### Based on Port Scan Results

1. **Close Unnecessary Ports**: Only open required ports
2. **Disable Deprecated Protocols**: Telnet, FTP, HTTP (use encrypted alternatives)
3. **Restrict Database Access**: Never expose databases to internet
4. **Use VPN**: For remote access instead of direct exposure
5. **Implement Firewall Rules**: Whitelist approach
6. **Regular Monitoring**: Continuous port monitoring for changes

### Based on SSL Assessment Results

1. **Disable TLS 1.0/1.1**: Use TLS 1.2 minimum, TLS 1.3 preferred
2. **Strong Ciphers Only**: Disable weak cipher suites
3. **2048-bit Keys Minimum**: 4096-bit for high-security
4. **SHA-256 or Better**: Avoid SHA-1, never use MD5
5. **Complete Certificate Chain**: Include all intermediates
6. **Certificate Monitoring**: Alert 30-45 days before expiration
7. **Automated Renewal**: Use ACME/Let's Encrypt where possible

---

## Additional Resources

### For More Comprehensive Scanning

For production security assessments, consider professional tools:
- **Nmap**: Advanced port scanning
- **OpenSSL**: Detailed SSL/TLS testing
- **SSLLabs**: Online SSL testing (ssllabs.com/ssltest)
- **Qualys**: Commercial vulnerability scanning
- **Nessus**: Professional vulnerability scanner

### References

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)

## Support

For issues or questions, contact your Infrastructure Security team.
