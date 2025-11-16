# Sophos XG/XGS Firewall Scripts

Scripts for Sophos XG and XGS Firewall configuration backup and security auditing via XML API.

## Prerequisites

- PowerShell 5.1 or later (PowerShell Core 7+ recommended)
- Sophos XG/XGS Firewall with XML API enabled
- Administrator credentials
- Network connectivity to firewall on port 4444 (API port)

## Sophos Firewall API Setup

### Enable XML API Access

1. Log into Sophos Firewall web admin console
2. Navigate to **System > Administration > Device Access**
3. Under **API**, enable **API Configuration**
4. Set allowed IP addresses or allow from any (less secure)
5. Click **Apply**

### Create API Administrator (Optional)

For better security, create a dedicated API user:

1. Go to **System > Administration > Admin Users**
2. Click **Add**
3. Create user with appropriate permissions (read-only for backups recommended)
4. Note the username and password

**Security Note:** Use strong passwords and limit API access to specific IP addresses.

## Scripts

### Get-SophosFirewallConfig.ps1

Comprehensive Sophos XG/XGS Firewall configuration backup and security audit using XML API.

**Features:**
- Complete configuration backup (XML format)
- Firewall rule analysis
- Web filtering policy review
- IPS configuration audit
- VPN security assessment
- Administrator account audit
- Network interface configuration export
- Security zone analysis
- Generates HTML security report

**Usage:**
```powershell
# Basic usage
.\Get-SophosFirewallConfig.ps1 -SophosIP "192.168.1.1" -Username "admin" -Password "YourPassword"

# With FQDN and custom export path
.\Get-SophosFirewallConfig.ps1 -SophosIP "firewall.company.com" -Username "admin" -Password "pass" -ExportPath "C:\SophosBackups"

# Skip certificate validation (self-signed certs)
.\Get-SophosFirewallConfig.ps1 -SophosIP "192.168.1.1" -Username "admin" -Password "pass" -SkipCertificateCheck

# Using secure string for password
$securePass = Read-Host -AsSecureString -Prompt "Enter password"
$password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass))
.\Get-SophosFirewallConfig.ps1 -SophosIP "192.168.1.1" -Username "admin" -Password $password
```

**Security Checks Performed:**

1. **Firewall Rules**
   - Disabled rules (cleanup opportunities)
   - Rules without logging enabled
   - Overly permissive source/destination (ANY)
   - Rules allowing all services/ports

2. **Web Filtering**
   - Open/unrestricted policies
   - HTTPS scanning disabled
   - Missing content filtering

3. **IPS (Intrusion Prevention)**
   - Missing IPS policies
   - Unconfigured IPS protection

4. **VPN Security**
   - Weak encryption algorithms (DES/3DES)
   - Pre-shared key (PSK) authentication
   - Missing perfect forward secrecy

5. **Administrative Access**
   - Default admin account in use
   - Two-factor authentication disabled
   - Unrestricted access

**Output Files:**
- `system_info.xml` - System information
- `firewall_rules.xml` - Complete firewall ruleset
- `web_filter_policies.xml` - Web filtering policies
- `ips_policies.xml` - IPS configurations
- `vpn_ipsec.xml` - IPsec VPN configurations
- `admin_users.xml` - Administrator accounts
- `interfaces.xml` - Network interfaces
- `zones.xml` - Security zones
- `services.xml` - Service configurations
- `Security_Audit_Report.html` - Comprehensive security report

---

## Security Best Practices

### Password Security

```powershell
# Don't hardcode passwords in scripts
# Use secure input:
$username = Read-Host -Prompt "Enter Sophos username"
$securePass = Read-Host -AsSecureString -Prompt "Enter password"
$password = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass))

.\Get-SophosFirewallConfig.ps1 -SophosIP "192.168.1.1" -Username $username -Password $password
```

### API Access Restrictions

Best practices for Sophos API security:

1. **IP Restrictions**: Limit API access to specific management IPs
   - System > Administration > Device Access > API
   - Add only trusted IP addresses

2. **Dedicated API User**: Create read-only API user
   - Minimal permissions required
   - Separate from regular admin accounts
   - Unique strong password

3. **Certificate Validation**: Use valid SSL certificates
   - Avoid `-SkipCertificateCheck` in production
   - Install proper CA-signed certificates
   - Monitor certificate expiration

4. **Audit Logging**: Enable API access logging
   - Monitor for unauthorized access
   - Regular log review
   - Alert on suspicious activity

### Backup Security

1. **Encryption**: Encrypt backup files at rest
   ```powershell
   # Encrypt sensitive backups
   $backupPath = "C:\SophosBackups\Sophos_Backup_20240115_120000"
   Compress-Archive -Path $backupPath -DestinationPath "$backupPath.zip"
   # Use encryption tools like 7-Zip with password or BitLocker
   ```

2. **Access Control**: Restrict backup directory access
   ```powershell
   # Set restrictive permissions
   $acl = Get-Acl "C:\SophosBackups"
   $acl.SetAccessRuleProtection($true, $false)
   # Add only necessary users/groups
   Set-Acl "C:\SophosBackups" $acl
   ```

3. **Off-site Storage**: Replicate to secure location
4. **Retention**: Follow compliance requirements
5. **Testing**: Regular restoration testing

---

## Sophos Firewall Hardening Recommendations

### Firewall Policy Hardening

1. **Principle of Least Privilege**
   - Deny by default, allow only necessary traffic
   - Specific sources and destinations
   - Limited service/port ranges
   - Regular rule review and cleanup

2. **Enable Logging**
   - All firewall rules should log traffic
   - Forward logs to SIEM
   - Configure alerts for suspicious patterns

3. **Remove Unused Rules**
   - Disable rules for testing
   - Delete after 30 days if not needed
   - Document rule purpose and owner

### Web Filtering

1. **Enable HTTPS Scanning**
   - Inspect encrypted web traffic
   - Install SSL inspection certificate
   - Monitor for certificate errors

2. **Apply Appropriate Policies**
   - Different policies for different user groups
   - Block high-risk categories
   - Regular policy review

3. **SafeSearch Enforcement**
   - Enable for all search engines
   - Prevent bypassing filters

### IPS Configuration

1. **Enable IPS on All Critical Segments**
   - DMZ zones
   - LAN to WAN
   - Guest networks

2. **Keep Signatures Updated**
   - Automatic updates enabled
   - Regular update verification
   - Test after major updates

3. **Appropriate Action**
   - Drop for critical threats
   - Alert for monitoring
   - Regular tuning to reduce false positives

### VPN Security

1. **Strong Encryption**
   - AES-256 for encryption
   - SHA-256 or better for authentication
   - Enable Perfect Forward Secrecy (PFS)

2. **Certificate-Based Authentication**
   - Prefer certificates over PSK
   - Strong certificate management
   - Regular certificate rotation

3. **Split Tunneling**
   - Disable unless specifically required
   - Monitor VPN user activity
   - Implement MFA

### Administrative Security

1. **Multi-Factor Authentication**
   - Enable for all admin accounts
   - Use Sophos Authenticator or compatible app
   - Backup codes securely stored

2. **Named Accounts**
   - Disable default 'admin' account
   - Individual named accounts
   - Audit trail for changes

3. **Access Restrictions**
   - Limit admin interface access by IP
   - Use dedicated management VLAN
   - Disable unused admin protocols

4. **Regular Audits**
   - Review admin accounts monthly
   - Remove terminated users immediately
   - Check for unauthorized privilege escalation

---

## Automation Examples

### Daily Automated Backup

```powershell
# Daily-Sophos-Backup.ps1
param(
    [string]$BackupPath = "D:\SecureBackups\Sophos"
)

$sophosFirewalls = @(
    @{
        IP = "192.168.1.1"
        Name = "Primary-Firewall"
        User = "api-backup"
        Pass = (Get-Content "D:\Secure\sophos-primary.txt" | ConvertTo-SecureString)
    },
    @{
        IP = "192.168.2.1"
        Name = "Secondary-Firewall"
        User = "api-backup"
        Pass = (Get-Content "D:\Secure\sophos-secondary.txt" | ConvertTo-SecureString)
    }
)

foreach ($fw in $sophosFirewalls) {
    Write-Host "Backing up $($fw.Name)..." -ForegroundColor Cyan

    $plainPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($fw.Pass))

    $exportPath = Join-Path $BackupPath $fw.Name

    .\Get-SophosFirewallConfig.ps1 `
        -SophosIP $fw.IP `
        -Username $fw.User `
        -Password $plainPass `
        -ExportPath $exportPath `
        -SkipCertificateCheck

    Write-Host "Backup completed for $($fw.Name)" -ForegroundColor Green
}

# Cleanup old backups (keep 90 days)
Get-ChildItem $BackupPath -Recurse -Directory |
    Where-Object { $_.Name -match "Sophos_Backup_" -and $_.CreationTime -lt (Get-Date).AddDays(-90) } |
    Remove-Item -Recurse -Force

Write-Host "Backup rotation completed" -ForegroundColor Green
```

### Schedule with Task Scheduler

```powershell
# Create scheduled task for daily backups
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\Daily-Sophos-Backup.ps1"

$trigger = New-ScheduledTaskTrigger -Daily -At 2am

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" `
    -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "Sophos Daily Backup" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Description "Daily backup of Sophos Firewall configurations"
```

### Weekly Security Audit

```powershell
# Weekly-Sophos-Audit.ps1
$reportPath = "C:\SecurityReports\Sophos"
$emailTo = "security-team@company.com"
$smtpServer = "smtp.company.com"

.\Get-SophosFirewallConfig.ps1 `
    -SophosIP "192.168.1.1" `
    -Username "api-audit" `
    -Password (Get-Content "secure-pass.txt") `
    -ExportPath $reportPath

# Email report
$latestReport = Get-ChildItem $reportPath -Recurse -Filter "Security_Audit_Report.html" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1

Send-MailMessage -From "sophos-audit@company.com" `
    -To $emailTo `
    -Subject "Weekly Sophos Firewall Security Audit" `
    -Body "Please find attached the weekly security audit report." `
    -Attachments $latestReport.FullName `
    -SmtpServer $smtpServer
```

---

## Troubleshooting

### API Connection Issues

**Error: "Connection refused" or "Cannot connect"**

1. Verify API is enabled:
   - System > Administration > Device Access > API

2. Check firewall rules:
   - Allow port 4444 from management IP
   - Verify no blocking rules

3. Test connectivity:
   ```powershell
   Test-NetConnection -ComputerName 192.168.1.1 -Port 4444
   ```

**Error: "Authentication failed"**

1. Verify credentials are correct
2. Check account has API access permissions
3. Ensure account is not locked
4. Try from Sophos web interface first

### Certificate Errors

**Error: "The underlying connection was closed: Could not establish trust relationship"**

Temporary solution (testing only):
```powershell
.\Get-SophosFirewallConfig.ps1 -SophosIP "192.168.1.1" -Username "admin" -Password "pass" -SkipCertificateCheck
```

Production solution:
1. Install valid SSL certificate on Sophos
2. Or add Sophos certificate to trusted root store:
   ```powershell
   # Export cert from Sophos, then:
   Import-Certificate -FilePath "sophos-cert.cer" -CertStoreLocation Cert:\LocalMachine\Root
   ```

### XML Parsing Errors

If you encounter XML parsing errors:
1. Check Sophos firmware version (requires relatively recent version)
2. Verify API version compatibility
3. Enable detailed error output:
   ```powershell
   $ErrorActionPreference = "Continue"
   $VerbosePreference = "Continue"
   .\Get-SophosFirewallConfig.ps1 ... -Verbose
   ```

---

## Additional Resources

- [Sophos XG Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/API/index.html)
- [Sophos Firewall Best Practices](https://docs.sophos.com/nsg/sophos-firewall/help/en-us/webhelp/onlinehelp/index.html)
- [Sophos Community Forums](https://community.sophos.com/)

## Support

For issues or questions, contact your Infrastructure Security team.
