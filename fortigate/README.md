# FortiGate Firewall Scripts

Scripts for FortiGate firewall configuration backup, security auditing, and management.

## Prerequisites

### For PowerShell Scripts (Get-FortiGateConfig.ps1)
- PowerShell 5.1 or later (PowerShell Core 7+ recommended)
- FortiGate REST API enabled
- API key generated in FortiGate

### For Bash Scripts (FortiGate-Backup.sh)
- SSH access to FortiGate
- sshpass (optional, for password automation)
- bash shell (Linux/macOS/WSL)

## FortiGate API Setup

### Enable REST API
1. Log into FortiGate GUI
2. Navigate to **System > Feature Visibility**
3. Enable **REST API**

### Create API Administrator
1. Navigate to **System > Administrators**
2. Click **Create New > REST API Admin**
3. Set username and trusted hosts
4. Generate and copy API key
5. Set appropriate admin profile (read-only for backups)

**Important:** Store API keys securely!

## Scripts

### Get-FortiGateConfig.ps1
PowerShell script for comprehensive FortiGate configuration backup and security audit via REST API.

**Features:**
- Complete configuration backup (JSON format)
- Firewall policy analysis
- Security posture assessment
- Administrative access audit
- VPN configuration export
- Interface security review
- NAT policy analysis
- Generates HTML security report

**Usage:**
```powershell
# Basic usage
.\Get-FortiGateConfig.ps1 -FortiGateIP "192.168.1.99" -ApiKey "your-api-key-here"

# With custom export path
.\Get-FortiGateConfig.ps1 -FortiGateIP "firewall.company.com" -ApiKey "api-key" -ExportPath "C:\FortiGateBackups"

# Skip certificate validation (self-signed certs)
.\Get-FortiGateConfig.ps1 -FortiGateIP "192.168.1.99" -ApiKey "api-key" -SkipCertificateCheck
```

**Security Checks:**
- Overly permissive firewall rules (ANY source/destination)
- Policies allowing all services
- Disabled logging on policies
- Missing UTM profiles (AV, IPS, Web Filter)
- Unrestricted administrative access
- Weak VPN encryption
- Insecure management protocols (HTTP, Telnet)
- Disabled policies (cleanup opportunities)

**Output:**
- Configuration JSON files (policies, addresses, services, VPN, etc.)
- System information
- HTML security audit report with severity-based findings
- Backup organized by timestamp

---

### FortiGate-Backup.sh
Bash script for CLI-based FortiGate configuration backup via SSH.

**Features:**
- Full configuration backup via SSH
- System information collection
- Policy statistics gathering
- Automatic compression (tar.gz)
- Old backup cleanup (30-day retention)
- Multi-FortiGate support
- Automated backup report generation

**Usage:**
```bash
# Basic usage (manual password entry)
./FortiGate-Backup.sh 192.168.1.99 admin

# With custom backup directory
./FortiGate-Backup.sh 192.168.1.99 admin /backups/fortigate

# Using SSH keys (no password prompt)
./FortiGate-Backup.sh firewall.company.com admin /secure/backups
```

**Installation (Ubuntu/Debian):**
```bash
# Install sshpass for password automation (optional)
sudo apt-get install sshpass

# Make script executable
chmod +x FortiGate-Backup.sh
```

**Automated Scheduling (Cron):**
```bash
# Edit crontab
crontab -e

# Add daily backup at 2 AM
0 2 * * * /path/to/FortiGate-Backup.sh 192.168.1.99 admin /backups/fortigate >> /var/log/fortigate-backup.log 2>&1
```

**Output:**
- Compressed configuration file (.tar.gz)
- System information
- Policy statistics
- Backup report
- Organized by hostname and timestamp
- Automatic cleanup of backups older than 30 days

---

## Security Best Practices

### API Key Security
```powershell
# Store API key securely, don't hardcode
$apiKey = Read-Host -Prompt "Enter FortiGate API Key" -AsSecureString
$apiKeyPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($apiKey))

# Or use encrypted credential files
$apiKey = Get-Content "encrypted_key.txt" | ConvertTo-SecureString
```

### SSH Key Authentication
```bash
# Generate SSH key pair
ssh-keygen -t rsa -b 4096 -f ~/.ssh/fortigate_backup_key

# Copy public key to FortiGate
# In FortiGate CLI:
config system admin
    edit "backup-user"
        set ssh-public-key1 "ssh-rsa AAAAB3NzaC1yc2EA..."
    next
end
```

### Backup Storage Security
1. **Encryption**: Encrypt backup files at rest
2. **Access Control**: Restrict access to backup directories
3. **Off-site**: Replicate backups to secure off-site location
4. **Retention**: Follow compliance requirements for retention
5. **Testing**: Regularly test backup restoration

### FortiGate Hardening Recommendations
Based on audit findings:

1. **Firewall Policies**
   - Avoid "ANY" source/destination/service
   - Enable logging on all policies
   - Apply UTM profiles (AV, IPS, Web Filter)
   - Remove disabled/unused policies
   - Review policies quarterly

2. **Administrative Access**
   - Use HTTPS only (disable HTTP)
   - Disable Telnet (use SSH)
   - Configure trusted host restrictions
   - Implement MFA for administrators
   - Use least-privilege access profiles

3. **VPN Security**
   - Use AES encryption (disable DES/3DES)
   - Implement strong authentication
   - Enable perfect forward secrecy (PFS)
   - Regular certificate rotation

4. **Logging & Monitoring**
   - Enable logging on all policies
   - Forward logs to SIEM
   - Configure alerts for critical events
   - Regular log review

## Backup Workflow Example

### Daily Automated Backups
```bash
#!/bin/bash
# Daily backup script for multiple FortiGates

FORTIGATES=(
    "192.168.1.99:admin"
    "192.168.2.99:admin"
    "firewall-dmz.company.com:admin"
)

BACKUP_BASE="/secure/backups/fortigate"

for fg in "${FORTIGATES[@]}"; do
    IP=$(echo $fg | cut -d: -f1)
    USER=$(echo $fg | cut -d: -f2)

    echo "Backing up $IP..."
    /path/to/FortiGate-Backup.sh "$IP" "$USER" "$BACKUP_BASE"
done

# Sync to off-site location
rsync -avz "$BACKUP_BASE/" backup-server:/offsite/fortigate/
```

### Weekly Security Audit
```powershell
# Weekly security audit script
$fortiGates = @(
    @{IP="192.168.1.99"; Key="key1"},
    @{IP="192.168.2.99"; Key="key2"}
)

$reportPath = "C:\SecurityReports\FortiGate"

foreach ($fg in $fortiGates) {
    Write-Host "Auditing $($fg.IP)..."
    .\Get-FortiGateConfig.ps1 -FortiGateIP $fg.IP -ApiKey $fg.Key -ExportPath $reportPath -SkipCertificateCheck
}

# Email reports to security team
# (Add email logic here)
```

## Troubleshooting

### API Connection Issues
```powershell
# Test API connectivity
$uri = "https://192.168.1.99/api/v2/monitor/system/status"
$headers = @{"Authorization" = "Bearer your-api-key"}
Invoke-RestMethod -Uri $uri -Headers $headers -SkipCertificateCheck
```

### SSH Connection Issues
```bash
# Test SSH connectivity
ssh -v admin@192.168.1.99

# Check SSH service on FortiGate
# In FortiGate GUI: System > Admin Settings > Enable SSH
```

### Certificate Errors
For self-signed certificates, use `-SkipCertificateCheck` parameter in PowerShell scripts.

For production environments, consider:
- Installing FortiGate certificate in trusted store
- Using FortiManager for centralized management
- Implementing proper PKI with valid certificates

## Additional Resources

- [FortiGate REST API Documentation](https://docs.fortinet.com/document/fortigate/latest/rest-api)
- [FortiGate CLI Reference](https://docs.fortinet.com/document/fortigate/latest/cli-reference)
- [FortiGate Security Best Practices](https://docs.fortinet.com/document/fortigate/latest/best-practices)

## Support

For issues or questions, contact your Infrastructure Security team.
