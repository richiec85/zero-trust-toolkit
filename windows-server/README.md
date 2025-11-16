# Windows Server Security Scripts

PowerShell scripts for Windows Server security auditing, hardening, and monitoring.

## Scripts

### Get-SecurityAudit.ps1
Performs comprehensive security audit of Windows Server infrastructure.

**Features:**
- Password policy analysis
- Local administrator enumeration
- Windows Firewall status
- Windows Defender configuration
- Installed updates review
- Security event log analysis
- Network configuration audit
- High-privilege services enumeration
- SMB security settings

**Usage:**
```powershell
# Run basic audit
.\Get-SecurityAudit.ps1

# Specify custom export path
.\Get-SecurityAudit.ps1 -ExportPath "D:\SecurityReports"
```

**Requirements:**
- Administrator privileges
- Windows Server 2012 R2 or later

**Output:**
- HTML report with detailed security findings
- Located in C:\SecurityAudits (default)

---

### Set-ServerHardening.ps1
Applies security hardening measures based on CIS benchmarks and best practices.

**Features:**
- Disables SMBv1 protocol
- Configures Windows Firewall
- Disables unnecessary services
- Configures audit policies
- Applies registry security settings
- Enables LSA protection
- Disables LLMNR
- Configures UAC
- Enables PowerShell logging
- Configures event log sizes

**Usage:**
```powershell
# Run with WhatIf (preview changes)
.\Set-ServerHardening.ps1 -WhatIf

# Apply hardening with report
.\Set-ServerHardening.ps1 -GenerateReport

# Skip specific components
.\Set-ServerHardening.ps1 -SkipServices -SkipFirewall
```

**Requirements:**
- Administrator privileges
- Windows Server 2012 R2 or later

**Important:**
- Review settings before applying to production
- Server restart required for full effect
- Test in non-production environment first

---

### Monitor-FailedLogins.ps1
Monitors and alerts on suspicious failed login attempts.

**Features:**
- Real-time failed login monitoring
- Configurable thresholds
- Email alerting
- Detailed logging
- Continuous or single-check modes
- Source IP tracking
- User account analysis

**Usage:**
```powershell
# Single check with default settings (5 attempts in 15 minutes)
.\Monitor-FailedLogins.ps1

# Custom threshold
.\Monitor-FailedLogins.ps1 -ThresholdCount 3 -TimeWindowMinutes 10

# Continuous monitoring with email alerts
.\Monitor-FailedLogins.ps1 -ThresholdCount 5 -EmailRecipient "security@company.com" -SMTPServer "smtp.company.com" -ContinuousMonitoring

# Custom log path
.\Monitor-FailedLogins.ps1 -LogPath "D:\SecurityLogs"
```

**Requirements:**
- Administrator privileges
- Access to Security Event Log

**Output:**
- Log file: C:\SecurityLogs\FailedLoginMonitor.log
- Alert files for threshold violations
- Optional email notifications

---

## Best Practices

1. **Regular Audits**: Run Get-SecurityAudit.ps1 monthly or after significant changes
2. **Hardening**: Apply Set-ServerHardening.ps1 to new server builds
3. **Monitoring**: Use Monitor-FailedLogins.ps1 in continuous mode on critical servers
4. **Testing**: Always test scripts in non-production environment first
5. **Documentation**: Maintain records of security configurations and changes

## Security Considerations

- All scripts require Administrator privileges
- Review and customize settings for your environment
- Monitor logs for anomalies after applying changes
- Maintain backups before applying hardening measures
- Coordinate changes with change management processes

## Support

For issues or questions, contact your Infrastructure Security team.
