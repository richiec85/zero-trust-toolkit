# Zero Trust Toolkit

A comprehensive collection of security scripts and tools for Infrastructure Security Architects working with Windows Server, Azure, FortiGate, Sophos Firewalls, and more.

## Overview

This repository provides production-ready PowerShell and Bash scripts for:
- **Security Auditing**: Comprehensive security assessments
- **Configuration Backup**: Automated backup solutions
- **Hardening**: Security baseline implementation
- **Monitoring**: Continuous security monitoring
- **Compliance**: Audit and compliance reporting

## Repository Structure

```
zero-trust-toolkit/
├── windows-server/      # Windows Server security scripts
├── azure/              # Azure cloud security tools
├── fortigate/          # FortiGate firewall management
├── sophos/             # Sophos XG/XGS firewall tools
├── utilities/          # Cross-platform security utilities
└── docs/               # Additional documentation
```

## Quick Start

### Prerequisites

- **PowerShell**: 5.1 or later (PowerShell Core 7+ recommended)
- **Azure PowerShell**: For Azure scripts (`Install-Module -Name Az`)
- **Administrative Access**: Most scripts require elevated privileges
- **API Access**: FortiGate and Sophos scripts require API keys/credentials

### Installation

```powershell
# Clone the repository
git clone https://github.com/yourusername/zero-trust-toolkit.git
cd zero-trust-toolkit

# For Azure scripts, install Az module
Install-Module -Name Az -AllowClobber -Scope CurrentUser

# Make bash scripts executable
chmod +x fortigate/*.sh
```

## Script Categories

### Windows Server Security

**Location**: `windows-server/`

| Script | Purpose | Key Features |
|--------|---------|--------------|
| `Get-SecurityAudit.ps1` | Comprehensive security audit | Password policies, firewall status, Windows Defender, event logs |
| `Set-ServerHardening.ps1` | Apply security hardening | CIS benchmarks, disable SMBv1, configure UAC, audit policies |
| `Monitor-FailedLogins.ps1` | Monitor failed login attempts | Real-time alerts, email notifications, threshold-based |

**Quick Example**:
```powershell
# Run security audit
.\windows-server\Get-SecurityAudit.ps1 -ExportPath "C:\Reports"

# Apply hardening (with preview)
.\windows-server\Set-ServerHardening.ps1 -WhatIf
```

[📖 Full Documentation](windows-server/README.md)

---

### Azure Cloud Security

**Location**: `azure/`

| Script | Purpose | Key Features |
|--------|---------|--------------|
| `Get-AzureSecurityPosture.ps1` | Azure security assessment | NSG analysis, storage security, VM security, Key Vault audit |
| `Manage-AzureNSGRules.ps1` | NSG rule management | Audit, export, block, remediate risky rules |
| `Get-AzureCostSecurity.ps1` | Cost & security analysis | Find unused resources, security risks, cost optimization |

**Quick Example**:
```powershell
# Connect to Azure
Connect-AzAccount

# Run security assessment
.\azure\Get-AzureSecurityPosture.ps1

# Audit NSG rules
.\azure\Manage-AzureNSGRules.ps1 -Action Audit
```

[📖 Full Documentation](azure/README.md)

---

### FortiGate Firewall

**Location**: `fortigate/`

| Script | Purpose | Key Features |
|--------|---------|--------------|
| `Get-FortiGateConfig.ps1` | Configuration backup & audit (API) | Policy analysis, VPN audit, admin access review |
| `FortiGate-Backup.sh` | CLI-based backup (SSH) | Full config backup, automated rotation, compression |

**Quick Example**:
```powershell
# API-based backup and audit
.\fortigate\Get-FortiGateConfig.ps1 -FortiGateIP "192.168.1.99" -ApiKey "your-api-key" -SkipCertificateCheck
```

```bash
# SSH-based backup
./fortigate/FortiGate-Backup.sh 192.168.1.99 admin /backups/fortigate
```

[📖 Full Documentation](fortigate/README.md)

---

### Sophos Firewall

**Location**: `sophos/`

| Script | Purpose | Key Features |
|--------|---------|--------------|
| `Get-SophosFirewallConfig.ps1` | Configuration backup & audit | Firewall rules, web filtering, IPS, VPN, admin accounts |

**Quick Example**:
```powershell
# Backup and security audit
.\sophos\Get-SophosFirewallConfig.ps1 -SophosIP "192.168.1.1" -Username "admin" -Password "yourpass" -SkipCertificateCheck
```

[📖 Full Documentation](sophos/README.md)

---

### Security Utilities

**Location**: `utilities/`

| Script | Purpose | Key Features |
|--------|---------|--------------|
| `Test-NetworkPorts.ps1` | Port scanning & assessment | Risk-based analysis, common port detection, compliance |
| `Test-SSLCertificate.ps1` | SSL/TLS security testing | Certificate validation, expiration, TLS version testing |

**Quick Example**:
```powershell
# Scan common ports
.\utilities\Test-NetworkPorts.ps1 -Target "192.168.1.1" -CommonPorts

# Check SSL certificate
.\utilities\Test-SSLCertificate.ps1 -Target "www.example.com"
```

[📖 Full Documentation](utilities/README.md)

---

## Common Use Cases

### Daily Operations

#### Morning Security Check
```powershell
# Check for failed logins overnight
.\windows-server\Monitor-FailedLogins.ps1 -TimeWindowMinutes 720

# Review Azure security posture
.\azure\Get-AzureSecurityPosture.ps1
```

#### Weekly Audits
```powershell
# Weekly server hardening check
.\windows-server\Get-SecurityAudit.ps1 -ExportPath "C:\WeeklyReports"

# Weekly NSG audit
.\azure\Manage-AzureNSGRules.ps1 -Action Audit -ExportPath "C:\NSGReports"

# Weekly firewall backup
.\fortigate\Get-FortiGateConfig.ps1 -FortiGateIP "firewall.local" -ApiKey $apiKey
```

#### Monthly Reviews
```powershell
# Monthly cost and security optimization
.\azure\Get-AzureCostSecurity.ps1 -Days 30

# Monthly certificate expiration check
.\utilities\Test-SSLCertificate.ps1 -Target "*.company.com" -CheckExpiration 60
```

### Incident Response

#### Suspected Breach Investigation
```powershell
# Check for unusual failed login patterns
.\windows-server\Monitor-FailedLogins.ps1 -ThresholdCount 3 -TimeWindowMinutes 60

# Scan for unexpected open ports
.\utilities\Test-NetworkPorts.ps1 -Target "suspect-server" -Ports "1-10000"

# Review firewall rules for unauthorized changes
.\fortigate\Get-FortiGateConfig.ps1 -FortiGateIP "firewall.local" -ApiKey $key
```

#### Post-Incident Hardening
```powershell
# Apply security hardening
.\windows-server\Set-ServerHardening.ps1 -GenerateReport

# Lock down Azure NSGs
.\azure\Manage-AzureNSGRules.ps1 -Action Block
```

### Compliance & Auditing

#### PCI DSS Compliance
```powershell
# Ensure no insecure protocols
.\utilities\Test-NetworkPorts.ps1 -Target "payment-server" -Ports "21,23,80"

# Verify TLS 1.2+
.\utilities\Test-SSLCertificate.ps1 -Target "payment-api.company.com"

# Audit firewall rules
.\fortigate\Get-FortiGateConfig.ps1 -FortiGateIP "payment-firewall" -ApiKey $key
```

#### ISO 27001 Evidence
```powershell
# Collect security audit evidence
$reportPath = "C:\ISO27001\Evidence\$(Get-Date -Format 'yyyyMM')"

.\windows-server\Get-SecurityAudit.ps1 -ExportPath $reportPath
.\azure\Get-AzureSecurityPosture.ps1 -ExportPath $reportPath
.\fortigate\Get-FortiGateConfig.ps1 -FortiGateIP "fw1" -ApiKey $key -ExportPath $reportPath
```

## Automation & Scheduling

### Windows Task Scheduler

```powershell
# Daily backup automation
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\zero-trust-toolkit\fortigate\Get-FortiGateConfig.ps1 -FortiGateIP 192.168.1.99 -ApiKey 'key'"

$trigger = New-ScheduledTaskTrigger -Daily -At 2am

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "Daily FortiGate Backup" `
    -Action $action -Trigger $trigger -Principal $principal
```

### Linux Cron

```bash
# Add to crontab
crontab -e

# Daily FortiGate backup at 2 AM
0 2 * * * /opt/zero-trust-toolkit/fortigate/FortiGate-Backup.sh 192.168.1.99 admin /backups

# Weekly security scan every Monday at 6 AM
0 6 * * 1 pwsh /opt/zero-trust-toolkit/utilities/Test-NetworkPorts.ps1 -Target gateway.local -CommonPorts
```

## Best Practices

### Security

1. **Credential Management**
   - Never hardcode passwords in scripts
   - Use secure credential storage (Azure Key Vault, Windows Credential Manager)
   - Implement least privilege access
   - Rotate API keys regularly

2. **Testing**
   - Always test scripts in non-production first
   - Use `-WhatIf` parameter when available
   - Review reports before taking action
   - Maintain change control documentation

3. **Backup & Recovery**
   - Store backups in encrypted, secure locations
   - Implement off-site backup replication
   - Regular restoration testing
   - Maintain 30-90 day retention

### Operational

1. **Regular Execution**
   - Daily: Failed login monitoring, critical system checks
   - Weekly: Full security audits, configuration backups
   - Monthly: Cost optimization, compliance reviews

2. **Alerting**
   - Configure email alerts for critical findings
   - Integrate with SIEM for centralized monitoring
   - Set up threshold-based notifications

3. **Documentation**
   - Maintain runbooks for each script
   - Document baseline configurations
   - Track remediation actions
   - Record exceptions and waivers

## Troubleshooting

### Common Issues

**Execution Policy Errors**
```powershell
# Set execution policy (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Module Not Found**
```powershell
# Install required modules
Install-Module -Name Az -AllowClobber -Scope CurrentUser
```

**API Connection Failures**
- Verify network connectivity
- Check firewall rules
- Validate API keys/credentials
- Review certificate trust (use `-SkipCertificateCheck` for testing only)

**Permission Denied**
- Run PowerShell as Administrator
- Verify account has required permissions
- Check RBAC assignments in Azure

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test your changes thoroughly
4. Submit a pull request with detailed description

## Security Notice

⚠️ **Important Security Considerations**:

1. **Authorization**: Only run scripts on systems you own or have explicit permission to scan/modify
2. **Credentials**: Store credentials securely, never commit to version control
3. **Production Changes**: Always test in non-production environments first
4. **Audit Trail**: Maintain logs of all script executions
5. **Sensitive Data**: Backup files contain sensitive information - encrypt and restrict access

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support & Contact

For issues, questions, or feature requests:
- **Issues**: [GitHub Issues](https://github.com/yourusername/zero-trust-toolkit/issues)
- **Documentation**: See individual README files in each directory
- **Security Team**: Contact your Infrastructure Security team

## Changelog

### Version 1.0.0 (Initial Release)
- Windows Server security audit and hardening scripts
- Azure security posture assessment tools
- FortiGate firewall backup and audit (API & SSH)
- Sophos XG/XGS firewall management
- Network port scanning utilities
- SSL/TLS certificate assessment tools
- Comprehensive documentation

## Roadmap

Planned features:
- [ ] Palo Alto Networks firewall support
- [ ] Cisco ASA/FTD scripts
- [ ] AWS security assessment tools
- [ ] Kubernetes security scanning
- [ ] SIEM integration modules
- [ ] Automated remediation workflows
- [ ] Compliance reporting templates (PCI DSS, ISO 27001, SOC 2)

---

**Built with ❤️ by Infrastructure Security Architects, for Infrastructure Security Architects**

*Making infrastructure security auditable, automated, and accessible.*
