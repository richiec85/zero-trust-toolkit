# Azure Security Scripts

PowerShell scripts for Azure security assessment, NSG management, and cost-security analysis.

## Prerequisites

- Azure PowerShell Module (Az)
- Appropriate Azure RBAC permissions
- Active Azure subscription

### Install Azure PowerShell
```powershell
Install-Module -Name Az -AllowClobber -Scope CurrentUser
```

### Connect to Azure
```powershell
Connect-AzAccount
Set-AzContext -Subscription "YourSubscriptionName"
```

## Scripts

### Get-AzureSecurityPosture.ps1
Comprehensive Azure security posture assessment across multiple resource types.

**Features:**
- Network Security Groups (NSG) analysis
- Storage account security settings
- Virtual machine security
- Key Vault configurations
- RBAC assignments review
- SQL Database security
- Public IP exposure analysis
- Generates HTML report with findings by severity

**Usage:**
```powershell
# Audit current subscription
.\Get-AzureSecurityPosture.ps1

# Audit specific subscription
.\Get-AzureSecurityPosture.ps1 -SubscriptionId "12345678-abcd-1234-abcd-123456789012"

# Custom export path
.\Get-AzureSecurityPosture.ps1 -ExportPath "D:\AzureReports"
```

**Required Permissions:**
- Reader (minimum)
- Security Reader (recommended)

**Output:**
- HTML report categorized by severity (Critical, High, Medium, Low, Info)
- Specific recommendations for each finding

---

### Manage-AzureNSGRules.ps1
NSG rule management and security auditing tool.

**Features:**
- Audit NSG rules for security risks
- Export NSG configurations
- Apply security hardening
- Generate remediation guides
- Identifies risky ports exposed to Internet
- Detects overly permissive rules

**Actions:**
- **Audit**: Scan NSGs for security issues
- **Export**: Backup NSG configurations
- **Block**: Add deny rules for common attack vectors
- **Remediate**: Generate detailed remediation guide

**Usage:**
```powershell
# Audit all NSGs
.\Manage-AzureNSGRules.ps1 -Action Audit

# Export NSG configurations
.\Manage-AzureNSGRules.ps1 -Action Export -ExportPath "C:\NSGBackups"

# Apply hardening to specific resource group
.\Manage-AzureNSGRules.ps1 -Action Block -ResourceGroupName "Production-RG"

# Generate remediation guide
.\Manage-AzureNSGRules.ps1 -Action Remediate

# Audit specific NSG
.\Manage-AzureNSGRules.ps1 -Action Audit -ResourceGroupName "MyRG" -NSGName "MyNSG"
```

**Required Permissions:**
- Reader (for Audit and Export)
- Network Contributor (for Block and Remediate actions)

**Risky Ports Monitored:**
- 22 (SSH)
- 23 (Telnet)
- 80 (HTTP)
- 135 (RPC)
- 139 (NetBIOS)
- 445 (SMB)
- 1433 (SQL Server)
- 3306 (MySQL)
- 3389 (RDP)
- 5432 (PostgreSQL)
- And more...

---

### Get-AzureCostSecurity.ps1
Azure cost analysis with security risk identification.

**Features:**
- Identifies unattached managed disks
- Finds unused public IP addresses
- Locates stopped/deallocated VMs
- Detects orphaned NSGs
- Finds old snapshots
- Identifies unused load balancers
- Combines cost optimization with security risk assessment

**Usage:**
```powershell
# Analyze last 30 days (default)
.\Get-AzureCostSecurity.ps1

# Analyze last 90 days
.\Get-AzureCostSecurity.ps1 -Days 90

# Specific subscription with custom export
.\Get-AzureCostSecurity.ps1 -SubscriptionId "12345678-abcd-1234-abcd-123456789012" -ExportPath "D:\Reports"
```

**Required Permissions:**
- Reader or Cost Management Reader

**Output:**
- HTML report with detailed findings
- Security risk assessment for each finding
- Cost impact analysis
- Recommendations for remediation

**Security Considerations:**
- Unattached disks may contain sensitive data
- Unused public IPs waste address space
- Stopped VMs may miss security updates
- Orphaned resources complicate security posture

---

## Best Practices

### Regular Security Assessments
```powershell
# Monthly security posture review
.\Get-AzureSecurityPosture.ps1 -ExportPath "C:\MonthlyReports"
```

### NSG Management
```powershell
# Weekly NSG audit
.\Manage-AzureNSGRules.ps1 -Action Audit

# Monthly NSG backup
.\Manage-AzureNSGRules.ps1 -Action Export -ExportPath "C:\NSGBackups\$(Get-Date -Format 'yyyyMM')"
```

### Cost & Security Optimization
```powershell
# Bi-weekly resource cleanup review
.\Get-AzureCostSecurity.ps1 -Days 14
```

## Security Recommendations

1. **Network Security:**
   - Never expose sensitive ports (RDP, SSH, SQL) directly to Internet
   - Use Azure Bastion for secure remote access
   - Implement Just-In-Time VM access
   - Use Application Security Groups

2. **Storage Security:**
   - Enable HTTPS-only traffic
   - Set minimum TLS version to 1.2
   - Disable public blob access unless required
   - Enable soft delete for blobs and containers

3. **Access Control:**
   - Follow principle of least privilege
   - Use Azure AD groups instead of individual user assignments
   - Regularly review and remove unnecessary permissions
   - Enable MFA for all privileged accounts

4. **Monitoring:**
   - Enable NSG Flow Logs
   - Configure Azure Security Center
   - Set up alerts for suspicious activities
   - Regular review of audit logs

## Automation

### Scheduled Security Audits
Create scheduled tasks to run these scripts regularly:

```powershell
# Example: Create weekly security audit task
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\Get-AzureSecurityPosture.ps1"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 9am
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Weekly Azure Security Audit"
```

## Troubleshooting

### Authentication Issues
```powershell
# Clear and re-authenticate
Clear-AzContext
Connect-AzAccount
```

### Module Issues
```powershell
# Update Az modules
Update-Module -Name Az -Force
```

### Permission Errors
Ensure you have the required permissions for each script. Contact your Azure administrator if you lack necessary roles.

## Support

For issues or enhancement requests, contact your Infrastructure Security team.
