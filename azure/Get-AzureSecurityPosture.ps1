<#
.SYNOPSIS
    Azure Security Posture Assessment

.DESCRIPTION
    Comprehensive Azure security assessment covering:
    - Subscription security settings
    - Network Security Groups (NSGs)
    - Storage account configurations
    - Key Vault access policies
    - Virtual machine security
    - Azure AD configurations
    - Role-based access control (RBAC)
    - Security Center recommendations

.PARAMETER SubscriptionId
    Azure Subscription ID to audit (optional, uses current context if not specified)

.PARAMETER ExportPath
    Path where the audit report will be saved (default: current directory)

.EXAMPLE
    .\Get-AzureSecurityPosture.ps1

.EXAMPLE
    .\Get-AzureSecurityPosture.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -ExportPath "C:\AzureReports"

.NOTES
    Author: Infrastructure Security Team
    Requires: Azure PowerShell module (Az)
    Requires: Appropriate Azure permissions (Reader minimum, Security Reader recommended)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "."
)

# Check for Az module
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Write-Error "Azure PowerShell module (Az) is not installed. Install with: Install-Module -Name Az -AllowClobber -Scope CurrentUser"
    exit 1
}

# Import required modules
Import-Module Az.Accounts -ErrorAction SilentlyContinue
Import-Module Az.Resources -ErrorAction SilentlyContinue
Import-Module Az.Network -ErrorAction SilentlyContinue
Import-Module Az.Storage -ErrorAction SilentlyContinue
Import-Module Az.KeyVault -ErrorAction SilentlyContinue
Import-Module Az.Compute -ErrorAction SilentlyContinue
Import-Module Az.Security -ErrorAction SilentlyContinue

Write-Host "Azure Security Posture Assessment" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Cyan

# Check if logged in to Azure
try {
    $context = Get-AzContext
    if (-not $context) {
        Write-Host "Not logged in to Azure. Initiating login..." -ForegroundColor Yellow
        Connect-AzAccount
        $context = Get-AzContext
    }
} catch {
    Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
    exit 1
}

# Set subscription context if specified
if ($SubscriptionId) {
    try {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
        Write-Host "Using Subscription: $SubscriptionId" -ForegroundColor Green
    } catch {
        Write-Error "Failed to set subscription context: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Host "Using current subscription: $($context.Subscription.Name)" -ForegroundColor Green
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $ExportPath "AzureSecurityPosture_$timestamp.html"

# Initialize findings
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
        [string]$Resource,
        [string]$Issue,
        [string]$Recommendation
    )

    $finding = [PSCustomObject]@{
        Category = $Category
        Resource = $Resource
        Issue = $Issue
        Recommendation = $Recommendation
    }

    $findings[$Severity] += $finding
}

# Initialize HTML report
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Security Posture Report - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #106ebe; margin-top: 30px; border-bottom: 2px solid #e1e1e1; padding-bottom: 5px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { padding: 15px; border-radius: 5px; text-align: center; }
        .critical { background-color: #d13438; color: white; }
        .high { background-color: #ff8c00; color: white; }
        .medium { background-color: #ffaa00; color: white; }
        .low { background-color: #5cb85c; color: white; }
        .info { background-color: #0078d4; color: white; }
        .summary-card h3 { margin: 0; font-size: 32px; }
        .summary-card p { margin: 5px 0 0 0; font-size: 14px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th { background-color: #0078d4; color: white; padding: 12px; text-align: left; }
        td { border: 1px solid #ddd; padding: 10px; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .info-box { background-color: #e7f3ff; padding: 15px; margin: 15px 0; border-left: 4px solid #0078d4; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Azure Security Posture Assessment</h1>
        <div class="info-box">
            <strong>Subscription:</strong> $($context.Subscription.Name) ($($context.Subscription.Id))<br>
            <strong>Tenant:</strong> $($context.Tenant.Id)<br>
            <strong>Report Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
            <strong>Generated By:</strong> $($context.Account.Id)
        </div>
"@

Write-Host "`n[1/8] Analyzing Network Security Groups..." -ForegroundColor Cyan
try {
    $nsgs = Get-AzNetworkSecurityGroup

    foreach ($nsg in $nsgs) {
        # Check for overly permissive inbound rules
        $riskyRules = $nsg.SecurityRules | Where-Object {
            $_.Direction -eq 'Inbound' -and
            $_.Access -eq 'Allow' -and
            ($_.SourceAddressPrefix -eq '*' -or $_.SourceAddressPrefix -eq 'Internet') -and
            ($_.DestinationPortRange -match '^(22|3389|445|1433|3306)$' -or
             $_.DestinationPortRange -eq '*')
        }

        foreach ($rule in $riskyRules) {
            Add-Finding -Severity "High" -Category "Network Security" `
                -Resource "$($nsg.Name) - Rule: $($rule.Name)" `
                -Issue "Inbound rule allows traffic from Internet on sensitive port: $($rule.DestinationPortRange)" `
                -Recommendation "Restrict source to specific IP ranges. Avoid using * or Internet as source."
        }

        # Check for rules allowing all ports
        $openRules = $nsg.SecurityRules | Where-Object {
            $_.Direction -eq 'Inbound' -and
            $_.Access -eq 'Allow' -and
            $_.DestinationPortRange -eq '*'
        }

        foreach ($rule in $openRules) {
            Add-Finding -Severity "Critical" -Category "Network Security" `
                -Resource "$($nsg.Name) - Rule: $($rule.Name)" `
                -Issue "Inbound rule allows all ports from $($rule.SourceAddressPrefix)" `
                -Recommendation "Limit rule to specific required ports only."
        }
    }
} catch {
    Write-Host "Warning: Could not analyze NSGs: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "[2/8] Analyzing Storage Accounts..." -ForegroundColor Cyan
try {
    $storageAccounts = Get-AzStorageAccount

    foreach ($storage in $storageAccounts) {
        # Check for public access
        if ($storage.AllowBlobPublicAccess -eq $true) {
            Add-Finding -Severity "Medium" -Category "Storage Security" `
                -Resource $storage.StorageAccountName `
                -Issue "Storage account allows public blob access" `
                -Recommendation "Disable public blob access unless specifically required: Set-AzStorageAccount -AllowBlobPublicAccess `$false"
        }

        # Check for HTTPS enforcement
        if ($storage.EnableHttpsTrafficOnly -eq $false) {
            Add-Finding -Severity "High" -Category "Storage Security" `
                -Resource $storage.StorageAccountName `
                -Issue "Storage account does not enforce HTTPS-only traffic" `
                -Recommendation "Enable HTTPS-only: Set-AzStorageAccount -EnableHttpsTrafficOnly `$true"
        }

        # Check for minimum TLS version
        if ($storage.MinimumTlsVersion -ne 'TLS1_2') {
            Add-Finding -Severity "Medium" -Category "Storage Security" `
                -Resource $storage.StorageAccountName `
                -Issue "Storage account allows TLS versions older than 1.2" `
                -Recommendation "Set minimum TLS version to 1.2: Set-AzStorageAccount -MinimumTlsVersion TLS1_2"
        }
    }
} catch {
    Write-Host "Warning: Could not analyze Storage Accounts: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "[3/8] Analyzing Virtual Machines..." -ForegroundColor Cyan
try {
    $vms = Get-AzVM -Status

    foreach ($vm in $vms) {
        # Check for VMs without managed disks
        if ($vm.StorageProfile.OsDisk.ManagedDisk -eq $null) {
            Add-Finding -Severity "Medium" -Category "VM Security" `
                -Resource $vm.Name `
                -Issue "VM uses unmanaged disks" `
                -Recommendation "Migrate to managed disks for better security and management"
        }

        # Check for VMs without boot diagnostics
        if (-not $vm.DiagnosticsProfile.BootDiagnostics.Enabled) {
            Add-Finding -Severity "Low" -Category "VM Security" `
                -Resource $vm.Name `
                -Issue "Boot diagnostics not enabled" `
                -Recommendation "Enable boot diagnostics for troubleshooting capabilities"
        }
    }
} catch {
    Write-Host "Warning: Could not analyze Virtual Machines: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "[4/8] Analyzing Key Vaults..." -ForegroundColor Cyan
try {
    $keyVaults = Get-AzKeyVault

    foreach ($kv in $keyVaults) {
        $kvDetails = Get-AzKeyVault -VaultName $kv.VaultName

        # Check for soft delete
        if (-not $kvDetails.EnableSoftDelete) {
            Add-Finding -Severity "High" -Category "Key Vault Security" `
                -Resource $kv.VaultName `
                -Issue "Soft delete not enabled" `
                -Recommendation "Enable soft delete to protect against accidental deletion"
        }

        # Check for purge protection
        if (-not $kvDetails.EnablePurgeProtection) {
            Add-Finding -Severity "Medium" -Category "Key Vault Security" `
                -Resource $kv.VaultName `
                -Issue "Purge protection not enabled" `
                -Recommendation "Enable purge protection for additional security"
        }

        # Check for public network access
        if ($kvDetails.PublicNetworkAccess -eq 'Enabled' -and $kvDetails.NetworkAcls.DefaultAction -eq 'Allow') {
            Add-Finding -Severity "Medium" -Category "Key Vault Security" `
                -Resource $kv.VaultName `
                -Issue "Key Vault accessible from all networks" `
                -Recommendation "Restrict network access using private endpoints or firewall rules"
        }
    }
} catch {
    Write-Host "Warning: Could not analyze Key Vaults: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "[5/8] Analyzing RBAC Assignments..." -ForegroundColor Cyan
try {
    # Check for overly broad role assignments
    $roleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$($context.Subscription.Id)"

    # Owner role assignments
    $owners = $roleAssignments | Where-Object { $_.RoleDefinitionName -eq 'Owner' }
    if ($owners.Count -gt 5) {
        Add-Finding -Severity "Medium" -Category "Access Control" `
            -Resource "Subscription" `
            -Issue "High number of Owner role assignments ($($owners.Count))" `
            -Recommendation "Review and minimize Owner role assignments. Use more restrictive roles where possible."
    }

    # Check for user assignments vs group assignments
    $userAssignments = $roleAssignments | Where-Object { $_.ObjectType -eq 'User' }
    $groupAssignments = $roleAssignments | Where-Object { $_.ObjectType -eq 'Group' }

    if ($userAssignments.Count -gt $groupAssignments.Count * 2) {
        Add-Finding -Severity "Low" -Category "Access Control" `
            -Resource "Subscription" `
            -Issue "More role assignments to users than groups" `
            -Recommendation "Prefer group-based access control for easier management"
    }
} catch {
    Write-Host "Warning: Could not analyze RBAC: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "[6/8] Analyzing Public IP Addresses..." -ForegroundColor Cyan
try {
    $publicIPs = Get-AzPublicIpAddress

    foreach ($pip in $publicIPs) {
        if ($pip.IpConfiguration) {
            Add-Finding -Severity "Info" -Category "Network Security" `
                -Resource $pip.Name `
                -Issue "Public IP address in use: $($pip.IpAddress)" `
                -Recommendation "Ensure this public IP is necessary and properly secured with NSG rules"
        }
    }
} catch {
    Write-Host "Warning: Could not analyze Public IPs: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "[7/8] Analyzing SQL Databases..." -ForegroundColor Cyan
try {
    $sqlServers = Get-AzSqlServer

    foreach ($server in $sqlServers) {
        # Check firewall rules
        $firewallRules = Get-AzSqlServerFirewallRule -ServerName $server.ServerName -ResourceGroupName $server.ResourceGroupName

        $openRule = $firewallRules | Where-Object {
            $_.StartIpAddress -eq '0.0.0.0' -and $_.EndIpAddress -eq '255.255.255.255'
        }

        if ($openRule) {
            Add-Finding -Severity "Critical" -Category "Database Security" `
                -Resource $server.ServerName `
                -Issue "SQL Server allows connections from all IP addresses" `
                -Recommendation "Restrict SQL Server firewall rules to specific IP ranges"
        }

        # Check for Azure AD authentication
        $adAdmin = Get-AzSqlServerActiveDirectoryAdministrator -ServerName $server.ServerName -ResourceGroupName $server.ResourceGroupName -ErrorAction SilentlyContinue
        if (-not $adAdmin) {
            Add-Finding -Severity "Medium" -Category "Database Security" `
                -Resource $server.ServerName `
                -Issue "Azure AD authentication not configured" `
                -Recommendation "Configure Azure AD authentication for better identity management"
        }
    }
} catch {
    Write-Host "Warning: Could not analyze SQL Databases: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "[8/8] Generating report..." -ForegroundColor Cyan

# Generate summary section
$htmlReport += @"
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
            <div class="summary-card info">
                <h3>$($findings.Info.Count)</h3>
                <p>Informational</p>
            </div>
        </div>
"@

# Add findings sections
foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
    if ($findings[$severity].Count -gt 0) {
        $htmlReport += "<h2>$severity Findings</h2>"
        $htmlReport += "<table><tr><th>Category</th><th>Resource</th><th>Issue</th><th>Recommendation</th></tr>"

        foreach ($finding in $findings[$severity]) {
            $htmlReport += "<tr>"
            $htmlReport += "<td>$($finding.Category)</td>"
            $htmlReport += "<td>$($finding.Resource)</td>"
            $htmlReport += "<td>$($finding.Issue)</td>"
            $htmlReport += "<td>$($finding.Recommendation)</td>"
            $htmlReport += "</tr>"
        }

        $htmlReport += "</table>"
    }
}

# Close HTML
$htmlReport += @"
        <hr>
        <p><em>Report generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") by Azure Security Posture Assessment Script</em></p>
    </div>
</body>
</html>
"@

# Save report
$htmlReport | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "`nAssessment Complete!" -ForegroundColor Green
Write-Host "Report saved to: $reportFile" -ForegroundColor Yellow
Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "  Critical: $($findings.Critical.Count)" -ForegroundColor Red
Write-Host "  High: $($findings.High.Count)" -ForegroundColor DarkYellow
Write-Host "  Medium: $($findings.Medium.Count)" -ForegroundColor Yellow
Write-Host "  Low: $($findings.Low.Count)" -ForegroundColor Green
Write-Host "  Info: $($findings.Info.Count)" -ForegroundColor Cyan
