<#
.SYNOPSIS
    Azure Cost Analysis with Security Focus

.DESCRIPTION
    Analyzes Azure costs with a focus on security-related resources:
    - Identifies unused resources (security risk and cost)
    - Analyzes security service costs
    - Finds unattached resources
    - Recommends cost optimization without compromising security

.PARAMETER SubscriptionId
    Azure Subscription ID (optional)

.PARAMETER Days
    Number of days to analyze (default: 30)

.PARAMETER ExportPath
    Export path for reports (default: current directory)

.EXAMPLE
    .\Get-AzureCostSecurity.ps1

.EXAMPLE
    .\Get-AzureCostSecurity.ps1 -Days 90 -ExportPath "C:\Reports"

.NOTES
    Author: Infrastructure Security Team
    Requires: Azure PowerShell module (Az)
    Requires: Reader or Cost Management Reader role
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory=$false)]
    [int]$Days = 30,

    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "."
)

if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Write-Error "Azure PowerShell module required. Install: Install-Module -Name Az -AllowClobber"
    exit 1
}

Import-Module Az.Accounts, Az.Compute, Az.Network, Az.Storage, Az.Resources

$context = Get-AzContext
if (-not $context) {
    Connect-AzAccount
    $context = Get-AzContext
}

if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
}

Write-Host "Azure Cost & Security Analysis" -ForegroundColor Cyan
Write-Host "Subscription: $($context.Subscription.Name)" -ForegroundColor Green
Write-Host "Analyzing last $Days days...`n" -ForegroundColor Yellow

$findings = @{
    UnattachedDisks = @()
    UnusedPublicIPs = @()
    StoppedVMs = @()
    EmptyNSGs = @()
    UnusedLoadBalancers = @()
    OldSnapshots = @()
}

# 1. Find unattached managed disks
Write-Host "[1/6] Checking for unattached managed disks..." -ForegroundColor Cyan
$allDisks = Get-AzDisk
$unattachedDisks = $allDisks | Where-Object { $_.ManagedBy -eq $null }

foreach ($disk in $unattachedDisks) {
    $findings.UnattachedDisks += [PSCustomObject]@{
        Name = $disk.Name
        ResourceGroup = $disk.ResourceGroupName
        Size = "$($disk.DiskSizeGB) GB"
        Tier = $disk.Sku.Name
        Location = $disk.Location
        Created = $disk.TimeCreated
        SecurityRisk = "Unattached disks may contain sensitive data"
        CostImpact = "Ongoing storage costs"
    }
}
Write-Host "  Found: $($unattachedDisks.Count) unattached disks" -ForegroundColor $(if($unattachedDisks.Count -gt 0){'Yellow'}else{'Green'})

# 2. Find unused public IP addresses
Write-Host "[2/6] Checking for unused public IP addresses..." -ForegroundColor Cyan
$allPublicIPs = Get-AzPublicIpAddress
$unusedIPs = $allPublicIPs | Where-Object { $_.IpConfiguration -eq $null }

foreach ($ip in $unusedIPs) {
    $findings.UnusedPublicIPs += [PSCustomObject]@{
        Name = $ip.Name
        ResourceGroup = $ip.ResourceGroupName
        IPAddress = $ip.IpAddress
        SKU = $ip.Sku.Name
        Location = $ip.Location
        SecurityRisk = "Unused public IPs reduce available address space and may be overlooked in security reviews"
        CostImpact = "Static IP charges apply"
    }
}
Write-Host "  Found: $($unusedIPs.Count) unused public IPs" -ForegroundColor $(if($unusedIPs.Count -gt 0){'Yellow'}else{'Green'})

# 3. Find stopped/deallocated VMs (running costs for disks)
Write-Host "[3/6] Checking for stopped virtual machines..." -ForegroundColor Cyan
$allVMs = Get-AzVM -Status
$stoppedVMs = $allVMs | Where-Object { $_.PowerState -eq 'VM deallocated' -or $_.PowerState -eq 'VM stopped' }

foreach ($vm in $stoppedVMs) {
    $vmDetails = Get-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name
    $osDiskSize = $vmDetails.StorageProfile.OsDisk.DiskSizeGB
    $dataDisksSize = ($vmDetails.StorageProfile.DataDisks | Measure-Object DiskSizeGB -Sum).Sum

    $findings.StoppedVMs += [PSCustomObject]@{
        Name = $vm.Name
        ResourceGroup = $vm.ResourceGroupName
        PowerState = $vm.PowerState
        Location = $vm.Location
        OSDiskSize = "$osDiskSize GB"
        DataDisksSize = "$dataDisksSize GB"
        SecurityRisk = "Stopped VMs may not receive security updates, potential attack vector if restarted"
        CostImpact = "Disk storage costs continue"
    }
}
Write-Host "  Found: $($stoppedVMs.Count) stopped VMs" -ForegroundColor $(if($stoppedVMs.Count -gt 0){'Yellow'}else{'Green'})

# 4. Find NSGs not associated with any resources
Write-Host "[4/6] Checking for unused Network Security Groups..." -ForegroundColor Cyan
$allNSGs = Get-AzNetworkSecurityGroup
$unusedNSGs = $allNSGs | Where-Object {
    ($_.NetworkInterfaces.Count -eq 0) -and ($_.Subnets.Count -eq 0)
}

foreach ($nsg in $unusedNSGs) {
    $findings.EmptyNSGs += [PSCustomObject]@{
        Name = $nsg.Name
        ResourceGroup = $nsg.ResourceGroupName
        Location = $nsg.Location
        RulesCount = $nsg.SecurityRules.Count
        SecurityRisk = "Orphaned NSGs make security posture unclear and harder to manage"
        CostImpact = "Minimal direct cost, but management overhead"
    }
}
Write-Host "  Found: $($unusedNSGs.Count) unused NSGs" -ForegroundColor $(if($unusedNSGs.Count -gt 0){'Yellow'}else{'Green'})

# 5. Find old snapshots
Write-Host "[5/6] Checking for old snapshots..." -ForegroundColor Cyan
$cutoffDate = (Get-Date).AddDays(-$Days)
$allSnapshots = Get-AzSnapshot
$oldSnapshots = $allSnapshots | Where-Object { $_.TimeCreated -lt $cutoffDate }

foreach ($snapshot in $oldSnapshots) {
    $age = [math]::Round(((Get-Date) - $snapshot.TimeCreated).TotalDays)

    $findings.OldSnapshots += [PSCustomObject]@{
        Name = $snapshot.Name
        ResourceGroup = $snapshot.ResourceGroupName
        Size = "$($snapshot.DiskSizeGB) GB"
        Created = $snapshot.TimeCreated
        Age = "$age days"
        SecurityRisk = "Old snapshots may contain outdated security configurations or vulnerabilities"
        CostImpact = "Storage costs for snapshots"
    }
}
Write-Host "  Found: $($oldSnapshots.Count) snapshots older than $Days days" -ForegroundColor $(if($oldSnapshots.Count -gt 0){'Yellow'}else{'Green'})

# 6. Find load balancers with no backend pools
Write-Host "[6/6] Checking for unused load balancers..." -ForegroundColor Cyan
$allLBs = Get-AzLoadBalancer
$unusedLBs = $allLBs | Where-Object {
    $backendPools = $_.BackendAddressPools
    $hasBackends = $false
    foreach ($pool in $backendPools) {
        if ($pool.BackendIpConfigurations.Count -gt 0) {
            $hasBackends = $true
            break
        }
    }
    -not $hasBackends
}

foreach ($lb in $unusedLBs) {
    $findings.UnusedLoadBalancers += [PSCustomObject]@{
        Name = $lb.Name
        ResourceGroup = $lb.ResourceGroupName
        SKU = $lb.Sku.Name
        Location = $lb.Location
        SecurityRisk = "Unused load balancers may have open ports or misconfigurations"
        CostImpact = "Load balancer hourly charges"
    }
}
Write-Host "  Found: $($unusedLBs.Count) unused load balancers" -ForegroundColor $(if($unusedLBs.Count -gt 0){'Yellow'}else{'Green'})

# Generate report
Write-Host "`nGenerating report..." -ForegroundColor Cyan

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $ExportPath "Azure_Cost_Security_Report_$timestamp.html"

$totalIssues = $findings.UnattachedDisks.Count + $findings.UnusedPublicIPs.Count +
               $findings.StoppedVMs.Count + $findings.EmptyNSGs.Count +
               $findings.UnusedLoadBalancers.Count + $findings.OldSnapshots.Count

$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Cost & Security Analysis - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background-color: white; padding: 20px; }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #106ebe; margin-top: 30px; }
        .summary { background-color: #e7f3ff; padding: 20px; margin: 20px 0; border-left: 4px solid #0078d4; }
        .warning { background-color: #fff4e5; padding: 20px; margin: 20px 0; border-left: 4px solid #ff8c00; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; font-size: 14px; }
        th { background-color: #0078d4; color: white; padding: 10px; text-align: left; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .count { font-size: 24px; font-weight: bold; color: #d13438; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Azure Cost & Security Analysis Report</h1>
        <div class="summary">
            <strong>Subscription:</strong> $($context.Subscription.Name)<br>
            <strong>Report Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
            <strong>Analysis Period:</strong> Last $Days days<br>
            <strong>Total Issues Found:</strong> <span class="count">$totalIssues</span>
        </div>

        <div class="warning">
            <strong>Security Note:</strong> Unused and unattached resources represent both cost waste and potential security risks.
            They may contain sensitive data, be overlooked in security reviews, or represent misconfigurations.
        </div>
"@

# Add findings sections
if ($findings.UnattachedDisks.Count -gt 0) {
    $htmlReport += "<h2>Unattached Managed Disks ($($findings.UnattachedDisks.Count))</h2>"
    $htmlReport += "<table><tr><th>Name</th><th>Resource Group</th><th>Size</th><th>Tier</th><th>Security Risk</th></tr>"
    foreach ($item in $findings.UnattachedDisks) {
        $htmlReport += "<tr><td>$($item.Name)</td><td>$($item.ResourceGroup)</td><td>$($item.Size)</td><td>$($item.Tier)</td><td>$($item.SecurityRisk)</td></tr>"
    }
    $htmlReport += "</table>"
}

if ($findings.UnusedPublicIPs.Count -gt 0) {
    $htmlReport += "<h2>Unused Public IP Addresses ($($findings.UnusedPublicIPs.Count))</h2>"
    $htmlReport += "<table><tr><th>Name</th><th>Resource Group</th><th>IP Address</th><th>SKU</th><th>Security Risk</th></tr>"
    foreach ($item in $findings.UnusedPublicIPs) {
        $htmlReport += "<tr><td>$($item.Name)</td><td>$($item.ResourceGroup)</td><td>$($item.IPAddress)</td><td>$($item.SKU)</td><td>$($item.SecurityRisk)</td></tr>"
    }
    $htmlReport += "</table>"
}

if ($findings.StoppedVMs.Count -gt 0) {
    $htmlReport += "<h2>Stopped Virtual Machines ($($findings.StoppedVMs.Count))</h2>"
    $htmlReport += "<table><tr><th>Name</th><th>Resource Group</th><th>Power State</th><th>OS Disk</th><th>Security Risk</th></tr>"
    foreach ($item in $findings.StoppedVMs) {
        $htmlReport += "<tr><td>$($item.Name)</td><td>$($item.ResourceGroup)</td><td>$($item.PowerState)</td><td>$($item.OSDiskSize)</td><td>$($item.SecurityRisk)</td></tr>"
    }
    $htmlReport += "</table>"
}

if ($findings.EmptyNSGs.Count -gt 0) {
    $htmlReport += "<h2>Unused Network Security Groups ($($findings.EmptyNSGs.Count))</h2>"
    $htmlReport += "<table><tr><th>Name</th><th>Resource Group</th><th>Rules Count</th><th>Security Risk</th></tr>"
    foreach ($item in $findings.EmptyNSGs) {
        $htmlReport += "<tr><td>$($item.Name)</td><td>$($item.ResourceGroup)</td><td>$($item.RulesCount)</td><td>$($item.SecurityRisk)</td></tr>"
    }
    $htmlReport += "</table>"
}

if ($findings.OldSnapshots.Count -gt 0) {
    $htmlReport += "<h2>Old Snapshots (>$Days days) ($($findings.OldSnapshots.Count))</h2>"
    $htmlReport += "<table><tr><th>Name</th><th>Resource Group</th><th>Size</th><th>Age</th><th>Security Risk</th></tr>"
    foreach ($item in $findings.OldSnapshots) {
        $htmlReport += "<tr><td>$($item.Name)</td><td>$($item.ResourceGroup)</td><td>$($item.Size)</td><td>$($item.Age)</td><td>$($item.SecurityRisk)</td></tr>"
    }
    $htmlReport += "</table>"
}

if ($findings.UnusedLoadBalancers.Count -gt 0) {
    $htmlReport += "<h2>Unused Load Balancers ($($findings.UnusedLoadBalancers.Count))</h2>"
    $htmlReport += "<table><tr><th>Name</th><th>Resource Group</th><th>SKU</th><th>Security Risk</th></tr>"
    foreach ($item in $findings.UnusedLoadBalancers) {
        $htmlReport += "<tr><td>$($item.Name)</td><td>$($item.ResourceGroup)</td><td>$($item.SKU)</td><td>$($item.SecurityRisk)</td></tr>"
    }
    $htmlReport += "</table>"
}

$htmlReport += @"
        <h2>Recommendations</h2>
        <ol>
            <li><strong>Review and Delete:</strong> Evaluate each unused resource and delete if no longer needed</li>
            <li><strong>Backup Before Delete:</strong> Ensure unattached disks don't contain needed data before deletion</li>
            <li><strong>Automation:</strong> Implement Azure Policy to prevent resource sprawl</li>
            <li><strong>Tagging:</strong> Use tags to track resource ownership and lifecycle</li>
            <li><strong>Regular Audits:</strong> Run this analysis monthly to catch unused resources early</li>
            <li><strong>Security Review:</strong> Audit stopped VMs and unattached disks for sensitive data before removal</li>
        </ol>

        <hr>
        <p><em>Report generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</em></p>
    </div>
</body>
</html>
"@

$htmlReport | Out-File -FilePath $reportFile -Encoding UTF8

# Console summary
Write-Host "`nAnalysis Complete!" -ForegroundColor Green
Write-Host "==================" -ForegroundColor Green
Write-Host "Unattached Disks: $($findings.UnattachedDisks.Count)" -ForegroundColor Yellow
Write-Host "Unused Public IPs: $($findings.UnusedPublicIPs.Count)" -ForegroundColor Yellow
Write-Host "Stopped VMs: $($findings.StoppedVMs.Count)" -ForegroundColor Yellow
Write-Host "Unused NSGs: $($findings.EmptyNSGs.Count)" -ForegroundColor Yellow
Write-Host "Old Snapshots: $($findings.OldSnapshots.Count)" -ForegroundColor Yellow
Write-Host "Unused Load Balancers: $($findings.UnusedLoadBalancers.Count)" -ForegroundColor Yellow
Write-Host "`nReport saved to: $reportFile" -ForegroundColor Cyan
