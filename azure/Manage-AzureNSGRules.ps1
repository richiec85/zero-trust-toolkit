<#
.SYNOPSIS
    Azure Network Security Group (NSG) Rule Management and Auditing

.DESCRIPTION
    Helps manage and audit Azure NSG rules with security best practices:
    - List all risky NSG rules
    - Block common attack vectors
    - Export NSG configurations
    - Generate compliance reports
    - Apply security baselines

.PARAMETER Action
    Action to perform: Audit, Block, Export, or Remediate

.PARAMETER ResourceGroupName
    Resource Group name (optional, analyzes all if not specified)

.PARAMETER NSGName
    Specific NSG to analyze (optional)

.PARAMETER ExportPath
    Path for exports and reports (default: current directory)

.EXAMPLE
    .\Manage-AzureNSGRules.ps1 -Action Audit

.EXAMPLE
    .\Manage-AzureNSGRules.ps1 -Action Export -ExportPath "C:\NSGBackups"

.EXAMPLE
    .\Manage-AzureNSGRules.ps1 -Action Block -ResourceGroupName "Production-RG"

.NOTES
    Author: Infrastructure Security Team
    Requires: Azure PowerShell module (Az.Network)
    Requires: Contributor or Network Contributor role
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Audit', 'Block', 'Export', 'Remediate')]
    [string]$Action,

    [Parameter(Mandatory=$false)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory=$false)]
    [string]$NSGName,

    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "."
)

# Check for Az.Network module
if (-not (Get-Module -ListAvailable -Name Az.Network)) {
    Write-Error "Azure Network module is not installed. Install with: Install-Module -Name Az.Network -AllowClobber"
    exit 1
}

Import-Module Az.Network

# Verify Azure context
$context = Get-AzContext
if (-not $context) {
    Write-Error "Not connected to Azure. Run Connect-AzAccount first."
    exit 1
}

Write-Host "Azure NSG Rule Management" -ForegroundColor Cyan
Write-Host "Subscription: $($context.Subscription.Name)" -ForegroundColor Green
Write-Host "Action: $Action`n" -ForegroundColor Yellow

# Define risky ports and configurations
$riskyPorts = @{
    '22' = 'SSH'
    '23' = 'Telnet'
    '80' = 'HTTP'
    '135' = 'RPC'
    '139' = 'NetBIOS'
    '445' = 'SMB'
    '1433' = 'SQL Server'
    '3306' = 'MySQL'
    '3389' = 'RDP'
    '5432' = 'PostgreSQL'
    '5900' = 'VNC'
    '8080' = 'HTTP Proxy'
    '27017' = 'MongoDB'
}

# Get NSGs based on parameters
function Get-TargetNSGs {
    if ($NSGName -and $ResourceGroupName) {
        return @(Get-AzNetworkSecurityGroup -Name $NSGName -ResourceGroupName $ResourceGroupName)
    } elseif ($ResourceGroupName) {
        return Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName
    } else {
        return Get-AzNetworkSecurityGroup
    }
}

# Analyze NSG rule for security risks
function Test-NSGRuleSecurity {
    param($Rule, $NSGName)

    $issues = @()

    # Check for internet-facing rules
    if ($Rule.Direction -eq 'Inbound' -and $Rule.Access -eq 'Allow') {
        # Check source address
        if ($Rule.SourceAddressPrefix -in @('*', 'Internet', '0.0.0.0/0')) {
            # Check if it's a risky port
            foreach ($port in $Rule.DestinationPortRange) {
                if ($riskyPorts.ContainsKey($port)) {
                    $issues += [PSCustomObject]@{
                        NSG = $NSGName
                        Rule = $Rule.Name
                        Priority = $Rule.Priority
                        Severity = 'Critical'
                        Issue = "Allows $($riskyPorts[$port]) (port $port) from Internet"
                        Source = $Rule.SourceAddressPrefix
                        Destination = $Rule.DestinationAddressPrefix
                        Port = $port
                        Protocol = $Rule.Protocol
                    }
                } elseif ($port -eq '*') {
                    $issues += [PSCustomObject]@{
                        NSG = $NSGName
                        Rule = $Rule.Name
                        Priority = $Rule.Priority
                        Severity = 'Critical'
                        Issue = "Allows ALL ports from Internet"
                        Source = $Rule.SourceAddressPrefix
                        Destination = $Rule.DestinationAddressPrefix
                        Port = $port
                        Protocol = $Rule.Protocol
                    }
                }
            }

            # Check for overly broad ranges
            if ($Rule.DestinationPortRange -match '-') {
                $issues += [PSCustomObject]@{
                    NSG = $NSGName
                    Rule = $Rule.Name
                    Priority = $Rule.Priority
                    Severity = 'High'
                    Issue = "Allows port range from Internet: $($Rule.DestinationPortRange)"
                    Source = $Rule.SourceAddressPrefix
                    Destination = $Rule.DestinationAddressPrefix
                    Port = $Rule.DestinationPortRange
                    Protocol = $Rule.Protocol
                }
            }
        }

        # Check for overly broad source ranges
        if ($Rule.SourceAddressPrefix -match '^(\d+\.){3}\d+/[0-9]$|^(\d+\.){3}\d+/1[0-5]$') {
            $issues += [PSCustomObject]@{
                NSG = $NSGName
                Rule = $Rule.Name
                Priority = $Rule.Priority
                Severity = 'Medium'
                Issue = "Very broad source IP range (/$($Rule.SourceAddressPrefix -replace '.*/'))"
                Source = $Rule.SourceAddressPrefix
                Destination = $Rule.DestinationAddressPrefix
                Port = $Rule.DestinationPortRange -join ','
                Protocol = $Rule.Protocol
            }
        }
    }

    return $issues
}

# Audit NSG rules
function Invoke-NSGAudit {
    Write-Host "Starting NSG Security Audit...`n" -ForegroundColor Cyan

    $allIssues = @()
    $nsgs = Get-TargetNSGs

    foreach ($nsg in $nsgs) {
        Write-Host "Analyzing NSG: $($nsg.Name)" -ForegroundColor Yellow

        foreach ($rule in $nsg.SecurityRules) {
            $issues = Test-NSGRuleSecurity -Rule $rule -NSGName $nsg.Name
            $allIssues += $issues
        }
    }

    # Display results
    if ($allIssues.Count -eq 0) {
        Write-Host "`nNo security issues found!" -ForegroundColor Green
    } else {
        Write-Host "`nFound $($allIssues.Count) potential security issues:`n" -ForegroundColor Red

        # Group by severity
        $critical = $allIssues | Where-Object { $_.Severity -eq 'Critical' }
        $high = $allIssues | Where-Object { $_.Severity -eq 'High' }
        $medium = $allIssues | Where-Object { $_.Severity -eq 'Medium' }

        if ($critical) {
            Write-Host "CRITICAL ISSUES ($($critical.Count)):" -ForegroundColor Red
            $critical | Format-Table NSG, Rule, Issue, Port, Source -AutoSize
        }

        if ($high) {
            Write-Host "HIGH SEVERITY ($($high.Count)):" -ForegroundColor DarkRed
            $high | Format-Table NSG, Rule, Issue, Port, Source -AutoSize
        }

        if ($medium) {
            Write-Host "MEDIUM SEVERITY ($($medium.Count)):" -ForegroundColor Yellow
            $medium | Format-Table NSG, Rule, Issue, Port, Source -AutoSize
        }

        # Save detailed report
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $reportFile = Join-Path $ExportPath "NSG_Audit_Report_$timestamp.csv"
        $allIssues | Export-Csv -Path $reportFile -NoTypeInformation
        Write-Host "Detailed report saved to: $reportFile" -ForegroundColor Green
    }
}

# Export NSG configurations
function Export-NSGConfiguration {
    Write-Host "Exporting NSG Configurations...`n" -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $exportDir = Join-Path $ExportPath "NSG_Export_$timestamp"

    if (-not (Test-Path $exportDir)) {
        New-Item -ItemType Directory -Path $exportDir | Out-Null
    }

    $nsgs = Get-TargetNSGs

    foreach ($nsg in $nsgs) {
        Write-Host "Exporting: $($nsg.Name)" -ForegroundColor Yellow

        # Export as JSON
        $jsonFile = Join-Path $exportDir "$($nsg.Name).json"
        $nsg | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile

        # Export rules as CSV
        $csvFile = Join-Path $exportDir "$($nsg.Name)_rules.csv"
        $nsg.SecurityRules | Select-Object Name, Priority, Direction, Access, Protocol, `
            SourceAddressPrefix, SourcePortRange, DestinationAddressPrefix, DestinationPortRange | `
            Export-Csv -Path $csvFile -NoTypeInformation
    }

    Write-Host "`nExport completed: $exportDir" -ForegroundColor Green
}

# Block common attack vectors
function Invoke-NSGHardening {
    Write-Host "Applying NSG Security Hardening...`n" -ForegroundColor Cyan
    Write-Host "WARNING: This will modify NSG rules!" -ForegroundColor Red
    Write-Host "Press Enter to continue or Ctrl+C to cancel..." -ForegroundColor Yellow
    Read-Host

    $nsgs = Get-TargetNSGs

    foreach ($nsg in $nsgs) {
        Write-Host "`nHardening NSG: $($nsg.Name)" -ForegroundColor Yellow

        # Get current highest priority
        $highestPriority = ($nsg.SecurityRules | Measure-Object Priority -Minimum).Minimum

        if ($highestPriority -gt 100) {
            $basePriority = 100
        } else {
            $basePriority = $highestPriority - 50
            if ($basePriority -lt 100) { $basePriority = 100 }
        }

        # Block rules to add
        $blockRules = @(
            @{
                Name = 'BlockTelnet'
                Port = 23
                Description = 'Block Telnet from Internet'
            },
            @{
                Name = 'BlockSMBFromInternet'
                Port = 445
                Description = 'Block SMB from Internet'
            },
            @{
                Name = 'BlockRPCFromInternet'
                Port = 135
                Description = 'Block RPC from Internet'
            }
        )

        $priority = $basePriority
        foreach ($blockRule in $blockRules) {
            # Check if rule already exists
            $existingRule = $nsg.SecurityRules | Where-Object { $_.Name -eq $blockRule.Name }

            if (-not $existingRule) {
                Write-Host "  Adding rule: $($blockRule.Name)" -ForegroundColor Green

                $nsg | Add-AzNetworkSecurityRuleConfig `
                    -Name $blockRule.Name `
                    -Description $blockRule.Description `
                    -Access Deny `
                    -Protocol * `
                    -Direction Inbound `
                    -Priority $priority `
                    -SourceAddressPrefix Internet `
                    -SourcePortRange * `
                    -DestinationAddressPrefix * `
                    -DestinationPortRange $blockRule.Port | Out-Null

                $priority += 10
            } else {
                Write-Host "  Rule already exists: $($blockRule.Name)" -ForegroundColor Yellow
            }
        }

        # Apply changes
        try {
            Set-AzNetworkSecurityGroup -NetworkSecurityGroup $nsg | Out-Null
            Write-Host "  NSG updated successfully" -ForegroundColor Green
        } catch {
            Write-Host "  ERROR: Failed to update NSG: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host "`nHardening completed!" -ForegroundColor Green
}

# Remediate specific issues
function Invoke-NSGRemediation {
    Write-Host "NSG Remediation Mode`n" -ForegroundColor Cyan

    # First, run audit to find issues
    $allIssues = @()
    $nsgs = Get-TargetNSGs

    foreach ($nsg in $nsgs) {
        foreach ($rule in $nsg.SecurityRules) {
            $issues = Test-NSGRuleSecurity -Rule $rule -NSGName $nsg.Name
            $allIssues += $issues
        }
    }

    if ($allIssues.Count -eq 0) {
        Write-Host "No issues to remediate!" -ForegroundColor Green
        return
    }

    Write-Host "Found $($allIssues.Count) issues to remediate`n" -ForegroundColor Yellow

    # Group issues by NSG
    $issuesByNSG = $allIssues | Group-Object NSG

    foreach ($group in $issuesByNSG) {
        Write-Host "NSG: $($group.Name)" -ForegroundColor Cyan
        Write-Host "Issues: $($group.Count)" -ForegroundColor Yellow

        $group.Group | Format-Table Rule, Severity, Issue -AutoSize

        Write-Host "Recommended actions:" -ForegroundColor Green
        Write-Host "1. Review and restrict source IP ranges" -ForegroundColor White
        Write-Host "2. Remove rules allowing Internet access to sensitive ports" -ForegroundColor White
        Write-Host "3. Use Application Security Groups for better management" -ForegroundColor White
        Write-Host ""
    }

    # Save remediation guide
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $guideFile = Join-Path $ExportPath "NSG_Remediation_Guide_$timestamp.txt"

    $guide = @"
NSG Remediation Guide
Generated: $(Get-Date)
Subscription: $($context.Subscription.Name)

ISSUES FOUND: $($allIssues.Count)

CRITICAL PRIORITIES:
$($allIssues | Where-Object {$_.Severity -eq 'Critical'} | ForEach-Object { "- [$($_.NSG)] $($_.Rule): $($_.Issue)" } | Out-String)

RECOMMENDED ACTIONS:
1. Review all rules allowing Internet access to sensitive ports
2. Replace broad IP ranges with specific addresses or ranges
3. Use Azure Bastion for RDP/SSH access instead of direct exposure
4. Implement Application Security Groups for logical grouping
5. Enable NSG Flow Logs for monitoring and analysis
6. Regular audit NSG rules (monthly minimum)

DETAILED FINDINGS:
$($allIssues | Format-Table -AutoSize | Out-String)
"@

    $guide | Out-File -FilePath $guideFile
    Write-Host "Remediation guide saved to: $guideFile" -ForegroundColor Green
}

# Main execution
switch ($Action) {
    'Audit' {
        Invoke-NSGAudit
    }
    'Export' {
        Export-NSGConfiguration
    }
    'Block' {
        Invoke-NSGHardening
    }
    'Remediate' {
        Invoke-NSGRemediation
    }
}

Write-Host "`nOperation completed!" -ForegroundColor Green
