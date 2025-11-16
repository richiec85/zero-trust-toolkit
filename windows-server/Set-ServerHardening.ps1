<#
.SYNOPSIS
    Windows Server Hardening Script

.DESCRIPTION
    Implements security hardening measures based on CIS benchmarks and security best practices:
    - Disables unnecessary services
    - Configures secure password policies
    - Enables Windows Firewall
    - Disables SMBv1
    - Configures audit policies
    - Sets registry security settings

.PARAMETER SkipServices
    Skip disabling unnecessary services

.PARAMETER SkipFirewall
    Skip firewall configuration

.PARAMETER GenerateReport
    Generate a hardening report after completion

.EXAMPLE
    .\Set-ServerHardening.ps1 -GenerateReport

.NOTES
    Author: Infrastructure Security Team
    Requires: Administrator privileges
    WARNING: Review settings before applying to production systems
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipServices,

    [Parameter(Mandatory=$false)]
    [switch]$SkipFirewall,

    [Parameter(Mandatory=$false)]
    [switch]$GenerateReport
)

# Ensure running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

$hardeningLog = @()

function Write-HardeningLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $hardeningLog += $logEntry

    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default { Write-Host $logEntry -ForegroundColor White }
    }
}

Write-HardeningLog "Starting Windows Server Hardening Process..." "SUCCESS"

# 1. Disable SMBv1
Write-HardeningLog "Disabling SMBv1 protocol..." "INFO"
try {
    if ($PSCmdlet.ShouldProcess("SMBv1", "Disable")) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
        Write-HardeningLog "SMBv1 disabled successfully" "SUCCESS"
    }
} catch {
    Write-HardeningLog "Failed to disable SMBv1: $($_.Exception.Message)" "ERROR"
}

# 2. Enable and Configure Windows Firewall
if (-not $SkipFirewall) {
    Write-HardeningLog "Configuring Windows Firewall..." "INFO"
    try {
        if ($PSCmdlet.ShouldProcess("Windows Firewall", "Enable and Configure")) {
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
            Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block -DefaultOutboundAction Allow
            Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block -DefaultOutboundAction Allow
            Write-HardeningLog "Windows Firewall enabled and configured" "SUCCESS"
        }
    } catch {
        Write-HardeningLog "Failed to configure firewall: $($_.Exception.Message)" "ERROR"
    }
}

# 3. Disable Unnecessary Services
if (-not $SkipServices) {
    Write-HardeningLog "Disabling unnecessary services..." "INFO"

    $servicesToDisable = @(
        "RemoteRegistry",
        "Telnet",
        "tlntsvr",
        "SNMP",
        "SNMPTRAP",
        "SSDPSRV",           # SSDP Discovery
        "upnphost",          # UPnP Device Host
        "WMPNetworkSvc",     # Windows Media Player Network Sharing
        "RemoteAccess",      # Routing and Remote Access
        "SharedAccess"       # Internet Connection Sharing
    )

    foreach ($service in $servicesToDisable) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                if ($PSCmdlet.ShouldProcess($service, "Stop and Disable")) {
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                    Write-HardeningLog "Disabled service: $service" "SUCCESS"
                }
            }
        } catch {
            Write-HardeningLog "Could not disable service $service : $($_.Exception.Message)" "WARNING"
        }
    }
}

# 4. Configure Audit Policies
Write-HardeningLog "Configuring audit policies..." "INFO"
try {
    if ($PSCmdlet.ShouldProcess("Audit Policies", "Configure")) {
        & auditpol /set /category:"Account Logon" /success:enable /failure:enable
        & auditpol /set /category:"Account Management" /success:enable /failure:enable
        & auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
        & auditpol /set /category:"Policy Change" /success:enable /failure:enable
        & auditpol /set /category:"Privilege Use" /failure:enable
        & auditpol /set /category:"System" /success:enable /failure:enable
        Write-HardeningLog "Audit policies configured successfully" "SUCCESS"
    }
} catch {
    Write-HardeningLog "Failed to configure audit policies: $($_.Exception.Message)" "ERROR"
}

# 5. Registry Security Settings
Write-HardeningLog "Applying registry security settings..." "INFO"

$registrySettings = @(
    # Disable AutoRun for all drives
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Name = "NoDriveTypeAutoRun"
        Value = 255
        Type = "DWord"
        Description = "Disable AutoRun for all drives"
    },
    # Enable LSA Protection
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name = "RunAsPPL"
        Value = 1
        Type = "DWord"
        Description = "Enable LSA Protection"
    },
    # Disable LLMNR
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        Name = "EnableMulticast"
        Value = 0
        Type = "DWord"
        Description = "Disable LLMNR"
    },
    # Enable DEP and ASLR
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        Name = "MoveImages"
        Value = 1
        Type = "DWord"
        Description = "Enable ASLR"
    },
    # Disable NetBIOS over TCP/IP
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
        Name = "NodeType"
        Value = 2
        Type = "DWord"
        Description = "Configure NetBIOS node type"
    },
    # Enable Windows Defender real-time monitoring
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        Name = "DisableRealtimeMonitoring"
        Value = 0
        Type = "DWord"
        Description = "Enable Windows Defender real-time monitoring"
    },
    # Restrict anonymous access to Named Pipes and Shares
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        Name = "RestrictNullSessAccess"
        Value = 1
        Type = "DWord"
        Description = "Restrict anonymous access to Named Pipes and Shares"
    }
)

foreach ($setting in $registrySettings) {
    try {
        if ($PSCmdlet.ShouldProcess($setting.Path, "Set Registry Value: $($setting.Name)")) {
            # Create path if it doesn't exist
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }

            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
            Write-HardeningLog "Applied: $($setting.Description)" "SUCCESS"
        }
    } catch {
        Write-HardeningLog "Failed to apply $($setting.Description): $($_.Exception.Message)" "ERROR"
    }
}

# 6. Configure User Account Control (UAC)
Write-HardeningLog "Configuring User Account Control..." "INFO"
try {
    if ($PSCmdlet.ShouldProcess("UAC", "Enable and Configure")) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -Force
        Write-HardeningLog "UAC configured successfully" "SUCCESS"
    }
} catch {
    Write-HardeningLog "Failed to configure UAC: $($_.Exception.Message)" "ERROR"
}

# 7. Configure Screen Saver Lock
Write-HardeningLog "Configuring automatic screen lock..." "INFO"
try {
    if ($PSCmdlet.ShouldProcess("Screen Lock", "Configure")) {
        $screenLockPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $screenLockPath -Name "InactivityTimeoutSecs" -Value 900 -Type DWord -Force
        Write-HardeningLog "Screen lock configured (15 minutes)" "SUCCESS"
    }
} catch {
    Write-HardeningLog "Failed to configure screen lock: $($_.Exception.Message)" "WARNING"
}

# 8. Enable PowerShell Logging
Write-HardeningLog "Enabling PowerShell logging..." "INFO"
try {
    if ($PSCmdlet.ShouldProcess("PowerShell Logging", "Enable")) {
        $psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (-not (Test-Path $psLogPath)) {
            New-Item -Path $psLogPath -Force | Out-Null
        }
        Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force

        $psModLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        if (-not (Test-Path $psModLogPath)) {
            New-Item -Path $psModLogPath -Force | Out-Null
        }
        Set-ItemProperty -Path $psModLogPath -Name "EnableModuleLogging" -Value 1 -Type DWord -Force

        Write-HardeningLog "PowerShell logging enabled" "SUCCESS"
    }
} catch {
    Write-HardeningLog "Failed to enable PowerShell logging: $($_.Exception.Message)" "ERROR"
}

# 9. Disable Guest Account
Write-HardeningLog "Disabling Guest account..." "INFO"
try {
    if ($PSCmdlet.ShouldProcess("Guest Account", "Disable")) {
        Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        Write-HardeningLog "Guest account disabled" "SUCCESS"
    }
} catch {
    Write-HardeningLog "Failed to disable Guest account: $($_.Exception.Message)" "WARNING"
}

# 10. Configure Event Log Sizes
Write-HardeningLog "Configuring Event Log sizes..." "INFO"
$eventLogs = @("Application", "Security", "System")
foreach ($log in $eventLogs) {
    try {
        if ($PSCmdlet.ShouldProcess($log, "Configure Log Size")) {
            Limit-EventLog -LogName $log -MaximumSize 512MB -OverflowAction OverwriteAsNeeded
            Write-HardeningLog "Configured $log event log size to 512MB" "SUCCESS"
        }
    } catch {
        Write-HardeningLog "Failed to configure $log event log: $($_.Exception.Message)" "WARNING"
    }
}

Write-HardeningLog "`nHardening process completed!" "SUCCESS"
Write-HardeningLog "IMPORTANT: Review changes and restart the server for all settings to take effect." "WARNING"

# Generate Report
if ($GenerateReport) {
    $reportPath = "C:\SecurityReports"
    if (-not (Test-Path $reportPath)) {
        New-Item -ItemType Directory -Path $reportPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = Join-Path $reportPath "HardeningReport_$timestamp.txt"

    $hardeningLog | Out-File -FilePath $reportFile -Encoding UTF8
    Write-HardeningLog "Report saved to: $reportFile" "SUCCESS"
}

Write-Host "`nRestart required for all changes to take effect. Restart now? (Y/N): " -NoNewline -ForegroundColor Yellow
