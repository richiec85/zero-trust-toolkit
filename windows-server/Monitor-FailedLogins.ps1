<#
.SYNOPSIS
    Monitor and Alert on Failed Login Attempts

.DESCRIPTION
    Monitors Windows Security Event Log for failed login attempts and generates alerts
    when threshold is exceeded. Can send email notifications and log to file.

.PARAMETER ThresholdCount
    Number of failed logins to trigger an alert (default: 5)

.PARAMETER TimeWindowMinutes
    Time window in minutes to check for failed logins (default: 15)

.PARAMETER EmailRecipient
    Email address to send alerts to

.PARAMETER SMTPServer
    SMTP server for sending email alerts

.PARAMETER ContinuousMonitoring
    Enable continuous monitoring mode (runs indefinitely)

.EXAMPLE
    .\Monitor-FailedLogins.ps1 -ThresholdCount 5 -TimeWindowMinutes 15

.EXAMPLE
    .\Monitor-FailedLogins.ps1 -ThresholdCount 3 -EmailRecipient "security@company.com" -SMTPServer "smtp.company.com" -ContinuousMonitoring

.NOTES
    Author: Infrastructure Security Team
    Requires: Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [int]$ThresholdCount = 5,

    [Parameter(Mandatory=$false)]
    [int]$TimeWindowMinutes = 15,

    [Parameter(Mandatory=$false)]
    [string]$EmailRecipient,

    [Parameter(Mandatory=$false)]
    [string]$SMTPServer,

    [Parameter(Mandatory=$false)]
    [switch]$ContinuousMonitoring,

    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\SecurityLogs"
)

# Ensure running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

# Create log directory
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$logFile = Join-Path $LogPath "FailedLoginMonitor.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    Add-Content -Path $logFile -Value $logEntry

    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ALERT" { Write-Host $logEntry -ForegroundColor Magenta }
        default { Write-Host $logEntry -ForegroundColor White }
    }
}

function Send-EmailAlert {
    param(
        [string]$Subject,
        [string]$Body
    )

    if ($EmailRecipient -and $SMTPServer) {
        try {
            $emailParams = @{
                To = $EmailRecipient
                From = "security-alerts@$env:COMPUTERNAME"
                Subject = $Subject
                Body = $Body
                SmtpServer = $SMTPServer
            }
            Send-MailMessage @emailParams
            Write-Log "Email alert sent to $EmailRecipient" "INFO"
        } catch {
            Write-Log "Failed to send email alert: $($_.Exception.Message)" "ERROR"
        }
    }
}

function Get-FailedLoginAttempts {
    param([int]$Minutes)

    $startTime = (Get-Date).AddMinutes(-$Minutes)

    try {
        # Event ID 4625 = Failed Logon
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4625
            StartTime = $startTime
        } -ErrorAction SilentlyContinue

        return $events
    } catch {
        Write-Log "Error retrieving failed login events: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Analyze-FailedLogins {
    param($Events)

    if (-not $Events) {
        return
    }

    # Group by account name
    $failedAttempts = @{}

    foreach ($event in $Events) {
        $xml = [xml]$event.ToXml()
        $eventData = $xml.Event.EventData.Data

        # Extract target username (different fields depending on event)
        $targetUser = ($eventData | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
        $sourceIP = ($eventData | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
        $workstation = ($eventData | Where-Object {$_.Name -eq 'WorkstationName'}).'#text'
        $logonType = ($eventData | Where-Object {$_.Name -eq 'LogonType'}).'#text'

        if ($targetUser) {
            $key = "$targetUser|$sourceIP"

            if (-not $failedAttempts.ContainsKey($key)) {
                $failedAttempts[$key] = @{
                    Username = $targetUser
                    SourceIP = $sourceIP
                    Workstation = $workstation
                    LogonType = $logonType
                    Count = 0
                    Times = @()
                }
            }

            $failedAttempts[$key].Count++
            $failedAttempts[$key].Times += $event.TimeCreated
        }
    }

    return $failedAttempts
}

function Process-Alerts {
    param($FailedAttempts)

    foreach ($key in $FailedAttempts.Keys) {
        $attempt = $FailedAttempts[$key]

        if ($attempt.Count -ge $ThresholdCount) {
            $alertMessage = @"
SECURITY ALERT: Multiple Failed Login Attempts Detected

Server: $env:COMPUTERNAME
Username: $($attempt.Username)
Source IP: $($attempt.SourceIP)
Workstation: $($attempt.Workstation)
Logon Type: $($attempt.LogonType)
Failed Attempts: $($attempt.Count)
Time Window: $TimeWindowMinutes minutes
First Attempt: $($attempt.Times | Sort-Object | Select-Object -First 1)
Last Attempt: $($attempt.Times | Sort-Object | Select-Object -Last 1)

Recommended Actions:
1. Verify if this is legitimate user activity
2. Check for potential brute force attack
3. Consider blocking source IP if malicious
4. Review account security status
"@

            Write-Log $alertMessage "ALERT"

            # Send email alert if configured
            Send-EmailAlert -Subject "SECURITY ALERT: Failed Login Attempts on $env:COMPUTERNAME" -Body $alertMessage

            # Save detailed alert to file
            $alertFile = Join-Path $LogPath "Alert_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            $alertMessage | Out-File -FilePath $alertFile -Encoding UTF8
        }
    }
}

function Monitor-LoopIteration {
    Write-Log "Starting failed login monitoring check..." "INFO"
    Write-Log "Threshold: $ThresholdCount attempts in $TimeWindowMinutes minutes" "INFO"

    # Get failed login events
    $failedEvents = Get-FailedLoginAttempts -Minutes $TimeWindowMinutes

    if ($failedEvents) {
        Write-Log "Found $($failedEvents.Count) failed login attempts in the last $TimeWindowMinutes minutes" "WARNING"

        # Analyze and group events
        $analysis = Analyze-FailedLogins -Events $failedEvents

        # Process alerts
        Process-Alerts -FailedAttempts $analysis

    } else {
        Write-Log "No failed login attempts found in the last $TimeWindowMinutes minutes" "INFO"
    }
}

# Main execution
Write-Log "Failed Login Monitor Started" "INFO"
Write-Log "Server: $env:COMPUTERNAME" "INFO"
Write-Log "Threshold: $ThresholdCount failed attempts" "INFO"
Write-Log "Time Window: $TimeWindowMinutes minutes" "INFO"

if ($ContinuousMonitoring) {
    Write-Log "Continuous monitoring mode enabled. Press Ctrl+C to stop." "INFO"

    while ($true) {
        Monitor-LoopIteration
        Write-Log "Sleeping for $TimeWindowMinutes minutes before next check..." "INFO"
        Start-Sleep -Seconds ($TimeWindowMinutes * 60)
    }
} else {
    Monitor-LoopIteration
    Write-Log "Single check completed" "INFO"
}
