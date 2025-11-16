#!/bin/bash

#
# FortiGate Configuration Backup Script (CLI-based)
#
# Description:
#   Connects to FortiGate via SSH and backs up configuration
#   Supports multiple FortiGates and automated scheduling
#
# Usage:
#   ./FortiGate-Backup.sh <fortigate_ip> <username> [backup_dir]
#
# Requirements:
#   - SSH access to FortiGate
#   - sshpass (for automated authentication) or SSH keys
#
# Author: Infrastructure Security Team
#

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check arguments
if [ $# -lt 2 ]; then
    echo "Usage: $0 <fortigate_ip> <username> [backup_dir]"
    echo ""
    echo "Example:"
    echo "  $0 192.168.1.99 admin /backups/fortigate"
    echo ""
    echo "Options:"
    echo "  fortigate_ip  : IP address or FQDN of FortiGate"
    echo "  username      : Admin username"
    echo "  backup_dir    : Backup directory (default: ./fortigate-backups)"
    exit 1
fi

FORTIGATE_IP=$1
USERNAME=$2
BACKUP_DIR=${3:-"./fortigate-backups"}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOSTNAME=""

# Create backup directory
if [ ! -d "$BACKUP_DIR" ]; then
    mkdir -p "$BACKUP_DIR"
    print_info "Created backup directory: $BACKUP_DIR"
fi

print_info "FortiGate Configuration Backup"
print_info "==============================="
print_info "FortiGate: $FORTIGATE_IP"
print_info "Username: $USERNAME"
print_info "Backup Dir: $BACKUP_DIR"
echo ""

# Check if sshpass is available
if ! command -v sshpass &> /dev/null; then
    print_warning "sshpass not found. You'll need to enter password manually or use SSH keys."
    print_info "Install sshpass: sudo apt-get install sshpass (Debian/Ubuntu)"
    USE_SSHPASS=0
else
    USE_SSHPASS=1
    # Prompt for password
    read -s -p "Enter password for $USERNAME: " PASSWORD
    echo ""
fi

# Function to execute SSH commands
execute_ssh_command() {
    local command=$1

    if [ $USE_SSHPASS -eq 1 ]; then
        sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -q "$USERNAME@$FORTIGATE_IP" "$command" 2>/dev/null
    else
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -q "$USERNAME@$FORTIGATE_IP" "$command" 2>/dev/null
    fi
}

# Test connection
print_info "Testing connection..."
if execute_ssh_command "get system status" &> /dev/null; then
    print_success "Connection successful"
else
    print_error "Failed to connect to FortiGate"
    exit 1
fi

# Get hostname
print_info "Retrieving FortiGate hostname..."
HOSTNAME=$(execute_ssh_command "get system status" | grep "Hostname" | awk '{print $2}')
if [ -z "$HOSTNAME" ]; then
    HOSTNAME="unknown"
fi
print_info "Hostname: $HOSTNAME"

# Create hostname-specific directory
HOST_BACKUP_DIR="$BACKUP_DIR/$HOSTNAME"
mkdir -p "$HOST_BACKUP_DIR"

# Backup filename
BACKUP_FILE="$HOST_BACKUP_DIR/${HOSTNAME}_config_${TIMESTAMP}.conf"

# Backup configuration
print_info "Backing up configuration..."
execute_ssh_command "show full-configuration" > "$BACKUP_FILE"

if [ $? -eq 0 ] && [ -s "$BACKUP_FILE" ]; then
    FILESIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    print_success "Configuration backed up successfully"
    print_info "Backup file: $BACKUP_FILE"
    print_info "File size: $FILESIZE"
else
    print_error "Backup failed"
    exit 1
fi

# Get system information
SYSINFO_FILE="$HOST_BACKUP_DIR/${HOSTNAME}_sysinfo_${TIMESTAMP}.txt"
print_info "Collecting system information..."

{
    echo "=== FortiGate System Information ==="
    echo "Collected: $(date)"
    echo ""
    echo "=== System Status ==="
    execute_ssh_command "get system status"
    echo ""
    echo "=== HA Status ==="
    execute_ssh_command "get system ha status"
    echo ""
    echo "=== Interface List ==="
    execute_ssh_command "get system interface physical"
    echo ""
    echo "=== Routing Table ==="
    execute_ssh_command "get router info routing-table all"
    echo ""
    echo "=== License Status ==="
    execute_ssh_command "get system status" | grep -A 10 "License Status"
} > "$SYSINFO_FILE"

print_success "System information collected"

# Get policy statistics
POLICY_STATS_FILE="$HOST_BACKUP_DIR/${HOSTNAME}_policy_stats_${TIMESTAMP}.txt"
print_info "Collecting policy statistics..."

{
    echo "=== Firewall Policy Statistics ==="
    echo "Collected: $(date)"
    echo ""
    execute_ssh_command "diagnose firewall iprope list 100"
} > "$POLICY_STATS_FILE"

print_success "Policy statistics collected"

# Compress backups (optional)
print_info "Compressing backup files..."
ARCHIVE_FILE="$HOST_BACKUP_DIR/${HOSTNAME}_backup_${TIMESTAMP}.tar.gz"

tar -czf "$ARCHIVE_FILE" -C "$HOST_BACKUP_DIR" \
    "$(basename $BACKUP_FILE)" \
    "$(basename $SYSINFO_FILE)" \
    "$(basename $POLICY_STATS_FILE)" 2>/dev/null

if [ $? -eq 0 ]; then
    print_success "Backup compressed: $ARCHIVE_FILE"

    # Remove uncompressed files
    rm "$BACKUP_FILE" "$SYSINFO_FILE" "$POLICY_STATS_FILE"

    ARCHIVE_SIZE=$(du -h "$ARCHIVE_FILE" | cut -f1)
    print_info "Archive size: $ARCHIVE_SIZE"
else
    print_warning "Compression failed, keeping uncompressed files"
fi

# Cleanup old backups (keep last 30 days)
print_info "Cleaning up old backups (keeping last 30 days)..."
find "$HOST_BACKUP_DIR" -name "${HOSTNAME}_backup_*.tar.gz" -mtime +30 -delete 2>/dev/null
find "$HOST_BACKUP_DIR" -name "${HOSTNAME}_config_*.conf" -mtime +30 -delete 2>/dev/null

REMAINING_BACKUPS=$(find "$HOST_BACKUP_DIR" -name "${HOSTNAME}_backup_*.tar.gz" | wc -l)
print_info "Total backups for $HOSTNAME: $REMAINING_BACKUPS"

# Generate backup report
REPORT_FILE="$HOST_BACKUP_DIR/backup_report.txt"
{
    echo "FortiGate Backup Report"
    echo "======================="
    echo "Hostname: $HOSTNAME"
    echo "IP Address: $FORTIGATE_IP"
    echo "Last Backup: $(date)"
    echo "Backup File: $(basename $ARCHIVE_FILE)"
    echo "File Size: $ARCHIVE_SIZE"
    echo "Total Backups: $REMAINING_BACKUPS"
    echo ""
    echo "Recent Backups:"
    find "$HOST_BACKUP_DIR" -name "${HOSTNAME}_backup_*.tar.gz" -printf "%T+ %p\n" | sort -r | head -10
} > "$REPORT_FILE"

print_success "Backup report generated: $REPORT_FILE"

echo ""
print_success "=== Backup Complete ==="
echo ""
print_info "Summary:"
echo "  Hostname: $HOSTNAME"
echo "  Backup Location: $HOST_BACKUP_DIR"
echo "  Archive: $(basename $ARCHIVE_FILE)"
echo "  Size: $ARCHIVE_SIZE"
echo "  Total Backups: $REMAINING_BACKUPS"
echo ""

# Security recommendations
echo ""
print_warning "Security Recommendations:"
echo "  1. Store backups in a secure, encrypted location"
echo "  2. Implement off-site backup replication"
echo "  3. Regularly test backup restoration"
echo "  4. Limit access to backup files (contain sensitive data)"
echo "  5. Consider using FortiManager for centralized backup management"
echo ""

exit 0
