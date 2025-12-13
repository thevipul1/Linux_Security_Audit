#!/bin/bash
# Disable SSH root login
set -e

echo "Hardening SSH configuration..."

BACKUP_FILE="/etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"
cp /etc/ssh/sshd_config "$BACKUP_FILE"
echo "Backup created: $BACKUP_FILE"

# Disable root login
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# Disable password authentication (key-based only)
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# Disable X11 forwarding
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config

# Reload SSH service
if systemctl is-active ssh >/dev/null 2>&1; then
    systemctl reload ssh
elif systemctl is-active sshd >/dev/null 2>&1; then
    systemctl reload sshd
else
    service ssh reload 2>/dev/null || service sshd reload 2>/dev/null || true
fi

echo "SSH hardening completed"
