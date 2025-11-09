#!/bin/bash
# Enable UFW firewall with sane defaults
set -e

echo "Configuring UFW firewall..."

# Reset to defaults
ufw --force reset

# Deny all incoming, allow all outgoing
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (check current port)
SSH_PORT=$(grep -E "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
ufw allow "${SSH_PORT:-22}/tcp"

# Enable UFW
ufw --force enable

echo "UFW firewall enabled with SSH port ${SSH_PORT:-22} open"
