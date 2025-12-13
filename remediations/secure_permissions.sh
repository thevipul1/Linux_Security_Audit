#!/bin/bash
# Secure file and directory permissions
set -e

echo "Securing file permissions..."

# Secure home directories
find /home -maxdepth 1 -type d -exec chmod 750 {} \;

# Secure configuration files
chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/gshadow

# Secure SSH files
chmod 600 /etc/ssh/ssh_host_*_key
chmod 644 /etc/ssh/ssh_host_*_key.pub
chmod 600 /root/.ssh/authorized_keys 2>/dev/null || true

echo "File permissions secured"
