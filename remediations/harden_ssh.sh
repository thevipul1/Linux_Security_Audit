#!/bin/bash
# Harden SSH protocol and ciphers
set -e

echo "🔒 Hardening SSH configuration..."
echo "================================"

# Backup SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)

echo "Configuring secure SSH protocols and ciphers..."

# Ensure Protocol 2 only
sed -i 's/^#*Protocol.*/Protocol 2/' /etc/ssh/sshd_config

# Set secure ciphers (remove weak ones)
if grep -q "^Ciphers" /etc/ssh/sshd_config; then
    # Update existing Ciphers line
    sed -i 's/^Ciphers.*/Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr/' /etc/ssh/sshd_config
else
    # Add Ciphers line
    echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config
fi

# Set secure MACs
if grep -q "^MACs" /etc/ssh/sshd_config; then
    sed -i 's/^MACs.*/MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com/' /etc/ssh/sshd_config
else
    echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
fi

# Reload SSH service
echo "Reloading SSH service..."
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null

echo "✅ SSH protocol and ciphers hardened:"
echo "   • Protocol: 2 only"
echo "   • Ciphers: Strong modern ciphers"
echo "   • MACs: Secure message authentication"
