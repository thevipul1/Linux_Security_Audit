#!/bin/bash
# Harden kernel security parameters
set -e

echo "🔧 Hardening kernel security parameters..."
echo "=========================================="

# Backup current sysctl settings
cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

# Add security settings to sysctl.conf
echo "Applying kernel security settings..."

SECURITY_SETTINGS=(
    "# Network Security"
    "net.ipv4.conf.all.accept_redirects = 0"
    "net.ipv4.conf.all.send_redirects = 0"
    "net.ipv4.conf.all.accept_source_route = 0"
    "net.ipv4.conf.all.rp_filter = 1"
    "net.ipv4.icmp_echo_ignore_broadcasts = 1"
    "net.ipv4.icmp_ignore_bogus_error_responses = 1"
    "net.ipv4.tcp_syncookies = 1"
    
    "# Memory Protection"
    "kernel.randomize_va_space = 2"
    "kernel.kptr_restrict = 2"
    "kernel.dmesg_restrict = 1"
    
    "# Filesystem Protection"
    "fs.suid_dumpable = 0"
    "fs.protected_hardlinks = 1"
    "fs.protected_symlinks = 1"
)

# Append settings if not already present
for setting in "${SECURITY_SETTINGS[@]}"; do
    if [[ $setting == \#* ]]; then
        # It's a comment, check if the next setting exists
        continue
    elif ! grep -q "^${setting%% = *}" /etc/sysctl.conf; then
        echo "$setting" >> /etc/sysctl.conf
    fi
done

# Apply settings immediately
echo "Applying settings immediately..."
sysctl -p /etc/sysctl.conf 2>/dev/null || sysctl --system

echo "✅ Kernel security parameters hardened:"
echo "   • Network security: ICMP redirects, source routing disabled"
echo "   • Memory protection: ASLR enabled, kernel pointers restricted"
echo "   • Filesystem protection: Hardened link handling"
