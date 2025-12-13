#!/bin/bash
# Enforce strong password policies
set -e

echo "🔐 Enforcing strong password policies..."
echo "========================================"

# Backup files
cp /etc/login.defs /etc/login.defs.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
cp /etc/pam.d/common-password /etc/pam.d/common-password.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

# Set PASS_MAX_DAYS to 90 in /etc/login.defs
echo "Setting maximum password age to 90 days..."
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs

# Ensure PAM configuration for password complexity
if [ -f /etc/pam.d/common-password ]; then
    echo "Configuring PAM password policies..."
    
    # Add password history (remember last 5 passwords)
    if ! grep -q "remember=5" /etc/pam.d/common-password; then
        sed -i 's/password.*pam_unix.so.*/& remember=5/' /etc/pam.d/common-password
    fi
    
    # Add minimum password length
    if ! grep -q "minlen=8" /etc/pam.d/common-password; then
        sed -i 's/password.*pam_unix.so.*/& minlen=8/' /etc/pam.d/common-password
    fi
fi

echo "✅ Password policies enforced:"
echo "   • Maximum password age: 90 days"
echo "   • Password history: 5 previous passwords"
echo "   • Minimum length: 8 characters"
echo ""
echo "Note: Existing user passwords will need to be changed to enforce new policies"
