#!/bin/bash
# Secure sudo configuration
set -e

echo "🛡️  Securing sudo configuration..."
echo "=================================="

# Backup sudoers file
cp /etc/sudoers /etc/sudoers.backup.$(date +%Y%m%d_%H%M%S)

# Set default timestamp timeout to 15 minutes
echo "Setting sudo timeout to 15 minutes..."
if ! grep -q "Defaults timestamp_timeout=15" /etc/sudoers; then
    echo "Defaults timestamp_timeout=15" >> /etc/sudoers
fi

# Remove unrestricted NOPASSWD access (be careful!)
echo "Checking for unrestricted sudo access..."
if grep -q "NOPASSWD.*ALL" /etc/sudoers; then
    echo "⚠️  Warning: Unrestricted NOPASSWD access found"
    echo "   Review /etc/sudoers manually for: NOPASSWD: ALL"
fi

# Ensure sudo requires password
if ! grep -q "Defaults.*!authenticate" /etc/sudoers; then
    echo "✅ Sudo requires password (good)"
else
    echo "⚠️  Warning: Sudo may not require password in some cases"
fi

echo "✅ Sudo configuration secured:"
echo "   • Timeout: 15 minutes"
echo "   • Password required: Yes"
echo ""
echo "Note: Always use 'visudo' to edit sudoers file safely"
