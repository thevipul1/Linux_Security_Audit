#!/bin/bash
# Update vulnerable packages
set -e

echo "🔄 Updating vulnerable packages..."
echo "=================================="

echo "📦 Checking for available updates..."
apt update

echo ""
echo "📊 Packages needing updates:"
apt list --upgradable

echo ""
echo "🚀 Performing security updates..."
# First, do a dry run to see what will be updated
echo "Dry run of security updates:"
apt upgrade --dry-run | grep -E '(upgraded|installed|removed)'

echo ""
read -p "Do you want to proceed with the updates? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Installing updates..."
    apt upgrade -y
    
    echo ""
    echo "🧹 Cleaning up..."
    apt autoremove -y
    apt autoclean
    
    echo ""
    echo "✅ System updates completed!"
    echo "📋 It's recommended to reboot if kernel was updated: sudo reboot"
else
    echo "❌ Updates cancelled"
    echo ""
    echo "💡 To update manually later:"
    echo "   sudo apt update && sudo apt upgrade"
fi
