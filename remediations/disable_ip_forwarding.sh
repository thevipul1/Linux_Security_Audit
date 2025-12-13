#!/bin/bash
# Disable IP forwarding (for workstations)
set -e

echo "🌐 Disabling IP forwarding..."
echo "============================"

# Only disable if this is not a router
read -p "Is this system a router/gateway? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "⚠️  IP forwarding left enabled (system is a router)"
    exit 0
fi

# Disable IP forwarding
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf

# Apply immediately
sysctl -w net.ipv4.ip_forward=0

echo "✅ IP forwarding disabled"
echo "   • This system will not route packets between networks"
echo "   • Appropriate for workstations and most servers"
