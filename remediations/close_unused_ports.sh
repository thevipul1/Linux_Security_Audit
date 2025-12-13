#!/bin/bash
# Close unnecessary open ports
set -e

echo "🔒 Closing unnecessary open ports..."
echo "===================================="

echo "📊 Current listening ports:"
echo "---------------------------"
ss -tuln | grep LISTEN

echo ""
echo "🛡️ Checking UFW firewall status..."
if command -v ufw >/dev/null 2>&1; then
    ufw status numbered
else
    echo "UFW not installed. Installing..."
    apt update && apt install -y ufw
fi

echo ""
echo "🔧 Recommended actions:"
echo "1. Identify services running on unnecessary ports:"
echo "   Use: lsof -i :PORT_NUMBER"
echo ""
echo "2. Stop unnecessary services:"
echo "   Use: systemctl stop SERVICE_NAME"
echo "   Use: systemctl disable SERVICE_NAME"
echo ""
echo "3. Configure UFW to block ports:"
echo "   Use: ufw deny PORT_NUMBER"
echo ""
echo "4. Common unnecessary services to check:"
echo "   • telnet (port 23)"
echo "   • FTP (port 21)" 
echo "   • rpcbind (port 111)"
echo "   • NFS (port 2049)"
echo "   • Unused database ports (3306, 5432, 27017)"
echo ""
echo "⚠️  WARNING: Be careful when closing ports!"
echo "   Make sure you're not blocking required services."
echo "   Always test connectivity after making changes."
