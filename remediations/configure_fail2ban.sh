#!/bin/bash
# Configure fail2ban for brute force protection
set -e

echo "🚨 Configuring fail2ban for brute force protection..."
echo "===================================================="

# Install fail2ban if not present
if ! command -v fail2ban-server &> /dev/null; then
    echo "📦 Installing fail2ban..."
    apt update && apt install -y fail2ban
fi

# Create fail2ban configuration
echo "⚙️ Creating fail2ban configuration..."

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Ban hosts for 1 hour
bantime = 3600
# Override /etc/fail2ban/jail.d/00-firewalld.conf:
banaction = iptables-multiport

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600

[recidive]
enabled = true
filter = recidive
logpath = /var/log/auth.log
action = iptables-allports[name=recidive]
         sendmail-whois-lines[name=recidive, logpath=/var/log/auth.log]
bantime = 604800  # 1 week
findtime = 86400  # 1 day
maxretry = 3
EOF

# Enable and start fail2ban
echo "🔧 Starting fail2ban service..."
systemctl enable fail2ban
systemctl start fail2ban

# Wait for service to start
sleep 3

# Verify service is running
if systemctl is-active fail2ban >/dev/null 2>&1; then
    echo "✅ fail2ban service is ACTIVE"
    
    # Show current banned IPs
    echo "📊 Current banned IPs:"
    fail2ban-client status sshd | grep "Banned IP list" || echo "No IPs currently banned"
else
    echo "❌ fail2ban service failed to start"
    systemctl status fail2ban --no-pager
    exit 1
fi

echo ""
echo "🎉 fail2ban configured successfully!"
echo "📋 Protection enabled for:"
echo "   • SSH brute force attacks"
echo "   • DDoS protection"
echo "   • Repeat offenders (1 week ban)"
echo ""
echo "🔍 Monitor with: fail2ban-client status sshd"
echo "📝 View logs with: tail -f /var/log/fail2ban.log"
