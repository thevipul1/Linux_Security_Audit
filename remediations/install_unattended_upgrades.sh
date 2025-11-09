#!/bin/bash
# Install and configure unattended-upgrades
set -e

echo "Setting up automatic security updates..."

# Install package
apt update
apt install -y unattended-upgrades

# Configure automatic updates
cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# Enable automatic removal of unused dependencies
sed -i 's|//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|' /etc/apt/apt.conf.d/50unattended-upgrades

# Enable the service
systemctl enable unattended-upgrades
systemctl start unattended-upgrades

echo "Automatic security updates configured"
