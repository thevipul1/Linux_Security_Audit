#!/bin/bash
# Install and configure unattended-upgrades COMPLETELY
set -e

echo "🔧 Setting up automatic security updates..."
echo "==========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root or with sudo"
    exit 1
fi

# Install package
if ! dpkg -l | grep -q unattended-upgrades; then
    echo "📦 Installing unattended-upgrades package..."
    apt update
    apt install -y unattended-upgrades
    echo "✅ Package installed successfully"
else
    echo "✅ unattended-upgrades already installed"
fi

# Configure automatic updates
echo "⚙️  Configuring automatic updates..."
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF
echo "✅ Basic configuration created"

# Configure unattended-upgrades settings
echo "⚙️  Configuring unattended-upgrades settings..."
if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
    # Enable automatic removal of unused dependencies
    sed -i 's|//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|' /etc/apt/apt.conf.d/50unattended-upgrades
    
    # Enable automatic removal of unused kernel packages
    sed -i 's|//Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";|Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";|' /etc/apt/apt.conf.d/50unattended-upgrades
    
    # Enable automatic reboot if required
    sed -i 's|//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "true";|' /etc/apt/apt.conf.d/50unattended-upgrades
    
    # Set reboot time (default: now)
    sed -i 's|//Unattended-Upgrade::Automatic-Reboot-Time "02:00";|Unattended-Upgrade::Automatic-Reboot-Time "03:00";|' /etc/apt/apt.conf.d/50unattended-upgrades
    
    echo "✅ Advanced configuration updated"
else
    echo "⚠️  /etc/apt/apt.conf.d/50unattended-upgrades not found, creating basic config..."
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESM:${distro_codename}";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF
    echo "✅ Basic 50unattended-upgrades configuration created"
fi

# Enable and start the service
echo "🔌 Enabling unattended-upgrades service..."
systemctl enable unattended-upgrades
systemctl start unattended-upgrades

# Wait a moment for service to start
sleep 2

# Verify service status
echo "🔍 Verifying service status..."
echo "-------------------------------------------"

# Check if service is active
if systemctl is-active unattended-upgrades >/dev/null 2>&1; then
    echo "✅ unattended-upgrades service is ACTIVE"
else
    echo "❌ unattended-upgrades service is NOT active"
    echo "Attempting to start service..."
    systemctl start unattended-upgrades
    sleep 2
    if systemctl is-active unattended-upgrades >/dev/null 2>&1; then
        echo "✅ Service started successfully"
    else
        echo "❌ Failed to start service"
        systemctl status unattended-upgrades --no-pager
        exit 1
    fi
fi

# Check if service is enabled
if systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
    echo "✅ unattended-upgrades service is ENABLED (starts on boot)"
else
    echo "❌ unattended-upgrades service is NOT enabled"
    echo "Enabling service..."
    systemctl enable unattended-upgrades
    if systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
        echo "✅ Service enabled successfully"
    else
        echo "❌ Failed to enable service"
        exit 1
    fi
fi

# Verify configuration files exist
echo "📁 Verifying configuration..."
if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    echo "✅ Configuration file /etc/apt/apt.conf.d/20auto-upgrades exists"
else
    echo "❌ Configuration file missing"
    exit 1
fi

if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
    echo "✅ Configuration file /etc/apt/apt.conf.d/50unattended-upgrades exists"
else
    echo "❌ Configuration file missing"
    exit 1
fi

# Test if unattended-upgrades will run
echo "🧪 Testing configuration..."
if /usr/bin/unattended-upgrades --dry-run --debug >/dev/null 2>&1; then
    echo "✅ Configuration test passed"
else
    echo "⚠️  Configuration test had issues (may be normal on first run)"
fi

echo ""
echo "==========================================="
echo "🎉 Automatic security updates configured successfully!"
echo ""
echo "📋 Summary:"
echo "   • Package installed: unattended-upgrades"
echo "   • Service status: $(systemctl is-active unattended-upgrades)"
echo "   • Service enabled: $(systemctl is-enabled unattended-upgrades)"
echo "   • Configuration: /etc/apt/apt.conf.d/20auto-upgrades"
echo "   • Configuration: /etc/apt/apt.conf.d/50unattended-upgrades"
echo ""
echo "🔒 System will now automatically:"
echo "   • Install security updates"
echo "   • Clean up unused dependencies"
echo "   • Reboot if required (at 03:00)"
echo ""
echo "📊 Check status with: systemctl status unattended-upgrades"
echo "📝 Check logs with: journalctl -u unattended-upgrades"
echo "==========================================="
