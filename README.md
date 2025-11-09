# Linux Security Audit 🔒

![GitHub](https://img.shields.io/badge/license-GPL--3.0-green)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

Automated Linux security scanner that finds and fixes common misconfigurations with professional reporting.

## 🚀 Features

- Comprehensive Security Scanning: Audit SSH, password policies, file permissions, and more
- **Auto-Remediation**: Automatically fix common security misconfigurations
- **Professional Reporting**: Generate detailed HTML, PDF, and JSON reports
- **Customizable Scans**: Create custom audit profiles for your environment
- **Compliance Checking**: Check against CIS benchmarks and industry standards
- **Non-Intrusive**: Read-only mode available for sensitive environments

## 📋 Quick Start

### Prerequisites
- Python 3.8 or higher
- Linux system (tested on Ubuntu, CentOS, RHEL)
- Root/sudo access (for auto-fixes)

### Installation

```bash
# Clone the repository
git clone https://github.com/thevipull/Linux_Security_Audit.git
cd Linux_Security_Audit

# Install dependencies
pip install -r requirements.txt

# Run your first security audit
python src/main.py --scan basic
```

### Basic Usage

```bash
# Run comprehensive security scan
python src/main.py --scan comprehensive

# Scan with auto-fix enabled
python src/main.py --scan comprehensive --auto-fix

# Generate HTML report only
python src/main.py --scan basic --report html

# Custom scan profile
python src/main.py --profile webserver --report pdf
```

## 🛠️ Installation Details

### Method 1: Direct Clone
```bash
git clone https://github.com/thevipull/Linux_Security_Audit.git
cd Linux_Security_Audit
pip install -r requirements.txt
```

### Method 2: Docker
```bash
docker build -t linux-security-audit .
docker run -v /etc:/host/etc linux-security-audit --scan basic
```

### Method 3: System Package (Future)
```bash
# Coming soon
wget https://github.com/thevipull/Linux_Security_Audit/releases/latest/linux-security-audit.deb
sudo dpkg -i linux-security-audit.deb
```

## 📊 Scan Categories

| Category | Checks | Auto-fix |
|----------|--------|----------|
| **SSH Security** | Protocol version, Root login, Key authentication | ✅ |
| **Password Policies** | Password aging, Complexity requirements | ✅ |
| **File Permissions** | World-writable files, SUID binaries | ✅ |
| **Network Security** | Open ports, Firewall status | ⚠️ Partial |
| **System Updates** | Security patches, Package versions | ❌ |
| **Audit & Logging** | Auditd configuration, Log rotation | ✅ |
| **Kernel Parameters** | sysctl security settings | ✅ |

## 📝 Usage Examples

### Basic Security Audit
```bash
python src/main.py --scan basic --output /tmp/security_report.html
```

### Production Server Scan
```bash
python src/main.py --scan production --auto-fix --report pdf,json
```

### Custom Scan Configuration
```bash
python src/main.py --config custom_profile.yaml --verbose
```

### Continuous Monitoring
```bash
# Add to crontab for daily scans
0 2 * * * /opt/Linux_Security_Audit/src/main.py --scan basic --report html --email admin@company.com
```

## 📁 Project Structure

```
1_Linux_hardening_and_security_audit
├── config
│   └── rules.yaml
├── debug_scan.py
├── main.py
├── modules
│   ├── __init__.py
│   ├── __pycache__
│   │   ├── __init__.cpython-312.pyc
│   │   ├── __init__.cpython-313.pyc
│   │   ├── remediator.cpython-312.pyc
│   │   ├── remediator.cpython-313.pyc
│   │   ├── reporter.cpython-312.pyc
│   │   ├── reporter.cpython-313.pyc
│   │   ├── scanner.cpython-312.pyc
│   │   ├── scanner.cpython-313.pyc
│   │   ├── utils.cpython-312.pyc
│   │   └── utils.cpython-313.pyc
│   ├── remediator.py
│   ├── reporter.py
│   ├── scanner.py
│   └── utils.py
├── outputs
│   ├── logs
│   │   └── audit.log
│   └── reports
│       ├── debug_scan.json
│       ├── modern_scan.html
│       └── secure_scan.json
├── readme.txt
├── remediations
│   ├── audit_suid_files.sh
│   ├── basic_hardening.sh
│   ├── install_unattended_upgrades.sh
│   ├── secure_permissions.sh
│   ├── ssh_disable_root.sh
│   └── ufw_enable.sh
├── requirements.txt
├── rules
│   └── __init__.py
├── safety_check.py
├── templates
└── tests
    └── __init__.py
           # Usage examples
```

## 🎯 Sample Output

```json
{
  "scan_summary": {
    "total_checks": 45,
    "passed": 38,
    "failed": 7,
    "fixed": 5,
    "duration": "2.3s"
  },
  "critical_findings": [
    {
      "check": "SSH Root Login",
      "status": "FAILED",
      "risk": "HIGH",
      "description": "Root login via SSH is enabled",
      "remediation": "Set PermitRootLogin to no in sshd_config",
      "auto_fixed": true
    }
  ]
}
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/thevipull/Linux_Security_Audit.git
cd Linux_Security_Audit
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
```

### Running Tests
```bash
pytest tests/ -v
```

## 📄 License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for educational and authorized security auditing purposes only. Always ensure you have proper authorization before scanning systems. The authors are not responsible for any misuse or damage caused by this program.

## 🆘 Support

- 📖 [Documentation](docs/)
- 🐛 [Report Issues](https://github.com/thevipull/Linux_Security_Audit/issues)
- 💬 [Discussions](https://github.com/thevipull/Linux_Security_Audit/discussions)
- 📧 Email: [Your Email]

---

**⭐ If you find this project useful, please give it a star on GitHub!**
```

## Key Enhancements Made:

1. **Professional Header** with badges for license, Python version, and platform
2. **Clear Features List** highlighting key capabilities
3. **Multiple Installation Methods** for different use cases
4. **Comprehensive Usage Examples** with real command examples
5. **Scan Categories Table** showing what the tool checks
6. **Project Structure** visualization
7. **Sample Output** to show users what to expect
8. **Contribution Guidelines** section to encourage community involvement
9. **Professional Disclaimer** for responsible usage
10. **Support Section** with multiple contact options

## Next Steps:

1. **Copy this content** to your `README.md` file
2. **Customize** the email, support links, and specific features
3. **Add actual command examples** once you start building the tool
4. **Include screenshots** of reports when you have them
5. **Update the features list** as you develop more capabilities

Would you like me to help you create any specific sections in more detail, like the configuration files or contribution guidelines?
