import subprocess
import json
import os
import re
import psutil
import glob
from modules.utils import run_command

class SecurityScanner:
    def __init__(self):
        self.results = []
    
    def run_all_checks(self):
        """Run all security checks"""
        self.results = []
        
        # System checks
        self.results.append(self.check_ssh_root_login())
        self.results.append(self.check_ufw_status())
        self.results.append(self.check_unattended_upgrades())
        self.results.append(self.check_suid_files())
        self.results.append(self.check_world_writable_dirs())
        
        # NEW CHECKS - Phase 1
        self.results.append(self.check_password_policy())
        self.results.append(self.check_sudo_config())
        self.results.append(self.check_kernel_parameters())
        self.results.append(self.check_ssh_protocol())
        self.results.append(self.check_ip_forwarding())
        
        # PRIORITY 1 CYBERSECURITY CHECKS
        self.results.append(self.check_failed_logins())           # Brute force detection
        self.results.append(self.check_suspicious_processes())    # Malware detection  
        self.results.append(self.check_open_ports())              # Attack surface reduction
        self.results.append(self.check_cve_vulnerabilities())     # Vulnerability assessment
        
        return self.results
    
    def check_ssh_root_login(self):
        """Check if SSH root login is disabled"""
        try:
            with open('/etc/ssh/sshd_config', 'r') as f:
                for line in f:
                    if line.strip().startswith('PermitRootLogin'):
                        value = line.split()[1].lower()
                        status = 'PASS' if value == 'no' else 'FAIL'
                        return {
                            'id': 'SSH-001',
                            'title': 'SSH Root Login Disabled',
                            'status': status,
                            'severity': 'HIGH',
                            'description': 'SSH should not allow direct root login',
                            'remediation': 'remediations/ssh_disable_root.sh',
                            'evidence': f'PermitRootLogin {value}'
                        }
            return {
                'id': 'SSH-001',
                'title': 'SSH Root Login Disabled',
                'status': 'FAIL',
                'severity': 'HIGH',
                'description': 'PermitRootLogin directive not found',
                'remediation': 'remediations/ssh_disable_root.sh',
                'evidence': 'Directive missing'
            }
        except Exception as e:
            return {
                'id': 'SSH-001',
                'title': 'SSH Root Login Disabled',
                'status': 'ERROR',
                'severity': 'HIGH',
                'description': f'Error checking SSH config: {e}',
                'remediation': 'remediations/ssh_disable_root.sh',
                'evidence': f'Error: {e}'
            }
    
    def check_ufw_status(self):
        """Check if UFW firewall is active"""
        try:
            exit_code, output, error = run_command('ufw status')
            status = 'PASS' if 'Status: active' in output else 'FAIL'
            
            return {
                'id': 'NET-001',
                'title': 'UFW Firewall Active',
                'status': status,
                'severity': 'HIGH',
                'description': 'UFW firewall should be enabled',
                'remediation': 'remediations/ufw_enable.sh',
                'evidence': output.split('\n')[0] if output else 'No output'
            }
        except Exception as e:
            return {
                'id': 'NET-001',
                'title': 'UFW Firewall Active',
                'status': 'ERROR',
                'severity': 'HIGH',
                'description': f'Error checking UFW: {e}',
                'remediation': 'remediations/ufw_enable.sh',
                'evidence': f'Error: {e}'
            }
    
    def check_unattended_upgrades(self):
        """Check if unattended-upgrades is installed AND running"""
        try:
            # Check if package is installed
            exit_code, output, _ = run_command("dpkg -l unattended-upgrades")
            installed = exit_code == 0
            
            if not installed:
                return {
                    'id': 'SYS-001',
                    'title': 'Unattended Upgrades Installed & Active',
                    'status': 'FAIL',
                    'severity': 'MEDIUM',
                    'description': 'Automatic security updates should be enabled',
                    'remediation': 'remediations/install_unattended_upgrades.sh',
                    'evidence': 'Package not installed'
                }
            
            # Check if service is active
            exit_code, service_output, _ = run_command("systemctl is-active unattended-upgrades")
            service_active = exit_code == 0 and 'active' in service_output.lower()
            
            # Check if service is enabled (starts on boot)
            exit_code, enabled_output, _ = run_command("systemctl is-enabled unattended-upgrades")
            service_enabled = exit_code == 0
            
            # Check if configuration exists
            config_exists = os.path.exists('/etc/apt/apt.conf.d/20auto-upgrades')
            
            if service_active and service_enabled and config_exists:
                return {
                    'id': 'SYS-001',
                    'title': 'Unattended Upgrades Installed & Active',
                    'status': 'PASS',
                    'severity': 'MEDIUM',
                    'description': 'Automatic security updates are enabled and running',
                    'remediation': 'remediations/install_unattended_upgrades.sh',
                    'evidence': 'Package installed, service active and enabled, configuration present'
                }
            elif installed:
                # Provide detailed evidence about what's missing
                evidence_parts = []
                if not service_active:
                    evidence_parts.append('service not active')
                if not service_enabled:
                    evidence_parts.append('service not enabled')
                if not config_exists:
                    evidence_parts.append('configuration missing')
                
                evidence = 'Package installed but: ' + ', '.join(evidence_parts)
                
                return {
                    'id': 'SYS-001',
                    'title': 'Unattended Upgrades Installed & Active',
                    'status': 'WARN',
                    'severity': 'MEDIUM',
                    'description': 'Package installed but service not fully configured',
                    'remediation': 'remediations/install_unattended_upgrades.sh',
                    'evidence': evidence
                }
            else:
                return {
                    'id': 'SYS-001',
                    'title': 'Unattended Upgrades Installed & Active',
                    'status': 'FAIL',
                    'severity': 'MEDIUM',
                    'description': 'Automatic security updates should be enabled',
                    'remediation': 'remediations/install_unattended_upgrades.sh',
                    'evidence': 'Unexpected state'
                }
                
        except Exception as e:
            return {
                'id': 'SYS-001',
                'title': 'Unattended Upgrades Installed & Active',
                'status': 'ERROR',
                'severity': 'MEDIUM',
                'description': f'Error checking automatic updates: {e}',
                'remediation': 'remediations/install_unattended_upgrades.sh',
                'evidence': f'Error: {e}'
            }
    
    def check_suid_files(self):
        """Check for unusual SUID files"""
        try:
            exit_code, output, error = run_command('find / -perm /4000 -type f 2>/dev/null | head -20')
            suid_files = [f for f in output.split('\n') if f and '/proc' not in f]
            
            # Common SUID files that are normal
            common_suid = ['/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/chsh', '/bin/mount', '/bin/umount', '/usr/bin/chfn', '/usr/bin/gpasswd', '/usr/bin/newgrp', '/bin/su']
            unusual_suid = [f for f in suid_files if f not in common_suid]
            
            status = 'PASS' if len(unusual_suid) == 0 else 'WARN'
            
            return {
                'id': 'FILE-001',
                'title': 'Unusual SUID Files',
                'status': status,
                'severity': 'MEDIUM',
                'description': 'Unusual SUID files can be security risks',
                'remediation': 'remediations/audit_suid_files.sh',
                'evidence': f'Found {len(unusual_suid)} unusual SUID files: {unusual_suid[:3]}' if unusual_suid else 'No unusual SUID files found'
            }
        except Exception as e:
            return {
                'id': 'FILE-001',
                'title': 'Unusual SUID Files',
                'status': 'ERROR',
                'severity': 'MEDIUM',
                'description': f'Error checking SUID files: {e}',
                'remediation': 'remediations/audit_suid_files.sh',
                'evidence': f'Error: {e}'
            }
    
    def check_world_writable_dirs(self):
        """Check for world-writable directories"""
        try:
            exit_code, output, error = run_command('find / -xdev -type d -perm -0002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/tmp/*" 2>/dev/null')
            world_writable = [f for f in output.split('\n') if f]
            
            status = 'PASS' if len(world_writable) == 0 else 'FAIL'
            
            return {
                'id': 'FILE-002',
                'title': 'World Writable Directories',
                'status': status,
                'severity': 'HIGH',
                'description': 'World writable directories outside /tmp are security risks',
                'remediation': 'remediations/secure_permissions.sh',
                'evidence': f'Found {len(world_writable)} world-writable directories: {world_writable[:3]}' if world_writable else 'No world-writable directories found'
            }
        except Exception as e:
            return {
                'id': 'FILE-002',
                'title': 'World Writable Directories',
                'status': 'ERROR',
                'severity': 'HIGH',
                'description': f'Error checking permissions: {e}',
                'remediation': 'remediations/secure_permissions.sh',
                'evidence': f'Error: {e}'
            }
    
    def check_password_policy(self):
        """Check password aging and complexity policies"""
        try:
            issues = []
            
            # Check PASS_MAX_DAYS (should be <= 90)
            exit_code, output, _ = run_command("grep PASS_MAX_DAYS /etc/login.defs")
            if exit_code == 0:
                for line in output.split('\n'):
                    if line.strip() and not line.startswith('#'):
                        max_days = line.split()[1]
                        if int(max_days) > 90:
                            issues.append(f"PASS_MAX_DAYS too long: {max_days} (should be <= 90)")
            
            # Check password history (should remember last 5 passwords)
            exit_code, output, _ = run_command("grep remember /etc/pam.d/common-password 2>/dev/null || echo 'not set'")
            if 'remember=5' not in output:
                issues.append("Password history not set to remember last 5 passwords")
            
            # Check minimum password length
            exit_code, output, _ = run_command("grep minlen /etc/pam.d/common-password 2>/dev/null || echo 'not set'")
            if 'minlen=' not in output:
                issues.append("Minimum password length not enforced")
            
            status = 'PASS' if not issues else 'FAIL'
            
            return {
                'id': 'AUTH-001',
                'title': 'Password Policy Enforcement',
                'status': status,
                'severity': 'MEDIUM',
                'description': 'Strong password policies should be enforced',
                'remediation': 'remediations/enforce_password_policy.sh',
                'evidence': 'All policies good' if not issues else '; '.join(issues)
            }
            
        except Exception as e:
            return {
                'id': 'AUTH-001',
                'title': 'Password Policy Enforcement',
                'status': 'ERROR',
                'severity': 'MEDIUM',
                'description': f'Error checking password policies: {e}',
                'remediation': 'remediations/enforce_password_policy.sh',
                'evidence': f'Error: {e}'
            }
    
    def check_sudo_config(self):
        """Check sudo security configuration"""
        try:
            issues = []
            
            # Check sudo timeout (should be 15 minutes or less)
            exit_code, output, _ = run_command("sudo -l | grep timestamp_timeout 2>/dev/null || echo 'not set'")
            if 'timestamp_timeout' in output:
                timeout_match = re.search(r'timestamp_timeout=(\d+)', output)
                if timeout_match:
                    timeout = int(timeout_match.group(1))
                    if timeout > 15:
                        issues.append(f"Sudo timeout too long: {timeout} minutes (should be <= 15)")
            
            # Check if root has a password
            exit_code, output, _ = run_command("sudo -n true 2>&1")
            if exit_code != 0 and "password is required" in output:
                issues.append("Sudo requires password (this is good)")
            else:
                issues.append("Sudo may not require password")
            
            # Check for unrestricted sudo access
            exit_code, output, _ = run_command("grep -r 'NOPASSWD' /etc/sudoers* 2>/dev/null || echo 'none found'")
            if 'NOPASSWD' in output and 'ALL' in output:
                issues.append("Unrestricted passwordless sudo access found")
            
            status = 'PASS' if not issues else 'WARN'
            
            return {
                'id': 'AUTH-002',
                'title': 'Sudo Security Configuration',
                'status': status,
                'severity': 'MEDIUM',
                'description': 'Sudo should be configured with security best practices',
                'remediation': 'remediations/secure_sudo.sh',
                'evidence': 'All configurations good' if not issues else '; '.join(issues)
            }
            
        except Exception as e:
            return {
                'id': 'AUTH-002',
                'title': 'Sudo Security Configuration',
                'status': 'ERROR',
                'severity': 'MEDIUM',
                'description': f'Error checking sudo configuration: {e}',
                'remediation': 'remediations/secure_sudo.sh',
                'evidence': f'Error: {e}'
            }
    
    def check_kernel_parameters(self):
        """Check important kernel security parameters"""
        try:
            issues = []
            
            # Check ICMP redirects (should be 0)
            exit_code, output, _ = run_command("sysctl net.ipv4.conf.all.accept_redirects")
            if '= 1' in output:
                issues.append("ICMP redirects accepted (should be 0)")
            
            # Check source route verification (should be 1)
            exit_code, output, _ = run_command("sysctl net.ipv4.conf.all.rp_filter")
            if '= 0' in output:
                issues.append("Reverse path filtering disabled (should be 1)")
            
            # Check ICMP broadcast (should be 0)
            exit_code, output, _ = run_command("sysctl net.ipv4.icmp_echo_ignore_broadcasts")
            if '= 0' in output:
                issues.append("ICMP broadcast replies enabled (should be 0)")
            
            # Check ASLR (should be 2 - full randomization)
            exit_code, output, _ = run_command("sysctl kernel.randomize_va_space")
            if '= 2' not in output:
                issues.append("ASLR not fully enabled (should be 2)")
            
            status = 'PASS' if not issues else 'FAIL'
            
            return {
                'id': 'KERN-001',
                'title': 'Kernel Security Parameters',
                'status': status,
                'severity': 'HIGH',
                'description': 'Kernel should have security-hardened parameters',
                'remediation': 'remediations/harden_kernel.sh',
                'evidence': 'All parameters secure' if not issues else '; '.join(issues)
            }
            
        except Exception as e:
            return {
                'id': 'KERN-001',
                'title': 'Kernel Security Parameters',
                'status': 'ERROR',
                'severity': 'HIGH',
                'description': f'Error checking kernel parameters: {e}',
                'remediation': 'remediations/harden_kernel.sh',
                'evidence': f'Error: {e}'
            }
    
    def check_ssh_protocol(self):
        """Check SSH protocol version and ciphers"""
        try:
            issues = []
            sshd_config = ""
            
            # Check SSH protocol version (should be 2 only)
            if os.path.exists('/etc/ssh/sshd_config'):
                with open('/etc/ssh/sshd_config', 'r') as f:
                    sshd_config = f.read()
                    if 'Protocol 1' in sshd_config:
                        issues.append("SSH Protocol 1 enabled (insecure)")
                    if 'Protocol 2' not in sshd_config and 'Protocol' not in sshd_config:
                        issues.append("SSH Protocol 2 not explicitly set")
            
            # Check for weak ciphers
            weak_ciphers = ['arcfour', 'cbc', 'md5']
            for cipher in weak_ciphers:
                if cipher in sshd_config.lower() and not cipher.startswith('#') and 'Ciphers' in sshd_config:
                    issues.append(f"Weak cipher potentially enabled: {cipher}")
            
            status = 'PASS' if not issues else 'WARN'
            
            return {
                'id': 'SSH-002',
                'title': 'SSH Protocol Security',
                'status': status,
                'severity': 'MEDIUM',
                'description': 'SSH should use secure protocols and ciphers',
                'remediation': 'remediations/harden_ssh.sh',
                'evidence': 'Protocol and ciphers secure' if not issues else '; '.join(issues)
            }
            
        except Exception as e:
            return {
                'id': 'SSH-002',
                'title': 'SSH Protocol Security',
                'status': 'ERROR',
                'severity': 'MEDIUM',
                'description': f'Error checking SSH protocol: {e}',
                'remediation': 'remediations/harden_ssh.sh',
                'evidence': f'Error: {e}'
            }
    
    def check_ip_forwarding(self):
        """Check if IP forwarding is disabled (unless router)"""
        try:
            exit_code, output, _ = run_command("sysctl net.ipv4.ip_forward")
            
            if '= 1' in output:
                return {
                    'id': 'NET-002',
                    'title': 'IP Forwarding Disabled',
                    'status': 'WARN',
                    'severity': 'MEDIUM',
                    'description': 'IP forwarding should be disabled on workstations',
                    'remediation': 'remediations/disable_ip_forwarding.sh',
                    'evidence': 'IP forwarding enabled (OK if this is a router)'
                }
            else:
                return {
                    'id': 'NET-002',
                    'title': 'IP Forwarding Disabled',
                    'status': 'PASS',
                    'severity': 'MEDIUM',
                    'description': 'IP forwarding should be disabled on workstations',
                    'remediation': 'remediations/disable_ip_forwarding.sh',
                    'evidence': 'IP forwarding disabled'
                }
                
        except Exception as e:
            return {
                'id': 'NET-002',
                'title': 'IP Forwarding Disabled',
                'status': 'ERROR',
                'severity': 'MEDIUM',
                'description': f'Error checking IP forwarding: {e}',
                'remediation': 'remediations/disable_ip_forwarding.sh',
                'evidence': f'Error: {e}'
            }
    
    # PRIORITY 1 CYBERSECURITY CHECKS
    
    def check_failed_logins(self):
        """Monitor failed login attempts for brute force detection"""
        try:
            # Check multiple auth log files
            auth_files = []
            if os.path.exists('/var/log/auth.log'):
                auth_files.append('/var/log/auth.log')
            
            # Add rotated logs
            for rotated_log in glob.glob('/var/log/auth.log.*'):
                if rotated_log.endswith('.gz'):
                    # Handle gzipped logs
                    exit_code, output, _ = run_command(f"zcat {rotated_log} | grep 'Failed password' | wc -l")
                    if exit_code == 0:
                        auth_files.append(rotated_log)
                else:
                    # Regular log files
                    auth_files.append(rotated_log)
            
            total_failed = 0
            for auth_file in auth_files[:3]:  # Check last 3 log files
                if auth_file.endswith('.gz'):
                    exit_code, output, _ = run_command(f"zcat {auth_file} 2>/dev/null | grep 'Failed password' | wc -l")
                else:
                    exit_code, output, _ = run_command(f"grep 'Failed password' {auth_file} 2>/dev/null | wc -l")
                
                if exit_code == 0:
                    total_failed += int(output.strip())
            
            if total_failed > 100:
                status = 'FAIL'
                evidence = f"🚨 CRITICAL: {total_failed} failed login attempts (likely brute force attack)"
                severity = 'HIGH'
            elif total_failed > 30:
                status = 'WARN'
                evidence = f"⚠️ Warning: {total_failed} failed login attempts (suspicious activity)"
                severity = 'MEDIUM'
            elif total_failed > 0:
                status = 'PASS'
                evidence = f"✅ Normal: {total_failed} failed login attempts"
                severity = 'LOW'
            else:
                status = 'PASS'
                evidence = "✅ No failed login attempts detected"
                severity = 'LOW'
            
            return {
                'id': 'AUTH-003',
                'title': 'Failed Login Monitoring',
                'status': status,
                'severity': severity,
                'description': 'Monitor and detect brute force attack attempts in authentication logs',
                'remediation': 'remediations/configure_fail2ban.sh',
                'evidence': evidence
            }
            
        except Exception as e:
            return {
                'id': 'AUTH-003',
                'title': 'Failed Login Monitoring',
                'status': 'ERROR',
                'severity': 'MEDIUM',
                'description': 'Monitor and detect brute force attack attempts',
                'remediation': 'remediations/configure_fail2ban.sh',
                'evidence': f'Error checking failed logins: {str(e)}'
            }
    
    def check_suspicious_processes(self):
        """Detect crypto miners, malware, and suspicious processes"""
        try:
            # Known suspicious process patterns
            suspicious_patterns = [
                # Crypto miners
                'xmrig', 'cpuminer', 'ccminer', 'minerd', 'miner', 'crypto', 'monero',
                # Common malware indicators
                'kinsing', 'kdevtmpfsi', 'watchdogs', 'masscan', 'sqlmap',
                # Unusual names that might be hidden malware
                'udevd', 'kthreadd', 'kworker', '[kworker]', 'flush',
                # Network scanners and tools
                'nmap', 'metasploit', 'hydra', 'john', 'hashcat'
            ]
            
            suspicious_found = []
            
            for process in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                try:
                    process_info = process.info
                    process_name = process_info['name'].lower() if process_info['name'] else ''
                    cmdline = ' '.join(process_info['cmdline']) if process_info['cmdline'] else ''
                    
                    # Check for suspicious patterns in name or command line
                    for pattern in suspicious_patterns:
                        if pattern in process_name or pattern in cmdline.lower():
                            # Skip if it's a system process with legitimate use
                            if not self._is_legitimate_system_process(process_name, cmdline):
                                suspicious_found.append({
                                    'pid': process_info['pid'],
                                    'name': process_info['name'],
                                    'cmdline': cmdline[:100] + '...' if len(cmdline) > 100 else cmdline,
                                    'user': process_info['username']
                                })
                                break  # Don't duplicate entries
                                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if suspicious_found:
                # Limit output to first 3 suspicious processes
                evidence_list = [f"{p['name']} (PID:{p['pid']}, User:{p['user']})" for p in suspicious_found[:3]]
                evidence = f"🚨 Found {len(suspicious_found)} suspicious processes: {', '.join(evidence_list)}"
                
                return {
                    'id': 'THREAT-001',
                    'title': 'Suspicious Processes Detection',
                    'status': 'FAIL',
                    'severity': 'HIGH',
                    'description': 'Detection of cryptocurrency miners, malware, and suspicious processes',
                    'remediation': 'remediations/investigate_suspicious_processes.sh',
                    'evidence': evidence
                }
            else:
                return {
                    'id': 'THREAT-001',
                    'title': 'Suspicious Processes Detection',
                    'status': 'PASS',
                    'severity': 'HIGH',
                    'description': 'Detection of cryptocurrency miners, malware, and suspicious processes',
                    'remediation': 'remediations/investigate_suspicious_processes.sh',
                    'evidence': '✅ No suspicious processes detected'
                }
                
        except Exception as e:
            return {
                'id': 'THREAT-001',
                'title': 'Suspicious Processes Detection',
                'status': 'ERROR',
                'severity': 'HIGH',
                'description': 'Detection of cryptocurrency miners, malware, and suspicious processes',
                'remediation': 'remediations/investigate_suspicious_processes.sh',
                'evidence': f'Error scanning processes: {str(e)}'
            }
    
    def _is_legitimate_system_process(self, process_name, cmdline):
        """Check if a process is a legitimate system process"""
        legitimate_indicators = [
            '/usr/bin/nmap',  # Legitimate security tool
            '/opt/metasploit',  # Legitimate security tool
            'systemd',  # System process
            'kernel'  # Kernel process
        ]
        
        for indicator in legitimate_indicators:
            if indicator in cmdline:
                return True
        
        return False
    
    def check_open_ports(self):
        """Identify unnecessary open ports and services"""
        try:
            # Get all listening ports
            exit_code, output, _ = run_command("ss -tuln | grep LISTEN")
            
            if exit_code != 0:
                return {
                    'id': 'NET-003',
                    'title': 'Unnecessary Open Ports',
                    'status': 'ERROR',
                    'severity': 'MEDIUM',
                    'description': 'Identify unnecessary open network ports',
                    'remediation': 'remediations/close_unused_ports.sh',
                    'evidence': 'Could not retrieve listening ports'
                }
            
            listening_ports = []
            safe_ports = ['22', '80', '443', '53']  # Common safe ports (SSH, HTTP, HTTPS, DNS)
            
            for line in output.split('\n'):
                if 'LISTEN' in line:
                    # Extract port number
                    port_match = re.search(r':(\d+)\s', line)
                    if port_match:
                        port = port_match.group(1)
                        protocol = 'tcp' if 'tcp' in line else 'udp'
                        
                        # Check if port is unnecessary
                        if port not in safe_ports:
                            # Get process info for the port
                            process_exit, process_out, _ = run_command(f"lsof -i :{port} | grep LISTEN | head -1")
                            process_info = process_out.strip() if process_exit == 0 else "Unknown process"
                            
                            listening_ports.append({
                                'port': port,
                                'protocol': protocol,
                                'process': process_info
                            })
            
            if listening_ports:
                # Format evidence
                port_details = []
                for port_info in listening_ports[:5]:  # Show first 5
                    port_details.append(f"{port_info['port']}/{port_info['protocol']}")
                
                evidence = f"🚨 Found {len(listening_ports)} unnecessary open ports: {', '.join(port_details)}"
                
                # Show process info for first port
                if listening_ports[0]['process']:
                    evidence += f" | Process: {listening_ports[0]['process'][:50]}"
                
                return {
                    'id': 'NET-003',
                    'title': 'Unnecessary Open Ports',
                    'status': 'FAIL',
                    'severity': 'HIGH',
                    'description': 'Close unnecessary network ports to reduce attack surface',
                    'remediation': 'remediations/close_unused_ports.sh',
                    'evidence': evidence
                }
            else:
                return {
                    'id': 'NET-003',
                    'title': 'Unnecessary Open Ports',
                    'status': 'PASS',
                    'severity': 'HIGH',
                    'description': 'Close unnecessary network ports to reduce attack surface',
                    'remediation': 'remediations/close_unused_ports.sh',
                    'evidence': '✅ No unnecessary open ports detected'
                }
                
        except Exception as e:
            return {
                'id': 'NET-003',
                'title': 'Unnecessary Open Ports',
                'status': 'ERROR',
                'severity': 'HIGH',
                'description': 'Close unnecessary network ports to reduce attack surface',
                'remediation': 'remediations/close_unused_ports.sh',
                'evidence': f'Error scanning ports: {str(e)}'
            }
    
    def check_cve_vulnerabilities(self):
        """Check for outdated packages with known vulnerabilities"""
        try:
            # Get upgradable packages
            exit_code, output, _ = run_command("apt list --upgradable 2>/dev/null")
            
            if exit_code != 0:
                return {
                    'id': 'VULN-001',
                    'title': 'CVE Vulnerability Assessment',
                    'status': 'ERROR',
                    'severity': 'HIGH',
                    'description': 'Check for packages with known CVEs that need updates',
                    'remediation': 'remediations/update_vulnerable_packages.sh',
                    'evidence': 'Could not check for upgradable packages'
                }
            
            upgradable_packages = []
            lines = output.strip().split('\n')
            
            # Skip the first line (header)
            for line in lines[1:]:
                if line.strip():
                    # Extract package name (everything before /)
                    package_match = re.match(r'^([^/]+)/', line)
                if package_match:
                    package_name = package_match.group(1)
                    upgradable_packages.append(package_name)
            
            # Check for critical packages that should always be updated
            critical_packages = ['openssl', 'openssh', 'linux-', 'kernel', 'libc', 'systemd']
            critical_updates = []
            
            for package in upgradable_packages:
                for critical in critical_packages:
                    if critical in package.lower():
                        critical_updates.append(package)
                        break
            
            if critical_updates:
                evidence = f"🚨 CRITICAL: {len(critical_updates)} security updates available for: {', '.join(critical_updates[:3])}"
                status = 'FAIL'
                severity = 'HIGH'
            elif upgradable_packages:
                evidence = f"⚠️ Warning: {len(upgradable_packages)} packages need updates (may contain CVEs)"
                status = 'WARN'
                severity = 'MEDIUM'
            else:
                evidence = "✅ All packages are up to date"
                status = 'PASS'
                severity = 'LOW'
            
            return {
                'id': 'VULN-001',
                'title': 'CVE Vulnerability Assessment',
                'status': status,
                'severity': severity,
                'description': 'Check for outdated packages with known Common Vulnerabilities and Exposures (CVEs)',
                'remediation': 'remediations/update_vulnerable_packages.sh',
                'evidence': evidence
            }
            
        except Exception as e:
            return {
                'id': 'VULN-001',
                'title': 'CVE Vulnerability Assessment',
                'status': 'ERROR',
                'severity': 'HIGH',
                'description': 'Check for outdated packages with known Common Vulnerabilities and Exposures (CVEs)',
                'remediation': 'remediations/update_vulnerable_packages.sh',
                'evidence': f'Error checking vulnerabilities: {str(e)}'
            }
