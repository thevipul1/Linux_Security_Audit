import subprocess
import json
import os
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
        """Check if unattended-upgrades is installed"""
        try:
            exit_code, output, error = run_command('dpkg -l | grep unattended-upgrades')
            status = 'PASS' if exit_code == 0 else 'FAIL'
            
            return {
                'id': 'SYS-001',
                'title': 'Unattended Upgrades Installed',
                'status': status,
                'severity': 'MEDIUM',
                'description': 'Automatic security updates should be enabled',
                'remediation': 'remediations/install_unattended_upgrades.sh',
                'evidence': 'Installed' if status == 'PASS' else 'Not installed'
            }
        except Exception as e:
            return {
                'id': 'SYS-001',
                'title': 'Unattended Upgrades Installed',
                'status': 'ERROR',
                'severity': 'MEDIUM',
                'description': f'Error checking packages: {e}',
                'remediation': 'remediations/install_unattended_upgrades.sh',
                'evidence': f'Error: {e}'
            }
    
    def check_suid_files(self):
        """Check for unusual SUID files"""
        try:
            exit_code, output, error = run_command('find / -perm /4000 -type f 2>/dev/null | head -20')
            suid_files = [f for f in output.split('\n') if f and '/proc' not in f]
            
            # Common SUID files that are normal
            common_suid = ['/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/chsh', '/bin/mount']
            unusual_suid = [f for f in suid_files if f not in common_suid]
            
            status = 'PASS' if len(unusual_suid) == 0 else 'WARN'
            
            return {
                'id': 'FILE-001',
                'title': 'Unusual SUID Files',
                'status': status,
                'severity': 'MEDIUM',
                'description': 'Unusual SUID files can be security risks',
                'remediation': 'remediations/audit_suid_files.sh',
                'evidence': f'Found {len(unusual_suid)} unusual SUID files: {unusual_suid[:5]}'
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
            exit_code, output, error = run_command('find / -xdev -type d -perm -0002 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null')
            world_writable = [f for f in output.split('\n') if f and f != '/tmp']
            
            status = 'PASS' if len(world_writable) == 0 else 'FAIL'
            
            return {
                'id': 'FILE-002',
                'title': 'World Writable Directories',
                'status': status,
                'severity': 'HIGH',
                'description': 'World writable directories outside /tmp are security risks',
                'remediation': 'remediations/secure_permissions.sh',
                'evidence': f'Found {len(world_writable)} world-writable directories: {world_writable[:5]}'
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
