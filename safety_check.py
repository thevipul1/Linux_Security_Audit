#!/usr/bin/env python3
import os
import sys

def safety_checks():
    """Perform safety checks before remediation"""
    print("🔒 Performing safety checks...")
    
    checks = {
        "Running as root": os.geteuid() == 0,
        "In project directory": os.path.exists("remediations/ssh_disable_root.sh"),
        "Remediation scripts executable": all(
            os.access(f"remediations/{script}", os.X_OK) 
            for script in ["ssh_disable_root.sh", "ufw_enable.sh"]
        )
    }
    
    all_ok = True
    for check, result in checks.items():
        status = "✅" if result else "❌"
        print(f"  {status} {check}")
        if not result:
            all_ok = False
    
    if not all_ok:
        print("\n⚠️  Safety checks failed! Please fix issues before proceeding.")
        return False
    
    print("\n✅ All safety checks passed!")
    return True

def show_planned_changes():
    """Show what changes will be made"""
    print("\n📋 PLANNED CHANGES:")
    print("1. SSH: Disable root login (creates backup first)")
    print("2. Firewall: Enable UFW with SSH allowed") 
    print("3. Updates: Install automatic security updates")
    print("4. Services: Will reload SSH after changes")
    
    print("\n⚠️  WARNING: These changes will modify system configuration!")
    print("   Make sure you have alternative access (just in case)")

if __name__ == "__main__":
    if safety_checks():
        show_planned_changes()
        
        response = input("\n❓ Do you want to proceed with remediation? (yes/no): ")
        if response.lower() in ['yes', 'y']:
            print("🚀 Starting remediation...")
            os.system("sudo python3 main.py --remediate")
        else:
            print("❌ Remediation cancelled.")
