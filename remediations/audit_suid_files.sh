#!/bin/bash
# Audit and secure SUID files
set -e

echo "Auditing SUID files..."

# Create backup of current SUID files
BACKUP_FILE="/var/tmp/suid_files.backup.$(date +%Y%m%d_%H%M%S)"
find / -perm /4000 -type f 2>/dev/null > "$BACKUP_FILE"
echo "SUID files backup created: $BACKUP_FILE"

# List unusual SUID files (excluding common ones)
echo "Current SUID files:"
find / -perm /4000 -type f 2>/dev/null | grep -v -E "^/(proc|sys|dev)|/usr/bin/sudo|/usr/bin/passwd|/usr/bin/chsh|/bin/mount|/bin/umount"

echo "SUID audit completed. Review the list above for unusual files."
