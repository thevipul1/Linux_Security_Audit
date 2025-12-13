#!/bin/bash
# Investigate and handle suspicious processes
set -e

echo "🔍 Investigating suspicious processes..."
echo "======================================="

# Get suspicious processes
echo "📊 Current running processes that might be suspicious:"

# Crypto miners
echo "1. Checking for crypto miners..."
ps aux | grep -E '(xmrig|cpuminer|ccminer|minerd|monero)' | grep -v grep || echo "No crypto miners found"

# Suspicious hidden processes
echo ""
echo "2. Checking for hidden processes..."
ps aux | awk '{print $2, $11}' | grep -E '(\[|\])' || echo "No hidden processes found"

# High CPU processes
echo ""
echo "3. Checking high CPU usage processes..."
ps aux --sort=-%cpu | head -10 | awk '{print $2, $11, $3"% CPU"}' 

# Network connections of suspicious processes
echo ""
echo "4. Checking network connections..."
netstat -tunap 2>/dev/null | grep ESTABLISHED | head -10

echo ""
echo "🛡️ Recommended actions:"
echo "   • Investigate high CPU processes above"
echo "   • Check network connections for unknown services"
echo "   • Use: lsof -p PID to see files opened by suspicious process"
echo "   • Use: kill -9 PID to terminate confirmed malicious processes"
echo ""
echo "🔧 For advanced analysis:"
echo "   • Install and run: chkrootkit"
echo "   • Install and run: rkhunter"
echo "   • Use: strace -p PID to trace process system calls"
