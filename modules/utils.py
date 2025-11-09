import subprocess
import shlex
import logging

def run_command(cmd, timeout=30):
    """Execute shell command safely"""
    try:
        result = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out: {cmd}")
        return -1, "", "Command timed out"
    except Exception as e:
        logging.error(f"Error running command {cmd}: {e}")
        return -1, "", str(e)

def is_root():
    """Check if running as root"""
    import os
    return os.geteuid() == 0
