#!/usr/bin/env python3
import sys
import os
import json

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.scanner import SecurityScanner
from modules.reporter import ReportGenerator

def main():
    print("🔍 Debugging JSON report generation...")
    
    # Test scanner
    scanner = SecurityScanner()
    results = scanner.run_all_checks()
    print(f"✅ Scanner returned {len(results)} results")
    
    # Test reporter
    reporter = ReportGenerator()
    
    # Test JSON generation
    try:
        json_report = reporter._generate_json(results, "2025-11-04T10:00:00")
        print("✅ JSON generation successful")
        print(f"JSON length: {len(json_report)} characters")
        
        # Try to parse the JSON to validate it
        parsed = json.loads(json_report)
        print("✅ JSON is valid and parsable")
        
        # Save the report
        output_file = "outputs/reports/debug_scan.json"
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w') as f:
            f.write(json_report)
        print(f"✅ JSON report saved to: {output_file}")
        
        # Show file permissions
        import subprocess
        result = subprocess.run(['ls', '-la', output_file], capture_output=True, text=True)
        print(f"File permissions: {result.stdout}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
