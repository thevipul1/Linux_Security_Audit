#!/usr/bin/env python3
import argparse
import sys
import logging
import os
from modules.scanner import SecurityScanner
from modules.reporter import ReportGenerator
from modules.remediator import RemediationEngine

def setup_logging():
    """Setup logging configuration"""
    os.makedirs("outputs/logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('outputs/logs/audit.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def main():
    parser = argparse.ArgumentParser(description='Linux Security Audit Tool')
    parser.add_argument('--scan', action='store_true', help='Run security scan')
    parser.add_argument('--remediate', action='store_true', help='Apply fixes')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be fixed')
    parser.add_argument('--format', choices=['text', 'html', 'json'], default='text')
    parser.add_argument('--output', help='Output file path')
    
    args = parser.parse_args()
    
    if not any([args.scan, args.remediate]):
        parser.print_help()
        sys.exit(1)
    
    setup_logging()
    logger = logging.getLogger(__name__)
    
    try:
        scan_results = None
        
        if args.scan:
            logger.info("Starting security scan...")
            scanner = SecurityScanner()
            scan_results = scanner.run_all_checks()
            
            reporter = ReportGenerator()
            report = reporter.generate(scan_results, args.format, args.output)
            
            logger.info(f"Scan completed. Report: {report}")
            
        if args.remediate:
            logger.info("Starting remediation...")
            remediator = RemediationEngine(dry_run=args.dry_run)
            
            # Use scan results if available, otherwise generate basic hardening
            if scan_results:
                fixes = remediator.apply_fixes(scan_results)
                logger.info(f"Remediation completed. Applied {len(fixes)} fixes.")
            else:
                logger.info("No scan results available, generating basic hardening script...")
                remediator.generate_basic_hardening()
                
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
