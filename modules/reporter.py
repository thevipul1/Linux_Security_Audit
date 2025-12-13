import json
import os
import tempfile
from datetime import datetime
from jinja2 import Template

class ReportGenerator:
    def generate(self, results, format='text', output_file=None):
        """Generate report in specified format"""
        timestamp = datetime.now().isoformat()
        
        if format == 'json':
            report = self._generate_json(results, timestamp)
        elif format == 'html':
            report = self._generate_html(results, timestamp)
        else:
            report = self._generate_text(results, timestamp)
        
        if output_file:
            self._safe_write_file(report, output_file)
            return output_file
        
        return report
    
    def _safe_write_file(self, content, output_file):
        """Safely write file with proper permissions"""
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
        
        # Write to a temporary file first
        temp_dir = os.path.dirname(output_file) or '.'
        with tempfile.NamedTemporaryFile(mode='w', dir=temp_dir, delete=False, encoding='utf-8') as f:
            f.write(content)
            temp_path = f.name
        
        # Move to final location
        os.replace(temp_path, output_file)
        
        # Set readable permissions (644: owner read/write, others read)
        os.chmod(output_file, 0o644)
        
        # Try to change ownership to current user if we're root
        self._fix_file_ownership(output_file)
    
    def _fix_file_ownership(self, file_path):
        """Fix file ownership to current user if running as root"""
        try:
            if os.geteuid() == 0:  # Running as root
                import pwd
                # Get the original user from SUDO_USER environment variable
                original_user = os.environ.get('SUDO_USER')
                if original_user:
                    uid = pwd.getpwnam(original_user).pw_uid
                    gid = pwd.getpwnam(original_user).pw_gid
                    os.chown(file_path, uid, gid)
                    print(f"✅ Fixed ownership for {file_path} to user {original_user}")
        except (ImportError, KeyError, OSError) as e:
            # If we can't change ownership, just continue
            print(f"⚠️  Could not change file ownership: {e}")
    
    def _generate_text(self, results, timestamp):
        """Generate text report"""
        report = f"Security Audit Report - {timestamp}\n"
        report += "=" * 50 + "\n\n"
        
        for result in results:
            status_icon = "✅" if result['status'] == 'PASS' else "❌" if result['status'] == 'FAIL' else "⚠️"
            report += f"{status_icon} {result['id']}: {result['title']}\n"
            report += f"   Status: {result['status']} | Severity: {result['severity']}\n"
            report += f"   Evidence: {result['evidence']}\n"
            if result['status'] in ['FAIL', 'WARN']:
                report += f"   Fix: {result['remediation']}\n"
            report += "\n"
        
        # Summary
        passed = len([r for r in results if r['status'] == 'PASS'])
        failed = len([r for r in results if r['status'] == 'FAIL'])
        warnings = len([r for r in results if r['status'] == 'WARN'])
        
        security_score = self._calculate_security_score(results)
        
        report += f"\nSummary: {passed} passed, {failed} failed, {warnings} warnings\n"
        report += f"Security Score: {security_score}/100\n"
        return report
    
    def _generate_json(self, results, timestamp):
        """Generate JSON report"""
        report_data = {
            'metadata': {
                'timestamp': timestamp,
                'tool': 'Linux Security Audit Tool',
                'version': '2.0',
                'audit_scope': 'Comprehensive System Security Assessment',
                'compliance_frameworks': ['CIS', 'NIST', 'ISO27001']
            },
            'summary': {
                'total_checks': len(results),
                'passed': len([r for r in results if r['status'] == 'PASS']),
                'failed': len([r for r in results if r['status'] == 'FAIL']),
                'warnings': len([r for r in results if r['status'] == 'WARN']),
                'error': len([r for r in results if r['status'] == 'ERROR']),
                'security_score': self._calculate_security_score(results),
                'risk_level': self._get_risk_level(self._calculate_security_score(results)),
                'compliance_score': self._calculate_compliance_score(results),
                'priority_breakdown': self._get_priority_breakdown(results)
            },
            'results': results,
            'recommendations': self._generate_recommendations(results)
        }
        return json.dumps(report_data, indent=2, ensure_ascii=False)
    
    def _calculate_security_score(self, results):
        """Calculate overall security score (0-100)"""
        if not results:
            return 0
        
        total_weight = 0
        weighted_score = 0
        
        severity_weights = {
            'CRITICAL': 5,
            'HIGH': 4,
            'MEDIUM': 3, 
            'LOW': 2,
            'INFO': 1
        }
        
        for result in results:
            weight = severity_weights.get(result.get('severity', 'LOW'), 1)
            total_weight += weight
            
            if result['status'] == 'PASS':
                weighted_score += weight
            elif result['status'] == 'WARN':
                weighted_score += weight * 0.7
            elif result['status'] == 'ERROR':
                weighted_score += weight * 0.3
        
        if total_weight == 0:
            return 100
        
        return round((weighted_score / total_weight) * 100, 1)
    
    def _calculate_compliance_score(self, results):
        """Calculate compliance score based on passed security controls"""
        if not results:
            return 0
        
        passed_controls = len([r for r in results if r['status'] == 'PASS'])
        total_controls = len(results)
        
        return round((passed_controls / total_controls) * 100, 1)
    
    def _get_priority_breakdown(self, results):
        """Get priority breakdown for remediation"""
        critical_failed = len([r for r in results if r['severity'] == 'CRITICAL' and r['status'] in ['FAIL', 'WARN']])
        high_failed = len([r for r in results if r['severity'] == 'HIGH' and r['status'] in ['FAIL', 'WARN']])
        medium_failed = len([r for r in results if r['severity'] == 'MEDIUM' and r['status'] in ['FAIL', 'WARN']])
        low_failed = len([r for r in results if r['severity'] == 'LOW' and r['status'] in ['FAIL', 'WARN']])
        
        return {
            'critical': critical_failed,
            'high': high_failed,
            'medium': medium_failed,
            'low': low_failed
        }
    
    def _get_risk_level(self, score):
        """Get risk level based on security score"""
        if score >= 90:
            return "LOW"
        elif score >= 75:
            return "MEDIUM"
        elif score >= 60:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def _generate_recommendations(self, results):
        """Generate automated recommendations based on findings"""
        recommendations = []
        
        failed_critical = len([r for r in results if r['severity'] == 'CRITICAL' and r['status'] == 'FAIL'])
        failed_high = len([r for r in results if r['severity'] == 'HIGH' and r['status'] == 'FAIL'])
        
        if failed_critical > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'title': 'Immediate Critical Issues',
                'description': f'Address {failed_critical} critical security issues immediately',
                'action': 'Review and remediate all critical findings within 24 hours'
            })
        
        if failed_high > 0:
            recommendations.append({
                'priority': 'HIGH',
                'title': 'High Severity Remediation',
                'description': f'Resolve {failed_high} high severity findings',
                'action': 'Schedule remediation within 7 days'
            })
        
        # Add general recommendations
        recommendations.extend([
            {
                'priority': 'MEDIUM',
                'title': 'Security Monitoring',
                'description': 'Implement continuous security monitoring',
                'action': 'Deploy SIEM solution and enable real-time alerts'
            },
            {
                'priority': 'LOW',
                'title': 'Documentation Update',
                'description': 'Update security policies and procedures',
                'action': 'Review and refresh security documentation quarterly'
            }
        ])
        
        return recommendations
    
    def _generate_html(self, results, timestamp):
        """Generate modern HTML report with enterprise-grade features and animations"""
        template_str = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Security Audit Report - CyberShield v2.0</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/apexcharts"></script>
    <style>
        :root {
            --primary: #0066cc;
            --primary-dark: #004499;
            --primary-light: #4d94ff;
            --success: #00cc66;
            --warning: #ff9900;
            --danger: #ff3333;
            --critical: #cc0000;
            --info: #66ccff;
            --dark: #1a1a1a;
            --darker: #0d0d0d;
            --light: #f8f9fa;
            --lighter: #ffffff;
            --gray: #6c757d;
            --border: #dee2e6;
            --sidebar: #2c3e50;
            --sidebar-hover: #34495e;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', 'SF Pro Display', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #0c0c0c 0%, #1a1a2e 50%, #16213e 100%);
            min-height: 100vh;
            color: var(--lighter);
            line-height: 1.6;
            overflow-x: hidden;
        }
        
        .cyber-grid {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px),
                linear-gradient(180deg, rgba(255,255,255,0.03) 1px, transparent 1px);
            background-size: 20px 20px;
            pointer-events: none;
            z-index: -1;
            animation: gridMove 20s linear infinite;
        }
        
        @keyframes gridMove {
            0% { transform: translate(0, 0); }
            100% { transform: translate(20px, 20px); }
        }
        
        .glow-effect {
            position: fixed;
            top: 50%;
            left: 50%;
            width: 500px;
            height: 500px;
            background: radial-gradient(circle, var(--primary-light) 0%, transparent 70%);
            opacity: 0.1;
            filter: blur(50px);
            transform: translate(-50%, -50%);
            z-index: -1;
            animation: glowPulse 8s ease-in-out infinite;
        }
        
        @keyframes glowPulse {
            0%, 100% { opacity: 0.05; transform: translate(-50%, -50%) scale(1); }
            50% { opacity: 0.15; transform: translate(-50%, -50%) scale(1.2); }
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
            background: rgba(13, 17, 28, 0.95);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 24px;
            box-shadow: 
                0 25px 50px -12px rgba(0, 0, 0, 0.5),
                0 0 0 1px rgba(255, 255, 255, 0.05),
                inset 0 1px 0 rgba(255, 255, 255, 0.1);
            overflow: hidden;
            margin: 20px;
            position: relative;
            animation: containerSlideIn 0.8s ease-out;
        }
        
        @keyframes containerSlideIn {
            0% { opacity: 0; transform: translateY(30px); }
            100% { opacity: 1; transform: translateY(0); }
        }
        
        .header {
            background: linear-gradient(135deg, 
                rgba(0, 102, 204, 0.9) 0%, 
                rgba(0, 68, 153, 0.8) 50%, 
                rgba(13, 17, 28, 0.9) 100%);
            padding: 40px;
            position: relative;
            overflow: hidden;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(circle at 20% 80%, rgba(77, 148, 255, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(0, 204, 102, 0.2) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(255, 51, 51, 0.15) 0%, transparent 50%);
            animation: pulse 8s ease-in-out infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 0.5; transform: scale(1); }
            50% { opacity: 0.8; transform: scale(1.05); }
        }
        
        .header-content {
            position: relative;
            z-index: 2;
            text-align: center;
            animation: headerContentFade 1s ease-out 0.3s both;
        }
        
        @keyframes headerContentFade {
            0% { opacity: 0; transform: translateY(20px); }
            100% { opacity: 1; transform: translateY(0); }
        }
        
        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .logo-icon {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: white;
            box-shadow: 0 8px 20px rgba(0, 102, 204, 0.4);
            animation: logoSpin 15s linear infinite;
        }
        
        @keyframes logoSpin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .header h1 {
            font-size: 3em;
            font-weight: 800;
            background: linear-gradient(135deg, #ffffff 0%, #a0c8ff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
            letter-spacing: -0.5px;
            animation: titleGlow 3s ease-in-out infinite alternate;
        }
        
        @keyframes titleGlow {
            0% { text-shadow: 0 0 10px rgba(160, 200, 255, 0.5); }
            100% { text-shadow: 0 0 20px rgba(160, 200, 255, 0.8), 0 0 30px rgba(160, 200, 255, 0.6); }
        }
        
        .header-subtitle {
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 10px;
            font-weight: 300;
        }
        
        .timestamp {
            font-size: 0.9em;
            opacity: 0.7;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: 300px 1fr;
            min-height: 100vh;
        }
        
        .sidebar {
            background: rgba(25, 30, 45, 0.9);
            border-right: 1px solid rgba(255, 255, 255, 0.1);
            padding: 30px 20px;
            backdrop-filter: blur(10px);
            animation: sidebarSlideIn 0.6s ease-out 0.2s both;
        }
        
        @keyframes sidebarSlideIn {
            0% { opacity: 0; transform: translateX(-20px); }
            100% { opacity: 1; transform: translateX(0); }
        }
        
        .nav-section {
            margin-bottom: 30px;
        }
        
        .nav-title {
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--primary-light);
            margin-bottom: 15px;
            font-weight: 600;
        }
        
        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 15px;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-bottom: 5px;
            color: var(--light);
            text-decoration: none;
            position: relative;
            overflow: hidden;
        }
        
        .nav-item::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
            transition: left 0.5s;
        }
        
        .nav-item:hover::before, .nav-item.active::before {
            left: 100%;
        }
        
        .nav-item:hover, .nav-item.active {
            background: rgba(0, 102, 204, 0.2);
            color: var(--primary-light);
            transform: translateX(5px);
        }
        
        .nav-item i {
            width: 20px;
            text-align: center;
        }
        
        .main-content {
            padding: 30px;
            background: rgba(13, 17, 28, 0.8);
            animation: mainContentFade 0.8s ease-out 0.4s both;
        }
        
        @keyframes mainContentFade {
            0% { opacity: 0; }
            100% { opacity: 1; }
        }
        
        .overview-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .overview-card {
            background: rgba(25, 30, 45, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 25px;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
            animation: cardSlideUp 0.6s ease-out both;
        }
        
        .overview-card:nth-child(1) { animation-delay: 0.5s; }
        .overview-card:nth-child(2) { animation-delay: 0.6s; }
        .overview-card:nth-child(3) { animation-delay: 0.7s; }
        .overview-card:nth-child(4) { animation-delay: 0.8s; }
        
        @keyframes cardSlideUp {
            0% { opacity: 0; transform: translateY(30px); }
            100% { opacity: 1; transform: translateY(0); }
        }
        
        .overview-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--primary) 0%, var(--primary-light) 100%);
        }
        
        .overview-card.critical::before { background: linear-gradient(90deg, var(--critical) 0%, #ff6666 100%); }
        .overview-card.high::before { background: linear-gradient(90deg, var(--danger) 0%, #ff6666 100%); }
        .overview-card.medium::before { background: linear-gradient(90deg, var(--warning) 0%, #ffcc66 100%); }
        .overview-card.low::before { background: linear-gradient(90deg, var(--success) 0%, #66ff99 100%); }
        
        .overview-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.3);
        }
        
        .card-header {
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .card-icon {
            width: 50px;
            height: 50px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            background: rgba(255, 255, 255, 0.1);
            transition: all 0.3s ease;
        }
        
        .overview-card:hover .card-icon {
            transform: scale(1.1) rotate(5deg);
        }
        
        .card-value {
            font-size: 2.5em;
            font-weight: 800;
            margin: 10px 0;
            background: linear-gradient(135deg, #ffffff 0%, #a0c8ff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            transition: all 0.3s ease;
        }
        
        .overview-card:hover .card-value {
            transform: scale(1.05);
        }
        
        .card-label {
            color: var(--gray);
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .score-section {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 30px;
            margin-bottom: 40px;
        }
        
        .score-card {
            background: linear-gradient(135deg, rgba(25, 30, 45, 0.8) 0%, rgba(40, 45, 60, 0.8) 100%);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            padding: 30px;
            text-align: center;
            backdrop-filter: blur(10px);
            position: relative;
            overflow: hidden;
            animation: scoreCardPulse 0.8s ease-out 0.9s both;
        }
        
        @keyframes scoreCardPulse {
            0% { opacity: 0; transform: scale(0.9); }
            100% { opacity: 1; transform: scale(1); }
        }
        
        .score-card::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            animation: rotate 20s linear infinite;
        }
        
        @keyframes rotate {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .score-content {
            position: relative;
            z-index: 2;
        }
        
        .score-value {
            font-size: 4em;
            font-weight: 800;
            margin: 20px 0;
            background: linear-gradient(135deg, var(--success) 0%, var(--primary-light) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: scoreValuePulse 2s ease-in-out infinite;
        }
        
        @keyframes scoreValuePulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        
        .score-value.critical { 
            background: linear-gradient(135deg, var(--critical) 0%, var(--danger) 100%);
            animation: scoreValueCritical 1.5s ease-in-out infinite;
        }
        
        @keyframes scoreValueCritical {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.08); }
        }
        
        .score-value.high { 
            background: linear-gradient(135deg, var(--danger) 0%, var(--warning) 100%);
            animation: scoreValueHigh 2s ease-in-out infinite;
        }
        
        .score-value.medium { 
            background: linear-gradient(135deg, var(--warning) 0%, #ffcc00 100%);
        }
        
        .risk-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 20px;
            border-radius: 25px;
            font-weight: 600;
            font-size: 0.9em;
            margin-top: 10px;
            backdrop-filter: blur(10px);
            animation: badgePulse 3s infinite;
        }
        
        @keyframes badgePulse {
            0%, 100% { box-shadow: 0 0 5px rgba(0,0,0,0.2); }
            50% { box-shadow: 0 0 15px currentColor; }
        }
        
        .risk-critical { 
            background: rgba(204, 0, 0, 0.2); 
            color: #ff6666; 
            border: 1px solid rgba(204, 0, 0, 0.3);
            animation: criticalPulse 1.5s infinite;
        }
        
        @keyframes criticalPulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        
        .risk-high { 
            background: rgba(255, 51, 51, 0.2); 
            color: #ff6666; 
            border: 1px solid rgba(255, 51, 51, 0.3);
        }
        
        .risk-medium { 
            background: rgba(255, 153, 0, 0.2); 
            color: #ffcc66; 
            border: 1px solid rgba(255, 153, 0, 0.3);
        }
        
        .risk-low { 
            background: rgba(0, 204, 102, 0.2); 
            color: #66ff99; 
            border: 1px solid rgba(0, 204, 102, 0.3);
        }
        
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            animation: chartsFadeIn 1s ease-out 1s both;
        }
        
        @keyframes chartsFadeIn {
            0% { opacity: 0; transform: translateY(20px); }
            100% { opacity: 1; transform: translateY(0); }
        }
        
        .chart-container {
            background: rgba(25, 30, 45, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 25px;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }
        
        .chart-container:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
        }
        
        .chart-title {
            font-size: 1.1em;
            font-weight: 600;
            margin-bottom: 20px;
            color: var(--light);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .section {
            margin: 40px 0;
        }
        
        .section-header {
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 25px;
            animation: sectionHeaderSlide 0.6s ease-out 1.1s both;
        }
        
        @keyframes sectionHeaderSlide {
            0% { opacity: 0; transform: translateX(-20px); }
            100% { opacity: 1; transform: translateX(0); }
        }
        
        .section-title {
            font-size: 1.8em;
            font-weight: 700;
            background: linear-gradient(135deg, #ffffff 0%, var(--primary-light) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .controls {
            display: flex;
            gap: 15px;
            align-items: center;
        }
        
        .control-group {
            display: flex;
            gap: 10px;
        }
        
        .btn {
            padding: 10px 20px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            background: rgba(255, 255, 255, 0.1);
            color: var(--light);
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
            display: flex;
            align-items: center;
            gap: 8px;
            position: relative;
            overflow: hidden;
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }
        
        .btn:hover::before {
            left: 100%;
        }
        
        .btn:hover {
            background: rgba(255, 255, 255, 0.2);
            transform: translateY(-2px);
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            border: none;
        }
        
        .btn-primary:hover {
            background: linear-gradient(135deg, var(--primary-light) 0%, var(--primary) 100%);
        }
        
        .search-box {
            padding: 10px 15px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            color: var(--light);
            backdrop-filter: blur(10px);
            min-width: 250px;
            transition: all 0.3s ease;
        }
        
        .search-box:focus {
            outline: none;
            border-color: var(--primary-light);
            box-shadow: 0 0 0 2px rgba(77, 148, 255, 0.2);
            transform: scale(1.02);
        }
        
        .search-box::placeholder {
            color: var(--gray);
        }
        
        .findings-grid {
            display: grid;
            gap: 15px;
        }
        
        .finding-card {
            background: rgba(25, 30, 45, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 20px;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
            cursor: pointer;
            animation: findingCardSlide 0.5s ease-out both;
            position: relative;
            overflow: hidden;
        }
        
        .finding-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--primary);
            transform: scaleY(0);
            transition: transform 0.3s ease;
        }
        
        .finding-card.critical::before { background: var(--critical); }
        .finding-card.high::before { background: var(--danger); }
        .finding-card.medium::before { background: var(--warning); }
        .finding-card.low::before { background: var(--success); }
        
        .finding-card:hover::before {
            transform: scaleY(1);
        }
        
        @keyframes findingCardSlide {
            0% { opacity: 0; transform: translateY(20px); }
            100% { opacity: 1; transform: translateY(0); }
        }
        
        .finding-card:nth-child(odd) {
            animation-delay: 0.1s;
        }
        
        .finding-card:nth-child(even) {
            animation-delay: 0.2s;
        }
        
        .finding-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
            border-color: rgba(255, 255, 255, 0.2);
        }
        
        .finding-header {
            display: flex;
            justify-content: between;
            align-items: start;
            margin-bottom: 15px;
        }
        
        .finding-title {
            font-size: 1.1em;
            font-weight: 600;
            color: var(--light);
            flex: 1;
            transition: all 0.3s ease;
        }
        
        .finding-card:hover .finding-title {
            color: var(--primary-light);
        }
        
        .finding-meta {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .status-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: all 0.3s ease;
        }
        
        .finding-card:hover .status-badge {
            transform: scale(1.05);
        }
        
        .status-pass { background: rgba(0, 204, 102, 0.2); color: var(--success); border: 1px solid rgba(0, 204, 102, 0.3); }
        .status-fail { background: rgba(255, 51, 51, 0.2); color: var(--danger); border: 1px solid rgba(255, 51, 51, 0.3); }
        .status-warn { background: rgba(255, 153, 0, 0.2); color: var(--warning); border: 1px solid rgba(255, 153, 0, 0.3); }
        
        .severity-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: white;
            transition: all 0.3s ease;
        }
        
        .finding-card:hover .severity-badge {
            transform: scale(1.05);
        }
        
        .severity-critical { background: var(--critical); }
        .severity-high { background: var(--danger); }
        .severity-medium { background: var(--warning); }
        .severity-low { background: var(--success); }
        .severity-info { background: var(--info); }
        
        .finding-content {
            margin: 15px 0;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.5s ease, margin 0.3s ease;
        }
        
        .finding-card.active .finding-content {
            max-height: 500px;
            margin: 15px 0;
        }
        
        .evidence {
            background: rgba(255, 255, 255, 0.05);
            padding: 12px;
            border-radius: 8px;
            border-left: 3px solid var(--primary);
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: var(--gray);
        }
        
        .remediation {
            background: rgba(0, 102, 204, 0.1);
            padding: 12px;
            border-radius: 8px;
            border: 1px dashed var(--primary);
            margin-top: 10px;
            font-size: 0.9em;
            animation: remediationPulse 2s infinite;
        }
        
        @keyframes remediationPulse {
            0%, 100% { border-color: var(--primary); }
            50% { border-color: var(--primary-light); }
        }
        
        .recommendations-section {
            background: linear-gradient(135deg, rgba(25, 30, 45, 0.8) 0%, rgba(40, 45, 60, 0.8) 100%);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 30px;
            margin: 40px 0;
            animation: recommendationsSlide 0.6s ease-out 1.2s both;
        }
        
        @keyframes recommendationsSlide {
            0% { opacity: 0; transform: translateY(30px); }
            100% { opacity: 1; transform: translateY(0); }
        }
        
        .recommendation-card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 20px;
            margin: 15px 0;
            border-left: 4px solid var(--primary);
            transition: all 0.3s ease;
            animation: recommendationCardSlide 0.5s ease-out both;
        }
        
        .recommendation-card:nth-child(odd) {
            animation-delay: 0.1s;
        }
        
        .recommendation-card:nth-child(even) {
            animation-delay: 0.2s;
        }
        
        @keyframes recommendationCardSlide {
            0% { opacity: 0; transform: translateX(-20px); }
            100% { opacity: 1; transform: translateX(0); }
        }
        
        .recommendation-card.critical { border-left-color: var(--critical); }
        .recommendation-card.high { border-left-color: var(--danger); }
        .recommendation-card.medium { border-left-color: var(--warning); }
        .recommendation-card.low { border-left-color: var(--success); }
        
        .recommendation-card:hover {
            transform: translateX(5px);
            background: rgba(255, 255, 255, 0.08);
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            color: var(--gray);
            font-size: 0.9em;
            animation: footerFade 0.8s ease-out 1.3s both;
        }
        
        @keyframes footerFade {
            0% { opacity: 0; }
            100% { opacity: 1; }
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 1000;
            align-items: center;
            justify-content: center;
            backdrop-filter: blur(10px);
            animation: modalFadeIn 0.3s ease-out;
        }
        
        @keyframes modalFadeIn {
            0% { opacity: 0; }
            100% { opacity: 1; }
        }
        
        .modal-content {
            background: rgba(13, 17, 28, 0.95);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 20px;
            padding: 30px;
            max-width: 800px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
            backdrop-filter: blur(20px);
            animation: modalContentSlide 0.3s ease-out;
        }
        
        @keyframes modalContentSlide {
            0% { opacity: 0; transform: scale(0.9); }
            100% { opacity: 1; transform: scale(1); }
        }
        
        .progress-ring {
            transform: rotate(-90deg);
        }
        
        .progress-ring-circle {
            transition: stroke-dashoffset 0.5s ease;
            transform: rotate(90deg);
            transform-origin: 50% 50%;
        }
        
        @media (max-width: 1200px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
            
            .sidebar {
                display: none;
            }
            
            .score-section {
                grid-template-columns: 1fr;
            }
            
            .charts-grid {
                grid-template-columns: 1fr;
            }
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .overview-cards {
                grid-template-columns: 1fr;
            }
            
            .controls {
                flex-direction: column;
                align-items: stretch;
            }
            
            .control-group {
                justify-content: center;
            }
        }
    </style>
</head>
<body>
    <div class="cyber-grid"></div>
    <div class="glow-effect"></div>
    
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-content">
                <div class="logo">
                    <div class="logo-icon">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                </div>
                <h1>Enterprise Security Audit</h1>
                <p class="header-subtitle">Comprehensive System Security Assessment & Compliance Report</p>
                <p class="timestamp">
                    <i class="fas fa-clock"></i>
                    Generated: {{ timestamp }}
                </p>
            </div>
        </div>
        
        <div class="dashboard">
            <!-- Sidebar Navigation -->
            <div class="sidebar">
                <div class="nav-section">
                    <div class="nav-title">Dashboard</div>
                    <a href="#overview" class="nav-item active">
                        <i class="fas fa-chart-dashboard"></i>
                        Overview
                    </a>
                    <a href="#findings" class="nav-item">
                        <i class="fas fa-search"></i>
                        Security Findings
                    </a>
                    <a href="#compliance" class="nav-item">
                        <i class="fas fa-clipboard-check"></i>
                        Compliance
                    </a>
                    <a href="#recommendations" class="nav-item">
                        <i class="fas fa-lightbulb"></i>
                        Recommendations
                    </a>
                </div>
                
                <div class="nav-section">
                    <div class="nav-title">Quick Actions</div>
                    <a href="#export" class="nav-item">
                        <i class="fas fa-download"></i>
                        Export Report
                    </a>
                    <a href="#remediate" class="nav-item">
                        <i class="fas fa-tools"></i>
                        Remediation Guide
                    </a>
                    <a href="#settings" class="nav-item">
                        <i class="fas fa-cog"></i>
                        Report Settings
                    </a>
                </div>
                
                <div class="nav-section">
                    <div class="nav-title">System Info</div>
                    <div class="nav-item">
                        <i class="fas fa-server"></i>
                        {{ summary.total_checks }} Security Controls
                    </div>
                    <div class="nav-item">
                        <i class="fas fa-shield-alt"></i>
                        {{ summary.security_score }}/100 Security Score
                    </div>
                    <div class="nav-item">
                        <i class="fas fa-exclamation-triangle"></i>
                        {{ summary.failed }} Issues Found
                    </div>
                </div>
            </div>
            
            <!-- Main Content -->
            <div class="main-content">
                <!-- Score Section - NOW AT THE TOP -->
                <div class="score-section">
                    <div class="score-card">
                        <div class="score-content">
                            <div class="card-label">Overall Security Score</div>
                            <div class="score-value score-{{ summary.risk_level.lower() }}">{{ summary.security_score }}</div>
                            <div class="risk-badge risk-{{ summary.risk_level.lower() }}">
                                <i class="fas fa-{{ 'check-circle' if summary.risk_level == 'LOW' else 'exclamation-triangle' if summary.risk_level == 'MEDIUM' else 'times-circle' if summary.risk_level == 'HIGH' else 'skull-crossbones' }}"></i>
                                {{ summary.risk_level }} RISK LEVEL
                            </div>
                        </div>
                    </div>
                    
                    <div class="charts-grid">
                        <div class="chart-container">
                            <div class="chart-title">
                                <i class="fas fa-chart-pie"></i>
                                Findings by Severity
                            </div>
                            <canvas id="severityChart"></canvas>
                        </div>
                        <div class="chart-container">
                            <div class="chart-title">
                                <i class="fas fa-chart-bar"></i>
                                Compliance Status
                            </div>
                            <canvas id="complianceChart"></canvas>
                        </div>
                    </div>
                </div>
                
                <!-- Overview Cards - NOW BELOW SCORE SECTION -->
                <div class="overview-cards">
                    <div class="overview-card">
                        <div class="card-header">
                            <div class="card-icon" style="background: rgba(0, 204, 102, 0.2); color: var(--success);">
                                <i class="fas fa-check-circle"></i>
                            </div>
                        </div>
                        <div class="card-value">{{ summary.passed }}</div>
                        <div class="card-label">Controls Passed</div>
                    </div>
                    
                    <div class="overview-card critical">
                        <div class="card-header">
                            <div class="card-icon" style="background: rgba(204, 0, 0, 0.2); color: var(--critical);">
                                <i class="fas fa-times-circle"></i>
                            </div>
                        </div>
                        <div class="card-value">{{ summary.failed }}</div>
                        <div class="card-label">Controls Failed</div>
                    </div>
                    
                    <div class="overview-card medium">
                        <div class="card-header">
                            <div class="card-icon" style="background: rgba(255, 153, 0, 0.2); color: var(--warning);">
                                <i class="fas fa-exclamation-triangle"></i>
                            </div>
                        </div>
                        <div class="card-value">{{ summary.warnings }}</div>
                        <div class="card-label">Warnings</div>
                    </div>
                    
                    <div class="overview-card">
                        <div class="card-header">
                            <div class="card-icon" style="background: rgba(0, 102, 204, 0.2); color: var(--primary-light);">
                                <i class="fas fa-percentage"></i>
                            </div>
                        </div>
                        <div class="card-value">{{ summary.compliance_score }}%</div>
                        <div class="card-label">Compliance Score</div>
                    </div>
                </div>
                
                <!-- Security Findings Section -->
                <div class="section" id="findings">
                    <div class="section-header">
                        <h2 class="section-title">
                            <i class="fas fa-search"></i>
                            Security Findings
                        </h2>
                        <div class="controls">
                            <div class="control-group">
                                <select id="severityFilter" class="btn">
                                    <option value="all">All Severities</option>
                                    <option value="critical">Critical</option>
                                    <option value="high">High</option>
                                    <option value="medium">Medium</option>
                                    <option value="low">Low</option>
                                </select>
                                <select id="statusFilter" class="btn">
                                    <option value="all">All Status</option>
                                    <option value="pass">Passed</option>
                                    <option value="fail">Failed</option>
                                    <option value="warn">Warnings</option>
                                </select>
                            </div>
                            <input type="text" id="searchBox" class="search-box" placeholder="Search findings...">
                            <button class="btn btn-primary" onclick="exportReport()">
                                <i class="fas fa-download"></i> Export
                            </button>
                        </div>
                    </div>
                    
                    <div class="findings-grid">
                        {% for result in results %}
                        <div class="finding-card {{ result.severity.lower() }}" data-severity="{{ result.severity.lower() }}" data-status="{{ result.status.lower() }}">
                            <div class="finding-header">
                                <div class="finding-title">{{ result.title }}</div>
                                <div class="finding-meta">
                                    {% if result.status == 'PASS' %}
                                    <span class="status-badge status-pass">
                                        <i class="fas fa-check"></i> PASS
                                    </span>
                                    {% elif result.status == 'FAIL' %}
                                    <span class="status-badge status-fail">
                                        <i class="fas fa-times"></i> FAIL
                                    </span>
                                    {% else %}
                                    <span class="status-badge status-warn">
                                        <i class="fas fa-exclamation-triangle"></i> WARN
                                    </span>
                                    {% endif %}
                                    <span class="severity-badge severity-{{ result.severity.lower() }}">
                                        {{ result.severity }}
                                    </span>
                                </div>
                            </div>
                            <div class="finding-content">
                                <div class="evidence">{{ result.evidence }}</div>
                                {% if result.status in ['FAIL', 'WARN'] %}
                                <div class="remediation">
                                    <strong><i class="fas fa-tools"></i> Remediation:</strong> {{ result.remediation }}
                                </div>
                                {% endif %}
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
                
                <!-- Recommendations Section -->
                <div class="recommendations-section" id="recommendations">
                    <h2 class="section-title">
                        <i class="fas fa-lightbulb"></i>
                        Security Recommendations
                    </h2>
                    
                    {% for recommendation in summary.recommendations %}
                    <div class="recommendation-card {{ recommendation.priority.lower() }}">
                        <div class="finding-header">
                            <div class="finding-title">{{ recommendation.title }}</div>
                            <span class="severity-badge severity-{{ recommendation.priority.lower() }}">
                                {{ recommendation.priority }}
                            </span>
                        </div>
                        <div class="finding-content">
                            <p>{{ recommendation.description }}</p>
                            <div class="remediation">
                                <strong>Recommended Action:</strong> {{ recommendation.action }}
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
                
                <!-- Footer -->
                <div class="footer">
                    <p><strong>CyberShield Security Audit Tool v2.0</strong></p>
                    <p>Enterprise-Grade Security Assessment & Compliance Reporting</p>
                    <p class="timestamp">Report generated on {{ timestamp }} | Confidential</p>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Initialize charts and data
        const resultsData = {{ results | tojson }};
        const summaryData = {{ summary | tojson }};
        
        function initializeCharts() {
            // Severity Distribution Chart
            const severityCtx = document.getElementById('severityChart').getContext('2d');
            const severityData = {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [
                        resultsData.filter(r => r.severity.toLowerCase() === 'critical').length,
                        resultsData.filter(r => r.severity.toLowerCase() === 'high').length,
                        resultsData.filter(r => r.severity.toLowerCase() === 'medium').length,
                        resultsData.filter(r => r.severity.toLowerCase() === 'low').length,
                        resultsData.filter(r => r.severity.toLowerCase() === 'info').length
                    ],
                    backgroundColor: [
                        '#cc0000', '#ff3333', '#ff9900', '#00cc66', '#66ccff'
                    ],
                    borderWidth: 2,
                    borderColor: '#0d111c'
                }]
            };
            
            new Chart(severityCtx, {
                type: 'doughnut',
                data: severityData,
                options: {
                    responsive: true,
                    cutout: '70%',
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: '#f8f9fa',
                                font: {
                                    size: 11
                                }
                            }
                        }
                    },
                    animation: {
                        animateScale: true,
                        animateRotate: true,
                        duration: 2000,
                        easing: 'easeOutQuart'
                    }
                }
            });
            
            // Compliance Status Chart
            const complianceCtx = document.getElementById('complianceChart').getContext('2d');
            const complianceData = {
                labels: ['Passed', 'Failed', 'Warnings'],
                datasets: [{
                    data: [
                        summaryData.passed,
                        summaryData.failed,
                        summaryData.warnings
                    ],
                    backgroundColor: [
                        '#00cc66', '#ff3333', '#ff9900'
                    ],
                    borderWidth: 2,
                    borderColor: '#0d111c'
                }]
            };
            
            new Chart(complianceCtx, {
                type: 'bar',
                data: complianceData,
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: 'rgba(255,255,255,0.1)'
                            },
                            ticks: {
                                color: '#f8f9fa'
                            }
                        },
                        x: {
                            grid: {
                                display: false
                            },
                            ticks: {
                                color: '#f8f9fa'
                            }
                        }
                    },
                    animation: {
                        duration: 2000,
                        easing: 'easeOutQuart'
                    }
                }
            });
        }
        
        // Filter functionality
        function filterResults() {
            const severityFilter = document.getElementById('severityFilter').value;
            const statusFilter = document.getElementById('statusFilter').value;
            const searchTerm = document.getElementById('searchBox').value.toLowerCase();
            
            document.querySelectorAll('.finding-card').forEach(card => {
                const severity = card.getAttribute('data-severity');
                const status = card.getAttribute('data-status');
                const text = card.textContent.toLowerCase();
                
                const severityMatch = severityFilter === 'all' || severity === severityFilter;
                const statusMatch = statusFilter === 'all' || status === statusFilter;
                const searchMatch = searchTerm === '' || text.includes(searchTerm);
                
                if (severityMatch && statusMatch && searchMatch) {
                    card.style.display = 'block';
                    // Add animation for filtered cards
                    card.style.animation = 'findingCardSlide 0.5s ease-out';
                } else {
                    card.style.display = 'none';
                }
            });
        }
        
        // Expand/collapse finding details
        function toggleFindingDetails(card) {
            card.classList.toggle('active');
        }
        
        // Export functionality
        function exportReport() {
            const htmlContent = document.documentElement.outerHTML;
            const blob = new Blob([htmlContent], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `security-audit-report-${new Date().toISOString().split('T')[0]}.html`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
        
        // Initialize when page loads
        document.addEventListener('DOMContentLoaded', function() {
            initializeCharts();
            
            // Add event listeners for filters
            document.getElementById('severityFilter').addEventListener('change', filterResults);
            document.getElementById('statusFilter').addEventListener('change', filterResults);
            document.getElementById('searchBox').addEventListener('input', filterResults);
            
            // Add click event to finding cards to expand/collapse details
            document.querySelectorAll('.finding-card').forEach(card => {
                card.addEventListener('click', function() {
                    toggleFindingDetails(this);
                });
            });
            
            // Smooth scrolling for navigation
            document.querySelectorAll('.nav-item').forEach(item => {
                item.addEventListener('click', function(e) {
                    e.preventDefault();
                    const targetId = this.getAttribute('href').substring(1);
                    const targetElement = document.getElementById(targetId);
                    if (targetElement) {
                        targetElement.scrollIntoView({ behavior: 'smooth' });
                        
                        // Update active nav item
                        document.querySelectorAll('.nav-item').forEach(nav => {
                            nav.classList.remove('active');
                        });
                        this.classList.add('active');
                    }
                });
            });
            
            // Add scroll animations
            const observerOptions = {
                threshold: 0.1,
                rootMargin: '0px 0px -50px 0px'
            };
            
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.style.animationPlayState = 'running';
                        observer.unobserve(entry.target);
                    }
                });
            }, observerOptions);
            
            // Observe elements for scroll animations
            document.querySelectorAll('.finding-card, .recommendation-card').forEach(el => {
                el.style.animationPlayState = 'paused';
                observer.observe(el);
            });
        });
    </script>
</body>
</html>'''
        
        template = Template(template_str)
        
        # Enhanced summary with additional metrics
        summary = {
            'total_checks': len(results),
            'passed': len([r for r in results if r['status'] == 'PASS']),
            'failed': len([r for r in results if r['status'] == 'FAIL']),
            'warnings': len([r for r in results if r['status'] == 'WARN']),
            'security_score': self._calculate_security_score(results),
            'risk_level': self._get_risk_level(self._calculate_security_score(results)),
            'compliance_score': self._calculate_compliance_score(results),
            'priority_breakdown': self._get_priority_breakdown(results),
            'recommendations': self._generate_recommendations(results)
        }
        
        return template.render(
            timestamp=timestamp,
            results=results,
            summary=summary
        )
