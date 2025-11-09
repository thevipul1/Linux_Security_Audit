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
                'version': '1.0'
            },
            'summary': {
                'total_checks': len(results),
                'passed': len([r for r in results if r['status'] == 'PASS']),
                'failed': len([r for r in results if r['status'] == 'FAIL']),
                'warnings': len([r for r in results if r['status'] == 'WARN']),
                'error': len([r for r in results if r['status'] == 'ERROR']),
                'security_score': self._calculate_security_score(results)
            },
            'results': results
        }
        return json.dumps(report_data, indent=2, ensure_ascii=False)
    
    def _calculate_security_score(self, results):
        """Calculate overall security score (0-100)"""
        if not results:
            return 0
        
        total_weight = 0
        weighted_score = 0
        
        severity_weights = {
            'HIGH': 3,
            'MEDIUM': 2, 
            'LOW': 1
        }
        
        for result in results:
            weight = severity_weights.get(result.get('severity', 'LOW'), 1)
            total_weight += weight
            
            if result['status'] == 'PASS':
                weighted_score += weight
            elif result['status'] == 'WARN':
                weighted_score += weight * 0.5
        
        if total_weight == 0:
            return 100
        
        return round((weighted_score / total_weight) * 100, 1)
    
    def _generate_html(self, results, timestamp):
        """Generate modern HTML report"""
        template_str = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - Linux Security Tool</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #1f2937;
            --light: #f8fafc;
            --gray: #6b7280;
            --border: #e5e7eb;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: var(--dark);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            padding: 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 1px, transparent 1px);
            background-size: 20px 20px;
            animation: float 20s linear infinite;
        }
        
        @keyframes float {
            0% { transform: translate(0, 0) rotate(0deg); }
            100% { transform: translate(-20px, -20px) rotate(360deg); }
        }
        
        .header-content {
            position: relative;
            z-index: 2;
        }
        
        .header h1 {
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
            margin-bottom: 5px;
        }
        
        .score-card {
            background: white;
            color: var(--dark);
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1);
            margin: -50px auto 30px;
            max-width: 300px;
            position: relative;
            z-index: 3;
        }
        
        .score-value {
            font-size: 4em;
            font-weight: 800;
            line-height: 1;
            margin: 10px 0;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .score-label {
            color: var(--gray);
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }
        
        .content {
            padding: 40px;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .metric-card {
            background: var(--light);
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            border-left: 4px solid var(--primary);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .metric-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 30px -10px rgba(0, 0, 0, 0.15);
        }
        
        .metric-value {
            font-size: 2.5em;
            font-weight: 700;
            margin: 10px 0;
        }
        
        .metric-label {
            color: var(--gray);
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }
        
        .section-title {
            font-size: 1.5em;
            font-weight: 600;
            margin: 40px 0 20px 0;
            color: var(--dark);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .section-title i {
            color: var(--primary);
        }
        
        .results-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
            margin-bottom: 30px;
        }
        
        .results-table th {
            background: var(--light);
            padding: 15px 20px;
            text-align: left;
            font-weight: 600;
            color: var(--dark);
            border-bottom: 2px solid var(--border);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-size: 0.85em;
        }
        
        .results-table td {
            padding: 15px 20px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }
        
        .results-table tr:last-child td {
            border-bottom: none;
        }
        
        .results-table tr:hover {
            background: #f8fafc;
        }
        
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .status-pass {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success);
            border: 1px solid rgba(16, 185, 129, 0.2);
        }
        
        .status-fail {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
            border: 1px solid rgba(239, 68, 68, 0.2);
        }
        
        .status-warn {
            background: rgba(245, 158, 11, 0.1);
            color: var(--warning);
            border: 1px solid rgba(245, 158, 11, 0.2);
        }
        
        .severity-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .severity-high {
            background: var(--danger);
            color: white;
        }
        
        .severity-medium {
            background: var(--warning);
            color: white;
        }
        
        .severity-low {
            background: var(--success);
            color: white;
        }
        
        .evidence {
            font-size: 0.9em;
            color: var(--gray);
            font-family: 'Courier New', monospace;
            background: #f8fafc;
            padding: 8px 12px;
            border-radius: 6px;
            border-left: 3px solid var(--border);
        }
        
        .remediation {
            font-size: 0.85em;
            color: var(--primary);
            font-family: 'Courier New', monospace;
            background: rgba(99, 102, 241, 0.05);
            padding: 8px 12px;
            border-radius: 6px;
            border: 1px dashed var(--primary);
        }
        
        .recommendations {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin: 40px 0;
        }
        
        .recommendations h3 {
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .recommendations ul {
            list-style: none;
            margin-left: 0;
        }
        
        .recommendations li {
            margin: 10px 0;
            padding-left: 25px;
            position: relative;
        }
        
        .recommendations li::before {
            content: '✓';
            position: absolute;
            left: 0;
            color: white;
            font-weight: bold;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            background: var(--light);
            color: var(--gray);
            border-top: 1px solid var(--border);
        }
        
        .footer p {
            margin: 5px 0;
        }
        
        .timestamp {
            font-size: 0.9em;
            opacity: 0.7;
        }
        
        @media (max-width: 768px) {
            .header h1 {
                font-size: 2em;
            }
            
            .metrics-grid {
                grid-template-columns: 1fr;
            }
            
            .content {
                padding: 20px;
            }
            
            .results-table {
                font-size: 0.9em;
            }
            
            .results-table th,
            .results-table td {
                padding: 10px 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-content">
                <h1>
                    <i class="fas fa-shield-alt"></i>
                    Security Audit Report
                </h1>
                <p>Comprehensive System Security Assessment</p>
                <p class="timestamp">Generated: {{ timestamp }}</p>
            </div>
        </div>
        
        <!-- Score Card -->
        <div class="score-card">
            <div class="score-label">Security Score</div>
            <div class="score-value">{{ summary.security_score }}</div>
            <div class="score-label">out of 100</div>
        </div>
        
        <!-- Main Content -->
        <div class="content">
            <!-- Metrics -->
            <div class="metrics-grid">
                <div class="metric-card">
                    <i class="fas fa-list-alt fa-2x" style="color: var(--primary);"></i>
                    <div class="metric-value">{{ summary.total_checks }}</div>
                    <div class="metric-label">Total Checks</div>
                </div>
                <div class="metric-card">
                    <i class="fas fa-check-circle fa-2x" style="color: var(--success);"></i>
                    <div class="metric-value">{{ summary.passed }}</div>
                    <div class="metric-label">Passed</div>
                </div>
                <div class="metric-card">
                    <i class="fas fa-times-circle fa-2x" style="color: var(--danger);"></i>
                    <div class="metric-value">{{ summary.failed }}</div>
                    <div class="metric-label">Failed</div>
                </div>
                <div class="metric-card">
                    <i class="fas fa-exclamation-triangle fa-2x" style="color: var(--warning);"></i>
                    <div class="metric-value">{{ summary.warnings }}</div>
                    <div class="metric-label">Warnings</div>
                </div>
            </div>
            
            <!-- Results Table -->
            <h2 class="section-title">
                <i class="fas fa-search"></i>
                Detailed Security Findings
            </h2>
            
            <table class="results-table">
                <thead>
                    <tr>
                        <th>Check</th>
                        <th>Status</th>
                        <th>Severity</th>
                        <th>Evidence</th>
                        <th>Remediation</th>
                    </tr>
                </thead>
                <tbody>
                    {% for result in results %}
                    <tr>
                        <td>
                            <strong>{{ result.id }}</strong><br>
                            <small style="color: var(--gray);">{{ result.title }}</small>
                        </td>
                        <td>
                            {% if result.status == 'PASS' %}
                            <span class="status-badge status-pass">
                                <i class="fas fa-check"></i>
                                PASS
                            </span>
                            {% elif result.status == 'FAIL' %}
                            <span class="status-badge status-fail">
                                <i class="fas fa-times"></i>
                                FAIL
                            </span>
                            {% else %}
                            <span class="status-badge status-warn">
                                <i class="fas fa-exclamation-triangle"></i>
                                WARN
                            </span>
                            {% endif %}
                        </td>
                        <td>
                            <span class="severity-badge severity-{{ result.severity.lower() }}">
                                {{ result.severity }}
                            </span>
                        </td>
                        <td>
                            <div class="evidence">{{ result.evidence }}</div>
                        </td>
                        <td>
                            {% if result.status in ['FAIL', 'WARN'] %}
                            <div class="remediation">
                                <i class="fas fa-tools"></i>
                                {{ result.remediation }}
                            </div>
                            {% else %}
                            <em style="color: var(--gray);">No action required</em>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            
            <!-- Recommendations -->
            <div class="recommendations">
                <h3>
                    <i class="fas fa-lightbulb"></i>
                    Security Recommendations
                </h3>
                <ul>
                    {% if summary.failed > 0 %}
                    <li>Address <strong>{{ summary.failed }} critical security issue(s)</strong> immediately</li>
                    {% endif %}
                    {% if summary.security_score < 80 %}
                    <li>Implement additional security measures to reach target score of 80+</li>
                    {% endif %}
                    {% if summary.security_score >= 80 %}
                    <li>Maintain current security practices and conduct regular audits</li>
                    {% endif %}
                    <li>Schedule automated security scans for continuous monitoring</li>
                    <li>Review and update system configurations regularly</li>
                </ul>
                
                {% if summary.failed > 0 %}
                <div style="margin-top: 20px; padding: 15px; background: rgba(255,255,255,0.2); border-radius: 8px;">
                    <strong>Quick Fix:</strong> Run the remediation tool to automatically address issues
                    <div style="margin-top: 10px; font-family: 'Courier New', monospace; font-size: 0.9em;">
                        sudo python3 main.py --remediate
                    </div>
                </div>
                {% endif %}
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p><strong>Linux Security Audit Tool v1.0</strong></p>
            <p>Automated Security Assessment & Hardening</p>
            <p class="timestamp">Report generated on {{ timestamp }}</p>
        </div>
    </div>
    
    <script>
        // Add subtle animations
        document.addEventListener('DOMContentLoaded', function() {
            // Animate metric cards on scroll
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.style.opacity = '1';
                        entry.target.style.transform = 'translateY(0)';
                    }
                });
            });
            
            document.querySelectorAll('.metric-card').forEach(card => {
                card.style.opacity = '0';
                card.style.transform = 'translateY(20px)';
                card.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
                observer.observe(card);
            });
        });
    </script>
</body>
</html>'''
        
        template = Template(template_str)
        summary = {
            'total_checks': len(results),
            'passed': len([r for r in results if r['status'] == 'PASS']),
            'failed': len([r for r in results if r['status'] == 'FAIL']),
            'warnings': len([r for r in results if r['status'] == 'WARN']),
            'security_score': self._calculate_security_score(results)
        }
        
        return template.render(
            timestamp=timestamp,
            results=results,
            summary=summary
        )
