#!/usr/bin/env python3
"""
Hourly CloudWatch Log Analyzer with Email Alerts
================================================

Automatically analyzes all configured log groups every hour and sends
email alerts when errors are detected.

Usage:
    python scheduler.py                    # Run once
    python scheduler.py --daemon          # Run as daemon (continuous)
    python scheduler.py --interval 30     # Custom interval in minutes

Windows Service:
    Use Windows Task Scheduler to run this script hourly.
    See SCHEDULER_SETUP.md for instructions.
"""

from dotenv import load_dotenv
import os
import argparse
from datetime import datetime, timedelta
import time
import sys

# Load environment variables
load_dotenv()

from src.aws_logs import CloudWatchCollector
from src.analyzer import LogAnalyzer
from src.database import Database
from src.email_notifier import EmailNotifier
from src.models import AnalysisRun, Incident

# Optional feature analyzers (graceful import)
try:
    from src.security_analyzer import AWSSecurityAnalyzer
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False

try:
    from src.performance_analyzer import AWSPerformanceAnalyzer
    PERFORMANCE_AVAILABLE = True
except ImportError:
    PERFORMANCE_AVAILABLE = False

try:
    from src.health_dashboard import AWSHealthDashboard
    HEALTH_AVAILABLE = True
except ImportError:
    HEALTH_AVAILABLE = False

try:
    from src.compliance_checker import AWSComplianceChecker
    COMPLIANCE_AVAILABLE = True
except ImportError:
    COMPLIANCE_AVAILABLE = False

try:
    from src.quota_monitor import AWSQuotaMonitor
    QUOTA_AVAILABLE = True
except ImportError:
    QUOTA_AVAILABLE = False

try:
    from src.backup_analyzer import AWSBackupAnalyzer
    BACKUP_AVAILABLE = True
except ImportError:
    BACKUP_AVAILABLE = False


class AutomatedAnalyzer:
    """Automated log analysis with email notifications."""
    
    def __init__(self, enable_features: dict = None):
        """
        Initialize all components.
        
        Args:
            enable_features: dict of feature flags, e.g. {'security': True, 'performance': False}
                            If None, reads from environment variables.
        """
        print("🔧 Initializing CloudWatch Sentinel Scheduler...")
        
        # Feature flags from args or environment
        self.features = enable_features or {
            'security': os.getenv('ENABLE_SECURITY_SCAN', 'false').lower() == 'true',
            'performance': os.getenv('ENABLE_PERFORMANCE_SCAN', 'false').lower() == 'true',
            'health': os.getenv('ENABLE_HEALTH_CHECK', 'false').lower() == 'true',
            'compliance': os.getenv('ENABLE_COMPLIANCE_CHECK', 'false').lower() == 'true',
            'quota': os.getenv('ENABLE_QUOTA_CHECK', 'false').lower() == 'true',
            'backup': os.getenv('ENABLE_BACKUP_CHECK', 'false').lower() == 'true',
        }
        
        try:
            self.collector = CloudWatchCollector()
            print("✅ AWS CloudWatch collector initialized")
        except Exception as e:
            print(f"❌ Failed to initialize AWS collector: {e}")
            sys.exit(1)
        
        try:
            self.analyzer = LogAnalyzer()
            print("✅ OpenAI analyzer initialized")
        except Exception as e:
            print(f"❌ Failed to initialize analyzer: {e}")
            sys.exit(1)
        
        try:
            self.db = Database()
            if not self.db.test_connection():
                raise Exception("Database connection test failed")
            print("✅ Database connection verified")
        except Exception as e:
            print(f"❌ Failed to initialize database: {e}")
            sys.exit(1)
        
        try:
            self.notifier = EmailNotifier()
            print("✅ Email notifier initialized")
        except Exception as e:
            print(f"⚠️  Email notifier not configured: {e}")
            print("   Alerts will be logged but not emailed.")
            self.notifier = None
        
        # Initialize optional feature analyzers
        self._init_feature_analyzers()
        
        # Get configured log groups or discover them
        self.log_groups = self._get_log_groups()
        print(f"📋 Monitoring {len(self.log_groups)} log group(s)")
    
    def _init_feature_analyzers(self):
        """Initialize optional feature analyzers based on enabled features."""
        self.security_analyzer = None
        self.performance_analyzer = None
        self.health_dashboard = None
        self.compliance_checker = None
        self.quota_monitor = None
        self.backup_analyzer = None
        
        enabled_features = []
        
        if self.features.get('security') and SECURITY_AVAILABLE:
            try:
                self.security_analyzer = AWSSecurityAnalyzer()
                enabled_features.append('Security')
            except Exception as e:
                print(f"⚠️  Security analyzer init failed: {e}")
        
        if self.features.get('performance') and PERFORMANCE_AVAILABLE:
            try:
                self.performance_analyzer = AWSPerformanceAnalyzer()
                enabled_features.append('Performance')
            except Exception as e:
                print(f"⚠️  Performance analyzer init failed: {e}")
        
        if self.features.get('health') and HEALTH_AVAILABLE:
            try:
                self.health_dashboard = AWSHealthDashboard()
                enabled_features.append('Health')
            except Exception as e:
                print(f"⚠️  Health dashboard init failed: {e}")
        
        if self.features.get('compliance') and COMPLIANCE_AVAILABLE:
            try:
                self.compliance_checker = AWSComplianceChecker()
                enabled_features.append('Compliance')
            except Exception as e:
                print(f"⚠️  Compliance checker init failed: {e}")
        
        if self.features.get('quota') and QUOTA_AVAILABLE:
            try:
                self.quota_monitor = AWSQuotaMonitor()
                enabled_features.append('Quota')
            except Exception as e:
                print(f"⚠️  Quota monitor init failed: {e}")
        
        if self.features.get('backup') and BACKUP_AVAILABLE:
            try:
                self.backup_analyzer = AWSBackupAnalyzer()
                enabled_features.append('Backup')
            except Exception as e:
                print(f"⚠️  Backup analyzer init failed: {e}")
        
        if enabled_features:
            print(f"✅ Optional features enabled: {', '.join(enabled_features)}")
    
    def _get_log_groups(self) -> list:
        """Get list of log groups to monitor from env or auto-discover."""
        # Option 1: Explicitly configured in environment variable
        configured = os.getenv('LOG_GROUPS_TO_MONITOR', '')
        if configured:
            groups = [g.strip() for g in configured.split(',') if g.strip()]
            if groups:
                print(f"   Using configured log groups from LOG_GROUPS_TO_MONITOR")
                return groups
        
        # Option 2: Auto-discover all log groups
        print("   Auto-discovering log groups...")
        discovered = self.collector.list_log_groups()
        if not discovered:
            print("⚠️  No log groups found. Check AWS credentials and region.")
            return []
        
        return discovered
    
    def analyze_all_log_groups(self) -> dict:
        """
        Analyze all log groups and return results.
        
        Returns:
            dict with 'incidents', 'log_groups_analyzed', and 'errors'
        """
        all_incidents = []
        new_incidents = []
        analyzed_groups = []
        errors = []
        
        print(f"\n{'='*60}")
        print(f"🔍 Starting analysis at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")
        
        for log_group in self.log_groups:
            try:
                print(f"\n📖 Analyzing: {log_group}")
                
                # Track analysis timing
                start_time = datetime.now()
                
                # Fetch logs from last hour (or configured timeframe)
                minutes = int(os.getenv('ANALYSIS_TIMEFRAME_MINUTES', 60))
                logs = self.collector.fetch_recent_error_logs(log_group, minutes=minutes)
                
                if not logs or not logs.strip():
                    print(f"   ℹ️  No error logs found in the last {minutes} minutes")
                    continue
                
                log_count = logs.count('\n') + 1
                print(f"   Found {log_count} error log entries")
                
                # Check if logs contain real errors before making AI call
                if not self.analyzer.contains_real_errors(logs):
                    print(f"   ℹ️  No real errors detected (just warnings/info), skipping AI analysis")
                    continue
                
                # Get noise patterns from database
                noise_patterns = self.db.get_noise_patterns(log_group)
                
                # Analyze with OpenAI (only for real errors)
                print(f"   🤖 Analyzing with OpenAI (real errors detected)...")
                incidents = self.analyzer.analyze_logs(logs, log_group, noise_patterns)
                
                # Filter out NOISE severity
                real_incidents = [i for i in incidents if i.severity != "NOISE"]
                
                if real_incidents:
                    print(f"   🚨 Found {len(real_incidents)} incident(s)!")
                    for incident in real_incidents:
                        print(f"      - {incident.severity}: {incident.summary}")
                        # Save to database and check if it's new
                        success, is_new = self.db.save_incident_with_status(incident)
                        if success:
                            all_incidents.append(incident)
                            if is_new:
                                new_incidents.append(incident)
                    
                else:
                    print(f"   ✅ No actionable incidents (all logs are noise or normal)")
                
                # Record analysis run
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                
                run = AnalysisRun(
                    log_group=log_group,
                    start_time=start_time,
                    end_time=end_time,
                    total_logs=log_count,
                    incidents_found=len(real_incidents),
                    duration_seconds=duration
                )
                self.db.save_analysis_run(run)
                
                analyzed_groups.append(log_group)
                
            except Exception as e:
                error_msg = f"Failed to analyze {log_group}: {str(e)}"
                print(f"   ❌ {error_msg}")
                errors.append(error_msg)
        
        return {
            'incidents': all_incidents,
            'new_incidents': new_incidents,
            'log_groups_analyzed': analyzed_groups,
            'errors': errors
        }
    
    def run_once(self) -> bool:
        """
        Run analysis once and send email if incidents found.
        
        Returns:
            True if successful (even if no incidents), False on error
        """
        try:
            results = self.analyze_all_log_groups()
            
            incidents = results['incidents']
            new_incidents = results['new_incidents']
            analyzed_groups = results['log_groups_analyzed']
            errors = results['errors']
            
            # Run optional feature scans
            feature_results = self.run_feature_scans()
            
            # Print summary
            print(f"\n{'='*60}")
            print(f"📊 ANALYSIS SUMMARY")
            print(f"{'='*60}")
            print(f"Log Groups Analyzed: {len(analyzed_groups)}")
            print(f"Total Incidents Found: {len(incidents)} ({len(new_incidents)} new)")
            
            if incidents:
                critical = sum(1 for i in incidents if i.severity == "CRITICAL")
                warning = sum(1 for i in incidents if i.severity == "WARNING")
                info = sum(1 for i in incidents if i.severity == "INFO")
                print(f"  🔴 Critical: {critical}")
                print(f"  🟡 Warnings: {warning}")
                print(f"  🔵 Info: {info}")
            
            # Print feature scan results
            if feature_results:
                print(f"\n📋 FEATURE SCAN RESULTS:")
                for feature, result in feature_results.items():
                    if result.get('error'):
                        print(f"   ❌ {feature}: {result['error']}")
                    else:
                        print(f"   ✅ {feature}: {result.get('summary', 'Completed')}")
            
            if errors:
                print(f"\n⚠️  Errors encountered: {len(errors)}")
                for error in errors:
                    print(f"   - {error}")
            
            # Send email alert if NEW incidents found or critical feature findings
            alert_needed = self._check_alert_needed(new_incidents, feature_results)
            
            if alert_needed and self.notifier:
                print(f"\n📧 Sending email alert (new incidents detected)...")
                # We send ALL currently active incidents in the email for context, 
                # but we only TRIGGER the email if there are NEW ones.
                email_sent = self.notifier.send_alert(incidents, analyzed_groups, feature_results)
                if email_sent:
                    print(f"✅ Email alert sent successfully")
                else:
                    print(f"❌ Failed to send email alert")
            elif alert_needed and not self.notifier:
                print(f"\n⚠️  Email notifier not configured - new incidents detected but no alert sent!")
            elif incidents and not alert_needed:
                print(f"\nℹ️  {len(incidents)} incidents exist but all are duplicates - skipping email alert.")
            else:
                print(f"\n✅ No incidents to report - all systems normal")
            
            print(f"{'='*60}\n")
            return True
            
        except Exception as e:
            print(f"\n❌ Analysis run failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_feature_scans(self) -> dict:
        """
        Run enabled feature scans (security, performance, health, etc.).
        
        Returns:
            dict mapping feature name to results
        """
        results = {}
        
        if self.security_analyzer:
            results['Security'] = self._run_security_scan()
        
        if self.performance_analyzer:
            results['Performance'] = self._run_performance_scan()
        
        if self.health_dashboard:
            results['Health'] = self._run_health_check()
        
        if self.compliance_checker:
            results['Compliance'] = self._run_compliance_check()
        
        if self.quota_monitor:
            results['Quota'] = self._run_quota_check()
        
        if self.backup_analyzer:
            results['Backup'] = self._run_backup_check()
        
        return results
    
    def _run_security_scan(self) -> dict:
        """Run security scan and return summary."""
        try:
            print(f"\n🔒 Running security scan...")
            scan_result = self.security_analyzer.run_full_scan()
            summary = scan_result.get('summary', {})
            
            critical = summary.get('critical', 0)
            high = summary.get('high', 0)
            total = summary.get('total_findings', 0)
            
            result = {
                'critical_findings': critical,
                'high_findings': high,
                'total_findings': total,
                'summary': f"{total} findings ({critical} critical, {high} high)",
                'data': scan_result
            }
            
            if critical > 0:
                print(f"   🔴 {critical} CRITICAL security finding(s)!")
            
            return result
        except Exception as e:
            return {'error': str(e)}
    
    def _run_performance_scan(self) -> dict:
        """Run performance analysis and return summary."""
        try:
            print(f"\n📈 Running performance analysis...")
            hours = int(os.getenv('PERFORMANCE_ANALYSIS_HOURS', 24))
            scan_result = self.performance_analyzer.run_full_analysis(hours=hours)
            summary = scan_result.get('summary', {})
            
            score = self.performance_analyzer.get_performance_score(scan_result)
            resources_with_issues = summary.get('resources_with_issues', 0)
            
            result = {
                'score': score,
                'resources_with_issues': resources_with_issues,
                'summary': f"Score: {score}/100, {resources_with_issues} resources with issues",
                'data': scan_result
            }
            
            if score < 60:
                print(f"   🟡 Performance score is low: {score}/100")
            
            return result
        except Exception as e:
            return {'error': str(e)}
    
    def _run_health_check(self) -> dict:
        """Run health check and return summary."""
        try:
            print(f"\n🏥 Running health check...")
            scan_result = self.health_dashboard.run_full_health_check()
            scores = scan_result.get('health_scores', {})
            overall = scores.get('overall', {})
            
            score = overall.get('score', 100)
            status = overall.get('status', 'UNKNOWN')
            
            result = {
                'score': score,
                'status': status,
                'summary': f"Overall health: {score}/100 ({status})",
                'data': scan_result
            }
            
            if score < 60:
                print(f"   🔴 Health score is critical: {score}/100")
            elif score < 80:
                print(f"   🟡 Health needs attention: {score}/100")
            
            return result
        except Exception as e:
            return {'error': str(e)}
    
    def _run_compliance_check(self) -> dict:
        """Run compliance check and return summary."""
        try:
            print(f"\n📋 Running compliance check...")
            scan_result = self.compliance_checker.run_full_compliance_check()
            summary = scan_result.get('summary', {})
            
            score = summary.get('overall_compliance_score', 100)
            critical = summary.get('severity_breakdown', {}).get('CRITICAL', 0)
            total = summary.get('total_findings', 0)
            
            result = {
                'score': score,
                'critical_findings': critical,
                'total_findings': total,
                'summary': f"Compliance: {score}/100, {total} findings ({critical} critical)",
                'data': scan_result
            }
            
            if critical > 0:
                print(f"   🔴 {critical} CRITICAL compliance finding(s)!")
            
            return result
        except Exception as e:
            return {'error': str(e)}
    
    def _run_quota_check(self) -> dict:
        """Run quota check and return summary."""
        try:
            print(f"\n⚠️ Running quota check...")
            scan_result = self.quota_monitor.run_full_quota_check()
            summary = scan_result.get('summary', {})
            
            critical_alerts = summary.get('critical_alerts', 0)
            warning_alerts = summary.get('warning_alerts', 0)
            total_alerts = summary.get('total_alerts', 0)
            
            result = {
                'critical_alerts': critical_alerts,
                'warning_alerts': warning_alerts,
                'total_alerts': total_alerts,
                'summary': f"{total_alerts} quota alerts ({critical_alerts} critical)",
                'data': scan_result
            }
            
            if critical_alerts > 0:
                print(f"   🔴 {critical_alerts} quota(s) at CRITICAL level!")
            
            return result
        except Exception as e:
            return {'error': str(e)}
    
    def _run_backup_check(self) -> dict:
        """Run backup/DR check and return summary."""
        try:
            print(f"\n🔄 Running backup & DR check...")
            scan_result = self.backup_analyzer.run_full_backup_analysis()
            dr = scan_result.get('dr_readiness', {})
            
            score = dr.get('score', 100)
            level = dr.get('readiness_level', 'UNKNOWN')
            findings_count = len(dr.get('findings', []))
            
            result = {
                'score': score,
                'readiness_level': level,
                'findings_count': findings_count,
                'summary': f"DR Readiness: {score}/100 ({level})",
                'data': scan_result
            }
            
            if score < 60:
                print(f"   🔴 DR readiness is LOW: {score}/100")
            
            return result
        except Exception as e:
            return {'error': str(e)}
    
    def _check_alert_needed(self, incidents: list, feature_results: dict) -> bool:
        """
        Check if an alert should be sent based on incidents and feature scan results.
        
        Returns:
            True if alert should be sent
        """
        # Alert if any log incidents
        if incidents:
            return True
        
        # Alert if critical security findings
        security = feature_results.get('Security', {})
        if security.get('critical_findings', 0) > 0:
            return True
        
        # Alert if compliance critical findings
        compliance = feature_results.get('Compliance', {})
        if compliance.get('critical_findings', 0) > 0:
            return True
        
        # Alert if health is critical
        health = feature_results.get('Health', {})
        if health.get('score', 100) < 50:
            return True
        
        # Alert if quota is critical
        quota = feature_results.get('Quota', {})
        if quota.get('critical_alerts', 0) > 0:
            return True
        
        # Alert if DR readiness is very low
        backup = feature_results.get('Backup', {})
        if backup.get('score', 100) < 40:
            return True
        
        return False

    def run_daemon(self, interval_minutes: int = 60):
        """
        Run as daemon, executing analysis every N minutes.
        
        Args:
            interval_minutes: Minutes between runs (default 60)
        """
        print(f"🚀 Starting daemon mode - will run every {interval_minutes} minutes")
        print(f"   Press Ctrl+C to stop")
        
        try:
            while True:
                self.run_once()
                
                next_run = datetime.now() + timedelta(minutes=interval_minutes)
                print(f"⏰ Next run scheduled at: {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"   Sleeping for {interval_minutes} minutes...\n")
                
                time.sleep(interval_minutes * 60)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Daemon stopped by user")
            sys.exit(0)


def main():
    """Main entry point with CLI argument parsing."""
    parser = argparse.ArgumentParser(
        description='CloudWatch Sentinel - Automated Log Analysis with Email Alerts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scheduler.py                    # Run analysis once
  python scheduler.py --daemon           # Run continuously every 60 minutes
  python scheduler.py --daemon --interval 30  # Run every 30 minutes
  python scheduler.py --test             # Test email configuration
  python scheduler.py --security         # Run with security scan
  python scheduler.py --all-features     # Run with all features enabled
  
Environment variables for feature control:
  ENABLE_SECURITY_SCAN=true       Enable security scanning
  ENABLE_PERFORMANCE_SCAN=true    Enable performance analysis
  ENABLE_HEALTH_CHECK=true        Enable health checks
  ENABLE_COMPLIANCE_CHECK=true    Enable compliance checking
  ENABLE_QUOTA_CHECK=true         Enable quota monitoring
  ENABLE_BACKUP_CHECK=true        Enable backup/DR analysis
        """
    )
    
    parser.add_argument(
        '--daemon',
        action='store_true',
        help='Run as daemon (continuous mode)'
    )
    
    parser.add_argument(
        '--interval',
        type=int,
        default=60,
        help='Interval between runs in minutes (default: 60)'
    )
    
    parser.add_argument(
        '--test',
        action='store_true',
        help='Test email configuration and exit'
    )
    
    # Feature flags
    parser.add_argument(
        '--security',
        action='store_true',
        help='Enable security scanning'
    )
    
    parser.add_argument(
        '--performance',
        action='store_true',
        help='Enable performance analysis'
    )
    
    parser.add_argument(
        '--health',
        action='store_true',
        help='Enable health checks'
    )
    
    parser.add_argument(
        '--compliance',
        action='store_true',
        help='Enable compliance checking'
    )
    
    parser.add_argument(
        '--quota',
        action='store_true',
        help='Enable quota monitoring'
    )
    
    parser.add_argument(
        '--backup',
        action='store_true',
        help='Enable backup/DR analysis'
    )
    
    parser.add_argument(
        '--all-features',
        action='store_true',
        help='Enable all feature scans'
    )
    
    args = parser.parse_args()
    
    # Test mode
    if args.test:
        print("🧪 Testing email configuration...")
        try:
            notifier = EmailNotifier()
            if notifier.test_connection():
                print("✅ Email configuration is valid!")
                return 0
            else:
                print("❌ Email test failed")
                return 1
        except Exception as e:
            print(f"❌ Email configuration error: {e}")
            return 1
    
    # Build feature flags from CLI args
    enable_features = None
    if args.all_features:
        enable_features = {
            'security': True,
            'performance': True,
            'health': True,
            'compliance': True,
            'quota': True,
            'backup': True,
        }
    elif any([args.security, args.performance, args.health, args.compliance, args.quota, args.backup]):
        enable_features = {
            'security': args.security,
            'performance': args.performance,
            'health': args.health,
            'compliance': args.compliance,
            'quota': args.quota,
            'backup': args.backup,
        }
    
    # Initialize analyzer with feature flags
    analyzer = AutomatedAnalyzer(enable_features=enable_features)
    
    # Run mode
    if args.daemon:
        analyzer.run_daemon(interval_minutes=args.interval)
    else:
        success = analyzer.run_once()
        return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
