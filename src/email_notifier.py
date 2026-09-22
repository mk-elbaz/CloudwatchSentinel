import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List
from src.models import Incident
import os


class EmailNotifier:
    """Sends email notifications when critical errors are detected."""
    
    def __init__(self):
        """Initialize email configuration from environment variables."""
        self.smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', 587))
        self.smtp_user = os.getenv('SMTP_USER')
        self.smtp_password = os.getenv('SMTP_PASSWORD')
        self.from_email = os.getenv('ALERT_EMAIL_FROM', self.smtp_user)
        
        # Support multiple recipients (comma-separated)
        to_emails = os.getenv('ALERT_EMAIL_TO', '')
        self.to_emails = [email.strip() for email in to_emails.split(',') if email.strip()]
        
        # Validate configuration
        if not self.smtp_user or not self.smtp_password:
            raise ValueError("SMTP_USER and SMTP_PASSWORD must be set in .env file")
        
        if not self.to_emails:
            raise ValueError("ALERT_EMAIL_TO must be set in .env file")
    
    def send_alert(self, incidents: List[Incident], log_groups: List[str], feature_results: dict = None) -> bool:
        """
        Send email alert with incident details and feature results.
        
        Args:
            incidents: List of detected incidents
            log_groups: List of log groups that were analyzed
            feature_results: Optional dictionary of results from feature scans
            
        Returns:
            True if email sent successfully, False otherwise
        """
        if not incidents:
            return True  # No incidents, nothing to send
        
        # Count by severity
        critical_count = sum(1 for i in incidents if i.severity == "CRITICAL")
        warning_count = sum(1 for i in incidents if i.severity == "WARNING")
        info_count = sum(1 for i in incidents if i.severity == "INFO")
        
        # Create subject
        subject = f"🚨 CloudWatch Alert: {critical_count} Critical, {warning_count} Warnings"
        
        # Create HTML email body
        html_body = self._create_html_body(incidents, log_groups, critical_count, warning_count, info_count, feature_results)
        
        # Create text version for email clients that don't support HTML
        text_body = self._create_text_body(incidents, log_groups, critical_count, warning_count, info_count, feature_results)
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)
            
            # Attach both text and HTML versions
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            # Send email
            # Use SMTP_SSL for port 465, SMTP with STARTTLS for other ports
            if self.smtp_port == 465:
                with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=30) as server:
                    server.login(self.smtp_user, self.smtp_password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30) as server:
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_password)
                    server.send_message(msg)
            
            print(f"✅ Alert email sent to {len(self.to_emails)} recipient(s)")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send email: {e}")
            return False
    
    def _create_html_body(
        self, 
        incidents: List[Incident], 
        log_groups: List[str],
        critical_count: int,
        warning_count: int,
        info_count: int,
        feature_results: dict = None
    ) -> str:
        """Create HTML email body with formatted incident details and feature results."""
        
        severity_colors = {
            "CRITICAL": "#dc3545",
            "WARNING": "#ffc107",
            "INFO": "#17a2b8"
        }
        
        severity_bg_colors = {
            "CRITICAL": "#f8d7da",
            "WARNING": "#fff3cd",
            "INFO": "#d1ecf1"
        }
        
        severity_text_colors = {
            "CRITICAL": "#721c24",
            "WARNING": "#856404",
            "INFO": "#0c5460"
        }
        
        # Build incidents HTML
        incidents_html = ""
        for idx, incident in enumerate(incidents, 1):
            border_color = severity_colors.get(incident.severity, "#6c757d")
            severity_badge_bg = severity_bg_colors.get(incident.severity, "#e9ecef")
            severity_badge_text = severity_text_colors.get(incident.severity, "#495057")
            
            incidents_html += f"""
                                <div style="background-color: #f8f9fa; border-radius: 8px; padding: 25px; margin: 20px 0; border-left: 4px solid {border_color};">
                                    <h3 style="color: {border_color}; margin: 0 0 20px 0; font-size: 18px;">Incident #{idx}: {incident.summary}</h3>

                                    <div style="margin-bottom: 15px;">
                                        <strong style="color: #333; font-size: 14px;">Severity:</strong>
                                        <span style="background-color: {severity_badge_bg}; color: {severity_badge_text}; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-left: 8px;">{incident.severity}</span>
                                    </div>

                                    <div style="margin-bottom: 15px;">
                                        <strong style="color: #333; font-size: 14px;">Log Group:</strong>
                                        <p style="color: #555; font-size: 14px; margin: 5px 0 0 0; font-family: 'Courier New', monospace;">{incident.log_group}</p>
                                    </div>

                                    <div style="margin-bottom: 15px;">
                                        <strong style="color: #333; font-size: 14px;">Timestamp:</strong>
                                        <p style="color: #555; font-size: 14px; margin: 5px 0 0 0;">{incident.timestamp.strftime('%B %d, %Y at %I:%M %p UTC')}</p>
                                    </div>

                                    {f'''<div style="margin-bottom: 15px;">
                                        <strong style="color: #333; font-size: 14px;">Affected Service:</strong>
                                        <p style="color: #555; font-size: 14px; margin: 5px 0 0 0;">{incident.affected_service}</p>
                                    </div>''' if incident.affected_service != 'Unknown' else ''}

                                    <div style="margin-bottom: 15px;">
                                        <strong style="color: #333; font-size: 14px;">Root Cause:</strong>
                                        <div style="background-color: #ffffff; border: 1px solid #dee2e6; border-radius: 4px; padding: 15px; margin-top: 8px;">
                                            <p style="color: #555; font-size: 14px; line-height: 1.6; margin: 0;">{incident.root_cause}</p>
                                        </div>
                                    </div>

                                    <div>
                                        <strong style="color: #333; font-size: 14px;">Recommendation:</strong>
                                        <div style="background-color: #e8f4fd; border: 1px solid #bee5eb; border-radius: 4px; padding: 15px; margin-top: 8px;">
                                            <p style="color: #0c5460; font-size: 14px; line-height: 1.6; margin: 0; font-weight: 500;">{incident.recommendation}</p>
                                        </div>
                                    </div>
                                </div>
            """
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CloudWatch Sentinel - Incident Alert</title>
</head>
<body style="margin: 0; padding: 0; width: 100%; background-color: #f6f6f6; font-family: Arial, sans-serif;">
    <table role="presentation" style="width: 100%; border-collapse: collapse;">
        <tr>
            <td align="center" style="padding: 40px 0;">
                <table role="presentation" style="width: 100%; max-width: 600px; border-collapse: collapse; background: #fff; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <!-- Header Section -->
                    <tr>
                        <td style="background-color: #050A44; padding: 30px; border-radius: 8px 8px 0 0; text-align: center;">
                            <h2 style="color: #FFFFFF; margin: 0; font-size: 28px; letter-spacing: 0.5px;">🛡️ CloudWatch Sentinel</h2>
                            <p style="color: #FFFFFF; margin: 10px 0 0 0; font-size: 16px;">Incident Alert Notification</p>
                        </td>
                    </tr>

                    <!-- Email Body -->
                    <tr>
                        <td style="padding: 40px 35px;">
                            <p style="margin-top: 0; margin-bottom: 25px; color: #333; font-size: 17px;">Dear Operations Team,</p>

                            <p style="color: #555; font-size: 16px; line-height: 1.5; margin-bottom: 25px;">CloudWatch Sentinel has detected {len(incidents)} incident(s) that require your attention. Please review the details below:</p>

                            <!-- Summary Section -->
                            <div style="background-color: #e8f4fd; border-radius: 8px; padding: 20px 25px; margin: 30px 0; border-left: 4px solid #050A44;">
                                <p style="color: #050A44; font-size: 16px; margin: 0 0 15px 0; font-weight: bold;">📊 Summary</p>
                                <table style="width: 100%; border-collapse: collapse;">
                                    <tr>
                                        <td style="padding: 5px 0; color: #555; font-size: 14px;"><strong>Total Incidents:</strong></td>
                                        <td style="padding: 5px 0; color: #555; font-size: 14px; text-align: right;">{len(incidents)}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 5px 0; color: #555; font-size: 14px;"><strong>🔴 Critical:</strong></td>
                                        <td style="padding: 5px 0; color: #dc3545; font-size: 14px; text-align: right; font-weight: bold;">{critical_count}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 5px 0; color: #555; font-size: 14px;"><strong>🟡 Warnings:</strong></td>
                                        <td style="padding: 5px 0; color: #ffc107; font-size: 14px; text-align: right; font-weight: bold;">{warning_count}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 5px 0; color: #555; font-size: 14px;"><strong>🔵 Info:</strong></td>
                                        <td style="padding: 5px 0; color: #17a2b8; font-size: 14px; text-align: right; font-weight: bold;">{info_count}</td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 5px 0; color: #555; font-size: 14px;"><strong>Log Groups Analyzed:</strong></td>
                                        <td style="padding: 5px 0; color: #555; font-size: 14px; text-align: right;">{len(log_groups)}</td>
                                    </tr>
                                </table>
                            </div>

                            <!-- Incident Details -->
                            {incidents_html}

                            <!-- Feature Results Section -->
                            {self._create_feature_results_html(feature_results) if feature_results else ''}

                            <!-- Next Steps -->
                            <div style="background-color: #e8f4fd; border-radius: 8px; padding: 20px 25px; margin: 30px 0; border-left: 4px solid #050A44;">
                                <p style="color: #050A44; font-size: 16px; margin: 0 0 10px 0; font-weight: bold;">⚡ Next Steps:</p>
                                <ul style="color: #555; font-size: 14px; margin: 0; padding-left: 20px; line-height: 1.6;">
                                    <li>Review each incident and assess priority</li>
                                    <li>Follow the recommended actions</li>
                                    <li>Update incident status in the dashboard</li>
                                    <li>Investigate root causes for critical issues</li>
                                    <li>Consider adding noise patterns for false positives</li>
                                </ul>
                            </div>

                            <div style="margin-top: 40px;">
                                <p style="color: #555; margin-bottom: 5px; font-size: 15px; line-height: 1.6;">
                                    Best regards,<br>
                                    <strong style="color: #050A44; font-size: 16px; display: inline-block; margin-top: 8px;">CloudWatch Sentinel System</strong>
                                </p>
                                <p style="color: #888; font-size: 13px; margin-top: 15px;">
                                    Analyzed log groups: {', '.join(log_groups[:5])}{' and ' + str(len(log_groups) - 5) + ' more' if len(log_groups) > 5 else ''}
                                </p>
                            </div>
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td style="background-color: #f5f5f5; padding: 25px; border-radius: 0 0 8px 8px; text-align: center;">
                            <p style="margin: 0; color: #777; font-size: 13px;">© CloudWatch Sentinel. All rights reserved.</p>
                            <p style="margin: 8px 0 0 0; color: #888; font-size: 12px;">This is an automated email, please do not reply.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"""
        
        return html
    
    def _create_text_body(
        self, 
        incidents: List[Incident], 
        log_groups: List[str],
        critical_count: int,
        warning_count: int,
        info_count: int,
        feature_results: dict = None
    ) -> str:
        """Create plain text email body."""
        
        text = f"""
CloudWatch Sentinel Alert
========================

SUMMARY
-------
Total Incidents: {len(incidents)}
Critical: {critical_count}
Warnings: {warning_count}
Info: {info_count}
Analyzed Log Groups: {len(log_groups)}

INCIDENT DETAILS
----------------
"""
        
        if not incidents:
            text += "No log incidents detected.\n"
        
        for i, incident in enumerate(incidents, 1):
            text += f"""
{i}. [{incident.severity}] {incident.summary}
   Log Group: {incident.log_group}
   Timestamp: {incident.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
   Root Cause: {incident.root_cause}
   Recommendation: {incident.recommendation}
   {f'Affected Service: {incident.affected_service}' if incident.affected_service != 'Unknown' else ''}

"""
        
        if feature_results:
            text += self._create_feature_results_text(feature_results)
            
        text += f"""
---
Analyzed log groups: {', '.join(log_groups[:5])}{' and ' + str(len(log_groups) - 5) + ' more...' if len(log_groups) > 5 else ''}

This is an automated alert from CloudWatch Sentinel.
"""
        
        return text
    
    def _create_feature_results_html(self, feature_results: dict) -> str:
        """Create HTML for feature scan results."""
        if not feature_results:
            return ""
            
        rows_html = ""
        for feature, result in feature_results.items():
            status_color = "#28a745" # Success green
            icon = "✅"
            
            if result.get('error'):
                status_color = "#dc3545" # Danger red
                icon = "❌"
            elif 'critical' in str(result.get('summary', '')).lower() or (isinstance(result.get('score'), (int, float)) and result.get('score') < 60):
                status_color = "#dc3545" # Danger red
                icon = "🚨"
            elif 'warning' in str(result.get('summary', '')).lower() or (isinstance(result.get('score'), (int, float)) and result.get('score') < 80):
                status_color = "#ffc107" # Warning yellow
                icon = "⚠️"
                
            summary = result.get('error') or result.get('summary', 'Completed')
            
            rows_html += f"""
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #dee2e6; color: #333;"><strong>{feature}</strong></td>
                    <td style="padding: 12px; border-bottom: 1px solid #dee2e6; color: {status_color}; text-align: right;">
                        <span style="margin-right: 8px;">{icon}</span>{summary}
                    </td>
                </tr>
            """
            
        return f"""
            <div style="background-color: #ffffff; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; margin: 30px 0;">
                <h3 style="color: #050A44; margin: 0 0 15px 0; font-size: 18px; border-bottom: 2px solid #e8f4fd; padding-bottom: 10px;">📋 Feature Scan Results</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    {rows_html}
                </table>
            </div>
        """

    def _create_feature_results_text(self, feature_results: dict) -> str:
        """Create text for feature scan results."""
        text = "\nFEATURE SCAN RESULTS\n--------------------\n"
        for feature, result in feature_results.items():
            summary = result.get('error') or result.get('summary', 'Completed')
            text += f"{feature}: {summary}\n"
        return text
    
    def test_connection(self) -> bool:
        """Test SMTP connection and credentials."""
        try:
            # Use SMTP_SSL for port 465, SMTP with STARTTLS for other ports
            if self.smtp_port == 465:
                with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=10) as server:
                    server.login(self.smtp_user, self.smtp_password)
            else:
                with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_password)
            print(f"✅ SMTP connection successful to {self.smtp_host}:{self.smtp_port}")
            return True
        except Exception as e:
            print(f"❌ SMTP connection failed: {e}")
            return False
