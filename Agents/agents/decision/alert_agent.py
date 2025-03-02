from typing import Dict, Any, List
from common.models.base_agent import BaseAgent
from common.utils.database import db
from common.utils.message_queue import mq
import logging
from datetime import datetime
import json
import aiohttp
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import os
from dotenv import load_dotenv

load_dotenv()

class AlertAgent(BaseAgent):
    """Agent responsible for sending alerts and notifications about phishing attempts."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("alert", config)
        self.notification_channels = {
            'email': self._send_email_alert,
            'slack': self._send_slack_alert,
            'webhook': self._send_webhook_alert
        }
        self.alert_templates = self._load_alert_templates()
        self.session = None

    async def initialize(self) -> None:
        """Initialize the alert agent."""
        self.logger.info("Initializing Alert Agent")
        self.session = aiohttp.ClientSession()
        
        # Validate configuration
        self._validate_config()

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process alert requests and send notifications."""
        try:
            incident_id = data.get('incident_id')
            score = data.get('score', 0.0)
            report = data.get('report', {})
            
            # Determine alert level and channels
            alert_config = self._get_alert_config(score)
            
            # Send alerts through configured channels
            alert_results = await self._send_alerts(
                incident_id,
                score,
                report,
                alert_config
            )
            
            # Log alert activity
            await self._log_alert_activity(incident_id, alert_results)
            
            return alert_results

        except Exception as e:
            await self.handle_error(e)
            raise

    def _validate_config(self) -> None:
        """Validate the agent's configuration."""
        required_configs = {
            'email': ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USERNAME', 'SMTP_PASSWORD'],
            'slack': ['SLACK_WEBHOOK_URL'],
            'webhook': ['WEBHOOK_URL']
        }
        
        for channel, configs in required_configs.items():
            if channel in self.config.get('enabled_channels', []):
                missing = [cfg for cfg in configs if not os.getenv(cfg)]
                if missing:
                    self.logger.warning(
                        f"Missing configuration for {channel} channel: {', '.join(missing)}"
                    )

    def _load_alert_templates(self) -> Dict[str, Dict[str, str]]:
        """Load alert templates for different channels and risk levels."""
        return {
            'email': {
                'high': """
                    <h2>⚠️ High Risk Phishing Attempt Detected</h2>
                    <p>A high-risk phishing attempt has been detected:</p>
                    <ul>
                        <li>Incident ID: {incident_id}</li>
                        <li>Risk Score: {score}</li>
                        <li>Detection Time: {timestamp}</li>
                    </ul>
                    <h3>Summary</h3>
                    <p>{summary}</p>
                    <h3>Recommendations</h3>
                    <ul>
                        {recommendations}
                    </ul>
                """,
                'medium': """
                    <h2>⚠️ Suspicious Activity Detected</h2>
                    <p>Suspicious activity has been detected that may indicate a phishing attempt:</p>
                    <ul>
                        <li>Incident ID: {incident_id}</li>
                        <li>Risk Score: {score}</li>
                        <li>Detection Time: {timestamp}</li>
                    </ul>
                    <h3>Summary</h3>
                    <p>{summary}</p>
                    <h3>Recommendations</h3>
                    <ul>
                        {recommendations}
                    </ul>
                """
            },
            'slack': {
                'high': """
                    🚨 *High Risk Phishing Attempt Detected*
                    
                    *Incident Details:*
                    • ID: {incident_id}
                    • Risk Score: {score}
                    • Time: {timestamp}
                    
                    *Summary:*
                    {summary}
                    
                    *Recommendations:*
                    {recommendations}
                """,
                'medium': """
                    ⚠️ *Suspicious Activity Detected*
                    
                    *Incident Details:*
                    • ID: {incident_id}
                    • Risk Score: {score}
                    • Time: {timestamp}
                    
                    *Summary:*
                    {summary}
                    
                    *Recommendations:*
                    {recommendations}
                """
            }
        }

    def _get_alert_config(self, score: float) -> Dict[str, Any]:
        """Determine alert configuration based on risk score."""
        if score >= 0.7:  # High risk
            return {
                'level': 'high',
                'channels': self.config.get('high_risk_channels', ['email', 'slack']),
                'priority': 'high',
                'recipients': self.config.get('high_risk_recipients', [])
            }
        else:  # Medium risk
            return {
                'level': 'medium',
                'channels': self.config.get('medium_risk_channels', ['email']),
                'priority': 'medium',
                'recipients': self.config.get('medium_risk_recipients', [])
            }

    async def _send_alerts(
        self,
        incident_id: str,
        score: float,
        report: Dict[str, Any],
        alert_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Send alerts through configured channels."""
        results = {}
        
        for channel in alert_config['channels']:
            if channel in self.notification_channels:
                try:
                    result = await self.notification_channels[channel](
                        incident_id,
                        score,
                        report,
                        alert_config
                    )
                    results[channel] = {
                        'status': 'success',
                        'timestamp': datetime.utcnow().isoformat(),
                        'details': result
                    }
                except Exception as e:
                    self.logger.error(f"Error sending {channel} alert: {str(e)}")
                    results[channel] = {
                        'status': 'error',
                        'timestamp': datetime.utcnow().isoformat(),
                        'error': str(e)
                    }
            
        return results

    async def _send_email_alert(
        self,
        incident_id: str,
        score: float,
        report: Dict[str, Any],
        alert_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Send email alert."""
        try:
            template = self.alert_templates['email'][alert_config['level']]
            
            # Format recommendations as HTML list items
            recommendations_html = ''.join(
                f"<li>{rec}</li>" for rec in report.get('recommendations', [])
            )
            
            # Format email content
            content = template.format(
                incident_id=incident_id,
                score=f"{score:.2f}",
                timestamp=report.get('timestamp', datetime.utcnow().isoformat()),
                summary=report.get('summary', ''),
                recommendations=recommendations_html
            )
            
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"Phishing Alert - {alert_config['level'].upper()} Risk Detected"
            msg['From'] = os.getenv('SMTP_USERNAME')
            msg['To'] = ', '.join(alert_config['recipients'])
            msg.attach(MIMEText(content, 'html'))
            
            # Send email
            with smtplib.SMTP(os.getenv('SMTP_HOST'), int(os.getenv('SMTP_PORT'))) as server:
                server.starttls()
                server.login(os.getenv('SMTP_USERNAME'), os.getenv('SMTP_PASSWORD'))
                server.send_message(msg)
            
            return {'message_id': msg['Message-ID']}
            
        except Exception as e:
            self.logger.error(f"Error sending email alert: {str(e)}")
            raise

    async def _send_slack_alert(
        self,
        incident_id: str,
        score: float,
        report: Dict[str, Any],
        alert_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Send Slack alert."""
        try:
            template = self.alert_templates['slack'][alert_config['level']]
            
            # Format recommendations as bullet points
            recommendations_text = '\n'.join(
                f"• {rec}" for rec in report.get('recommendations', [])
            )
            
            # Format message content
            content = template.format(
                incident_id=incident_id,
                score=f"{score:.2f}",
                timestamp=report.get('timestamp', datetime.utcnow().isoformat()),
                summary=report.get('summary', ''),
                recommendations=recommendations_text
            )
            
            # Send to Slack
            webhook_url = os.getenv('SLACK_WEBHOOK_URL')
            async with self.session.post(webhook_url, json={'text': content}) as response:
                return {'status_code': response.status}
                
        except Exception as e:
            self.logger.error(f"Error sending Slack alert: {str(e)}")
            raise

    async def _send_webhook_alert(
        self,
        incident_id: str,
        score: float,
        report: Dict[str, Any],
        alert_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Send alert to webhook endpoint."""
        try:
            webhook_url = os.getenv('WEBHOOK_URL')
            payload = {
                'incident_id': incident_id,
                'score': score,
                'level': alert_config['level'],
                'priority': alert_config['priority'],
                'timestamp': datetime.utcnow().isoformat(),
                'report': report
            }
            
            async with self.session.post(webhook_url, json=payload) as response:
                return {
                    'status_code': response.status,
                    'response': await response.text()
                }
                
        except Exception as e:
            self.logger.error(f"Error sending webhook alert: {str(e)}")
            raise

    async def _log_alert_activity(self, incident_id: str, results: Dict[str, Any]) -> None:
        """Log alert activity to the database."""
        await db.log_agent_activity(
            self.agent_id,
            {
                'incident_id': incident_id,
                'activity_type': 'alert_sent',
                'timestamp': datetime.utcnow().isoformat(),
                'details': results
            }
        )

    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        self.logger.info("Cleaning up Alert Agent")
        if self.session:
            await self.session.close() 