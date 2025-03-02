from typing import Dict, Any, List, Optional
from common.models.base_agent import BaseAgent
from common.utils.database import db
from common.utils.message_queue import mq
import logging
from datetime import datetime
import json
import aiohttp
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import jinja2
import os

class AutoResponseAgent(BaseAgent):
    """Agent responsible for automatically responding to detected phishing threats."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("auto_response", config)
        self.session = None
        self.response_templates = {}
        self.email_config = config.get('email_config', {})
        self.webhook_config = config.get('webhook_config', {})
        self.response_thresholds = {
            'high': 0.8,    # Immediate automated response
            'medium': 0.5,  # Response with human approval
            'low': 0.3      # Log and monitor
        }
        self.template_env = self._setup_template_env()
        self.max_retries = 3
        self.retry_delay = 5  # seconds

    def _setup_template_env(self) -> jinja2.Environment:
        """Setup Jinja2 template environment."""
        template_dir = os.path.join(os.path.dirname(__file__), '../../templates/responses')
        return jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            autoescape=True
        )

    async def initialize(self) -> None:
        """Initialize the auto-response agent."""
        self.logger.info("Initializing Auto-Response Agent")
        self.session = aiohttp.ClientSession()
        await self._load_response_templates()

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process and respond to phishing threats."""
        try:
            incident_id = data.get('incident_id')
            threat_data = data.get('threat_data', {})
            risk_level = threat_data.get('risk_level', 'low')
            confidence = threat_data.get('confidence', 0.0)

            # Initialize response tracking
            response_results = {
                'incident_id': incident_id,
                'timestamp': datetime.utcnow().isoformat(),
                'risk_level': risk_level,
                'confidence': confidence,
                'actions_taken': [],
                'response_status': 'pending'
            }

            # Determine appropriate response based on risk level and confidence
            if confidence >= self.response_thresholds[risk_level]:
                response_actions = await self._determine_response_actions(threat_data)
                
                # Execute response actions
                for action in response_actions:
                    action_result = await self._execute_response_action(action, threat_data)
                    response_results['actions_taken'].append(action_result)

                # Update response status
                response_results['response_status'] = 'completed'
            else:
                response_results['response_status'] = 'monitoring'

            # Store response results
            await db.update_analysis_result(incident_id, {
                'auto_response_results': response_results
            })

            # Notify other agents
            await self._notify_agents(incident_id, response_results)

            return response_results

        except Exception as e:
            await self.handle_error(e)
            raise

    async def _load_response_templates(self) -> None:
        """Load response templates for different scenarios."""
        try:
            template_files = [
                'user_notification.html',
                'admin_alert.html',
                'block_notification.html',
                'quarantine_notification.html'
            ]

            for template_file in template_files:
                template_name = template_file.split('.')[0]
                self.response_templates[template_name] = self.template_env.get_template(template_file)

        except Exception as e:
            self.logger.error(f"Error loading response templates: {str(e)}")
            raise

    async def _determine_response_actions(self, threat_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Determine appropriate response actions based on threat data."""
        actions = []
        risk_level = threat_data.get('risk_level', 'low')

        if risk_level == 'high':
            actions.extend([
                {
                    'type': 'block',
                    'target': 'sender',
                    'priority': 'immediate'
                },
                {
                    'type': 'quarantine',
                    'target': 'message',
                    'priority': 'immediate'
                },
                {
                    'type': 'notify',
                    'target': 'admin',
                    'priority': 'high'
                },
                {
                    'type': 'notify',
                    'target': 'user',
                    'priority': 'high'
                }
            ])
        elif risk_level == 'medium':
            actions.extend([
                {
                    'type': 'quarantine',
                    'target': 'message',
                    'priority': 'high'
                },
                {
                    'type': 'notify',
                    'target': 'admin',
                    'priority': 'medium'
                },
                {
                    'type': 'notify',
                    'target': 'user',
                    'priority': 'medium'
                }
            ])
        else:  # low risk
            actions.extend([
                {
                    'type': 'tag',
                    'target': 'message',
                    'priority': 'low'
                },
                {
                    'type': 'monitor',
                    'target': 'sender',
                    'priority': 'low'
                }
            ])

        return actions

    async def _execute_response_action(self, action: Dict[str, Any], threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific response action."""
        action_result = {
            'action_type': action['type'],
            'target': action['target'],
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'pending',
            'details': {}
        }

        try:
            if action['type'] == 'block':
                action_result.update(await self._block_sender(action, threat_data))
            elif action['type'] == 'quarantine':
                action_result.update(await self._quarantine_message(action, threat_data))
            elif action['type'] == 'notify':
                action_result.update(await self._send_notification(action, threat_data))
            elif action['type'] == 'tag':
                action_result.update(await self._tag_message(action, threat_data))
            elif action['type'] == 'monitor':
                action_result.update(await self._monitor_sender(action, threat_data))

            action_result['status'] = 'completed'

        except Exception as e:
            self.logger.error(f"Error executing response action {action['type']}: {str(e)}")
            action_result['status'] = 'failed'
            action_result['error'] = str(e)

        return action_result

    async def _block_sender(self, action: Dict[str, Any], threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Block a sender through email security controls."""
        result = {
            'action': 'block_sender',
            'details': {}
        }

        try:
            sender = threat_data.get('sender', {}).get('address')
            if not sender:
                raise ValueError("Sender address not provided")

            # Implement blocking logic through email security API
            if self.webhook_config.get('email_security_api'):
                block_data = {
                    'address': sender,
                    'reason': 'Phishing attempt detected',
                    'threat_data': threat_data
                }

                async with self.session.post(
                    self.webhook_config['email_security_api'] + '/block',
                    json=block_data,
                    headers={'Authorization': self.webhook_config.get('api_key', '')}
                ) as response:
                    if response.status == 200:
                        result['details'] = await response.json()
                        result['success'] = True
                    else:
                        raise Exception(f"Failed to block sender: {response.status}")

        except Exception as e:
            self.logger.error(f"Error blocking sender: {str(e)}")
            result['success'] = False
            result['error'] = str(e)

        return result

    async def _quarantine_message(self, action: Dict[str, Any], threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Quarantine a suspicious message."""
        result = {
            'action': 'quarantine_message',
            'details': {}
        }

        try:
            message_id = threat_data.get('message_id')
            if not message_id:
                raise ValueError("Message ID not provided")

            # Implement quarantine logic through email security API
            if self.webhook_config.get('email_security_api'):
                quarantine_data = {
                    'message_id': message_id,
                    'reason': 'Phishing attempt detected',
                    'threat_data': threat_data
                }

                async with self.session.post(
                    self.webhook_config['email_security_api'] + '/quarantine',
                    json=quarantine_data,
                    headers={'Authorization': self.webhook_config.get('api_key', '')}
                ) as response:
                    if response.status == 200:
                        result['details'] = await response.json()
                        result['success'] = True
                    else:
                        raise Exception(f"Failed to quarantine message: {response.status}")

        except Exception as e:
            self.logger.error(f"Error quarantining message: {str(e)}")
            result['success'] = False
            result['error'] = str(e)

        return result

    async def _send_notification(self, action: Dict[str, Any], threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send notification to user or admin."""
        result = {
            'action': 'send_notification',
            'details': {}
        }

        try:
            template_name = f"{action['target']}_notification"
            if template_name not in self.response_templates:
                raise ValueError(f"Template not found: {template_name}")

            # Render notification content
            template = self.response_templates[template_name]
            content = template.render(threat_data=threat_data)

            # Send notification
            if action['target'] == 'user':
                recipient = threat_data.get('target_user', {}).get('email')
                subject = "Important Security Alert - Potential Phishing Attempt Detected"
            else:  # admin
                recipient = self.email_config.get('admin_email')
                subject = f"Phishing Alert - {threat_data.get('risk_level', 'Unknown')} Risk Level Detected"

            if recipient:
                await self._send_email(recipient, subject, content)
                result['success'] = True
                result['details']['recipient'] = recipient
            else:
                raise ValueError(f"Recipient not found for {action['target']}")

        except Exception as e:
            self.logger.error(f"Error sending notification: {str(e)}")
            result['success'] = False
            result['error'] = str(e)

        return result

    async def _tag_message(self, action: Dict[str, Any], threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Tag a suspicious message."""
        result = {
            'action': 'tag_message',
            'details': {}
        }

        try:
            message_id = threat_data.get('message_id')
            if not message_id:
                raise ValueError("Message ID not provided")

            # Implement message tagging logic through email security API
            if self.webhook_config.get('email_security_api'):
                tag_data = {
                    'message_id': message_id,
                    'tags': ['SUSPICIOUS', f"RISK_{threat_data.get('risk_level', 'low').upper()}"],
                    'threat_data': threat_data
                }

                async with self.session.post(
                    self.webhook_config['email_security_api'] + '/tag',
                    json=tag_data,
                    headers={'Authorization': self.webhook_config.get('api_key', '')}
                ) as response:
                    if response.status == 200:
                        result['details'] = await response.json()
                        result['success'] = True
                    else:
                        raise Exception(f"Failed to tag message: {response.status}")

        except Exception as e:
            self.logger.error(f"Error tagging message: {str(e)}")
            result['success'] = False
            result['error'] = str(e)

        return result

    async def _monitor_sender(self, action: Dict[str, Any], threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Set up monitoring for a suspicious sender."""
        result = {
            'action': 'monitor_sender',
            'details': {}
        }

        try:
            sender = threat_data.get('sender', {}).get('address')
            if not sender:
                raise ValueError("Sender address not provided")

            # Implement sender monitoring logic through security API
            if self.webhook_config.get('email_security_api'):
                monitor_data = {
                    'address': sender,
                    'monitoring_level': 'enhanced',
                    'duration_days': 30,
                    'threat_data': threat_data
                }

                async with self.session.post(
                    self.webhook_config['email_security_api'] + '/monitor',
                    json=monitor_data,
                    headers={'Authorization': self.webhook_config.get('api_key', '')}
                ) as response:
                    if response.status == 200:
                        result['details'] = await response.json()
                        result['success'] = True
                    else:
                        raise Exception(f"Failed to set up sender monitoring: {response.status}")

        except Exception as e:
            self.logger.error(f"Error setting up sender monitoring: {str(e)}")
            result['success'] = False
            result['error'] = str(e)

        return result

    async def _send_email(self, recipient: str, subject: str, content: str) -> None:
        """Send an email using configured SMTP settings."""
        if not all([
            self.email_config.get('smtp_host'),
            self.email_config.get('smtp_port'),
            self.email_config.get('smtp_username'),
            self.email_config.get('smtp_password')
        ]):
            raise ValueError("Incomplete SMTP configuration")

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.email_config['smtp_username']
        msg['To'] = recipient

        # Attach HTML content
        msg.attach(MIMEText(content, 'html'))

        # Send email with retry logic
        for attempt in range(self.max_retries):
            try:
                with smtplib.SMTP(self.email_config['smtp_host'], self.email_config['smtp_port']) as server:
                    server.starttls()
                    server.login(
                        self.email_config['smtp_username'],
                        self.email_config['smtp_password']
                    )
                    server.send_message(msg)
                break
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise
                await asyncio.sleep(self.retry_delay)

    async def _notify_agents(self, incident_id: str, results: Dict[str, Any]) -> None:
        """Notify other agents about auto-response actions."""
        try:
            # Notify the Phishing Score Agent
            await mq.publish('score_aggregation', {
                'incident_id': incident_id,
                'auto_response_results': results
            })

            # Notify Logging Agent
            await mq.publish('logging', {
                'incident_id': incident_id,
                'auto_response_log': {
                    'timestamp': datetime.utcnow().isoformat(),
                    'actions': results['actions_taken'],
                    'response_status': results['response_status']
                }
            })

        except Exception as e:
            self.logger.error(f"Error notifying agents: {str(e)}")

    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        self.logger.info("Cleaning up Auto-Response Agent")
        if self.session:
            await self.session.close() 