import asyncio
import logging
import json
from datetime import datetime
from typing import Dict, Any, List
import os
import sys

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.ingestion.email_parser_agent import EmailParserAgent
from agents.analysis.text_analysis_agent import TextAnalysisAgent
from agents.analysis.url_analysis_agent import URLAnalysisAgent
from agents.intelligence.threat_intelligence_agent import ThreatIntelligenceAgent
from agents.intelligence.anomaly_detection_agent import AnomalyDetectionAgent
from agents.intelligence.reinforcement_learning_agent import ReinforcementLearningAgent
from agents.decision.alert_agent import AlertAgent
from agents.decision.auto_response_agent import AutoResponseAgent
from agents.monitoring.logging_agent import LoggingAgent
from agents.monitoring.feedback_agent import FeedbackAgent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AgentTester:
    """Test harness for verifying agent functionality."""

    def __init__(self):
        # Agent configurations
        self.config = {
            'email_parser': {
                'supported_formats': ['eml', 'msg', 'raw'],
                'max_size': 10485760  # 10MB
            },
            'text_analysis': {
                'min_confidence': 0.6,
                'language': 'en'
            },
            'url_analysis': {
                'timeout': 30,
                'max_redirects': 5
            },
            'threat_intelligence': {
                'update_interval': 3600,
                'cache_duration': 21600
            },
            'anomaly_detection': {
                'training_window': 30,
                'min_samples': 50
            },
            'reinforcement_learning': {
                'learning_rate': 0.001,
                'batch_size': 64
            },
            'alert': {
                'email_config': {
                    'smtp_host': 'smtp.example.com',
                    'smtp_port': 587,
                    'smtp_username': 'test@example.com',
                    'smtp_password': 'password'
                }
            },
            'auto_response': {
                'response_thresholds': {
                    'high': 0.8,
                    'medium': 0.5,
                    'low': 0.3
                }
            },
            'logging': {
                'log_directory': 'logs',
                'report_directory': 'reports'
            },
            'feedback': {
                'model_directory': 'models',
                'feedback_threshold': 100
            }
        }

        # Initialize agents
        self.agents = {
            'email_parser': EmailParserAgent(self.config['email_parser']),
            'text_analysis': TextAnalysisAgent(self.config['text_analysis']),
            'url_analysis': URLAnalysisAgent(self.config['url_analysis']),
            'threat_intelligence': ThreatIntelligenceAgent(self.config['threat_intelligence']),
            'anomaly_detection': AnomalyDetectionAgent(self.config['anomaly_detection']),
            'reinforcement_learning': ReinforcementLearningAgent(self.config['reinforcement_learning']),
            'alert': AlertAgent(self.config['alert']),
            'auto_response': AutoResponseAgent(self.config['auto_response']),
            'logging': LoggingAgent(self.config['logging']),
            'feedback': FeedbackAgent(self.config['feedback'])
        }

    async def initialize_agents(self):
        """Initialize all agents."""
        for agent_name, agent in self.agents.items():
            try:
                logger.info(f"Initializing {agent_name} agent...")
                await agent.initialize()
                logger.info(f"{agent_name} agent initialized successfully")
            except Exception as e:
                logger.error(f"Error initializing {agent_name} agent: {str(e)}")
                raise

    async def test_email_processing(self):
        """Test complete email processing workflow."""
        try:
            # Sample phishing email data
            email_data = {
                'incident_id': 'TEST-001',
                'raw_email': '''
From: suspicious@example.com
To: victim@company.com
Subject: Urgent: Account Security Update Required
Date: Thu, 20 Jul 2023 10:00:00 -0000

Dear User,

Your account security needs immediate attention. Click the link below to verify:
http://malicious-site.com/verify

Best regards,
Security Team
                ''',
                'metadata': {
                    'source': 'test',
                    'timestamp': datetime.utcnow().isoformat()
                }
            }

            # Process through email parser
            logger.info("Testing email parser...")
            email_results = await self.agents['email_parser'].process(email_data)
            
            # Text analysis
            logger.info("Testing text analysis...")
            text_results = await self.agents['text_analysis'].process({
                'incident_id': email_data['incident_id'],
                'text_content': email_results['extracted_text'],
                'metadata': email_results['metadata']
            })

            # URL analysis
            logger.info("Testing URL analysis...")
            url_results = await self.agents['url_analysis'].process({
                'incident_id': email_data['incident_id'],
                'urls': email_results['extracted_urls'],
                'metadata': email_results['metadata']
            })

            # Threat intelligence analysis
            logger.info("Testing threat intelligence...")
            threat_results = await self.agents['threat_intelligence'].process({
                'incident_id': email_data['incident_id'],
                'domains': email_results['extracted_domains'],
                'urls': email_results['extracted_urls'],
                'email_addresses': email_results['extracted_emails']
            })

            # Anomaly detection
            logger.info("Testing anomaly detection...")
            anomaly_results = await self.agents['anomaly_detection'].process({
                'incident_id': email_data['incident_id'],
                'email_analysis': email_results,
                'text_analysis': text_results,
                'url_analysis': url_results,
                'threat_intelligence': threat_results
            })

            # Reinforcement learning
            logger.info("Testing reinforcement learning...")
            rl_results = await self.agents['reinforcement_learning'].process({
                'incident_id': email_data['incident_id'],
                'analysis_results': {
                    'email_analysis': email_results,
                    'text_analysis': text_results,
                    'url_analysis': url_results,
                    'threat_intelligence': threat_results,
                    'anomaly_detection': anomaly_results
                }
            })

            # Alert generation
            logger.info("Testing alert generation...")
            alert_results = await self.agents['alert'].process({
                'incident_id': email_data['incident_id'],
                'risk_level': 'high',
                'analysis_results': {
                    'email_analysis': email_results,
                    'threat_intelligence': threat_results,
                    'anomaly_detection': anomaly_results
                }
            })

            # Auto-response
            logger.info("Testing auto-response...")
            response_results = await self.agents['auto_response'].process({
                'incident_id': email_data['incident_id'],
                'threat_data': {
                    'risk_level': 'high',
                    'confidence': 0.95
                }
            })

            # Logging
            logger.info("Testing logging...")
            log_results = await self.agents['logging'].process({
                'incident_id': email_data['incident_id'],
                'log_type': 'incident',
                'details': {
                    'email_analysis': email_results,
                    'text_analysis': text_results,
                    'url_analysis': url_results,
                    'threat_intelligence': threat_results,
                    'anomaly_detection': anomaly_results,
                    'rl_decision': rl_results,
                    'alert': alert_results,
                    'response': response_results
                }
            })

            # Feedback
            logger.info("Testing feedback processing...")
            feedback_results = await self.agents['feedback'].process({
                'incident_id': email_data['incident_id'],
                'feedback_type': 'automated_verification',
                'is_phishing': True,
                'confidence': 0.95,
                'features': {
                    'text_similarity': 0.8,
                    'url_suspicion': 0.9,
                    'domain_age': 0.1
                }
            })

            logger.info("All agent tests completed successfully")
            return {
                'email_results': email_results,
                'text_results': text_results,
                'url_results': url_results,
                'threat_results': threat_results,
                'anomaly_results': anomaly_results,
                'rl_results': rl_results,
                'alert_results': alert_results,
                'response_results': response_results,
                'log_results': log_results,
                'feedback_results': feedback_results
            }

        except Exception as e:
            logger.error(f"Error in test workflow: {str(e)}")
            raise

    async def cleanup_agents(self):
        """Cleanup all agents."""
        for agent_name, agent in self.agents.items():
            try:
                logger.info(f"Cleaning up {agent_name} agent...")
                await agent.cleanup()
                logger.info(f"{agent_name} agent cleaned up successfully")
            except Exception as e:
                logger.error(f"Error cleaning up {agent_name} agent: {str(e)}")

async def main():
    """Main test execution function."""
    tester = AgentTester()
    try:
        # Initialize agents
        await tester.initialize_agents()

        # Run tests
        results = await tester.test_email_processing()

        # Save test results
        with open('test_results.json', 'w') as f:
            json.dump(results, f, indent=2, default=str)

        logger.info("Test results saved to test_results.json")

    except Exception as e:
        logger.error(f"Test execution failed: {str(e)}")
        raise
    finally:
        # Cleanup
        await tester.cleanup_agents()

if __name__ == "__main__":
    asyncio.run(main()) 