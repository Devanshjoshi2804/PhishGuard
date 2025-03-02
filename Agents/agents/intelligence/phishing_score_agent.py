from typing import Dict, Any, List, Optional
from common.models.base_agent import BaseAgent
from common.utils.database import db
from common.utils.message_queue import mq
import logging
from datetime import datetime
import traceback

logger = logging.getLogger(__name__)

class PhishingScoreAgent(BaseAgent):
    """Agent for calculating overall phishing risk score."""

    def __init__(self, agent_id: str, config: Dict[str, Any] = None):
        """Initialize the phishing score agent."""
        config = config or {}
        super().__init__(agent_id, config)

    async def initialize(self) -> None:
        """Initialize the phishing score agent."""
        logger.info("Initializing Phishing Score Agent")

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process all analysis results and calculate phishing score."""
        try:
            incident_id = data.get('incident_id')
            if not incident_id:
                raise ValueError("Missing incident_id")

            # Gather all analysis results
            analysis_results = await db.get_analysis_result(incident_id)
            if not analysis_results:
                raise ValueError(f"No analysis results found for incident {incident_id}")

            # Calculate overall phishing score
            phishing_score = self._calculate_phishing_score(analysis_results)

            # Store the results
            await db.update_analysis_result(incident_id, {
                'threat_intelligence_analysis': {
                    'phishing_score': phishing_score,
                    'analyzed_at': datetime.utcnow().isoformat()
                }
            })

            return phishing_score

        except Exception as e:
            logger.error(f"Error in phishing_score: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    def _calculate_phishing_score(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall phishing score based on all analysis results."""
        scores = {
            'overall_score': 0.0,
            'confidence': 0.0,
            'risk_factors': [],
            'analyzed_at': datetime.utcnow().isoformat()
        }

        # Email metadata analysis
        if 'email_analysis' in analysis_results:
            email_score = self._analyze_email_results(analysis_results['email_analysis'])
            scores['email_score'] = email_score
            scores['risk_factors'].extend(email_score['risk_factors'])
            
            # Authentication failures are a strong indicator
            if email_score.get('auth_failures', 0) > 0:
                scores['overall_score'] += email_score['score'] * 0.6  # 60% weight for auth failures
            else:
                scores['overall_score'] += email_score['score'] * 0.4  # 40% weight otherwise

        # URL analysis
        if 'url_analysis' in analysis_results and analysis_results['url_analysis']:
            url_score = self._analyze_url_results(analysis_results['url_analysis'])
            scores['url_score'] = url_score
            scores['risk_factors'].extend(url_score['risk_factors'])
            
            # Suspicious URLs are a strong indicator
            if url_score.get('high_risk_urls', 0) > 0:
                scores['overall_score'] += url_score['score'] * 0.6  # 60% weight for high-risk URLs
            else:
                scores['overall_score'] += url_score['score'] * 0.4  # 40% weight otherwise

        # Text analysis
        if 'text_analysis' in analysis_results and analysis_results['text_analysis']:
            text_score = self._analyze_text_results(analysis_results['text_analysis'])
            scores['text_score'] = text_score
            scores['risk_factors'].extend(text_score['risk_factors'])
            scores['overall_score'] += text_score['score'] * 0.4  # 40% weight for text analysis

        # Normalize overall score to 0-1 range
        scores['overall_score'] = min(max(scores['overall_score'], 0.0), 1.0)

        # Boost score based on specific high-risk combinations
        if 'email_score' in scores and 'url_score' in scores:
            email_score = scores['email_score']
            url_score = scores['url_score']
            
            # If we have both authentication failures and suspicious URLs, this is highly suspicious
            if email_score.get('auth_failures', 0) > 0 and url_score.get('high_risk_urls', 0) > 0:
                scores['overall_score'] = min(scores['overall_score'] * 1.8, 1.0)  # 80% boost
                scores['risk_factors'].append("Multiple critical indicators: Authentication failures and suspicious URLs")
            
            # If we have multiple authentication failures, this is very suspicious
            elif email_score.get('auth_failures', 0) >= 2:
                scores['overall_score'] = min(scores['overall_score'] * 1.5, 1.0)  # 50% boost
                scores['risk_factors'].append("Multiple authentication failures detected")
            
            # If we have multiple high-risk URLs, this is very suspicious
            elif url_score.get('high_risk_urls', 0) >= 2:
                scores['overall_score'] = min(scores['overall_score'] * 1.5, 1.0)  # 50% boost
                scores['risk_factors'].append("Multiple high-risk URLs detected")

        # Set risk level
        scores['risk_level'] = self._get_risk_level(scores['overall_score'])
        
        # Set confidence based on amount of data analyzed and number of risk factors
        analyzed_components = sum(1 for k in ['email_score', 'url_score', 'text_score'] if k in scores)
        risk_factor_confidence = min(len(scores['risk_factors']) / 5.0, 1.0)  # Cap at 5 risk factors
        scores['confidence'] = min((analyzed_components / 3.0 + risk_factor_confidence) / 2.0, 1.0)

        return scores

    def _analyze_email_results(self, email_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email-related results."""
        score = 0.0
        risk_factors = []
        auth_failures = 0

        if not email_analysis:
            return {'score': score, 'risk_factors': risk_factors, 'auth_failures': auth_failures}

        # Check headers analysis
        headers = email_analysis.get('headers_analysis', {})
        if headers.get('risk_level') == 'high':
            score += 0.6  # Increased from 0.4
            risk_factors.extend(headers.get('suspicious_patterns', []))
        elif headers.get('risk_level') == 'medium':
            score += 0.3  # Increased from 0.2

        # Check authentication analysis
        auth = email_analysis.get('authentication_analysis', {})
        if auth:
            # Count authentication failures
            if auth.get('spf_result') not in ['pass', 'neutral']:
                auth_failures += 1
                risk_factors.append(f"SPF authentication failed: {auth.get('spf_result')}")
            
            if auth.get('dkim_result') != 'pass':
                auth_failures += 1
                risk_factors.append(f"DKIM authentication failed: {auth.get('dkim_result')}")
            
            if auth.get('dmarc_result') != 'pass':
                auth_failures += 1
                risk_factors.append(f"DMARC authentication failed: {auth.get('dmarc_result')}")
            
            # Add score based on failures
            if auth_failures > 0:
                score += min(0.4 * auth_failures, 1.0)  # Increased from 0.3 per failure

        # Check for mismatched sender domains
        if 'domain mismatch' in ' '.join(risk_factors).lower():
            score += 0.4  # Increased from 0.3

        return {
            'score': min(score, 1.0),
            'risk_factors': risk_factors,
            'auth_failures': auth_failures
        }

    def _analyze_url_results(self, url_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze URL-related results."""
        score = 0.0
        risk_factors = []
        high_risk_urls = 0

        if not url_analysis:
            return {'score': score, 'risk_factors': risk_factors, 'high_risk_urls': high_risk_urls}

        results = url_analysis.get('results', [])
        for result in results:
            url_risk_score = result.get('risk_score', 0.0)
            
            # Count high-risk URLs
            if url_risk_score > 0.7:
                high_risk_urls += 1
                risk_factors.append(f"High-risk URL detected: {result.get('url')} (score: {url_risk_score:.2f})")
                score += 0.4  # Increased from 0.3
            elif url_risk_score > 0.5:
                risk_factors.append(f"Medium-risk URL detected: {result.get('url')} (score: {url_risk_score:.2f})")
                score += 0.3  # Added medium-risk score
            
            # Check for specific risk factors
            checks = result.get('checks', {})
            
            # Domain age
            if checks.get('domain_age', {}).get('is_new_domain'):
                risk_factors.append(f"New domain detected: {result.get('url')}")
                score += 0.3  # Increased from 0.2
            
            # SSL certificate
            ssl_cert = checks.get('ssl_cert', {})
            if ssl_cert:
                if ssl_cert.get('is_expired') or ssl_cert.get('is_self_signed'):
                    risk_factors.append(f"Invalid SSL certificate: {result.get('url')}")
                    score += 0.3  # Increased from 0.2
            
            # Suspicious patterns
            patterns = checks.get('malicious_patterns', {})
            if patterns.get('found'):
                risk_factors.append(f"Malicious patterns in URL: {result.get('url')}")
                score += 0.4  # Increased from 0.3

        return {
            'score': min(score, 1.0),
            'risk_factors': risk_factors,
            'high_risk_urls': high_risk_urls
        }

    def _analyze_text_results(self, text_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze text-related results."""
        score = 0.0
        risk_factors = []

        if not text_analysis:
            return {'score': score, 'risk_factors': risk_factors}

        # Check sentiment analysis
        sentiment = text_analysis.get('sentiment', {})
        if sentiment.get('is_suspicious'):
            score += 0.3
            risk_factors.append("Suspicious sentiment detected")

        # Check urgency indicators
        urgency = text_analysis.get('urgency_indicators', {})
        if urgency.get('is_urgent'):
            score += 0.3
            risk_factors.extend(urgency.get('indicators', []))

        # Check suspicious phrases
        phrases = text_analysis.get('suspicious_phrases', {})
        if phrases.get('found'):
            phrase_count = len(phrases.get('phrases', []))
            score += min(0.2 * phrase_count, 0.6)  # Up to 0.6 for multiple phrases
            risk_factors.extend(phrases.get('phrases', []))

        # Check for sensitive information requests
        if text_analysis.get('requests_sensitive_info'):
            score += 0.4
            risk_factors.append("Requests for sensitive information detected")

        return {
            'score': min(score, 1.0),
            'risk_factors': risk_factors
        }

    def _get_risk_level(self, score: float) -> str:
        """Convert numerical score to risk level."""
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        elif score >= 0.2:
            return "low"
        else:
            return "minimal"

    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        logger.info("Cleaning up Phishing Score Agent") 