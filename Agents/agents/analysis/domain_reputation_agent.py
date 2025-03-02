from typing import Dict, Any, List, Optional
from common.models.base_agent import BaseAgent
from common.utils.database import db
from common.utils.message_queue import mq
import logging
import aiohttp
import asyncio
from datetime import datetime, timedelta
import json
import re
from urllib.parse import urlparse

class DomainReputationAgent(BaseAgent):
    """Agent responsible for analyzing domain reputation and historical data."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("domain_reputation", config)
        self.session = None
        self.reputation_apis = {
            'virustotal': config.get('virustotal_api_key'),
            'abuseipdb': config.get('abuseipdb_api_key'),
            'google_safebrowsing': config.get('google_safebrowsing_api_key')
        }
        self.cache_duration = timedelta(hours=24)
        self.malicious_threshold = 2  # Number of sources needed to consider domain malicious

    async def initialize(self) -> None:
        """Initialize the domain reputation agent."""
        self.logger.info("Initializing Domain Reputation Agent")
        self.session = aiohttp.ClientSession()

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process domain reputation analysis."""
        try:
            incident_id = data.get('incident_id')
            domains = data.get('domains', [])
            urls = data.get('urls', [])

            # Extract domains from URLs if provided
            if urls:
                domains.extend([urlparse(url).netloc for url in urls if url])
            domains = list(set(domains))  # Remove duplicates

            if not domains:
                raise ValueError("No domains or URLs provided for analysis")

            # Analyze each domain
            analysis_results = {
                'incident_id': incident_id,
                'timestamp': datetime.utcnow().isoformat(),
                'domains': []
            }

            for domain in domains:
                domain_analysis = await self._analyze_domain(domain)
                analysis_results['domains'].append(domain_analysis)

            # Store results
            await db.update_analysis_result(incident_id, {
                'domain_reputation_analysis': analysis_results
            })

            # Notify other agents
            await self._notify_agents(incident_id, analysis_results)

            return analysis_results

        except Exception as e:
            await self.handle_error(e)
            raise

    async def _analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze a single domain's reputation and history."""
        try:
            # Check cache first
            cached_result = await self._check_cache(domain)
            if cached_result:
                return cached_result

            analysis = {
                'domain': domain,
                'timestamp': datetime.utcnow().isoformat(),
                'reputation_scores': {},
                'historical_data': await self._get_historical_data(domain),
                'malicious_indicators': [],
                'risk_level': 'unknown'
            }

            # Gather reputation data from multiple sources
            reputation_tasks = [
                self._check_virustotal(domain),
                self._check_abuseipdb(domain),
                self._check_safebrowsing(domain)
            ]
            reputation_results = await asyncio.gather(*reputation_tasks, return_exceptions=True)

            # Process reputation results
            malicious_sources = 0
            for result in reputation_results:
                if isinstance(result, Exception):
                    continue
                if result:
                    analysis['reputation_scores'].update(result)
                    if result.get('is_malicious'):
                        malicious_sources += 1

            # Determine overall risk level
            analysis['risk_level'] = self._calculate_risk_level(malicious_sources)
            
            # Cache the results
            await self._cache_result(domain, analysis)

            return analysis

        except Exception as e:
            self.logger.error(f"Error analyzing domain {domain}: {str(e)}")
            return {
                'domain': domain,
                'error': str(e),
                'risk_level': 'unknown'
            }

    async def _check_virustotal(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain reputation using VirusTotal API."""
        if not self.reputation_apis['virustotal']:
            return None

        try:
            headers = {
                'x-apikey': self.reputation_apis['virustotal']
            }
            async with self.session.get(
                f'https://www.virustotal.com/api/v3/domains/{domain}',
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    attributes = data.get('data', {}).get('attributes', {})
                    
                    return {
                        'virustotal': {
                            'reputation_score': attributes.get('reputation', 0),
                            'total_votes': attributes.get('total_votes', {}),
                            'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                            'is_malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0) > 0
                        }
                    }
                return None

        except Exception as e:
            self.logger.error(f"Error checking VirusTotal for {domain}: {str(e)}")
            return None

    async def _check_abuseipdb(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain reputation using AbuseIPDB API."""
        if not self.reputation_apis['abuseipdb']:
            return None

        try:
            headers = {
                'Key': self.reputation_apis['abuseipdb'],
                'Accept': 'application/json'
            }
            async with self.session.get(
                'https://api.abuseipdb.com/api/v2/check',
                params={'domain': domain},
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    report = data.get('data', {})
                    
                    return {
                        'abuseipdb': {
                            'confidence_score': report.get('abuseConfidenceScore', 0),
                            'total_reports': report.get('totalReports', 0),
                            'last_reported_at': report.get('lastReportedAt'),
                            'is_malicious': report.get('abuseConfidenceScore', 0) > 50
                        }
                    }
                return None

        except Exception as e:
            self.logger.error(f"Error checking AbuseIPDB for {domain}: {str(e)}")
            return None

    async def _check_safebrowsing(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain reputation using Google Safe Browsing API."""
        if not self.reputation_apis['google_safebrowsing']:
            return None

        try:
            url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.reputation_apis['google_safebrowsing']}"
            payload = {
                "client": {
                    "clientId": "phishing-detection-system",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": f"http://{domain}"}, {"url": f"https://{domain}"}]
                }
            }

            async with self.session.post(url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    matches = data.get('matches', [])
                    
                    return {
                        'safebrowsing': {
                            'threat_matches': len(matches),
                            'threat_types': list(set(match.get('threatType') for match in matches)),
                            'platforms': list(set(match.get('platformType') for match in matches)),
                            'is_malicious': len(matches) > 0
                        }
                    }
                return None

        except Exception as e:
            self.logger.error(f"Error checking Safe Browsing for {domain}: {str(e)}")
            return None

    async def _get_historical_data(self, domain: str) -> Dict[str, Any]:
        """Get historical data for the domain."""
        try:
            # This could be expanded to include more historical data sources
            historical_data = {
                'registration_history': await self._get_registration_history(domain),
                'ip_history': await self._get_ip_history(domain),
                'ssl_history': await self._get_ssl_history(domain)
            }

            return historical_data

        except Exception as e:
            self.logger.error(f"Error getting historical data for {domain}: {str(e)}")
            return {}

    async def _get_registration_history(self, domain: str) -> List[Dict[str, Any]]:
        """Get domain registration history."""
        # This is a placeholder - would need to be implemented with actual data source
        return []

    async def _get_ip_history(self, domain: str) -> List[Dict[str, Any]]:
        """Get IP address history for the domain."""
        # This is a placeholder - would need to be implemented with actual data source
        return []

    async def _get_ssl_history(self, domain: str) -> List[Dict[str, Any]]:
        """Get SSL certificate history for the domain."""
        # This is a placeholder - would need to be implemented with actual data source
        return []

    def _calculate_risk_level(self, malicious_sources: int) -> str:
        """Calculate overall risk level based on analysis results."""
        if malicious_sources >= self.malicious_threshold:
            return 'high'
        elif malicious_sources > 0:
            return 'medium'
        return 'low'

    async def _check_cache(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check if we have a recent cache entry for this domain."""
        try:
            cached = await db.get_domain_reputation(domain)
            if cached:
                cache_time = datetime.fromisoformat(cached['timestamp'])
                if datetime.utcnow() - cache_time < self.cache_duration:
                    return cached
            return None
        except Exception:
            return None

    async def _cache_result(self, domain: str, result: Dict[str, Any]) -> None:
        """Cache the analysis result."""
        try:
            await db.store_domain_reputation(domain, result)
        except Exception as e:
            self.logger.error(f"Error caching result for {domain}: {str(e)}")

    async def _notify_agents(self, incident_id: str, results: Dict[str, Any]) -> None:
        """Notify other agents about the domain reputation analysis results."""
        try:
            # Notify the Phishing Score Agent
            await mq.publish('score_aggregation', {
                'incident_id': incident_id,
                'domain_reputation_analysis': results
            })

            # Notify Alert Agent if high-risk domains found
            high_risk_domains = [
                domain for domain in results['domains']
                if domain['risk_level'] == 'high'
            ]

            if high_risk_domains:
                await mq.publish('alert', {
                    'incident_id': incident_id,
                    'domain_reputation_alerts': high_risk_domains,
                    'severity': 'high'
                })

        except Exception as e:
            self.logger.error(f"Error notifying agents: {str(e)}")

    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        self.logger.info("Cleaning up Domain Reputation Agent")
        if self.session:
            await self.session.close() 