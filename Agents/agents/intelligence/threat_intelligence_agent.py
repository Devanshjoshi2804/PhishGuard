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
import hashlib
import base64

class ThreatIntelligenceAgent(BaseAgent):
    """Agent responsible for gathering and analyzing threat intelligence data."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("threat_intelligence", config)
        self.session = None
        self.intel_apis = {
            'otx_alienvault': config.get('otx_api_key'),
            'threatfox': config.get('threatfox_api_key'),
            'phishtank': config.get('phishtank_api_key'),
            'misp': {
                'url': config.get('misp_url'),
                'key': config.get('misp_api_key')
            }
        }
        self.cache_duration = timedelta(hours=6)  # Shorter cache for threat intel
        self.update_interval = timedelta(hours=1)  # How often to update threat feeds
        self.last_feed_update = None
        self.threat_feeds = {}

    async def initialize(self) -> None:
        """Initialize the threat intelligence agent."""
        self.logger.info("Initializing Threat Intelligence Agent")
        self.session = aiohttp.ClientSession()
        await self._update_threat_feeds()

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process threat intelligence analysis."""
        try:
            incident_id = data.get('incident_id')
            indicators = {
                'domains': data.get('domains', []),
                'urls': data.get('urls', []),
                'ips': data.get('ips', []),
                'email_addresses': data.get('email_addresses', []),
                'file_hashes': data.get('file_hashes', [])
            }

            # Check if threat feeds need updating
            if self._should_update_feeds():
                await self._update_threat_feeds()

            # Analyze indicators
            analysis_results = {
                'incident_id': incident_id,
                'timestamp': datetime.utcnow().isoformat(),
                'threat_matches': [],
                'emerging_threats': [],
                'campaign_matches': [],
                'risk_assessment': {}
            }

            # Process each type of indicator
            for indicator_type, values in indicators.items():
                if values:
                    results = await self._analyze_indicators(indicator_type, values)
                    analysis_results['threat_matches'].extend(results.get('matches', []))
                    analysis_results['emerging_threats'].extend(results.get('emerging', []))
                    analysis_results['campaign_matches'].extend(results.get('campaigns', []))

            # Calculate overall risk assessment
            analysis_results['risk_assessment'] = self._calculate_risk_assessment(analysis_results)

            # Store results
            await db.update_analysis_result(incident_id, {
                'threat_intelligence_analysis': analysis_results
            })

            # Notify other agents
            await self._notify_agents(incident_id, analysis_results)

            return analysis_results

        except Exception as e:
            await self.handle_error(e)
            raise

    async def _analyze_indicators(self, indicator_type: str, indicators: List[str]) -> Dict[str, Any]:
        """Analyze indicators against threat intelligence sources."""
        results = {
            'matches': [],
            'emerging': [],
            'campaigns': []
        }

        # Create tasks for each intelligence source
        tasks = [
            self._check_otx(indicator_type, indicators),
            self._check_threatfox(indicator_type, indicators),
            self._check_phishtank(indicator_type, indicators),
            self._check_misp(indicator_type, indicators)
        ]

        # Add feed checking tasks
        tasks.extend([
            self._check_against_feeds(indicator_type, indicator)
            for indicator in indicators
        ])

        # Gather all results
        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in all_results:
            if isinstance(result, Exception):
                continue
            if result:
                results['matches'].extend(result.get('matches', []))
                results['emerging'].extend(result.get('emerging', []))
                results['campaigns'].extend(result.get('campaigns', []))

        return results

    async def _check_otx(self, indicator_type: str, indicators: List[str]) -> Optional[Dict[str, Any]]:
        """Check indicators against AlienVault OTX."""
        if not self.intel_apis['otx_alienvault']:
            return None

        try:
            results = {
                'matches': [],
                'emerging': [],
                'campaigns': []
            }

            headers = {'X-OTX-API-KEY': self.intel_apis['otx_alienvault']}

            for indicator in indicators:
                # Convert indicator type to OTX type
                otx_type = self._map_indicator_type(indicator_type)
                if not otx_type:
                    continue

                url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator}/general"
                async with self.session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('pulse_info', {}).get('count', 0) > 0:
                            results['matches'].append({
                                'indicator': indicator,
                                'type': indicator_type,
                                'source': 'otx',
                                'pulses': data['pulse_info']['pulses'],
                                'timestamp': datetime.utcnow().isoformat()
                            })

            return results

        except Exception as e:
            self.logger.error(f"Error checking OTX: {str(e)}")
            return None

    async def _check_threatfox(self, indicator_type: str, indicators: List[str]) -> Optional[Dict[str, Any]]:
        """Check indicators against ThreatFox."""
        if not self.intel_apis['threatfox']:
            return None

        try:
            results = {
                'matches': [],
                'emerging': [],
                'campaigns': []
            }

            headers = {'API-KEY': self.intel_apis['threatfox']}
            
            for indicator in indicators:
                payload = {
                    "query": "search_ioc",
                    "search_term": indicator
                }

                async with self.session.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    json=payload,
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('query_status') == "ok" and data.get('data'):
                            results['matches'].append({
                                'indicator': indicator,
                                'type': indicator_type,
                                'source': 'threatfox',
                                'threat_data': data['data'],
                                'timestamp': datetime.utcnow().isoformat()
                            })

            return results

        except Exception as e:
            self.logger.error(f"Error checking ThreatFox: {str(e)}")
            return None

    async def _check_phishtank(self, indicator_type: str, indicators: List[str]) -> Optional[Dict[str, Any]]:
        """Check indicators against PhishTank."""
        if not self.intel_apis['phishtank']:
            return None

        try:
            results = {
                'matches': [],
                'emerging': [],
                'campaigns': []
            }

            # Only process URLs for PhishTank
            if indicator_type != 'urls':
                return results

            headers = {'Api-Key': self.intel_apis['phishtank']}

            for url in indicators:
                encoded_url = base64.b64encode(url.encode()).decode()
                api_url = f"https://checkurl.phishtank.com/checkurl/{encoded_url}/"
                
                async with self.session.get(api_url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('results', {}).get('in_database', False):
                            results['matches'].append({
                                'indicator': url,
                                'type': 'url',
                                'source': 'phishtank',
                                'verified': data['results']['verified'],
                                'details': data['results'],
                                'timestamp': datetime.utcnow().isoformat()
                            })

            return results

        except Exception as e:
            self.logger.error(f"Error checking PhishTank: {str(e)}")
            return None

    async def _check_misp(self, indicator_type: str, indicators: List[str]) -> Optional[Dict[str, Any]]:
        """Check indicators against MISP instance."""
        if not all([self.intel_apis['misp']['url'], self.intel_apis['misp']['key']]):
            return None

        try:
            results = {
                'matches': [],
                'emerging': [],
                'campaigns': []
            }

            headers = {
                'Authorization': self.intel_apis['misp']['key'],
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }

            for indicator in indicators:
                payload = {
                    "returnFormat": "json",
                    "value": indicator,
                    "type": self._map_indicator_type_misp(indicator_type)
                }

                async with self.session.post(
                    f"{self.intel_apis['misp']['url']}/attributes/restSearch",
                    json=payload,
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('response', []):
                            results['matches'].append({
                                'indicator': indicator,
                                'type': indicator_type,
                                'source': 'misp',
                                'events': data['response'],
                                'timestamp': datetime.utcnow().isoformat()
                            })

            return results

        except Exception as e:
            self.logger.error(f"Error checking MISP: {str(e)}")
            return None

    def _map_indicator_type(self, indicator_type: str) -> str:
        """Map internal indicator types to OTX types."""
        mapping = {
            'domains': 'domain',
            'urls': 'url',
            'ips': 'IPv4',
            'email_addresses': 'email',
            'file_hashes': 'file'
        }
        return mapping.get(indicator_type)

    def _map_indicator_type_misp(self, indicator_type: str) -> str:
        """Map internal indicator types to MISP types."""
        mapping = {
            'domains': 'domain',
            'urls': 'url',
            'ips': 'ip-dst',
            'email_addresses': 'email-src',
            'file_hashes': 'md5'
        }
        return mapping.get(indicator_type)

    def _should_update_feeds(self) -> bool:
        """Check if threat feeds should be updated."""
        if not self.last_feed_update:
            return True
        return datetime.utcnow() - self.last_feed_update > self.update_interval

    async def _update_threat_feeds(self) -> None:
        """Update local threat intelligence feeds."""
        try:
            # Update feeds from various sources
            feed_tasks = [
                self._update_emerging_threats_feed(),
                self._update_abuse_feed(),
                self._update_blocklist_feed()
            ]
            
            await asyncio.gather(*feed_tasks, return_exceptions=True)
            self.last_feed_update = datetime.utcnow()

        except Exception as e:
            self.logger.error(f"Error updating threat feeds: {str(e)}")

    async def _update_emerging_threats_feed(self) -> None:
        """Update emerging threats feed."""
        try:
            async with self.session.get("https://rules.emergingthreats.net/blockrules/compromised-ips.txt") as response:
                if response.status == 200:
                    content = await response.text()
                    self.threat_feeds['emerging_threats'] = set(line.strip() for line in content.splitlines() if line.strip())
        except Exception as e:
            self.logger.error(f"Error updating emerging threats feed: {str(e)}")

    async def _update_abuse_feed(self) -> None:
        """Update abuse feed."""
        try:
            async with self.session.get("https://urlhaus.abuse.ch/downloads/csv/") as response:
                if response.status == 200:
                    content = await response.text()
                    self.threat_feeds['abuse'] = set(line.split(',')[2] for line in content.splitlines() if not line.startswith('#'))
        except Exception as e:
            self.logger.error(f"Error updating abuse feed: {str(e)}")

    async def _update_blocklist_feed(self) -> None:
        """Update blocklist feed."""
        try:
            async with self.session.get("https://www.spamhaus.org/drop/drop.txt") as response:
                if response.status == 200:
                    content = await response.text()
                    self.threat_feeds['blocklist'] = set(line.split(';')[0].strip() for line in content.splitlines() if not line.startswith(';'))
        except Exception as e:
            self.logger.error(f"Error updating blocklist feed: {str(e)}")

    async def _check_against_feeds(self, indicator_type: str, indicator: str) -> Dict[str, Any]:
        """Check an indicator against local threat feeds."""
        results = {
            'matches': [],
            'emerging': [],
            'campaigns': []
        }

        try:
            # Check emerging threats
            if indicator in self.threat_feeds.get('emerging_threats', set()):
                results['emerging'].append({
                    'indicator': indicator,
                    'type': indicator_type,
                    'source': 'emerging_threats_feed',
                    'timestamp': datetime.utcnow().isoformat()
                })

            # Check abuse feed
            if indicator in self.threat_feeds.get('abuse', set()):
                results['matches'].append({
                    'indicator': indicator,
                    'type': indicator_type,
                    'source': 'abuse_feed',
                    'timestamp': datetime.utcnow().isoformat()
                })

            # Check blocklist
            if indicator in self.threat_feeds.get('blocklist', set()):
                results['matches'].append({
                    'indicator': indicator,
                    'type': indicator_type,
                    'source': 'blocklist_feed',
                    'timestamp': datetime.utcnow().isoformat()
                })

        except Exception as e:
            self.logger.error(f"Error checking feeds for {indicator}: {str(e)}")

        return results

    def _calculate_risk_assessment(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk assessment based on threat intelligence."""
        assessment = {
            'risk_level': 'low',
            'confidence': 0.0,
            'threat_types': set(),
            'threat_sources': set(),
            'campaign_count': len(results['campaign_matches']),
            'emerging_threat_count': len(results['emerging_threats'])
        }

        # Calculate risk metrics
        total_matches = len(results['threat_matches'])
        unique_sources = set()
        threat_types = set()

        for match in results['threat_matches']:
            unique_sources.add(match['source'])
            if 'threat_type' in match:
                threat_types.add(match['threat_type'])

        # Calculate confidence based on number of sources and matches
        source_weight = len(unique_sources) / 4  # Normalize by maximum number of sources
        match_weight = min(total_matches / 10, 1.0)  # Cap at 10 matches
        assessment['confidence'] = (source_weight + match_weight) / 2

        # Determine risk level
        if assessment['confidence'] > 0.7 or assessment['campaign_count'] > 0:
            assessment['risk_level'] = 'high'
        elif assessment['confidence'] > 0.3 or assessment['emerging_threat_count'] > 0:
            assessment['risk_level'] = 'medium'

        assessment['threat_types'] = list(threat_types)
        assessment['threat_sources'] = list(unique_sources)

        return assessment

    async def _notify_agents(self, incident_id: str, results: Dict[str, Any]) -> None:
        """Notify other agents about threat intelligence results."""
        try:
            # Notify the Phishing Score Agent
            await mq.publish('score_aggregation', {
                'incident_id': incident_id,
                'threat_intelligence_analysis': results
            })

            # Notify Alert Agent for high-risk threats
            if results['risk_assessment']['risk_level'] == 'high':
                await mq.publish('alert', {
                    'incident_id': incident_id,
                    'threat_intelligence_alerts': {
                        'risk_assessment': results['risk_assessment'],
                        'threat_matches': results['threat_matches'],
                        'campaign_matches': results['campaign_matches']
                    },
                    'severity': 'high'
                })

        except Exception as e:
            self.logger.error(f"Error notifying agents: {str(e)}")

    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        self.logger.info("Cleaning up Threat Intelligence Agent")
        if self.session:
            await self.session.close() 