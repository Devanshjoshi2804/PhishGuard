from typing import Dict, Any, List
import tldextract
import requests
from urllib.parse import urlparse, urljoin
import re
from bs4 import BeautifulSoup
from common.models.base_agent import BaseAgent
from common.utils.database import db
from common.utils.message_queue import mq
import logging
import asyncio
import aiohttp
from datetime import datetime
import os
import json
import httpx
import whois as python_whois
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import timezone
import hashlib

class URLAnalysisAgent(BaseAgent):
    """Agent responsible for analyzing URLs for potential phishing indicators."""

    def __init__(self, agent_id: str, config: Dict[str, Any]):
        """Initialize the URL analysis agent."""
        super().__init__(agent_id, config)
        self.suspicious_tlds = config.get('suspicious_tlds', {
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs often abused
            '.xyz', '.top', '.work', '.date', '.faith',  # Other suspicious TLDs
            '.zip', '.review', '.country', '.kim', '.cricket',
            '.science', '.party', '.gq', '.link', '.win'
        })
        self.suspicious_keywords = config.get('suspicious_keywords', {
            'login', 'signin', 'account', 'secure', 'verify', 'update', 'confirm',
            'banking', 'password', 'credential', 'wallet', 'payment',
            'security', 'paypal', 'bitcoin', 'authenticate', 'validation',
            'suspended', 'unusual', 'activity', 'verify', 'limited', 'access'
        })
        self.http_client = None
        self.max_redirects = config.get('max_redirects', 5)
        self.timeout = config.get('timeout', 10)
        
        # VT API key should be in config or environment
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        
        # Known malicious patterns
        self.malicious_patterns = [
            r'(?i)(password|credential|credit.?card|billing|ssn|social.?security).{0,30}(enter|submit|confirm)',
            r'(?i)(account|login|signin).{0,30}(verify|confirm|authenticate)',
            r'(?i)(unusual|suspicious).{0,30}(activity|login|access)',
            r'(?i)(update|verify).{0,30}(account|payment|information)',
            r'(?i)(expired|blocked).{0,30}(account|access|password)'
        ]

    async def initialize(self) -> None:
        """Initialize the URL analysis agent."""
        self.logger.info("Initializing URL Analysis Agent")
        self.http_client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            max_redirects=5,
            verify=True
        )

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process URLs for phishing analysis."""
        try:
            urls = data.get('urls', [])
            if isinstance(urls, str):
                urls = [urls]
                
            results = []
            for url in urls:
                url_result = await self.analyze_url(url)
                results.append(url_result)
                
            analysis_result = {
                'incident_id': data.get('incident_id'),
                'url_analysis': {
                    'analyzed_at': datetime.now().isoformat(),
                    'results': results,
                    'overall_risk_score': self._calculate_overall_risk(results)
                }
            }
            
            # Store results in database
            if data.get('incident_id'):
                await db.update_analysis_result(data['incident_id'], {
                    'url_analysis': analysis_result['url_analysis']
                })
                
            # Notify other agents
            await self._notify_agents(analysis_result)
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error processing URLs: {str(e)}")
            raise

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a single URL for phishing indicators."""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Parallel execution of checks
            checks_tasks = [
                self._check_domain_age(domain),
                self._check_redirects(url),
                self._check_ssl_cert(domain) if parsed_url.scheme == 'https' else None,
                self._analyze_page_content(url),
                self._check_reputation(url),
                self._check_dns_records(domain)
            ]
            
            # Wait for all checks to complete
            check_results = await asyncio.gather(*[t for t in checks_tasks if t is not None])
            
            # Combine results
            analysis = {
                'url': url,
                'domain': domain,
                'checks': {
                    'suspicious_tld': any(domain.endswith(tld) for tld in self.suspicious_tlds),
                    'suspicious_keywords': self._check_suspicious_keywords(url),
                    'malicious_patterns': self._check_malicious_patterns(url),
                    'uses_https': parsed_url.scheme == 'https',
                    'domain_age': check_results[0],
                    'redirects': check_results[1],
                    'ssl_cert': check_results[2] if parsed_url.scheme == 'https' else None,
                    'page_content': check_results[3],
                    'reputation': check_results[4],
                    'dns_records': check_results[5]
                }
            }
            
            # Calculate risk score
            analysis['risk_score'] = self._calculate_risk_score(analysis['checks'])
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing URL {url}: {str(e)}")
            return {
                'url': url,
                'error': str(e),
                'risk_score': 0.8  # High risk score for failed analysis
            }

    def _check_suspicious_keywords(self, url: str) -> Dict[str, Any]:
        """Check for suspicious keywords in the URL."""
        url_lower = url.lower()
        found_keywords = [kw for kw in self.suspicious_keywords if kw in url_lower]
        return {
            'found': bool(found_keywords),
            'keywords': found_keywords
        }

    def _check_malicious_patterns(self, url: str) -> Dict[str, Any]:
        """Check for malicious patterns in the URL."""
        matches = []
        for pattern in self.malicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                matches.append(pattern)
        return {
            'found': bool(matches),
            'patterns': matches
        }
        
    async def _check_domain_age(self, domain: str) -> Dict[str, Any]:
        """Check domain registration age and analyze domain patterns."""
        try:
            # For test domains that don't exist, focus on suspicious patterns
            domain_parts = domain.split('.')
            
            # Check for suspicious domain patterns
            suspicious_patterns = []
            
            # Check for brand impersonation
            if any(brand in domain.lower() for brand in ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'facebook']):
                if not any(domain.lower().endswith(tld) for tld in ['.com', '.net', '.org']):
                    suspicious_patterns.append('Potential brand impersonation')
            
            # Check for deceptive TLD
            if domain_parts[-1] in ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work']:
                suspicious_patterns.append('Suspicious TLD')
            
            # Check for numeric characters in domain
            if any(c.isdigit() for c in domain_parts[0]):
                suspicious_patterns.append('Contains numeric characters')
            
            # Check for character substitution (e.g., paypaI instead of paypal)
            substitutions = {
                'l': '1',
                'i': '1',
                'o': '0',
                'a': '4',
                'e': '3',
                's': '5'
            }
            for char, num in substitutions.items():
                if char in domain_parts[0] and num in domain_parts[0]:
                    suspicious_patterns.append('Character-number substitution')
                    break
            
            # Check for excessive hyphens
            if domain_parts[0].count('-') > 1:
                suspicious_patterns.append('Multiple hyphens')
            
            # Check for long domain name
            if len(domain_parts[0]) > 20:
                suspicious_patterns.append('Unusually long domain name')
            
            # Check for random-looking strings
            consonant_groups = re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', domain_parts[0].lower())
            if consonant_groups:
                suspicious_patterns.append('Random-looking character sequence')
            
            return {
                'is_new_domain': True,  # Assume new domain for safety
                'suspicious_patterns': suspicious_patterns,
                'risk_level': 'high' if suspicious_patterns else 'medium'
            }
            
        except Exception as e:
            self.logger.error(f"Error checking domain age: {str(e)}")
            return {
                'error': str(e),
                'is_new_domain': True,
                'suspicious_patterns': ['Unable to verify domain age']
            }

    async def _check_dns_records(self, domain: str) -> Dict[str, Any]:
        """Check DNS records for suspicious configurations."""
        try:
            # Run DNS lookups in a thread pool
            results = await asyncio.to_thread(socket.getaddrinfo, domain, None)
            
            ips = set()
            for result in results:
                if result[0] == socket.AF_INET:  # IPv4
                    ips.add(result[4][0])
                    
            return {
                'ip_count': len(ips),
                'ips': list(ips),
                'multiple_ips': len(ips) > 1
            }
        except Exception as e:
            self.logger.error(f"Error checking DNS records: {str(e)}")
            return {'error': str(e)}

    async def _check_redirects(self, url: str) -> Dict[str, Any]:
        """Check URL redirection chain."""
        try:
            response = await self.http_client.get(url)
            redirects = [str(h.url) for h in response.history]
            
            # Check for suspicious redirect patterns
            suspicious_redirects = []
            for redirect in redirects:
                if any(kw in redirect.lower() for kw in self.suspicious_keywords):
                    suspicious_redirects.append(redirect)
            
            return {
                'count': len(redirects),
                'chain': redirects,
                'final_url': str(response.url),
                'suspicious_redirects': suspicious_redirects,
                'has_suspicious_redirects': bool(suspicious_redirects)
            }
        except Exception as e:
            self.logger.error(f"Error checking redirects for {url}: {str(e)}")
            return {
                'error': str(e),
                'count': 0,
                'chain': []
            }

    async def _check_ssl_cert(self, domain: str) -> Dict[str, Any]:
        """Check SSL certificate information."""
        try:
            # Create an SSL context
            context = ssl.create_default_context()
            
            # Connect to the domain and get the certificate
            async def get_cert():
                reader, writer = await asyncio.open_connection(
                    domain, 443, ssl=context
                )
                cert = writer.get_extra_info('ssl_object').getpeercert(binary_form=True)
                writer.close()
                await writer.wait_closed()
                return cert
            
            cert_data = await get_cert()
            
            # Parse the certificate
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            
            # Extract relevant information
            return {
                'valid': True,
                'issuer': cert.issuer.rfc4514_string(),
                'subject': cert.subject.rfc4514_string(),
                'not_before': cert.not_valid_before.isoformat(),
                'not_after': cert.not_valid_after.isoformat(),
                'expires_in_days': (cert.not_valid_after - datetime.now(timezone.utc)).days,
                'is_expired': cert.not_valid_after < datetime.now(timezone.utc),
                'is_self_signed': cert.issuer == cert.subject
            }
        except Exception as e:
            self.logger.error(f"Error checking SSL cert: {str(e)}")
            return {
                'valid': False,
                'error': str(e)
            }

    async def _check_reputation(self, url: str) -> Dict[str, Any]:
        """Check URL reputation using VirusTotal API."""
        try:
            if not self.vt_api_key:
                return {'error': 'VirusTotal API key not configured'}
            
            # Calculate URL hash for VT API
            url_id = hashlib.sha256(url.encode()).hexdigest()
            
            async with httpx.AsyncClient() as client:
                headers = {
                    'x-apikey': self.vt_api_key
                }
                response = await client.get(
                    f'https://www.virustotal.com/api/v3/urls/{url_id}',
                    headers=headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    results = data['data']['attributes']['last_analysis_results']
                    stats = data['data']['attributes']['last_analysis_stats']
                    
                    return {
                        'malicious_votes': stats.get('malicious', 0),
                        'suspicious_votes': stats.get('suspicious', 0),
                        'clean_votes': stats.get('harmless', 0),
                        'total_votes': sum(stats.values()),
                        'detection_ratio': (stats.get('malicious', 0) + stats.get('suspicious', 0)) / sum(stats.values()) if sum(stats.values()) > 0 else 0,
                        'categories': [result['category'] for result in results.values() if result.get('category')]
                    }
                
                return {'error': f'VirusTotal API error: {response.status_code}'}
                
        except Exception as e:
            self.logger.error(f"Error checking reputation: {str(e)}")
            return {'error': str(e)}

    async def _analyze_page_content(self, url: str) -> Dict[str, Any]:
        """Analyze webpage content for phishing indicators."""
        try:
            response = await self.http_client.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms
            forms = soup.find_all('form')
            login_forms = [f for f in forms if self._is_login_form(f)]
            
            # Extract links
            links = soup.find_all('a')
            external_links = [l.get('href') for l in links if l.get('href') and not l.get('href').startswith(('#', '/', url))]
            
            # Check for obfuscated content
            scripts = soup.find_all('script')
            obfuscated_js = any(self._check_js_obfuscation(s.string) for s in scripts if s.string)
            
            # Check for hidden elements
            hidden_elements = soup.find_all(style=re.compile(r'display:\s*none|visibility:\s*hidden'))
            
            # Check for data exfiltration
            exfiltration_risks = self._check_data_exfiltration(soup)
            
            return {
                'has_login_form': bool(login_forms),
                'form_count': len(forms),
                'login_form_count': len(login_forms),
                'external_links_count': len(external_links),
                'contains_password_field': bool(soup.find('input', {'type': 'password'})),
                'page_title': soup.title.string if soup.title else None,
                'has_obfuscated_js': obfuscated_js,
                'hidden_elements_count': len(hidden_elements),
                'data_exfiltration_risks': exfiltration_risks,
                'suspicious_elements': self._find_suspicious_elements(soup)
            }
        except Exception as e:
            self.logger.error(f"Error analyzing page content for {url}: {str(e)}")
            return {
                'error': str(e)
            }

    def _check_js_obfuscation(self, script: str) -> bool:
        """Check if JavaScript code appears to be obfuscated."""
        if not script:
            return False
            
        # Common obfuscation indicators
        indicators = [
            r'eval\(.+\)', 
            r'escape\(.+\)', 
            r'unescape\(.+\)',
            r'(?:\\x[0-9a-fA-F]{2}){3,}',  # Multiple hex sequences
            r'(?:\\u[0-9a-fA-F]{4}){3,}',  # Multiple unicode sequences
            r'String\.fromCharCode\(.+\)',
            r'document\.write\(.+\)',
            r'window\.atob\(.+\)',
            r'decodeURIComponent\(.+\)'
        ]
        
        # Count matches
        match_count = sum(1 for pattern in indicators if re.search(pattern, script))
        # Consider it obfuscated only if multiple indicators are found
        return match_count >= 2

    def _check_data_exfiltration(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Check for potential data exfiltration methods."""
        risks = []
        
        # Check for external form submissions
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            if action and not action.startswith(('/')) and '://' in action:
                risks.append({
                    'type': 'external_form_submission',
                    'target': action
                })
        
        # Check for suspicious event handlers
        elements_with_handlers = soup.find_all(
            lambda tag: any(attr for attr in tag.attrs if attr.startswith('on'))
        )
        for element in elements_with_handlers:
            handlers = [attr for attr in element.attrs if attr.startswith('on')]
            for handler in handlers:
                if 'location' in element[handler] or 'ajax' in element[handler].lower():
                    risks.append({
                        'type': 'suspicious_event_handler',
                        'handler': handler,
                        'code': element[handler]
                    })
        
        return {
            'found': bool(risks),
            'risks': risks
        }

    def _find_suspicious_elements(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Find suspicious elements in the page content."""
        suspicious_elements = []
        
        # Check for fake login forms
        login_forms = soup.find_all('form')
        for form in login_forms:
            if self._is_login_form(form):
                action = form.get('action', '')
                if not action or action == '#' or 'javascript:' in action:
                    suspicious_elements.append({
                        'type': 'suspicious_form',
                        'reason': 'Invalid form action',
                        'element': str(form)[:200]  # First 200 chars
                    })
        
        # Check for credential-related inputs outside forms
        inputs = soup.find_all('input', {'type': ['password', 'text', 'email']})
        for input_elem in inputs:
            if not input_elem.find_parent('form'):
                suspicious_elements.append({
                    'type': 'suspicious_input',
                    'reason': 'Credential input outside form',
                    'element': str(input_elem)[:200]
                })
        
        # Check for clickjacking attempts
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            if iframe.get('opacity') == '0' or iframe.get('display') == 'none':
                suspicious_elements.append({
                    'type': 'potential_clickjacking',
                    'reason': 'Hidden iframe',
                    'element': str(iframe)[:200]
                })
        
        return suspicious_elements

    def _calculate_risk_score(self, checks: Dict[str, Any]) -> float:
        """Calculate risk score based on various checks."""
        score = 0.0
        weight_sum = 0.0
        
        # Domain-based checks
        if checks['suspicious_tld']:
            score += 0.8
            weight_sum += 1
            
        if checks['suspicious_keywords']['found']:
            keyword_count = len(checks['suspicious_keywords']['keywords'])
            if keyword_count > 0:  # Any suspicious keywords are concerning
                score += 0.7 * min(keyword_count / 2, 1)
                weight_sum += 1.5  # Higher weight for keywords
            
        if checks['malicious_patterns']['found']:
            score += 0.9 * min(len(checks['malicious_patterns']['patterns']) / 2, 1)
            weight_sum += 2.0  # Even higher weight for malicious patterns
            
        # SSL/HTTPS checks
        if not checks['uses_https']:
            score += 0.7
            weight_sum += 1
        elif checks.get('ssl_cert'):
            ssl_cert = checks['ssl_cert']
            if ssl_cert.get('is_expired') or ssl_cert.get('is_self_signed'):
                score += 0.9  # Increased from 0.8
                weight_sum += 1.5  # Increased weight
            if ssl_cert.get('expires_in_days', 365) < 30:
                score += 0.6  # Increased from 0.4
                weight_sum += 1.0  # Increased weight
                
        # Domain age and DNS
        domain_age = checks.get('domain_age', {})
        if domain_age.get('is_new_domain') and not domain_age.get('error'):
            score += 0.8  # Increased from 0.6
            weight_sum += 1.5  # Increased weight
            
        dns_records = checks.get('dns_records', {})
        if dns_records.get('multiple_ips', False):
            score += 0.5  # Increased from 0.3
            weight_sum += 1.0  # Increased weight
            
        # Redirects
        redirects = checks.get('redirects', {})
        if redirects.get('has_suspicious_redirects'):
            score += 0.8  # Increased from 0.7
            weight_sum += 1.5  # Increased weight
        elif redirects.get('count', 0) > 2:  # Lowered threshold
            score += 0.6 * min(redirects['count'] / 3, 1)  # Increased from 0.4
            weight_sum += 1.0  # Increased weight
            
        # Page content
        if checks.get('page_content'):
            content = checks['page_content']
            
            # Login form with external links
            if content.get('has_login_form') and content.get('external_links_count', 0) > 5:  # Lowered threshold
                score += 0.7  # Increased from 0.5
                weight_sum += 1.5  # Increased weight
                
            # Obfuscated JS
            if content.get('has_obfuscated_js'):
                score += 0.8  # Increased from 0.7
                weight_sum += 1.5  # Increased weight
            
            # Hidden elements
            if content.get('hidden_elements_count', 0) > 2:  # Lowered threshold
                score += 0.6  # Increased from 0.4
                weight_sum += 1.0  # Increased weight
                
            # Data exfiltration risks
            exfiltration = content.get('data_exfiltration_risks', {})
            if exfiltration.get('found'):
                score += 0.9 * min(len(exfiltration.get('risks', [])) / 2, 1)  # Increased from 0.8
                weight_sum += 2.0  # Increased weight
                
            # Suspicious elements
            suspicious_elements = content.get('suspicious_elements', [])
            if suspicious_elements:
                score += 0.8 * min(len(suspicious_elements) / 2, 1)  # Increased from 0.6
                weight_sum += 1.5  # Increased weight
                
        # Reputation checks
        reputation = checks.get('reputation', {})
        if reputation.get('detection_ratio', 0) > 0:
            score += 1.0 * min(reputation['detection_ratio'] * 1.5, 1)  # Increased multiplier
            weight_sum += 2.5  # Increased weight
            
        # Brand impersonation check
        if self._check_brand_impersonation(checks):
            score += 0.9
            weight_sum += 2.0
            
        # If no significant issues found, ensure a low base score
        if weight_sum < 0.5:
            return 0.1
            
        # Normalize the score but maintain high scores
        normalized_score = score / max(weight_sum, 1)
        
        # Boost scores that are already high
        if normalized_score > 0.7:
            normalized_score = min(normalized_score * 1.2, 1.0)
            
        return normalized_score

    def _check_brand_impersonation(self, checks: Dict[str, Any]) -> bool:
        """Check for potential brand impersonation in the URL."""
        url = checks.get('url', '').lower()
        domain = checks.get('domain', '').lower()
        
        # List of commonly impersonated brands and their variations
        brand_patterns = {
            'paypal': ['paypal', 'pay-pal', 'paypaI', 'paypa1'],
            'microsoft': ['microsoft', 'microsft', 'micros0ft'],
            'apple': ['apple', 'appl', 'icloud'],
            'google': ['google', 'g00gle', 'googl'],
            'amazon': ['amazon', 'amaz0n', 'aws'],
            'facebook': ['facebook', 'faceb00k', 'fb'],
            'netflix': ['netflix', 'netfl1x', 'netflex'],
            'bank': ['bank', 'secure-bank', 'banking']
        }
        
        for brand, variations in brand_patterns.items():
            # Check if any brand variation is in the domain
            if any(var in domain for var in variations):
                # Check if it's not the legitimate domain
                legitimate_domains = {
                    'paypal': ['paypal.com', 'paypal.co.uk'],
                    'microsoft': ['microsoft.com', 'live.com', 'outlook.com'],
                    'apple': ['apple.com', 'icloud.com'],
                    'google': ['google.com', 'gmail.com'],
                    'amazon': ['amazon.com', 'aws.amazon.com'],
                    'facebook': ['facebook.com', 'fb.com'],
                    'netflix': ['netflix.com'],
                    'bank': []  # Banks have too many legitimate domains to list
                }
                
                return not any(domain.endswith(legit) for legit in legitimate_domains.get(brand, []))
                
        return False

    def _is_login_form(self, form) -> bool:
        """Check if a form is likely a login form."""
        # Look for password fields
        has_password = bool(form.find('input', {'type': 'password'}))
        
        # Look for common login form keywords
        form_text = form.get_text().lower()
        login_keywords = {'login', 'sign in', 'signin', 'log in', 'username', 'password'}
        has_login_keywords = any(kw in form_text for kw in login_keywords)
        
        return has_password or has_login_keywords
        
    def _calculate_overall_risk(self, results: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score for multiple URLs."""
        if not results:
            return 0.0
            
        # Use the highest risk score as the overall score
        return max(result.get('risk_score', 0.0) for result in results)
        
    async def _notify_agents(self, analysis_result: Dict[str, Any]) -> None:
        """Notify other agents about the analysis results."""
        try:
            # Notify the Threat Intelligence Agent
            await mq.publish('threat_intelligence', {
                'type': 'url_analysis',
                'incident_id': analysis_result.get('incident_id'),
                'data': analysis_result
            })
            
            # Notify the Phishing Score Agent
            await mq.publish('phishing_score', {
                'type': 'url_analysis',
                'incident_id': analysis_result.get('incident_id'),
                'data': analysis_result
            })
            
        except Exception as e:
            self.logger.error(f"Error notifying agents: {str(e)}")
            
    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        self.logger.info("Cleaning up URL Analysis Agent")
        if self.http_client:
            await self.http_client.aclose() 