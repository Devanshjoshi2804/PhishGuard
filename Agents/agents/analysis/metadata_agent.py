from typing import Dict, Any, List, Optional
from common.models.base_agent import BaseAgent
from common.utils.database import db
from common.utils.message_queue import mq
import logging
import whois
import dns.resolver
import socket
import ssl
import OpenSSL
from datetime import datetime
import re
import aiohttp
import asyncio
from email.utils import parseaddr, parsedate_to_datetime
import traceback

logger = logging.getLogger(__name__)

class MetadataAgent(BaseAgent):
    """Agent responsible for extracting and analyzing metadata from various sources."""

    def __init__(self, agent_id: str, config: Dict[str, Any]):
        """Initialize the metadata agent."""
        super().__init__(agent_id, config)
        self.session = None
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5

    async def initialize(self) -> None:
        """Initialize the metadata agent."""
        self.logger.info("Initializing Metadata Agent")
        self.session = aiohttp.ClientSession()

    async def process(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process email metadata and extract relevant features."""
        try:
            incident_id = incident_data.get('incident_id')
            metadata = incident_data.get('metadata', {})
            headers = metadata.get('headers', {})
            
            analysis_results = {
                'headers_analysis': self._analyze_email_headers(headers),
                'routing_analysis': self._analyze_routing(headers),
                'timestamp_analysis': self._analyze_timestamps(headers),
                'authentication_analysis': self._analyze_authentication(headers)
            }
            
            # Store results in database
            await db.update_analysis_result(incident_id, {
                'email_analysis': analysis_results
            })
            
            return analysis_results
        except Exception as e:
            logger.error(f"Error in metadata: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    def _analyze_email_headers(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email headers for suspicious patterns."""
        analysis = {
            'suspicious_patterns': [],
            'risk_level': 'low'
        }
        
        # Check for missing or suspicious headers
        required_headers = ['from', 'to', 'subject', 'date']
        missing_headers = [h for h in required_headers if h not in headers]
        if missing_headers:
            analysis['suspicious_patterns'].append(f"Missing required headers: {', '.join(missing_headers)}")
            analysis['risk_level'] = 'medium'
        
        # Check for mismatched sender information
        if 'from' in headers and 'return-path' in headers:
            from_header = headers['from']
            return_path_header = headers['return-path']
            
            if isinstance(from_header, dict) and isinstance(return_path_header, dict):
                from_domain = from_header.get('domain')
                return_path_domain = return_path_header.get('domain')
                
                if from_domain and return_path_domain and from_domain != return_path_domain:
                    analysis['suspicious_patterns'].append(f"Domain mismatch: From '{from_domain}' vs Return-Path '{return_path_domain}'")
                    analysis['risk_level'] = 'high'
        
        # Check for suspicious display names
        if 'from' in headers:
            from_header = headers['from']
            if isinstance(from_header, dict):
                display_name = from_header.get('display_name', '').lower()
                if any(keyword in display_name for keyword in ['paypal', 'bank', 'security', 'admin']):
                    analysis['suspicious_patterns'].append(f"Suspicious sender display name: {display_name}")
                    analysis['risk_level'] = 'high'
        
        return analysis

    def _analyze_routing(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email routing information."""
        analysis = {
            'suspicious_patterns': [],
            'risk_level': 'low'
        }
        
        # Check received headers
        received_headers = headers.get('received', [])
        if not received_headers:
            analysis['suspicious_patterns'].append("No Received headers found")
            analysis['risk_level'] = 'medium'
        else:
            # Look for suspicious relay patterns
            relay_ips = []
            for header in received_headers:
                # Extract IPs from received headers
                if isinstance(header, str):
                    if '[' in header and ']' in header:
                        ip = header[header.find('[')+1:header.find(']')]
                        relay_ips.append(ip)
            
            if len(relay_ips) < 2:
                analysis['suspicious_patterns'].append("Unusually short email route")
                analysis['risk_level'] = 'medium'
            
            # Check for suspicious relay patterns
            for ip in relay_ips:
                if ip.startswith(('10.', '192.168.', '172.16.')):
                    analysis['suspicious_patterns'].append(f"Suspicious private IP in route: {ip}")
                    analysis['risk_level'] = 'high'
        
        return analysis

    def _analyze_timestamps(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email timestamps for anomalies."""
        analysis = {
            'suspicious_patterns': [],
            'risk_level': 'low'
        }
        
        # Check date header
        if 'date' in headers:
            try:
                date_header = headers['date']
                if isinstance(date_header, dict):
                    if 'timestamp' in date_header:
                        email_date = datetime.fromtimestamp(date_header['timestamp'])
                    else:
                        email_date = parsedate_to_datetime(date_header['raw'])
                else:
                    email_date = parsedate_to_datetime(date_header)
                
                now = datetime.utcnow()
                time_diff = now - email_date
                
                # Flag emails dated in the future
                if email_date > now:
                    analysis['suspicious_patterns'].append("Email dated in the future")
                    analysis['risk_level'] = 'high'
                
                # Flag emails with very old dates
                if time_diff.days > 7:
                    analysis['suspicious_patterns'].append("Email date is more than 7 days old")
                    analysis['risk_level'] = 'medium'
                
                # Flag emails sent at unusual hours
                hour = email_date.hour
                if hour < 6 or hour > 22:  # Between 10 PM and 6 AM
                    analysis['suspicious_patterns'].append("Email sent during unusual hours")
                    analysis['risk_level'] = 'medium'
            except Exception as e:
                analysis['suspicious_patterns'].append("Invalid date format")
                analysis['risk_level'] = 'medium'
        
        return analysis

    def _analyze_authentication(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email authentication results."""
        analysis = {
            'suspicious_patterns': [],
            'risk_level': 'low',
            'spf_result': None,
            'dkim_result': None,
            'dmarc_result': None
        }
        
        # Parse Authentication-Results header
        auth_header = headers.get('authentication-results', {})
        if isinstance(auth_header, dict):
            # Use pre-parsed results
            spf_result = auth_header.get('spf')
            dkim_result = auth_header.get('dkim')
            dmarc_result = auth_header.get('dmarc')
            
            if spf_result:
                analysis['spf_result'] = spf_result
                if spf_result not in ['pass', 'neutral']:
                    analysis['suspicious_patterns'].append(f"SPF authentication failed: {spf_result}")
                    analysis['risk_level'] = 'high'
            else:
                analysis['suspicious_patterns'].append("No SPF authentication results")
                analysis['risk_level'] = 'medium'
            
            if dkim_result:
                analysis['dkim_result'] = dkim_result
                if dkim_result != 'pass':
                    analysis['suspicious_patterns'].append(f"DKIM authentication failed: {dkim_result}")
                    analysis['risk_level'] = 'high'
            else:
                analysis['suspicious_patterns'].append("No DKIM authentication results")
                analysis['risk_level'] = 'medium'
            
            if dmarc_result:
                analysis['dmarc_result'] = dmarc_result
                if dmarc_result != 'pass':
                    analysis['suspicious_patterns'].append(f"DMARC authentication failed: {dmarc_result}")
                    analysis['risk_level'] = 'high'
            else:
                analysis['suspicious_patterns'].append("No DMARC authentication results")
                analysis['risk_level'] = 'medium'
        else:
            # Try parsing from raw header
            auth_results = auth_header.get('raw', '') if isinstance(auth_header, dict) else str(auth_header)
            
            # Extract SPF result
            spf_match = re.search(r'spf=(\w+)', auth_results)
            if spf_match:
                spf_result = spf_match.group(1).lower()
                analysis['spf_result'] = spf_result
                if spf_result not in ['pass', 'neutral']:
                    analysis['suspicious_patterns'].append(f"SPF authentication failed: {spf_result}")
                    analysis['risk_level'] = 'high'
            else:
                analysis['suspicious_patterns'].append("No SPF authentication results")
                analysis['risk_level'] = 'medium'
            
            # Extract DKIM result
            dkim_match = re.search(r'dkim=(\w+)', auth_results)
            if dkim_match:
                dkim_result = dkim_match.group(1).lower()
                analysis['dkim_result'] = dkim_result
                if dkim_result != 'pass':
                    analysis['suspicious_patterns'].append(f"DKIM authentication failed: {dkim_result}")
                    analysis['risk_level'] = 'high'
            else:
                analysis['suspicious_patterns'].append("No DKIM authentication results")
                analysis['risk_level'] = 'medium'
            
            # Extract DMARC result
            dmarc_match = re.search(r'dmarc=(\w+)', auth_results)
            if dmarc_match:
                dmarc_result = dmarc_match.group(1).lower()
                analysis['dmarc_result'] = dmarc_result
                if dmarc_result != 'pass':
                    analysis['suspicious_patterns'].append(f"DMARC authentication failed: {dmarc_result}")
                    analysis['risk_level'] = 'high'
            else:
                analysis['suspicious_patterns'].append("No DMARC authentication results")
                analysis['risk_level'] = 'medium'
        
        return analysis

    def _extract_domain(self, email_header: str) -> str:
        """Extract domain from an email address in a header."""
        if not email_header:
            return ''
        
        # Extract email address from "Display Name <email@domain.com>" format
        email_match = re.search(r'<(.+?)>', email_header)
        if email_match:
            email = email_match.group(1)
        else:
            email = email_header.strip()
        
        # Extract domain from email address
        domain_match = re.search(r'@(.+?)$', email)
        return domain_match.group(1) if domain_match else ''

    async def _analyze_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        """Analyze domain information including WHOIS and DNS records."""
        results = []
        
        for domain in domains:
            try:
                domain_info = {
                    'domain': domain,
                    'whois_info': await self._get_whois_info(domain),
                    'dns_records': await self._get_dns_records(domain),
                    'suspicious_indicators': []
                }

                # Check for suspicious characteristics
                domain_info['suspicious_indicators'].extend(
                    self._check_domain_anomalies(domain_info)
                )

                results.append(domain_info)

            except Exception as e:
                self.logger.error(f"Error analyzing domain {domain}: {str(e)}")
                continue

        return results

    async def _get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information for a domain."""
        try:
            whois_info = whois.whois(domain)
            return {
                'registrar': whois_info.registrar,
                'creation_date': self._format_whois_date(whois_info.creation_date),
                'expiration_date': self._format_whois_date(whois_info.expiration_date),
                'last_updated': self._format_whois_date(whois_info.updated_date),
                'status': whois_info.status,
                'name_servers': whois_info.name_servers
            }
        except Exception as e:
            self.logger.error(f"Error getting WHOIS info for {domain}: {str(e)}")
            return {}

    def _format_whois_date(self, date_value: Any) -> Optional[str]:
        """Format WHOIS date values consistently."""
        if isinstance(date_value, list):
            date_value = date_value[0] if date_value else None
        
        if date_value:
            try:
                return datetime.strftime(date_value, '%Y-%m-%dT%H:%M:%SZ')
            except Exception:
                return str(date_value)
        return None

    async def _get_dns_records(self, domain: str) -> Dict[str, Any]:
        """Get DNS records for a domain."""
        records = {
            'a': [],
            'mx': [],
            'txt': [],
            'ns': [],
            'spf': None
        }

        try:
            # A records
            try:
                answers = self.dns_resolver.resolve(domain, 'A')
                records['a'] = [str(rdata) for rdata in answers]
            except Exception:
                pass

            # MX records
            try:
                answers = self.dns_resolver.resolve(domain, 'MX')
                records['mx'] = [str(rdata.exchange) for rdata in answers]
            except Exception:
                pass

            # TXT records
            try:
                answers = self.dns_resolver.resolve(domain, 'TXT')
                records['txt'] = [str(rdata) for rdata in answers]
                # Extract SPF record
                records['spf'] = next(
                    (txt for txt in records['txt'] if txt.startswith('v=spf1')),
                    None
                )
            except Exception:
                pass

            # NS records
            try:
                answers = self.dns_resolver.resolve(domain, 'NS')
                records['ns'] = [str(rdata) for rdata in answers]
            except Exception:
                pass

        except Exception as e:
            self.logger.error(f"Error getting DNS records for {domain}: {str(e)}")

        return records

    def _check_domain_anomalies(self, domain_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for suspicious characteristics in domain information."""
        anomalies = []
        
        whois_info = domain_info.get('whois_info', {})
        
        # Check domain age
        creation_date = whois_info.get('creation_date')
        if creation_date:
            try:
                age = datetime.now() - datetime.strptime(creation_date, '%Y-%m-%dT%H:%M:%SZ')
                if age.days < 30:
                    anomalies.append({
                        'type': 'newly_registered_domain',
                        'detail': f"Domain was registered {age.days} days ago"
                    })
            except Exception:
                pass

        # Check for missing DNS records
        dns_records = domain_info.get('dns_records', {})
        if not dns_records.get('mx'):
            anomalies.append({
                'type': 'missing_mx_records',
                'detail': "Domain has no MX records"
            })
        
        if not dns_records.get('spf'):
            anomalies.append({
                'type': 'missing_spf_record',
                'detail': "Domain has no SPF record"
            })

        return anomalies

    async def _analyze_ssl_certificates(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Analyze SSL certificates from URLs."""
        results = []
        
        for url in urls:
            try:
                if not url.startswith('https://'):
                    continue

                cert_info = await self._get_ssl_certificate(url)
                if cert_info:
                    cert_info['url'] = url
                    cert_info['suspicious_indicators'] = self._check_ssl_anomalies(cert_info)
                    results.append(cert_info)

            except Exception as e:
                self.logger.error(f"Error analyzing SSL certificate for {url}: {str(e)}")
                continue

        return results

    async def _get_ssl_certificate(self, url: str) -> Optional[Dict[str, Any]]:
        """Get SSL certificate information for a URL."""
        try:
            hostname = url.split('https://')[-1].split('/')[0]
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }

        except Exception as e:
            self.logger.error(f"Error getting SSL certificate for {url}: {str(e)}")
            return None

    def _check_ssl_anomalies(self, cert_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for suspicious characteristics in SSL certificates."""
        anomalies = []
        
        try:
            # Check certificate validity
            not_before = datetime.strptime(cert_info['not_before'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert_info['not_after'], '%b %d %H:%M:%S %Y %Z')
            now = datetime.utcnow()

            if now < not_before:
                anomalies.append({
                    'type': 'certificate_not_yet_valid',
                    'detail': f"Certificate becomes valid on {cert_info['not_before']}"
                })

            if now > not_after:
                anomalies.append({
                    'type': 'expired_certificate',
                    'detail': f"Certificate expired on {cert_info['not_after']}"
                })

            # Check for self-signed certificates
            subject = cert_info['subject']
            issuer = cert_info['issuer']
            if subject == issuer:
                anomalies.append({
                    'type': 'self_signed_certificate',
                    'detail': "Certificate is self-signed"
                })

            # Check certificate age
            cert_age = not_after - not_before
            if cert_age.days < 30:
                anomalies.append({
                    'type': 'short_validity_period',
                    'detail': f"Certificate validity period is only {cert_age.days} days"
                })

        except Exception as e:
            self.logger.error(f"Error checking SSL anomalies: {str(e)}")

        return anomalies

    async def _notify_agents(self, incident_id: str, results: Dict[str, Any]) -> None:
        """Notify other agents about the metadata analysis results."""
        try:
            # Notify the Phishing Score Agent
            await mq.publish('score_aggregation', {
                'incident_id': incident_id,
                'metadata_analysis': results
            })

            # If suspicious indicators are found, notify the Alert Agent
            suspicious_indicators = (
                results.get('email_analysis', {}).get('suspicious_indicators', []) +
                [indicator for domain in results.get('domain_analysis', [])
                 for indicator in domain.get('suspicious_indicators', [])] +
                [indicator for cert in results.get('ssl_analysis', [])
                 for indicator in cert.get('suspicious_indicators', [])]
            )

            if suspicious_indicators:
                await mq.publish('alert', {
                    'incident_id': incident_id,
                    'metadata_alerts': suspicious_indicators,
                    'severity': 'medium'
                })

        except Exception as e:
            self.logger.error(f"Error notifying agents: {str(e)}")

    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        self.logger.info("Cleaning up Metadata Agent")
        if self.session:
            await self.session.close() 