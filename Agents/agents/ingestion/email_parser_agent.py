import email
from email import policy
from email.parser import BytesParser, Parser
from typing import Dict, Any, List
import base64
from common.models.base_agent import BaseAgent
from common.utils.database import db
from common.utils.message_queue import mq
import logging
import re
from bs4 import BeautifulSoup
from email.message import EmailMessage
import traceback
from email.utils import parseaddr, parsedate_to_datetime
from datetime import datetime

class EmailParserAgent(BaseAgent):
    """Agent responsible for parsing email content and extracting relevant information."""

    def __init__(self, agent_id: str, config: Dict[str, Any]):
        """Initialize the email parser agent."""
        super().__init__(agent_id, config)

    async def initialize(self) -> None:
        """Initialize the email parser agent."""
        self.logger.info("Initializing Email Parser Agent")
        await mq.connect()

    async def process(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process an email and extract relevant information."""
        try:
            incident_id = email_data.get('incident_id')
            content = email_data.get('email_content', '')

            # Parse the email
            email_message = email.message_from_string(content, policy=policy.default)

            # Extract headers
            headers = self._extract_headers(email_message)
            
            # Extract URLs from both text and HTML parts
            urls = self._extract_urls_from_email(email_message)

            # Log extracted information
            self.logger.info(f"Extracted {len(headers)} headers")
            self.logger.info(f"Found {len(urls)} URLs")
            
            # Store incident data
            incident_data = {
                'incident_id': incident_id,
                'raw_data': {
                    'content': content,
                    'headers': headers,
                    'urls': urls
                },
                'metadata': {
                    'headers': headers,
                    'urls': urls,
                    'analysis_timestamp': datetime.utcnow().isoformat()
                }
            }
            
            await db.insert_phishing_incident(incident_data)

            return {
                'incident_id': incident_id,
                'headers': headers,
                'urls': urls
            }
        except Exception as e:
            self.logger.error(f"Error processing email: {e}")
            self.logger.error(traceback.format_exc())
            raise

    def _extract_headers(self, email_message: EmailMessage) -> Dict[str, Any]:
        """Extract and normalize email headers."""
        headers = {}
        
        # Process all headers
        for name, value in email_message.items():
            name = name.lower()  # Normalize header names to lowercase
            
            # Handle special headers
            if name == 'received':
                if name not in headers:
                    headers[name] = []
                headers[name].append(self._clean_header_value(value))
            elif name == 'authentication-results':
                headers[name] = self._parse_auth_results(value)
            elif name in ['from', 'to', 'reply-to', 'return-path']:
                headers[name] = self._parse_address_header(value)
            elif name == 'date':
                headers[name] = self._parse_date_header(value)
            else:
                # General header processing
                headers[name] = self._clean_header_value(value)
        
        return headers

    def _clean_header_value(self, value: str) -> str:
        """Clean and normalize header values."""
        if not value:
            return ''
        
        # Remove excessive whitespace and newlines
        value = ' '.join(line.strip() for line in value.split('\n'))
        # Remove multiple spaces
        value = ' '.join(value.split())
        return value

    def _parse_auth_results(self, value: str) -> Dict[str, Any]:
        """Parse authentication results header into structured data."""
        results = {
            'spf': None,
            'dkim': None,
            'dmarc': None,
            'raw': self._clean_header_value(value)
        }
        
        # Extract SPF result
        spf_match = re.search(r'spf=(\w+)', value)
        if spf_match:
            results['spf'] = spf_match.group(1).lower()
        
        # Extract DKIM result
        dkim_match = re.search(r'dkim=(\w+)', value)
        if dkim_match:
            results['dkim'] = dkim_match.group(1).lower()
        
        # Extract DMARC result
        dmarc_match = re.search(r'dmarc=(\w+)', value)
        if dmarc_match:
            results['dmarc'] = dmarc_match.group(1).lower()
        
        return results

    def _parse_address_header(self, value: str) -> Dict[str, str]:
        """Parse email address headers into structured data."""
        display_name, email_address = parseaddr(value)
        return {
            'display_name': display_name,
            'email': email_address,
            'domain': email_address.split('@')[-1] if '@' in email_address else None,
            'raw': value
        }

    def _parse_date_header(self, value: str) -> Dict[str, Any]:
        """Parse date header into structured data."""
        try:
            parsed_date = parsedate_to_datetime(value)
            return {
                'timestamp': parsed_date.timestamp(),
                'iso': parsed_date.isoformat(),
                'raw': value
            }
        except Exception:
            return {'raw': value}

    def _extract_urls_from_email(self, email_message: EmailMessage) -> List[str]:
        """Extract URLs from both text and HTML parts of the email."""
        urls = set()
        
        if email_message.is_multipart():
            for part in email_message.walk():
                urls.update(self._extract_urls_from_part(part))
        else:
            urls.update(self._extract_urls_from_part(email_message))
            
        return list(urls)

    def _extract_urls_from_part(self, part: EmailMessage) -> List[str]:
        """Extract URLs from a single email part."""
        urls = set()
        content_type = part.get_content_type()
        
        try:
            if content_type == 'text/plain':
                content = part.get_content()
                urls.update(self._extract_urls_from_text(content))
            elif content_type == 'text/html':
                content = part.get_content()
                urls.update(self._extract_urls_from_html(content))
        except Exception as e:
            self.logger.error(f"Error extracting URLs from {content_type}: {e}")
            
        return urls

    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from plain text using regex."""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, text)

    def _extract_urls_from_html(self, html: str) -> List[str]:
        """Extract URLs from HTML content using BeautifulSoup."""
        urls = set()
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Extract URLs from links
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and href.startswith(('http://', 'https://')):
                    urls.add(href)
            
            # Extract URLs from images
            for img in soup.find_all('img'):
                src = img.get('src')
                if src and src.startswith(('http://', 'https://')):
                    urls.add(src)
            
            # Extract URLs from forms
            for form in soup.find_all('form'):
                action = form.get('action')
                if action and action.startswith(('http://', 'https://')):
                    urls.add(action)
                    
            # Extract URLs from scripts
            for script in soup.find_all('script'):
                src = script.get('src')
                if src and src.startswith(('http://', 'https://')):
                    urls.add(src)
                    
            # Extract URLs from iframes
            for iframe in soup.find_all('iframe'):
                src = iframe.get('src')
                if src and src.startswith(('http://', 'https://')):
                    urls.add(src)
                    
            # Extract URLs from background images
            for elem in soup.find_all(style=True):
                style = elem['style']
                urls.update(re.findall(r'url\(["\']?(http[s]?://[^"\'\)]+)', style))
                
        except Exception as e:
            self.logger.error(f"Error parsing HTML: {e}")
            
        return urls

    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        self.logger.info("Cleaning up Email Parser Agent")
        await mq.close() 