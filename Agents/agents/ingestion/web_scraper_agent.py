from typing import Dict, Any, List, Optional
from common.models.base_agent import BaseAgent
from common.utils.database import db
from common.utils.message_queue import mq
import logging
import aiohttp
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import json
from datetime import datetime

class WebScraperAgent(BaseAgent):
    """Agent responsible for scraping and analyzing web content."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("web_scraper", config)
        self.session = None
        self.timeout = 30
        self.max_size = 10 * 1024 * 1024  # 10MB
        self.max_redirects = 5

    async def initialize(self) -> None:
        """Initialize the web scraper agent."""
        self.logger.info("Initializing Web Scraper Agent")
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        )

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process webpage content."""
        try:
            url = data.get('url')
            incident_id = data.get('incident_id')
            
            if not url:
                raise ValueError("URL not provided")

            # Scrape and analyze the webpage
            scrape_results = await self._scrape_webpage(url)
            
            # Extract additional content
            analysis_results = {
                'incident_id': incident_id,
                'url': url,
                'scrape_results': scrape_results,
                'hidden_content': await self._extract_hidden_content(scrape_results['html']),
                'forms': await self._analyze_forms(scrape_results['html']),
                'scripts': await self._analyze_scripts(scrape_results['html']),
                'links': await self._extract_links(scrape_results['html'], url),
                'timestamp': datetime.utcnow().isoformat()
            }

            # Store results
            await db.update_analysis_result(incident_id, {
                'web_scrape_analysis': analysis_results
            })

            # Notify other agents
            await self._notify_agents(incident_id, analysis_results)

            return analysis_results

        except Exception as e:
            await self.handle_error(e)
            raise

    async def _scrape_webpage(self, url: str) -> Dict[str, Any]:
        """Scrape webpage content and track redirects."""
        try:
            async with self.session.get(
                url,
                allow_redirects=True,
                max_redirects=self.max_redirects
            ) as response:
                content_type = response.headers.get('Content-Type', '')
                
                if 'text/html' not in content_type.lower():
                    raise ValueError(f"Invalid content type: {content_type}")

                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')

                return {
                    'status_code': response.status,
                    'final_url': str(response.url),
                    'redirect_chain': [str(h.url) for h in response.history],
                    'headers': dict(response.headers),
                    'html': html,
                    'text_content': soup.get_text(separator=' ', strip=True),
                    'title': soup.title.string if soup.title else None
                }

        except Exception as e:
            self.logger.error(f"Error scraping webpage {url}: {str(e)}")
            raise

    async def _extract_hidden_content(self, html: str) -> List[Dict[str, Any]]:
        """Extract hidden content from webpage."""
        soup = BeautifulSoup(html, 'html.parser')
        hidden_elements = []

        # Find elements with hidden styles
        for element in soup.find_all(style=True):
            style = element.get('style', '').lower()
            if any(h in style for h in ['display:none', 'visibility:hidden']):
                hidden_elements.append({
                    'type': element.name,
                    'content': element.get_text(strip=True),
                    'html': str(element),
                    'hiding_method': 'css-style'
                })

        # Find elements with hidden class
        hidden_classes = ['hidden', 'invisible', 'd-none']
        for element in soup.find_all(class_=hidden_classes):
            hidden_elements.append({
                'type': element.name,
                'content': element.get_text(strip=True),
                'html': str(element),
                'hiding_method': 'css-class'
            })

        return hidden_elements

    async def _analyze_forms(self, html: str) -> List[Dict[str, Any]]:
        """Analyze forms in the webpage."""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []

        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action'),
                'method': form.get('method', 'get').upper(),
                'inputs': [],
                'has_password_field': False,
                'has_file_upload': False
            }

            # Analyze form inputs
            for input_field in form.find_all('input'):
                input_type = input_field.get('type', 'text')
                form_data['inputs'].append({
                    'type': input_type,
                    'name': input_field.get('name'),
                    'id': input_field.get('id'),
                    'required': input_field.get('required') is not None
                })

                if input_type == 'password':
                    form_data['has_password_field'] = True
                elif input_type == 'file':
                    form_data['has_file_upload'] = True

            forms.append(form_data)

        return forms

    async def _analyze_scripts(self, html: str) -> List[Dict[str, Any]]:
        """Analyze JavaScript content in the webpage."""
        soup = BeautifulSoup(html, 'html.parser')
        scripts = []

        for script in soup.find_all('script'):
            script_data = {
                'src': script.get('src'),
                'type': script.get('type', 'text/javascript'),
                'async': script.get('async') is not None,
                'defer': script.get('defer') is not None,
                'content_length': len(script.string) if script.string else 0,
                'is_external': bool(script.get('src'))
            }

            # Basic analysis of script content for suspicious patterns
            if script.string:
                script_data['suspicious_patterns'] = self._check_script_patterns(script.string)

            scripts.append(script_data)

        return scripts

    def _check_script_patterns(self, script_content: str) -> List[str]:
        """Check for suspicious patterns in JavaScript code."""
        suspicious_patterns = {
            'eval': r'eval\s*\(',
            'document.write': r'document\.write\s*\(',
            'base64': r'base64',
            'encoded_strings': r'\\x[0-9a-fA-F]{2}',
            'obfuscated_functions': r'\[\s*([\'"])\w+\1\s*\]',
            'suspicious_redirects': r'window\.location\s*=',
            'data_exfiltration': r'navigator\.sendBeacon|fetch\s*\('
        }

        found_patterns = []
        for name, pattern in suspicious_patterns.items():
            if re.search(pattern, script_content):
                found_patterns.append(name)

        return found_patterns

    async def _extract_links(self, html: str, base_url: str) -> Dict[str, Any]:
        """Extract and analyze links from the webpage."""
        soup = BeautifulSoup(html, 'html.parser')
        links_analysis = {
            'internal_links': [],
            'external_links': [],
            'resource_links': [],
            'suspicious_links': []
        }

        base_domain = urlparse(base_url).netloc

        for link in soup.find_all('a', href=True):
            href = link.get('href')
            absolute_url = urljoin(base_url, href)
            parsed_url = urlparse(absolute_url)
            
            link_data = {
                'url': absolute_url,
                'text': link.get_text(strip=True),
                'title': link.get('title'),
                'rel': link.get('rel', []),
                'onclick': link.get('onclick')
            }

            # Categorize the link
            if parsed_url.netloc == base_domain:
                links_analysis['internal_links'].append(link_data)
            else:
                links_analysis['external_links'].append(link_data)

            # Check for suspicious characteristics
            if self._is_suspicious_link(link_data):
                links_analysis['suspicious_links'].append(link_data)

        # Extract resource links (images, scripts, stylesheets)
        for tag in soup.find_all(['img', 'script', 'link']):
            src = tag.get('src') or tag.get('href')
            if src:
                links_analysis['resource_links'].append({
                    'url': urljoin(base_url, src),
                    'type': tag.name,
                    'attributes': dict(tag.attrs)
                })

        return links_analysis

    def _is_suspicious_link(self, link_data: Dict[str, Any]) -> bool:
        """Check if a link has suspicious characteristics."""
        suspicious_indicators = [
            # Mismatched text and URL
            lambda l: 'http' in l['text'].lower() and l['text'] not in l['url'],
            # Encoded characters in URL
            lambda l: '%' in l['url'],
            # Numeric IP in URL
            lambda l: re.search(r'\d+\.\d+\.\d+\.\d+', l['url']),
            # Suspicious TLDs
            lambda l: any(tld in l['url'].lower() for tld in ['.xyz', '.top', '.click', '.loan']),
            # JavaScript in href
            lambda l: 'javascript:' in l['url'].lower(),
            # Data URLs
            lambda l: 'data:' in l['url'].lower()
        ]

        return any(check(link_data) for check in suspicious_indicators)

    async def _notify_agents(self, incident_id: str, results: Dict[str, Any]) -> None:
        """Notify other agents about the scraping results."""
        # Notify Text Analysis Agent
        await mq.publish('text_analysis', {
            'incident_id': incident_id,
            'content': results['scrape_results']['text_content'],
            'source': 'web_scraper'
        })

        # Notify URL Analysis Agent about found links
        if results['links']['external_links']:
            await mq.publish('url_analysis', {
                'incident_id': incident_id,
                'urls': [link['url'] for link in results['links']['external_links']],
                'source': 'web_scraper'
            })

    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        self.logger.info("Cleaning up Web Scraper Agent")
        if self.session:
            await self.session.close() 