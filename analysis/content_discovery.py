"""
Advanced content discovery suite with intelligent crawling and endpoint analysis.

This module implements comprehensive content discovery including web crawling,
API endpoint discovery, parameter extraction, and intelligent path analysis.
"""

import asyncio
import logging
import re
import json
from datetime import datetime
from typing import Dict, List, Optional, Set, Any, Tuple, Union
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from pathlib import Path
import aiohttp
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET

from recon.collectors import BaseCollector
from automation.logging_config import evidence_store


logger = logging.getLogger(__name__)


class WebCrawler:
    """Advanced web crawler with intelligent link discovery."""
    
    def __init__(self, max_depth: int = 3, max_pages: int = 100):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_urls = set()
        self.discovered_endpoints = []
        self.discovered_parameters = set()
        self.discovered_technologies = []
        
        # Common file extensions to discover
        self.interesting_extensions = {
            '.php', '.asp', '.aspx', '.jsp', '.do', '.action',
            '.json', '.xml', '.yaml', '.yml', '.config',
            '.bak', '.backup', '.old', '.tmp', '.swp',
            '.sql', '.db', '.sqlite', '.log'
        }
        
        # API-related patterns
        self.api_patterns = [
            r'/api/', r'/v[0-9]+/', r'/rest/', r'/graphql',
            r'/swagger', r'/openapi', r'/docs/api'
        ]
    
    async def crawl_website(self, base_url: str, **kwargs) -> Dict[str, Any]:
        """Crawl website starting from base URL."""
        
        crawl_results = {
            'base_url': base_url,
            'endpoints_discovered': [],
            'parameters_discovered': [],
            'forms_discovered': [],
            'technologies_detected': [],
            'api_endpoints': [],
            'interesting_files': [],
            'crawl_stats': {
                'pages_crawled': 0,
                'max_depth_reached': 0,
                'errors_encountered': 0
            }
        }
        
        # Initialize crawling queue
        crawl_queue = [(base_url, 0)]  # (url, depth)
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(ssl=False, limit=50)
        ) as session:
            
            while crawl_queue and len(self.visited_urls) < self.max_pages:
                current_url, depth = crawl_queue.pop(0)
                
                if current_url in self.visited_urls or depth > self.max_depth:
                    continue
                
                try:
                    page_data = await self._crawl_page(session, current_url, depth)
                    
                    if page_data:
                        # Add discovered links to queue
                        for link in page_data.get('links', []):
                            if self._should_crawl_url(link, base_url):
                                crawl_queue.append((link, depth + 1))
                        
                        # Collect results
                        crawl_results['endpoints_discovered'].extend(page_data.get('endpoints', []))
                        crawl_results['parameters_discovered'].extend(page_data.get('parameters', []))
                        crawl_results['forms_discovered'].extend(page_data.get('forms', []))
                        crawl_results['technologies_detected'].extend(page_data.get('technologies', []))
                        
                        # Check for API endpoints
                        if self._is_api_endpoint(current_url):
                            crawl_results['api_endpoints'].append({
                                'url': current_url,
                                'method': 'GET',
                                'response_type': page_data.get('content_type', ''),
                                'status_code': page_data.get('status_code', 0)
                            })
                        
                        # Check for interesting files
                        if self._is_interesting_file(current_url):
                            crawl_results['interesting_files'].append({
                                'url': current_url,
                                'type': self._get_file_type(current_url),
                                'size': page_data.get('content_length', 0)
                            })
                        
                        crawl_results['crawl_stats']['pages_crawled'] += 1
                        crawl_results['crawl_stats']['max_depth_reached'] = max(
                            crawl_results['crawl_stats']['max_depth_reached'], depth
                        )
                
                except Exception as e:
                    logger.debug(f"Error crawling {current_url}: {e}")
                    crawl_results['crawl_stats']['errors_encountered'] += 1
        
        # Deduplicate results
        crawl_results['parameters_discovered'] = list(set(crawl_results['parameters_discovered']))
        
        return crawl_results
    
    async def _crawl_page(self, session: aiohttp.ClientSession, url: str, depth: int) -> Optional[Dict[str, Any]]:
        """Crawl a single page and extract information."""
        
        if url in self.visited_urls:
            return None
        
        self.visited_urls.add(url)
        
        try:
            async with session.get(url) as response:
                if response.status != 200:
                    return None
                
                content_type = response.headers.get('content-type', '').lower()
                content = await response.text()
                
                page_data = {
                    'url': url,
                    'depth': depth,
                    'status_code': response.status,
                    'content_type': content_type,
                    'content_length': len(content),
                    'headers': dict(response.headers),
                    'links': [],
                    'endpoints': [],
                    'parameters': [],
                    'forms': [],
                    'technologies': []
                }
                
                # Parse HTML content
                if 'text/html' in content_type:
                    html_data = self._parse_html_content(url, content)
                    page_data.update(html_data)
                
                # Parse JSON content
                elif 'application/json' in content_type:
                    json_data = self._parse_json_content(url, content)
                    page_data.update(json_data)
                
                # Parse XML content
                elif 'xml' in content_type:
                    xml_data = self._parse_xml_content(url, content)
                    page_data.update(xml_data)
                
                # Detect technologies from headers and content
                tech_data = self._detect_technologies(response.headers, content)
                page_data['technologies'].extend(tech_data)
                
                return page_data
        
        except Exception as e:
            logger.debug(f"Failed to crawl page {url}: {e}")
            return None
    
    def _parse_html_content(self, url: str, content: str) -> Dict[str, Any]:
        """Parse HTML content for links, forms, and other elements."""
        
        html_data = {
            'links': [],
            'endpoints': [],
            'parameters': [],
            'forms': [],
            'technologies': []
        }
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract links
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(url, href)
                html_data['links'].append(absolute_url)
                
                # Extract parameters from URLs
                parsed_url = urlparse(absolute_url)
                if parsed_url.query:
                    params = parse_qs(parsed_url.query)
                    html_data['parameters'].extend(params.keys())
                
                html_data['endpoints'].append({
                    'url': absolute_url,
                    'method': 'GET',
                    'source': 'html_link',
                    'text': link.get_text(strip=True)[:100]
                })
            
            # Extract forms
            for form in soup.find_all('form'):
                form_data = self._parse_form(url, form)
                html_data['forms'].append(form_data)
                html_data['endpoints'].append({
                    'url': form_data['action'],
                    'method': form_data['method'],
                    'source': 'html_form',
                    'parameters': form_data['fields']
                })
                html_data['parameters'].extend(form_data['fields'])
            
            # Extract JavaScript sources and inline scripts
            js_data = self._extract_javascript_info(url, soup)
            html_data['links'].extend(js_data['js_files'])
            html_data['endpoints'].extend(js_data['endpoints'])
            html_data['parameters'].extend(js_data['parameters'])
            
            # Extract CSS and other resources
            for link in soup.find_all('link', href=True):
                href = link['href']
                absolute_url = urljoin(url, href)
                html_data['links'].append(absolute_url)
            
            # Extract images and other media
            for img in soup.find_all('img', src=True):
                src = img['src']
                absolute_url = urljoin(url, src)
                html_data['links'].append(absolute_url)
            
            # Technology detection from HTML
            tech_indicators = self._detect_html_technologies(soup)
            html_data['technologies'].extend(tech_indicators)
        
        except Exception as e:
            logger.debug(f"Error parsing HTML content: {e}")
        
        return html_data
    
    def _parse_form(self, base_url: str, form) -> Dict[str, Any]:
        """Parse HTML form and extract fields."""
        
        action = form.get('action', '')
        if action:
            action_url = urljoin(base_url, action)
        else:
            action_url = base_url
        
        method = form.get('method', 'GET').upper()
        
        fields = []
        for input_tag in form.find_all(['input', 'select', 'textarea']):
            field_name = input_tag.get('name')
            if field_name:
                fields.append(field_name)
        
        return {
            'action': action_url,
            'method': method,
            'fields': fields,
            'enctype': form.get('enctype', ''),
            'id': form.get('id', ''),
            'class': form.get('class', [])
        }
    
    def _extract_javascript_info(self, base_url: str, soup) -> Dict[str, Any]:
        """Extract JavaScript files and analyze for endpoints."""
        
        js_data = {
            'js_files': [],
            'endpoints': [],
            'parameters': []
        }
        
        # External JavaScript files
        for script in soup.find_all('script', src=True):
            src = script['src']
            js_url = urljoin(base_url, src)
            js_data['js_files'].append(js_url)
        
        # Inline JavaScript analysis
        for script in soup.find_all('script'):
            if script.string:
                js_endpoints = self._analyze_javascript_content(script.string)
                js_data['endpoints'].extend(js_endpoints['endpoints'])
                js_data['parameters'].extend(js_endpoints['parameters'])
        
        return js_data
    
    def _analyze_javascript_content(self, js_content: str) -> Dict[str, Any]:
        """Analyze JavaScript content for API endpoints and parameters."""
        
        js_analysis = {
            'endpoints': [],
            'parameters': []
        }
        
        # URL patterns in JavaScript
        url_patterns = [
            r'["\']([/\w\-\.]+\.(?:php|asp|aspx|jsp|do|action|json|xml))["\']',
            r'["\']([/\w\-\.]+/api/[^"\']*)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']',
            r'ajax\s*\(\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in url_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                js_analysis['endpoints'].append({
                    'url': match,
                    'method': 'GET',  # Default, could be improved
                    'source': 'javascript'
                })
        
        # Parameter patterns
        param_patterns = [
            r'["\'](\w+)["\']:\s*["\']?\w+["\']?',  # Object properties
            r'data\s*:\s*\{([^}]+)\}',  # AJAX data objects
            r'params\s*:\s*\{([^}]+)\}'  # Parameter objects
        ]
        
        for pattern in param_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                # Extract parameter names from matched content
                param_names = re.findall(r'["\']?(\w+)["\']?\s*:', match)
                js_analysis['parameters'].extend(param_names)
        
        return js_analysis
    
    def _parse_json_content(self, url: str, content: str) -> Dict[str, Any]:
        """Parse JSON content for API structure."""
        
        json_data = {
            'endpoints': [],
            'parameters': [],
            'api_structure': {}
        }
        
        try:
            data = json.loads(content)
            
            # Analyze JSON structure for API endpoints
            if isinstance(data, dict):
                # Look for common API documentation patterns
                if 'paths' in data:  # OpenAPI/Swagger
                    swagger_data = self._parse_swagger_json(data)
                    json_data.update(swagger_data)
                
                elif 'data' in data and isinstance(data['data'], list):
                    # REST API response pattern
                    json_data['api_structure'] = self._analyze_json_structure(data)
                
                # Extract parameter names from JSON keys
                json_data['parameters'].extend(self._extract_json_parameters(data))
        
        except json.JSONDecodeError:
            logger.debug(f"Invalid JSON content at {url}")
        except Exception as e:
            logger.debug(f"Error parsing JSON content: {e}")
        
        return json_data
    
    def _parse_swagger_json(self, swagger_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Swagger/OpenAPI JSON for endpoints."""
        
        swagger_analysis = {
            'endpoints': [],
            'parameters': []
        }
        
        base_path = swagger_data.get('basePath', '')
        
        for path, methods in swagger_data.get('paths', {}).items():
            for method, details in methods.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    endpoint_url = base_path + path
                    
                    # Extract parameters
                    parameters = []
                    for param in details.get('parameters', []):
                        param_name = param.get('name')
                        if param_name:
                            parameters.append(param_name)
                            swagger_analysis['parameters'].append(param_name)
                    
                    swagger_analysis['endpoints'].append({
                        'url': endpoint_url,
                        'method': method.upper(),
                        'source': 'swagger_documentation',
                        'parameters': parameters,
                        'summary': details.get('summary', ''),
                        'tags': details.get('tags', [])
                    })
        
        return swagger_analysis
    
    def _parse_xml_content(self, url: str, content: str) -> Dict[str, Any]:
        """Parse XML content for endpoints and structure."""
        
        xml_data = {
            'endpoints': [],
            'parameters': []
        }
        
        try:
            root = ET.fromstring(content)
            
            # Check for sitemap.xml
            if root.tag.endswith('urlset'):
                for url_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                    loc_elem = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                    if loc_elem is not None:
                        xml_data['endpoints'].append({
                            'url': loc_elem.text,
                            'method': 'GET',
                            'source': 'sitemap_xml'
                        })
            
            # Extract all text content for parameter analysis
            all_text = ET.tostring(root, encoding='unicode', method='text')
            param_matches = re.findall(r'\b(\w+)=[\w\-\.]+', all_text)
            xml_data['parameters'].extend(param_matches)
        
        except ET.ParseError:
            logger.debug(f"Invalid XML content at {url}")
        except Exception as e:
            logger.debug(f"Error parsing XML content: {e}")
        
        return xml_data
    
    def _detect_technologies(self, headers: Dict[str, str], content: str) -> List[Dict[str, Any]]:
        """Detect technologies from HTTP headers and content."""
        
        technologies = []
        
        # Server header
        server = headers.get('server', '').lower()
        if server:
            if 'apache' in server:
                technologies.append({'name': 'Apache', 'category': 'Web Server', 'confidence': 0.9})
            elif 'nginx' in server:
                technologies.append({'name': 'Nginx', 'category': 'Web Server', 'confidence': 0.9})
            elif 'iis' in server:
                technologies.append({'name': 'IIS', 'category': 'Web Server', 'confidence': 0.9})
        
        # X-Powered-By header
        powered_by = headers.get('x-powered-by', '').lower()
        if powered_by:
            if 'php' in powered_by:
                technologies.append({'name': 'PHP', 'category': 'Programming Language', 'confidence': 0.9})
            elif 'asp.net' in powered_by:
                technologies.append({'name': 'ASP.NET', 'category': 'Framework', 'confidence': 0.9})
        
        # Content-based detection
        content_lower = content.lower()
        
        # WordPress detection
        if 'wp-content' in content_lower or 'wordpress' in content_lower:
            technologies.append({'name': 'WordPress', 'category': 'CMS', 'confidence': 0.8})
        
        # React detection
        if 'react' in content_lower and ('react-dom' in content_lower or 'reactjs' in content_lower):
            technologies.append({'name': 'React', 'category': 'JavaScript Framework', 'confidence': 0.7})
        
        # Angular detection
        if 'angular' in content_lower or 'ng-' in content_lower:
            technologies.append({'name': 'Angular', 'category': 'JavaScript Framework', 'confidence': 0.7})
        
        return technologies
    
    def _detect_html_technologies(self, soup) -> List[Dict[str, Any]]:
        """Detect technologies from HTML structure."""
        
        technologies = []
        
        # Meta generator tag
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and generator.get('content'):
            content = generator['content'].lower()
            if 'wordpress' in content:
                technologies.append({'name': 'WordPress', 'category': 'CMS', 'confidence': 0.9})
            elif 'drupal' in content:
                technologies.append({'name': 'Drupal', 'category': 'CMS', 'confidence': 0.9})
        
        # Script sources
        for script in soup.find_all('script', src=True):
            src = script['src'].lower()
            if 'jquery' in src:
                technologies.append({'name': 'jQuery', 'category': 'JavaScript Library', 'confidence': 0.8})
            elif 'bootstrap' in src:
                technologies.append({'name': 'Bootstrap', 'category': 'CSS Framework', 'confidence': 0.8})
        
        return technologies
    
    def _analyze_json_structure(self, data: Any, path: str = '') -> Dict[str, Any]:
        """Analyze JSON structure recursively."""
        
        structure = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                structure[current_path] = {
                    'type': type(value).__name__,
                    'sample_value': str(value)[:100] if not isinstance(value, (dict, list)) else None
                }
                
                if isinstance(value, (dict, list)):
                    nested = self._analyze_json_structure(value, current_path)
                    structure.update(nested)
        
        elif isinstance(data, list) and data:
            # Analyze first item in list
            first_item = data[0]
            if isinstance(first_item, dict):
                nested = self._analyze_json_structure(first_item, path)
                structure.update(nested)
        
        return structure
    
    def _extract_json_parameters(self, data: Any, params: Optional[Set[str]] = None) -> List[str]:
        """Extract parameter names from JSON data recursively."""
        
        if params is None:
            params = set()
        
        if isinstance(data, dict):
            params.update(data.keys())
            for value in data.values():
                if isinstance(value, (dict, list)):
                    self._extract_json_parameters(value, params)
        
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self._extract_json_parameters(item, params)
        
        return list(params)
    
    def _should_crawl_url(self, url: str, base_url: str) -> bool:
        """Determine if URL should be crawled."""
        
        parsed_url = urlparse(url)
        parsed_base = urlparse(base_url)
        
        # Only crawl same domain
        if parsed_url.netloc and parsed_url.netloc != parsed_base.netloc:
            return False
        
        # Skip certain file types
        skip_extensions = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar', '.tar', '.gz'}
        if any(url.lower().endswith(ext) for ext in skip_extensions):
            return False
        
        # Skip external resources
        if any(pattern in url.lower() for pattern in ['mailto:', 'tel:', 'javascript:', 'data:']):
            return False
        
        return True
    
    def _is_api_endpoint(self, url: str) -> bool:
        """Check if URL appears to be an API endpoint."""
        
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in self.api_patterns)
    
    def _is_interesting_file(self, url: str) -> bool:
        """Check if URL points to an interesting file."""
        
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()
        
        return any(path.endswith(ext) for ext in self.interesting_extensions)
    
    def _get_file_type(self, url: str) -> str:
        """Get file type from URL."""
        
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()
        
        for ext in self.interesting_extensions:
            if path.endswith(ext):
                return ext.lstrip('.')
        
        return 'unknown'


class ContentDiscoveryCollector(BaseCollector):
    """Advanced content discovery collector."""
    
    def __init__(self):
        super().__init__("content_discovery")
        self.crawler = WebCrawler()
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Perform comprehensive content discovery."""
        
        # Ensure target is a full URL
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # Run web crawling
        crawl_results = await self.crawler.crawl_website(target, **kwargs)
        
        # Store crawl results
        self.add_result({
            'type': 'web_crawl_results',
            'target': target,
            'crawl_data': crawl_results
        })
        
        # Process and categorize results
        await self._process_crawl_results(target, crawl_results)
        
        return self.results
    
    async def _process_crawl_results(self, target: str, crawl_results: Dict[str, Any]):
        """Process and categorize crawl results."""
        
        # Process discovered endpoints
        for endpoint in crawl_results.get('endpoints_discovered', []):
            self.add_result({
                'type': 'endpoint_discovered',
                'target': target,
                'endpoint': endpoint
            })
        
        # Process discovered parameters
        unique_params = list(set(crawl_results.get('parameters_discovered', [])))
        for param in unique_params:
            self.add_result({
                'type': 'parameter_discovered',
                'target': target,
                'parameter': param
            })
        
        # Process discovered forms
        for form in crawl_results.get('forms_discovered', []):
            self.add_result({
                'type': 'form_discovered',
                'target': target,
                'form': form
            })
        
        # Process API endpoints
        for api_endpoint in crawl_results.get('api_endpoints', []):
            self.add_result({
                'type': 'api_endpoint_discovered',
                'target': target,
                'api_endpoint': api_endpoint
            })
        
        # Process interesting files
        for file_info in crawl_results.get('interesting_files', []):
            self.add_result({
                'type': 'interesting_file_discovered',
                'target': target,
                'file': file_info
            })
        
        # Process technologies
        unique_technologies = []
        seen_tech = set()
        for tech in crawl_results.get('technologies_detected', []):
            tech_key = f"{tech['name']}_{tech['category']}"
            if tech_key not in seen_tech:
                seen_tech.add(tech_key)
                unique_technologies.append(tech)
        
        for tech in unique_technologies:
            self.add_result({
                'type': 'technology_detected',
                'target': target,
                'technology': tech
            })


# Standalone usage
if __name__ == "__main__":
    async def test_content_discovery():
        collector = ContentDiscoveryCollector()
        results = await collector.collect("https://httpbin.org")
        
        print(f"Content discovery completed with {len(results)} results")
        for result in results[:10]:  # Show first 10
            print(f"- {result.get('type')}: {result}")
    
    asyncio.run(test_content_discovery())
