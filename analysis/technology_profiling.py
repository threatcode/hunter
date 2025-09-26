"""
Advanced technology profiling and fingerprinting for web applications.

This module implements comprehensive technology detection including frameworks,
libraries, server technologies, and security configurations.
"""

import asyncio
import logging
import re
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Set, Any, Tuple
from urllib.parse import urljoin, urlparse
import aiohttp
from bs4 import BeautifulSoup

from recon.collectors import BaseCollector


logger = logging.getLogger(__name__)


class TechnologyProfiler:
    """Advanced technology profiler with multiple detection methods."""
    
    def __init__(self):
        self.signatures = self._load_signatures()
        self.security_headers = {
            'strict-transport-security': 'HSTS',
            'content-security-policy': 'CSP',
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-xss-protection': 'X-XSS-Protection',
            'referrer-policy': 'Referrer-Policy'
        }
    
    def _load_signatures(self) -> Dict[str, Any]:
        """Load technology signatures database."""
        return {
            'wordpress': {
                'patterns': [r'wp-content', r'wp-includes', r'/wp-json/'],
                'paths': ['/wp-admin/', '/wp-login.php'],
                'category': 'CMS',
                'confidence': 0.9
            },
            'drupal': {
                'patterns': [r'drupal', r'sites/default/files'],
                'paths': ['/user/login', '/core/'],
                'category': 'CMS',
                'confidence': 0.9
            },
            'react': {
                'patterns': [r'react', r'react-dom'],
                'category': 'JavaScript Framework',
                'confidence': 0.8
            },
            'angular': {
                'patterns': [r'angular', r'ng-app'],
                'category': 'JavaScript Framework',
                'confidence': 0.8
            },
            'php': {
                'headers': ['x-powered-by'],
                'patterns': [r'php'],
                'cookies': ['PHPSESSID'],
                'category': 'Programming Language',
                'confidence': 0.8
            },
            'asp.net': {
                'headers': ['x-powered-by', 'x-aspnet-version'],
                'patterns': [r'asp\.net'],
                'cookies': ['ASP.NET_SessionId'],
                'category': 'Framework',
                'confidence': 0.9
            }
        }
    
    async def profile_application(self, base_url: str, **kwargs) -> Dict[str, Any]:
        """Perform comprehensive technology profiling."""
        
        profile_results = {
            'base_url': base_url,
            'technologies': [],
            'security_headers': {},
            'missing_security_headers': [],
            'security_score': 0
        }
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            
            # Analyze main page
            main_analysis = await self._analyze_main_page(session, base_url)
            if main_analysis:
                profile_results.update(main_analysis)
            
            # Test technology paths
            path_analysis = await self._test_technology_paths(session, base_url)
            profile_results['technologies'].extend(path_analysis)
            
            # Calculate security score
            profile_results['security_score'] = self._calculate_security_score(profile_results)
        
        return profile_results
    
    async def _analyze_main_page(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict[str, Any]]:
        """Analyze main page for technology indicators."""
        
        try:
            async with session.get(url) as response:
                headers = dict(response.headers)
                content = await response.text()
                
                analysis = {
                    'technologies': [],
                    'security_headers': {},
                    'missing_security_headers': []
                }
                
                # Header analysis
                header_tech = self._analyze_headers(headers)
                analysis['technologies'].extend(header_tech['technologies'])
                analysis['security_headers'] = header_tech['security_headers']
                analysis['missing_security_headers'] = header_tech['missing_headers']
                
                # Content analysis
                if 'text/html' in headers.get('content-type', '').lower():
                    content_tech = self._analyze_content(content)
                    analysis['technologies'].extend(content_tech)
                
                # Cookie analysis
                cookie_tech = self._analyze_cookies(response.cookies)
                analysis['technologies'].extend(cookie_tech)
                
                return analysis
        
        except Exception as e:
            logger.error(f"Failed to analyze {url}: {e}")
            return None
    
    def _analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze headers for technologies and security."""
        
        analysis = {
            'technologies': [],
            'security_headers': {},
            'missing_headers': []
        }
        
        lower_headers = {k.lower(): v for k, v in headers.items()}
        
        # Technology detection
        for tech_name, signature in self.signatures.items():
            if 'headers' in signature:
                for header_name in signature['headers']:
                    if header_name in lower_headers:
                        header_value = lower_headers[header_name].lower()
                        for pattern in signature.get('patterns', []):
                            if re.search(pattern, header_value, re.IGNORECASE):
                                analysis['technologies'].append({
                                    'name': tech_name,
                                    'category': signature['category'],
                                    'confidence': signature['confidence'],
                                    'method': 'header_analysis'
                                })
        
        # Security headers
        for header_name, header_desc in self.security_headers.items():
            if header_name in lower_headers:
                analysis['security_headers'][header_desc] = lower_headers[header_name]
            else:
                analysis['missing_headers'].append(header_desc)
        
        return analysis
    
    def _analyze_content(self, content: str) -> List[Dict[str, Any]]:
        """Analyze content for technology patterns."""
        
        technologies = []
        
        for tech_name, signature in self.signatures.items():
            if 'patterns' in signature:
                for pattern in signature['patterns']:
                    if re.search(pattern, content, re.IGNORECASE):
                        technologies.append({
                            'name': tech_name,
                            'category': signature['category'],
                            'confidence': signature['confidence'],
                            'method': 'content_analysis'
                        })
                        break
        
        return technologies
    
    def _analyze_cookies(self, cookies) -> List[Dict[str, Any]]:
        """Analyze cookies for technology indicators."""
        
        technologies = []
        
        for cookie in cookies:
            cookie_name = cookie.key.lower()
            
            for tech_name, signature in self.signatures.items():
                if 'cookies' in signature:
                    for cookie_pattern in signature['cookies']:
                        if cookie_pattern.lower() in cookie_name:
                            technologies.append({
                                'name': tech_name,
                                'category': signature['category'],
                                'confidence': signature['confidence'],
                                'method': 'cookie_analysis'
                            })
        
        return technologies
    
    async def _test_technology_paths(self, session: aiohttp.ClientSession, base_url: str) -> List[Dict[str, Any]]:
        """Test technology-specific paths."""
        
        technologies = []
        
        for tech_name, signature in self.signatures.items():
            if 'paths' in signature:
                for path in signature['paths']:
                    try:
                        test_url = urljoin(base_url, path)
                        async with session.get(test_url) as response:
                            if response.status == 200:
                                technologies.append({
                                    'name': tech_name,
                                    'category': signature['category'],
                                    'confidence': signature['confidence'],
                                    'method': 'path_verification'
                                })
                                break
                    except:
                        continue
        
        return technologies
    
    def _calculate_security_score(self, profile_results: Dict[str, Any]) -> int:
        """Calculate security score."""
        
        score = 100
        missing_headers = len(profile_results.get('missing_security_headers', []))
        
        # Deduct points for missing security headers
        score -= missing_headers * 10
        
        return max(0, score)


class TechnologyProfilingCollector(BaseCollector):
    """Technology profiling collector."""
    
    def __init__(self):
        super().__init__("technology_profiling")
        self.profiler = TechnologyProfiler()
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Perform technology profiling."""
        
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # Run profiling
        profile_results = await self.profiler.profile_application(target, **kwargs)
        
        # Store results
        self.add_result({
            'type': 'technology_profile',
            'target': target,
            'profile_data': profile_results
        })
        
        # Process individual technologies
        for tech in profile_results.get('technologies', []):
            self.add_result({
                'type': 'technology_detected',
                'target': target,
                'technology': tech
            })
        
        return self.results


# Standalone usage
if __name__ == "__main__":
    async def test_profiling():
        collector = TechnologyProfilingCollector()
        results = await collector.collect("https://httpbin.org")
        
        print(f"Technology profiling completed with {len(results)} results")
        for result in results[:5]:
            print(f"- {result.get('type')}: {result}")
    
    asyncio.run(test_profiling())
