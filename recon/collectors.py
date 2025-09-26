"""
Reconnaissance collectors for the AI Bug Hunter framework.

This module implements atomic collectors for various reconnaissance tasks
including domain discovery, subdomain enumeration, and asset collection.
"""

import asyncio
import logging
import re
import json
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Set, Any, AsyncGenerator
import aiohttp
import dns.resolver
from urllib.parse import urlparse

from data.schemas import Domain, Host, Service, Organization, ASN
from automation.api_manager import make_api_request, get_api_key


logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Base class for all reconnaissance collectors."""
    
    def __init__(self, name: str):
        self.name = name
        self.results: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    @abstractmethod
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Collect reconnaissance data for the target."""
        pass
    
    def add_result(self, result: Dict[str, Any]) -> None:
        """Add a result to the collection."""
        result['collector'] = self.name
        result['timestamp'] = datetime.utcnow().isoformat()
        self.results.append(result)
    
    def add_error(self, error: str) -> None:
        """Add an error to the collection."""
        self.errors.append(f"{self.name}: {error}")
        logger.error(f"{self.name}: {error}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of collection results."""
        return {
            'collector': self.name,
            'results_count': len(self.results),
            'errors_count': len(self.errors),
            'errors': self.errors
        }


class CertificateTransparencyCollector(BaseCollector):
    """Collector for Certificate Transparency logs."""
    
    def __init__(self):
        super().__init__("certificate_transparency")
        self.ct_sources = [
            "https://crt.sh/?q={domain}&output=json",
            "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        ]
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Collect subdomains from Certificate Transparency logs."""
        domain = target.lower().strip()
        subdomains = set()
        
        async with aiohttp.ClientSession() as session:
            # Collect from crt.sh
            await self._collect_from_crtsh(session, domain, subdomains)
            
            # Collect from CertSpotter (if API key available)
            if get_api_key('certspotter'):
                await self._collect_from_certspotter(session, domain, subdomains)
        
        # Convert to results
        for subdomain in subdomains:
            self.add_result({
                'type': 'subdomain',
                'domain': subdomain,
                'parent_domain': domain,
                'source': 'certificate_transparency'
            })
        
        return self.results
    
    async def _collect_from_crtsh(self, session: aiohttp.ClientSession, domain: str, subdomains: Set[str]) -> None:
        """Collect from crt.sh."""
        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            async with session.get(url, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        for name in name_value.split('\n'):
                            name = name.strip().lower()
                            if name and self._is_valid_subdomain(name, domain):
                                subdomains.add(name)
        except Exception as e:
            self.add_error(f"crt.sh collection failed: {e}")
    
    async def _collect_from_certspotter(self, session: aiohttp.ClientSession, domain: str, subdomains: Set[str]) -> None:
        """Collect from CertSpotter."""
        try:
            api_key = get_api_key('certspotter')
            headers = {'Authorization': f'Bearer {api_key}'}
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            
            async with session.get(url, headers=headers, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data:
                        dns_names = entry.get('dns_names', [])
                        for name in dns_names:
                            name = name.lower()
                            if self._is_valid_subdomain(name, domain):
                                subdomains.add(name)
        except Exception as e:
            self.add_error(f"CertSpotter collection failed: {e}")
    
    def _is_valid_subdomain(self, name: str, domain: str) -> bool:
        """Check if a name is a valid subdomain."""
        if not name or '*' in name:
            return False
        
        # Remove leading dot
        name = name.lstrip('.')
        
        # Must end with the target domain
        if not name.endswith(domain):
            return False
        
        # Basic domain validation
        if not re.match(r'^[a-zA-Z0-9.-]+$', name):
            return False
        
        return True


class PassiveDNSCollector(BaseCollector):
    """Collector for passive DNS data."""
    
    def __init__(self):
        super().__init__("passive_dns")
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Collect passive DNS data."""
        domain = target.lower().strip()
        
        # Collect from multiple sources
        await self._collect_from_virustotal(domain)
        await self._collect_from_securitytrails(domain)
        
        return self.results
    
    async def _collect_from_virustotal(self, domain: str) -> None:
        """Collect from VirusTotal."""
        try:
            api_key = get_api_key('virustotal')
            if not api_key:
                return
            
            async with aiohttp.ClientSession() as session:
                headers = {'x-apikey': api_key}
                url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                params = {'apikey': api_key, 'domain': domain}
                
                async with session.get(url, headers=headers, params=params, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Extract subdomains
                        subdomains = data.get('subdomains', [])
                        for subdomain in subdomains:
                            self.add_result({
                                'type': 'subdomain',
                                'domain': subdomain,
                                'parent_domain': domain,
                                'source': 'virustotal_passive_dns'
                            })
                        
                        # Extract resolutions
                        resolutions = data.get('resolutions', [])
                        for resolution in resolutions:
                            self.add_result({
                                'type': 'dns_resolution',
                                'domain': domain,
                                'ip': resolution.get('ip_address'),
                                'last_resolved': resolution.get('last_resolved'),
                                'source': 'virustotal_passive_dns'
                            })
        
        except Exception as e:
            self.add_error(f"VirusTotal passive DNS failed: {e}")
    
    async def _collect_from_securitytrails(self, domain: str) -> None:
        """Collect from SecurityTrails."""
        try:
            api_key = get_api_key('securitytrails')
            if not api_key:
                return
            
            async with aiohttp.ClientSession() as session:
                headers = {'APIKEY': api_key}
                
                # Get subdomains
                url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
                async with session.get(url, headers=headers, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        subdomains = data.get('subdomains', [])
                        for subdomain in subdomains:
                            full_domain = f"{subdomain}.{domain}"
                            self.add_result({
                                'type': 'subdomain',
                                'domain': full_domain,
                                'parent_domain': domain,
                                'source': 'securitytrails'
                            })
        
        except Exception as e:
            self.add_error(f"SecurityTrails collection failed: {e}")


class ShodanCollector(BaseCollector):
    """Collector for Shodan data."""
    
    def __init__(self):
        super().__init__("shodan")
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Collect data from Shodan."""
        try:
            import shodan
            
            api_key = get_api_key('shodan')
            if not api_key:
                self.add_error("Shodan API key not configured")
                return self.results
            
            api = shodan.Shodan(api_key)
            
            # Search for the domain
            try:
                results = api.search(f'hostname:{target}')
                
                for result in results['matches']:
                    self.add_result({
                        'type': 'host',
                        'ip': result['ip_str'],
                        'port': result['port'],
                        'protocol': result.get('transport', 'tcp'),
                        'service': result.get('product', ''),
                        'version': result.get('version', ''),
                        'banner': result.get('data', ''),
                        'hostnames': result.get('hostnames', []),
                        'location': {
                            'country': result.get('location', {}).get('country_name'),
                            'city': result.get('location', {}).get('city'),
                            'latitude': result.get('location', {}).get('latitude'),
                            'longitude': result.get('location', {}).get('longitude')
                        },
                        'org': result.get('org', ''),
                        'isp': result.get('isp', ''),
                        'asn': result.get('asn', ''),
                        'source': 'shodan'
                    })
            
            except shodan.APIError as e:
                self.add_error(f"Shodan API error: {e}")
        
        except ImportError:
            self.add_error("Shodan library not installed")
        except Exception as e:
            self.add_error(f"Shodan collection failed: {e}")
        
        return self.results


class DNSCollector(BaseCollector):
    """Collector for DNS records."""
    
    def __init__(self):
        super().__init__("dns")
        self.record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Collect DNS records for the target."""
        domain = target.lower().strip()
        
        for record_type in self.record_types:
            await self._query_dns_record(domain, record_type)
        
        return self.results
    
    async def _query_dns_record(self, domain: str, record_type: str) -> None:
        """Query a specific DNS record type."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            resolver.lifetime = 10
            
            answers = resolver.resolve(domain, record_type)
            
            for answer in answers:
                self.add_result({
                    'type': 'dns_record',
                    'domain': domain,
                    'record_type': record_type,
                    'value': str(answer),
                    'ttl': answers.rrset.ttl,
                    'source': 'dns_query'
                })
        
        except dns.resolver.NXDOMAIN:
            # Domain doesn't exist - not an error for our purposes
            pass
        except dns.resolver.NoAnswer:
            # No records of this type - not an error
            pass
        except Exception as e:
            self.add_error(f"DNS query for {domain} {record_type} failed: {e}")


class WaybackCollector(BaseCollector):
    """Collector for Wayback Machine data."""
    
    def __init__(self):
        super().__init__("wayback")
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Collect URLs from Wayback Machine."""
        domain = target.lower().strip()
        
        try:
            async with aiohttp.ClientSession() as session:
                # Get URL list from Wayback Machine
                url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey"
                
                async with session.get(url, timeout=60) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Skip header row
                        for row in data[1:]:
                            if len(row) >= 3:
                                original_url = row[2]
                                timestamp = row[1]
                                
                                self.add_result({
                                    'type': 'wayback_url',
                                    'url': original_url,
                                    'timestamp': timestamp,
                                    'domain': domain,
                                    'source': 'wayback_machine'
                                })
        
        except Exception as e:
            self.add_error(f"Wayback Machine collection failed: {e}")
        
        return self.results


class GitHubCollector(BaseCollector):
    """Collector for GitHub reconnaissance."""
    
    def __init__(self):
        super().__init__("github")
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Collect data from GitHub."""
        domain = target.lower().strip()
        
        try:
            api_key = get_api_key('github')
            if not api_key:
                self.add_error("GitHub API key not configured")
                return self.results
            
            async with aiohttp.ClientSession() as session:
                headers = {'Authorization': f'token {api_key}'}
                
                # Search for domain mentions in code
                search_queries = [
                    f'"{domain}"',
                    f'"{domain.replace(".", "\\.")}"',  # Escaped for regex
                    f'api.{domain}',
                    f'*.{domain}'
                ]
                
                for query in search_queries:
                    await self._search_github_code(session, headers, query, domain)
        
        except Exception as e:
            self.add_error(f"GitHub collection failed: {e}")
        
        return self.results
    
    async def _search_github_code(self, session: aiohttp.ClientSession, headers: Dict[str, str], query: str, domain: str) -> None:
        """Search GitHub code for mentions of the domain."""
        try:
            url = "https://api.github.com/search/code"
            params = {'q': query, 'per_page': 30}
            
            async with session.get(url, headers=headers, params=params, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for item in data.get('items', []):
                        self.add_result({
                            'type': 'github_mention',
                            'domain': domain,
                            'repository': item['repository']['full_name'],
                            'file_path': item['path'],
                            'file_url': item['html_url'],
                            'repository_url': item['repository']['html_url'],
                            'query': query,
                            'source': 'github_search'
                        })
                
                elif response.status == 403:
                    # Rate limited
                    self.add_error("GitHub API rate limited")
                    break
        
        except Exception as e:
            self.add_error(f"GitHub code search failed for query '{query}': {e}")


class ReconOrchestrator:
    """Orchestrator for running multiple reconnaissance collectors."""
    
    def __init__(self):
        self.collectors = {
            'certificate_transparency': CertificateTransparencyCollector(),
            'passive_dns': PassiveDNSCollector(),
            'shodan': ShodanCollector(),
            'dns': DNSCollector(),
            'wayback': WaybackCollector(),
            'github': GitHubCollector()
        }
    
    async def run_recon(self, target: str, collectors: Optional[List[str]] = None, **kwargs) -> Dict[str, Any]:
        """Run reconnaissance using specified collectors."""
        if collectors is None:
            collectors = list(self.collectors.keys())
        
        results = {}
        errors = []
        
        # Run collectors concurrently
        tasks = []
        for collector_name in collectors:
            if collector_name in self.collectors:
                collector = self.collectors[collector_name]
                task = asyncio.create_task(collector.collect(target, **kwargs))
                tasks.append((collector_name, task))
        
        # Wait for all collectors to complete
        for collector_name, task in tasks:
            try:
                collector_results = await task
                collector = self.collectors[collector_name]
                
                results[collector_name] = {
                    'results': collector_results,
                    'summary': collector.summary()
                }
                
                if collector.errors:
                    errors.extend(collector.errors)
            
            except Exception as e:
                error_msg = f"{collector_name} failed: {e}"
                errors.append(error_msg)
                logger.error(error_msg)
        
        return {
            'target': target,
            'collectors_run': collectors,
            'results': results,
            'errors': errors,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def get_available_collectors(self) -> List[str]:
        """Get list of available collectors."""
        return list(self.collectors.keys())


# Global orchestrator instance
recon_orchestrator = ReconOrchestrator()
