"""
Advanced subdomain discovery with wildcard detection and enhanced enumeration.

This module implements sophisticated subdomain discovery techniques including
wildcard detection, permutation generation, and multi-source aggregation.
"""

import asyncio
import logging
import random
import string
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Set, Any, Tuple
import aiohttp
import dns.resolver
import dns.exception
from urllib.parse import urlparse

from recon.collectors import BaseCollector
from automation.api_manager import make_api_request, get_api_key


logger = logging.getLogger(__name__)


class WildcardDetector:
    """Detects and handles DNS wildcard configurations."""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    async def detect_wildcard(self, domain: str) -> Dict[str, Any]:
        """Detect if domain has wildcard DNS configuration."""
        
        wildcard_info = {
            'has_wildcard': False,
            'wildcard_ips': [],
            'test_subdomains': [],
            'confidence': 0.0
        }
        
        try:
            # Generate random subdomains for testing
            test_subdomains = []
            for _ in range(5):
                random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
                test_subdomains.append(f"{random_sub}.{domain}")
            
            wildcard_info['test_subdomains'] = test_subdomains
            
            # Test each random subdomain
            resolved_ips = []
            for test_domain in test_subdomains:
                try:
                    answers = self.resolver.resolve(test_domain, 'A')
                    ips = [str(answer) for answer in answers]
                    resolved_ips.extend(ips)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                    # Expected for non-wildcard domains
                    pass
                except Exception as e:
                    logger.debug(f"DNS resolution error for {test_domain}: {e}")
            
            # Analyze results
            if resolved_ips:
                # Check if all random subdomains resolve to same IPs
                unique_ips = list(set(resolved_ips))
                
                if len(unique_ips) <= 3:  # Likely wildcard if few unique IPs
                    wildcard_info['has_wildcard'] = True
                    wildcard_info['wildcard_ips'] = unique_ips
                    wildcard_info['confidence'] = min(len(resolved_ips) / len(test_subdomains), 1.0)
        
        except Exception as e:
            logger.error(f"Wildcard detection failed for {domain}: {e}")
        
        return wildcard_info
    
    def is_wildcard_response(self, domain: str, resolved_ips: List[str], wildcard_info: Dict[str, Any]) -> bool:
        """Check if resolved IPs match wildcard pattern."""
        
        if not wildcard_info.get('has_wildcard'):
            return False
        
        wildcard_ips = set(wildcard_info.get('wildcard_ips', []))
        resolved_ip_set = set(resolved_ips)
        
        # Check if resolved IPs overlap significantly with wildcard IPs
        overlap = len(wildcard_ips.intersection(resolved_ip_set))
        return overlap > 0


class SubdomainPermutationEngine:
    """Generates subdomain permutations and variations."""
    
    def __init__(self):
        self.common_prefixes = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'app', 'web', 'secure', 'vpn', 'remote', 'portal', 'blog',
            'shop', 'store', 'support', 'help', 'docs', 'wiki', 'forum',
            'chat', 'video', 'img', 'images', 'static', 'cdn', 'assets',
            'media', 'upload', 'download', 'files', 'data', 'backup',
            'archive', 'old', 'new', 'beta', 'alpha', 'demo', 'sandbox'
        ]
        
        self.common_suffixes = [
            'prod', 'production', 'live', 'www', 'web', 'app', 'api',
            'admin', 'panel', 'dashboard', 'portal', 'gateway', 'proxy',
            'lb', 'balancer', 'cluster', 'node', 'server', 'host',
            'db', 'database', 'cache', 'redis', 'mongo', 'sql',
            'test', 'testing', 'qa', 'stage', 'staging', 'dev', 'development'
        ]
        
        self.number_patterns = [str(i) for i in range(1, 21)] + ['01', '02', '03', '04', '05']
        
        self.environment_keywords = [
            'prod', 'production', 'live', 'stage', 'staging', 'test', 'testing',
            'dev', 'development', 'qa', 'uat', 'demo', 'sandbox', 'beta', 'alpha'
        ]
    
    def generate_permutations(self, domain: str, max_permutations: int = 1000) -> List[str]:
        """Generate subdomain permutations for the given domain."""
        
        permutations = set()
        base_domain = domain
        
        # Extract existing subdomains if any
        parts = domain.split('.')
        if len(parts) > 2:
            # Already a subdomain, extract base domain
            base_domain = '.'.join(parts[-2:])
            existing_sub = '.'.join(parts[:-2])
        else:
            existing_sub = ''
        
        # 1. Common prefix permutations
        for prefix in self.common_prefixes:
            permutations.add(f"{prefix}.{base_domain}")
            
            # Combine with existing subdomain
            if existing_sub:
                permutations.add(f"{prefix}.{existing_sub}.{base_domain}")
                permutations.add(f"{existing_sub}-{prefix}.{base_domain}")
                permutations.add(f"{prefix}-{existing_sub}.{base_domain}")
        
        # 2. Common suffix permutations
        for suffix in self.common_suffixes:
            permutations.add(f"{suffix}.{base_domain}")
            
            if existing_sub:
                permutations.add(f"{existing_sub}-{suffix}.{base_domain}")
                permutations.add(f"{suffix}-{existing_sub}.{base_domain}")
        
        # 3. Number-based permutations
        for num in self.number_patterns:
            permutations.add(f"{num}.{base_domain}")
            
            if existing_sub:
                permutations.add(f"{existing_sub}{num}.{base_domain}")
                permutations.add(f"{existing_sub}-{num}.{base_domain}")
        
        # 4. Environment-based permutations
        for env in self.environment_keywords:
            permutations.add(f"{env}.{base_domain}")
            
            # Combine with common services
            for service in ['api', 'app', 'web', 'admin']:
                permutations.add(f"{env}-{service}.{base_domain}")
                permutations.add(f"{service}-{env}.{base_domain}")
        
        # 5. Hyphenated variations
        if existing_sub and '-' not in existing_sub:
            # Try replacing common separators
            for sep in ['_', '.']:
                if sep in existing_sub:
                    hyphenated = existing_sub.replace(sep, '-')
                    permutations.add(f"{hyphenated}.{base_domain}")
        
        # 6. Common typos and variations
        if existing_sub:
            # Double letters
            for i, char in enumerate(existing_sub):
                if char.isalpha():
                    typo = existing_sub[:i] + char + char + existing_sub[i+1:]
                    permutations.add(f"{typo}.{base_domain}")
        
        # Remove the original domain and limit results
        permutations.discard(domain)
        return list(permutations)[:max_permutations]


class AdvancedSubdomainCollector(BaseCollector):
    """Advanced subdomain discovery with multiple sources and techniques."""
    
    def __init__(self):
        super().__init__("advanced_subdomain")
        self.wildcard_detector = WildcardDetector()
        self.permutation_engine = SubdomainPermutationEngine()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Perform advanced subdomain discovery."""
        
        # 1. Detect wildcard configuration
        wildcard_info = await self.wildcard_detector.detect_wildcard(target)
        
        self.add_result({
            'type': 'wildcard_detection',
            'domain': target,
            'has_wildcard': wildcard_info['has_wildcard'],
            'wildcard_ips': wildcard_info['wildcard_ips'],
            'confidence': wildcard_info['confidence'],
            'test_subdomains': wildcard_info['test_subdomains']
        })
        
        # 2. Collect from multiple sources
        discovered_subdomains = set()
        
        # Passive sources
        passive_subs = await self._collect_passive_subdomains(target)
        discovered_subdomains.update(passive_subs)
        
        # Certificate transparency (enhanced)
        ct_subs = await self._collect_certificate_subdomains(target)
        discovered_subdomains.update(ct_subs)
        
        # Search engines
        search_subs = await self._collect_search_engine_subdomains(target)
        discovered_subdomains.update(search_subs)
        
        # 3. Generate and test permutations
        if kwargs.get('enable_bruteforce', True):
            permutation_subs = await self._bruteforce_subdomains(target, wildcard_info)
            discovered_subdomains.update(permutation_subs)
        
        # 4. Validate and filter results
        validated_subdomains = await self._validate_subdomains(
            list(discovered_subdomains), target, wildcard_info
        )
        
        # 5. Analyze subdomain patterns
        await self._analyze_subdomain_patterns(target, validated_subdomains)
        
        return self.results
    
    async def _collect_passive_subdomains(self, domain: str) -> Set[str]:
        """Collect subdomains from passive sources."""
        
        subdomains = set()
        
        # SecurityTrails
        try:
            api_key = get_api_key('securitytrails')
            if api_key:
                async with aiohttp.ClientSession() as session:
                    headers = {'APIKEY': api_key}
                    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
                    
                    async with session.get(url, headers=headers, timeout=30) as response:
                        if response.status == 200:
                            data = await response.json()
                            for sub in data.get('subdomains', []):
                                subdomains.add(f"{sub}.{domain}")
        except Exception as e:
            self.add_error(f"SecurityTrails collection failed: {e}")
        
        # VirusTotal
        try:
            api_key = get_api_key('virustotal')
            if api_key:
                async with aiohttp.ClientSession() as session:
                    headers = {'x-apikey': api_key}
                    url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                    params = {'apikey': api_key, 'domain': domain}
                    
                    async with session.get(url, headers=headers, params=params, timeout=30) as response:
                        if response.status == 200:
                            data = await response.json()
                            for sub in data.get('subdomains', []):
                                subdomains.add(sub)
        except Exception as e:
            self.add_error(f"VirusTotal collection failed: {e}")
        
        return subdomains
    
    async def _collect_certificate_subdomains(self, domain: str) -> Set[str]:
        """Enhanced certificate transparency collection."""
        
        subdomains = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                # Multiple CT log sources
                ct_sources = [
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    f"https://crt.sh/?q={domain}&output=json"
                ]
                
                for url in ct_sources:
                    try:
                        async with session.get(url, timeout=60) as response:
                            if response.status == 200:
                                certificates = await response.json()
                                
                                for cert in certificates:
                                    name_value = cert.get('name_value', '')
                                    for name in name_value.split('\n'):
                                        name = name.strip().lower()
                                        
                                        # Clean and validate subdomain
                                        if name and self._is_valid_subdomain(name, domain):
                                            # Remove wildcard prefix
                                            if name.startswith('*.'):
                                                name = name[2:]
                                            
                                            if name != domain:
                                                subdomains.add(name)
                    except Exception as e:
                        logger.debug(f"CT source {url} failed: {e}")
        
        except Exception as e:
            self.add_error(f"Certificate transparency collection failed: {e}")
        
        return subdomains
    
    async def _collect_search_engine_subdomains(self, domain: str) -> Set[str]:
        """Collect subdomains from search engines."""
        
        subdomains = set()
        
        try:
            # Google search
            async with aiohttp.ClientSession() as session:
                search_queries = [
                    f"site:*.{domain}",
                    f"site:{domain} -www",
                    f"inurl:{domain}"
                ]
                
                for query in search_queries:
                    try:
                        # Use a search API or scrape carefully
                        # Note: This is a simplified example
                        url = f"https://www.google.com/search?q={query}&num=100"
                        headers = {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        }
                        
                        async with session.get(url, headers=headers, timeout=30) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Extract domains from search results
                                import re
                                pattern = r'https?://([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')'
                                matches = re.findall(pattern, content)
                                
                                for match in matches:
                                    if self._is_valid_subdomain(match, domain):
                                        subdomains.add(match)
                        
                        # Rate limiting
                        await asyncio.sleep(2)
                    
                    except Exception as e:
                        logger.debug(f"Search query {query} failed: {e}")
        
        except Exception as e:
            self.add_error(f"Search engine collection failed: {e}")
        
        return subdomains
    
    async def _bruteforce_subdomains(self, domain: str, wildcard_info: Dict[str, Any]) -> Set[str]:
        """Bruteforce subdomains using permutations."""
        
        discovered = set()
        
        # Generate permutations
        permutations = self.permutation_engine.generate_permutations(domain, max_permutations=500)
        
        # Test permutations in batches
        batch_size = 50
        for i in range(0, len(permutations), batch_size):
            batch = permutations[i:i + batch_size]
            
            # Test batch concurrently
            tasks = []
            for subdomain in batch:
                task = asyncio.create_task(self._test_subdomain_resolution(subdomain, wildcard_info))
                tasks.append((subdomain, task))
            
            # Wait for batch results
            for subdomain, task in tasks:
                try:
                    is_valid = await task
                    if is_valid:
                        discovered.add(subdomain)
                except Exception as e:
                    logger.debug(f"Subdomain test failed for {subdomain}: {e}")
            
            # Rate limiting
            await asyncio.sleep(0.5)
        
        return discovered
    
    async def _test_subdomain_resolution(self, subdomain: str, wildcard_info: Dict[str, Any]) -> bool:
        """Test if a subdomain resolves to a valid (non-wildcard) IP."""
        
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            resolved_ips = [str(answer) for answer in answers]
            
            # Check if this is a wildcard response
            if self.wildcard_detector.is_wildcard_response(subdomain, resolved_ips, wildcard_info):
                return False
            
            return True
        
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return False
        except Exception as e:
            logger.debug(f"DNS resolution error for {subdomain}: {e}")
            return False
    
    async def _validate_subdomains(self, subdomains: List[str], domain: str, wildcard_info: Dict[str, Any]) -> List[str]:
        """Validate discovered subdomains."""
        
        validated = []
        
        for subdomain in subdomains:
            try:
                # Test DNS resolution
                answers = self.resolver.resolve(subdomain, 'A')
                resolved_ips = [str(answer) for answer in answers]
                
                # Check if wildcard response
                is_wildcard = self.wildcard_detector.is_wildcard_response(
                    subdomain, resolved_ips, wildcard_info
                )
                
                # Store subdomain result
                self.add_result({
                    'type': 'subdomain_validated',
                    'subdomain': subdomain,
                    'parent_domain': domain,
                    'resolved_ips': resolved_ips,
                    'is_wildcard_response': is_wildcard,
                    'resolution_time': datetime.utcnow().isoformat()
                })
                
                if not is_wildcard:
                    validated.append(subdomain)
            
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                # Subdomain doesn't resolve
                pass
            except Exception as e:
                logger.debug(f"Validation failed for {subdomain}: {e}")
        
        return validated
    
    async def _analyze_subdomain_patterns(self, domain: str, subdomains: List[str]):
        """Analyze patterns in discovered subdomains."""
        
        try:
            # Pattern analysis
            patterns = {
                'environment_subdomains': [],
                'numeric_subdomains': [],
                'service_subdomains': [],
                'geographic_subdomains': [],
                'hyphenated_subdomains': []
            }
            
            for subdomain in subdomains:
                # Extract subdomain part
                sub_part = subdomain.replace(f".{domain}", "")
                
                # Analyze patterns
                if any(env in sub_part.lower() for env in ['dev', 'test', 'stage', 'prod', 'qa']):
                    patterns['environment_subdomains'].append(subdomain)
                
                if any(char.isdigit() for char in sub_part):
                    patterns['numeric_subdomains'].append(subdomain)
                
                if any(service in sub_part.lower() for service in ['api', 'mail', 'ftp', 'admin', 'app']):
                    patterns['service_subdomains'].append(subdomain)
                
                if '-' in sub_part:
                    patterns['hyphenated_subdomains'].append(subdomain)
            
            # Store pattern analysis
            for pattern_type, pattern_subdomains in patterns.items():
                if pattern_subdomains:
                    self.add_result({
                        'type': 'subdomain_pattern_analysis',
                        'domain': domain,
                        'pattern_type': pattern_type,
                        'count': len(pattern_subdomains),
                        'subdomains': pattern_subdomains[:10],  # Limit to first 10
                        'total_subdomains': len(subdomains)
                    })
        
        except Exception as e:
            self.add_error(f"Pattern analysis failed: {e}")
    
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
        
        # Must be longer than base domain
        if len(name) <= len(domain):
            return False
        
        return True


# Integration with existing recon orchestrator
def add_advanced_subdomain_collector():
    """Add advanced subdomain collector to existing orchestrator."""
    from recon.collectors import recon_orchestrator
    
    recon_orchestrator.collectors['advanced_subdomain'] = AdvancedSubdomainCollector()
    
    return recon_orchestrator


# Standalone usage
if __name__ == "__main__":
    async def test_subdomain_discovery():
        collector = AdvancedSubdomainCollector()
        results = await collector.collect("example.com", enable_bruteforce=True)
        
        print(f"Discovered {len(results)} subdomain-related results")
        for result in results[:10]:  # Show first 10
            print(f"- {result.get('type')}: {result}")
    
    asyncio.run(test_subdomain_discovery())
