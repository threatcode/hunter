"""
Advanced reconnaissance collectors for Phase B implementation.

This module implements enhanced collectors for ASN analysis, corporate acquisitions,
advanced certificate analysis, and other sophisticated reconnaissance techniques.
"""

import asyncio
import logging
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
import aiohttp
import ipaddress
from urllib.parse import urlparse

from recon.collectors import BaseCollector
from automation.api_manager import make_api_request, get_api_key


logger = logging.getLogger(__name__)


class ASNCollector(BaseCollector):
    """Collector for ASN analysis and netblock discovery."""
    
    def __init__(self):
        super().__init__("asn_analysis")
        self.asn_sources = [
            "https://api.bgpview.io/asn/{asn}",
            "https://api.bgpview.io/ip/{ip}",
            "https://api.bgpview.io/search?query_term={query}"
        ]
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Collect ASN information and related netblocks."""
        
        # Determine if target is IP, domain, or organization
        if self._is_ip_address(target):
            await self._collect_asn_for_ip(target)
        elif self._is_domain(target):
            await self._collect_asn_for_domain(target)
        else:
            await self._collect_asn_for_organization(target)
        
        return self.results
    
    async def _collect_asn_for_ip(self, ip: str):
        """Collect ASN information for an IP address."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.bgpview.io/ip/{ip}"
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('status') == 'ok':
                            ip_data = data.get('data', {})
                            
                            # Extract ASN information
                            for rib in ip_data.get('rib_entries', []):
                                asn = rib.get('asn', {}).get('asn')
                                if asn:
                                    await self._collect_asn_details(asn)
                            
                            # Store IP geolocation data
                            self.add_result({
                                'type': 'ip_geolocation',
                                'ip': ip,
                                'country': ip_data.get('ptr_record', ''),
                                'rir': ip_data.get('rir_allocation', {}).get('rir_name', ''),
                                'allocation_date': ip_data.get('rir_allocation', {}).get('date_allocated', ''),
                                'source': 'bgpview'
                            })
        
        except Exception as e:
            self.add_error(f"Failed to collect ASN for IP {ip}: {e}")
    
    async def _collect_asn_for_domain(self, domain: str):
        """Collect ASN information for a domain."""
        try:
            # First resolve domain to IP
            import dns.resolver
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            
            try:
                answers = resolver.resolve(domain, 'A')
                for answer in answers:
                    ip = str(answer)
                    await self._collect_asn_for_ip(ip)
            except Exception as e:
                self.add_error(f"Failed to resolve domain {domain}: {e}")
        
        except Exception as e:
            self.add_error(f"Failed to collect ASN for domain {domain}: {e}")
    
    async def _collect_asn_for_organization(self, org_name: str):
        """Search for ASNs by organization name."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.bgpview.io/search?query_term={org_name}"
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('status') == 'ok':
                            search_data = data.get('data', {})
                            
                            # Process ASN results
                            for asn_result in search_data.get('asns', []):
                                asn = asn_result.get('asn')
                                if asn:
                                    await self._collect_asn_details(asn)
        
        except Exception as e:
            self.add_error(f"Failed to search ASNs for organization {org_name}: {e}")
    
    async def _collect_asn_details(self, asn: int):
        """Collect detailed information about an ASN."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.bgpview.io/asn/{asn}"
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('status') == 'ok':
                            asn_data = data.get('data', {})
                            
                            # Store ASN information
                            self.add_result({
                                'type': 'asn',
                                'asn': asn,
                                'name': asn_data.get('name', ''),
                                'description': asn_data.get('description_short', ''),
                                'country': asn_data.get('country_code', ''),
                                'rir': asn_data.get('rir_allocation', {}).get('rir_name', ''),
                                'allocation_date': asn_data.get('rir_allocation', {}).get('date_allocated', ''),
                                'website': asn_data.get('website', ''),
                                'email_contacts': asn_data.get('email_contacts', []),
                                'abuse_contacts': asn_data.get('abuse_contacts', []),
                                'source': 'bgpview'
                            })
                            
                            # Collect prefixes/netblocks
                            await self._collect_asn_prefixes(asn)
        
        except Exception as e:
            self.add_error(f"Failed to collect ASN details for {asn}: {e}")
    
    async def _collect_asn_prefixes(self, asn: int):
        """Collect IP prefixes/netblocks for an ASN."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.bgpview.io/asn/{asn}/prefixes"
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('status') == 'ok':
                            prefixes_data = data.get('data', {})
                            
                            # Process IPv4 prefixes
                            for prefix in prefixes_data.get('ipv4_prefixes', []):
                                self.add_result({
                                    'type': 'netblock',
                                    'asn': asn,
                                    'prefix': prefix.get('prefix', ''),
                                    'ip_version': 4,
                                    'name': prefix.get('name', ''),
                                    'description': prefix.get('description', ''),
                                    'country': prefix.get('country_code', ''),
                                    'source': 'bgpview'
                                })
                            
                            # Process IPv6 prefixes
                            for prefix in prefixes_data.get('ipv6_prefixes', []):
                                self.add_result({
                                    'type': 'netblock',
                                    'asn': asn,
                                    'prefix': prefix.get('prefix', ''),
                                    'ip_version': 6,
                                    'name': prefix.get('name', ''),
                                    'description': prefix.get('description', ''),
                                    'country': prefix.get('country_code', ''),
                                    'source': 'bgpview'
                                })
        
        except Exception as e:
            self.add_error(f"Failed to collect prefixes for ASN {asn}: {e}")
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address."""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def _is_domain(self, target: str) -> bool:
        """Check if target is a domain name."""
        return '.' in target and not self._is_ip_address(target)


class CorporateAcquisitionsCollector(BaseCollector):
    """Collector for corporate acquisitions and subsidiary information."""
    
    def __init__(self):
        super().__init__("corporate_acquisitions")
        self.crunchbase_base_url = "https://api.crunchbase.com/api/v4"
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Collect corporate acquisition and subsidiary data."""
        
        # Collect from multiple sources
        await self._collect_from_crunchbase(target)
        await self._collect_from_opencorporates(target)
        await self._collect_from_wikipedia(target)
        
        return self.results
    
    async def _collect_from_crunchbase(self, company_name: str):
        """Collect data from Crunchbase API."""
        try:
            api_key = get_api_key('crunchbase')
            if not api_key:
                self.add_error("Crunchbase API key not configured")
                return
            
            async with aiohttp.ClientSession() as session:
                headers = {'X-cb-user-key': api_key}
                
                # Search for organization
                search_url = f"{self.crunchbase_base_url}/searches/organizations"
                search_params = {
                    'query': company_name,
                    'limit': 10
                }
                
                async with session.get(search_url, headers=headers, params=search_params, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for entity in data.get('entities', []):
                            org_id = entity.get('uuid')
                            if org_id:
                                await self._get_crunchbase_organization_details(session, headers, org_id)
        
        except Exception as e:
            self.add_error(f"Crunchbase collection failed: {e}")
    
    async def _get_crunchbase_organization_details(self, session: aiohttp.ClientSession, headers: Dict[str, str], org_id: str):
        """Get detailed organization information from Crunchbase."""
        try:
            url = f"{self.crunchbase_base_url}/entities/organizations/{org_id}"
            params = {
                'field_ids': [
                    'name', 'legal_name', 'website', 'description',
                    'founded_on', 'categories', 'headquarters_regions',
                    'acquisitions', 'acquired_by', 'subsidiaries'
                ]
            }
            
            async with session.get(url, headers=headers, params=params, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    properties = data.get('properties', {})
                    
                    # Store organization information
                    self.add_result({
                        'type': 'organization',
                        'name': properties.get('name', ''),
                        'legal_name': properties.get('legal_name', ''),
                        'website': properties.get('website', ''),
                        'description': properties.get('description', ''),
                        'founded_date': properties.get('founded_on', ''),
                        'categories': [cat.get('value') for cat in properties.get('categories', [])],
                        'headquarters': [hq.get('value') for hq in properties.get('headquarters_regions', [])],
                        'source': 'crunchbase'
                    })
                    
                    # Process acquisitions
                    for acquisition in properties.get('acquisitions', []):
                        self.add_result({
                            'type': 'acquisition',
                            'acquirer': properties.get('name', ''),
                            'acquired': acquisition.get('acquired_organization', {}).get('name', ''),
                            'acquisition_date': acquisition.get('announced_on', ''),
                            'price': acquisition.get('price', ''),
                            'source': 'crunchbase'
                        })
                    
                    # Process if acquired by someone
                    acquired_by = properties.get('acquired_by')
                    if acquired_by:
                        self.add_result({
                            'type': 'acquisition',
                            'acquirer': acquired_by.get('acquirer_organization', {}).get('name', ''),
                            'acquired': properties.get('name', ''),
                            'acquisition_date': acquired_by.get('announced_on', ''),
                            'price': acquired_by.get('price', ''),
                            'source': 'crunchbase'
                        })
        
        except Exception as e:
            self.add_error(f"Failed to get Crunchbase organization details: {e}")
    
    async def _collect_from_opencorporates(self, company_name: str):
        """Collect data from OpenCorporates."""
        try:
            async with aiohttp.ClientSession() as session:
                url = "https://api.opencorporates.com/v0.4/companies/search"
                params = {
                    'q': company_name,
                    'format': 'json',
                    'limit': 10
                }
                
                async with session.get(url, params=params, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for company in data.get('results', {}).get('companies', []):
                            company_data = company.get('company', {})
                            
                            self.add_result({
                                'type': 'corporate_entity',
                                'name': company_data.get('name', ''),
                                'company_number': company_data.get('company_number', ''),
                                'jurisdiction': company_data.get('jurisdiction_code', ''),
                                'incorporation_date': company_data.get('incorporation_date', ''),
                                'company_type': company_data.get('company_type', ''),
                                'status': company_data.get('current_status', ''),
                                'registered_address': company_data.get('registered_address_in_full', ''),
                                'source': 'opencorporates'
                            })
        
        except Exception as e:
            self.add_error(f"OpenCorporates collection failed: {e}")
    
    async def _collect_from_wikipedia(self, company_name: str):
        """Collect acquisition information from Wikipedia."""
        try:
            async with aiohttp.ClientSession() as session:
                # Search Wikipedia for the company
                search_url = "https://en.wikipedia.org/api/rest_v1/page/summary/" + company_name.replace(' ', '_')
                
                async with session.get(search_url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        extract = data.get('extract', '')
                        if extract:
                            # Look for acquisition-related keywords
                            acquisition_patterns = [
                                r'acquired by ([^.]+)',
                                r'purchased by ([^.]+)',
                                r'bought by ([^.]+)',
                                r'merged with ([^.]+)',
                                r'subsidiary of ([^.]+)'
                            ]
                            
                            for pattern in acquisition_patterns:
                                matches = re.findall(pattern, extract, re.IGNORECASE)
                                for match in matches:
                                    self.add_result({
                                        'type': 'acquisition_mention',
                                        'acquired': company_name,
                                        'acquirer': match.strip(),
                                        'source': 'wikipedia',
                                        'context': extract[:200] + '...'
                                    })
        
        except Exception as e:
            self.add_error(f"Wikipedia collection failed: {e}")


class AdvancedCertificateCollector(BaseCollector):
    """Advanced certificate analysis with deeper inspection."""
    
    def __init__(self):
        super().__init__("advanced_certificate")
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Perform advanced certificate analysis."""
        
        # Collect from multiple certificate sources
        await self._collect_from_crtsh_advanced(target)
        await self._collect_from_censys_certificates(target)
        await self._analyze_certificate_patterns(target)
        
        return self.results
    
    async def _collect_from_crtsh_advanced(self, domain: str):
        """Advanced certificate transparency collection with detailed analysis."""
        try:
            async with aiohttp.ClientSession() as session:
                # Get certificates with additional details
                url = f"https://crt.sh/?q={domain}&output=json&exclude=expired"
                
                async with session.get(url, timeout=60) as response:
                    if response.status == 200:
                        certificates = await response.json()
                        
                        # Group certificates by issuer and analyze patterns
                        issuer_stats = {}
                        validity_periods = []
                        
                        for cert in certificates:
                            # Extract detailed certificate information
                            issuer = cert.get('issuer_name', 'Unknown')
                            not_before = cert.get('not_before', '')
                            not_after = cert.get('not_after', '')
                            
                            # Track issuer statistics
                            if issuer not in issuer_stats:
                                issuer_stats[issuer] = 0
                            issuer_stats[issuer] += 1
                            
                            # Analyze validity periods
                            if not_before and not_after:
                                try:
                                    before_date = datetime.fromisoformat(not_before.replace('Z', '+00:00'))
                                    after_date = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
                                    validity_days = (after_date - before_date).days
                                    validity_periods.append(validity_days)
                                except:
                                    pass
                            
                            # Store detailed certificate info
                            self.add_result({
                                'type': 'certificate_detailed',
                                'domain': domain,
                                'subject_name': cert.get('name_value', ''),
                                'issuer': issuer,
                                'serial_number': cert.get('serial_number', ''),
                                'not_before': not_before,
                                'not_after': not_after,
                                'ca_id': cert.get('issuer_ca_id', ''),
                                'entry_timestamp': cert.get('entry_timestamp', ''),
                                'source': 'crt.sh_advanced'
                            })
                        
                        # Store issuer analysis
                        for issuer, count in issuer_stats.items():
                            self.add_result({
                                'type': 'certificate_issuer_analysis',
                                'domain': domain,
                                'issuer': issuer,
                                'certificate_count': count,
                                'source': 'crt.sh_analysis'
                            })
                        
                        # Store validity period analysis
                        if validity_periods:
                            avg_validity = sum(validity_periods) / len(validity_periods)
                            self.add_result({
                                'type': 'certificate_validity_analysis',
                                'domain': domain,
                                'average_validity_days': avg_validity,
                                'min_validity_days': min(validity_periods),
                                'max_validity_days': max(validity_periods),
                                'total_certificates': len(validity_periods),
                                'source': 'crt.sh_analysis'
                            })
        
        except Exception as e:
            self.add_error(f"Advanced crt.sh collection failed: {e}")
    
    async def _collect_from_censys_certificates(self, domain: str):
        """Collect certificate data from Censys."""
        try:
            api_key = get_api_key('censys')
            if not api_key:
                return
            
            async with aiohttp.ClientSession() as session:
                headers = {'Authorization': f'Bearer {api_key}'}
                url = "https://search.censys.io/api/v2/certificates/search"
                
                query = f"names: {domain}"
                params = {
                    'q': query,
                    'per_page': 100
                }
                
                async with session.get(url, headers=headers, params=params, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for cert in data.get('result', {}).get('hits', []):
                            self.add_result({
                                'type': 'certificate_censys',
                                'domain': domain,
                                'fingerprint_sha256': cert.get('fingerprint_sha256', ''),
                                'names': cert.get('names', []),
                                'issuer': cert.get('issuer', {}).get('common_name', ''),
                                'subject': cert.get('subject', {}).get('common_name', ''),
                                'validity_start': cert.get('validity', {}).get('start', ''),
                                'validity_end': cert.get('validity', {}).get('end', ''),
                                'key_algorithm': cert.get('subject_key_info', {}).get('key_algorithm', ''),
                                'key_size': cert.get('subject_key_info', {}).get('rsa_public_key', {}).get('length', ''),
                                'source': 'censys'
                            })
        
        except Exception as e:
            self.add_error(f"Censys certificate collection failed: {e}")
    
    async def _analyze_certificate_patterns(self, domain: str):
        """Analyze certificate patterns for security insights."""
        try:
            # Analyze existing certificate results for patterns
            cert_results = [r for r in self.results if r.get('type', '').startswith('certificate')]
            
            if not cert_results:
                return
            
            # Pattern analysis
            wildcard_certs = []
            short_validity_certs = []
            unusual_issuers = []
            
            common_issuers = {
                "Let's Encrypt", "DigiCert", "Comodo", "GeoTrust", 
                "Symantec", "GlobalSign", "Entrust", "Sectigo"
            }
            
            for cert in cert_results:
                subject_name = cert.get('subject_name', '')
                issuer = cert.get('issuer', '')
                
                # Check for wildcard certificates
                if '*.' in subject_name:
                    wildcard_certs.append(cert)
                
                # Check for unusual issuers
                if issuer and not any(common in issuer for common in common_issuers):
                    unusual_issuers.append(cert)
                
                # Check for short validity periods
                validity_days = cert.get('validity_days')
                if validity_days and validity_days < 90:
                    short_validity_certs.append(cert)
            
            # Store pattern analysis results
            if wildcard_certs:
                self.add_result({
                    'type': 'certificate_pattern_wildcard',
                    'domain': domain,
                    'wildcard_count': len(wildcard_certs),
                    'wildcard_subjects': [c.get('subject_name', '') for c in wildcard_certs],
                    'source': 'pattern_analysis'
                })
            
            if unusual_issuers:
                self.add_result({
                    'type': 'certificate_pattern_unusual_issuer',
                    'domain': domain,
                    'unusual_issuer_count': len(unusual_issuers),
                    'unusual_issuers': list(set(c.get('issuer', '') for c in unusual_issuers)),
                    'source': 'pattern_analysis'
                })
            
            if short_validity_certs:
                self.add_result({
                    'type': 'certificate_pattern_short_validity',
                    'domain': domain,
                    'short_validity_count': len(short_validity_certs),
                    'average_validity': sum(c.get('validity_days', 0) for c in short_validity_certs) / len(short_validity_certs),
                    'source': 'pattern_analysis'
                })
        
        except Exception as e:
            self.add_error(f"Certificate pattern analysis failed: {e}")


class EnhancedReconOrchestrator:
    """Enhanced orchestrator for Phase B reconnaissance."""
    
    def __init__(self):
        self.collectors = {
            'asn_analysis': ASNCollector(),
            'corporate_acquisitions': CorporateAcquisitionsCollector(),
            'advanced_certificate': AdvancedCertificateCollector()
        }
    
    async def run_enhanced_recon(self, target: str, collectors: Optional[List[str]] = None, **kwargs) -> Dict[str, Any]:
        """Run enhanced reconnaissance using Phase B collectors."""
        
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
                    'summary': collector.get_summary()
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
            'timestamp': datetime.utcnow().isoformat(),
            'phase': 'B'
        }
    
    def get_available_collectors(self) -> List[str]:
        """Get list of available Phase B collectors."""
        return list(self.collectors.keys())


# Global enhanced orchestrator instance
enhanced_recon_orchestrator = EnhancedReconOrchestrator()
