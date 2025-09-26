"""
Celery tasks for reconnaissance operations.

This module defines distributed tasks for running reconnaissance
collectors and processing the results.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from celery import Task
from automation.orchestrator import celery_app
from automation.database import get_db_session, job_repository, finding_repository, asset_repository
from automation.logging_config import audit_logger, log_scan_activity
from data.schemas import ScanStatus, AssetType, SeverityLevel, VulnerabilityType, FindingStatus
from recon.collectors import recon_orchestrator
from recon.advanced_collectors import enhanced_recon_orchestrator
from recon.subdomain_discovery import AdvancedSubdomainCollector
from recon.port_scanning import AdvancedPortScanCollector


logger = logging.getLogger(__name__)


class BaseReconTask(Task):
    """Base class for reconnaissance tasks."""
    
    def on_success(self, retval, task_id, args, kwargs):
        """Called when task succeeds."""
        job_id = args[0] if args else None
        if job_id:
            self._update_job_status(job_id, ScanStatus.COMPLETED, retval)
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Called when task fails."""
        job_id = args[0] if args else None
        if job_id:
            self._update_job_status(job_id, ScanStatus.FAILED, None, str(exc))
    
    def on_retry(self, exc, task_id, args, kwargs, einfo):
        """Called when task is retried."""
        job_id = args[0] if args else None
        if job_id:
            log_scan_activity(job_id, "task_retried", error=str(exc))
    
    def _update_job_status(self, job_id: str, status: ScanStatus, results: Optional[Dict] = None, error: Optional[str] = None):
        """Update job status in database."""
        try:
            with get_db_session() as session:
                update_data = {'status': status}
                
                if results:
                    results_count = sum(len(r.get('results', [])) for r in results.get('results', {}).values())
                    update_data['results_count'] = results_count
                
                if error:
                    update_data['error_message'] = error
                
                job_repository.update(session, job_id, update_data)
                
                # Log completion
                if status == ScanStatus.COMPLETED:
                    audit_logger.log_scan_complete(
                        job_id=job_id,
                        results_count=update_data.get('results_count', 0),
                        findings_count=0,  # Will be updated when findings are processed
                        status=status.value
                    )
        
        except Exception as e:
            logger.error(f"Failed to update job status: {e}")


@celery_app.task(bind=True, base=BaseReconTask, name='recon.tasks.run_recon_scan')
def run_recon_scan(self, job_id: str, target: str, **kwargs):
    """Run a comprehensive reconnaissance scan."""
    
    # Update job status to running
    with get_db_session() as session:
        job_repository.update_status(session, job_id, ScanStatus.RUNNING)
    
    log_scan_activity(job_id, "recon_scan_started", target=target)
    
    try:
        # Run reconnaissance
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        results = loop.run_until_complete(
            recon_orchestrator.run_recon(target, **kwargs)
        )
        
        # Process and store results
        findings_count = process_recon_results(job_id, target, results)
        
        # Update job with findings count
        with get_db_session() as session:
            job_repository.update(session, job_id, {'findings_count': findings_count})
        
        log_scan_activity(job_id, "recon_scan_completed", 
                         results_count=len(results.get('results', {})),
                         findings_count=findings_count)
        
        return results
    
    except Exception as e:
        logger.error(f"Recon scan failed for job {job_id}: {e}")
        log_scan_activity(job_id, "recon_scan_failed", error=str(e))
        raise


@celery_app.task(bind=True, base=BaseReconTask, name='recon.tasks.run_subdomain_scan')
def run_subdomain_scan(self, job_id: str, target: str, **kwargs):
    """Run subdomain discovery scan."""
    
    with get_db_session() as session:
        job_repository.update_status(session, job_id, ScanStatus.RUNNING)
    
    log_scan_activity(job_id, "subdomain_scan_started", target=target)
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run specific collectors for subdomain discovery
        collectors = ['certificate_transparency', 'passive_dns', 'dns']
        results = loop.run_until_complete(
            recon_orchestrator.run_recon(target, collectors=collectors, **kwargs)
        )
        
        # Process subdomain results
        subdomains_found = process_subdomain_results(job_id, target, results)
        
        log_scan_activity(job_id, "subdomain_scan_completed", 
                         subdomains_found=subdomains_found)
        
        return results
    
    except Exception as e:
        logger.error(f"Subdomain scan failed for job {job_id}: {e}")
        log_scan_activity(job_id, "subdomain_scan_failed", error=str(e))
        raise


@celery_app.task(bind=True, base=BaseReconTask, name='recon.tasks.run_port_scan')
def run_port_scan(self, job_id: str, target: str, **kwargs):
    """Run port scanning on target."""
    
    with get_db_session() as session:
        job_repository.update_status(session, job_id, ScanStatus.RUNNING)
    
    log_scan_activity(job_id, "port_scan_started", target=target)
    
    try:
        # Use nmap for port scanning
        import nmap
        
        nm = nmap.PortScanner()
        
        # Configure scan parameters
        ports = kwargs.get('ports', '1-1000')
        scan_type = kwargs.get('scan_type', '-sS')  # SYN scan
        
        # Perform scan
        scan_result = nm.scan(target, ports, arguments=scan_type)
        
        # Process results
        hosts_scanned = process_port_scan_results(job_id, target, scan_result)
        
        log_scan_activity(job_id, "port_scan_completed", 
                         hosts_scanned=hosts_scanned)
        
        return {
            'target': target,
            'scan_result': scan_result,
            'hosts_scanned': hosts_scanned
        }
    
    except Exception as e:
        logger.error(f"Port scan failed for job {job_id}: {e}")
        log_scan_activity(job_id, "port_scan_failed", error=str(e))
        raise


@celery_app.task(bind=True, base=BaseReconTask, name='recon.tasks.run_screenshot_scan')
def run_screenshot_scan(self, job_id: str, target: str, **kwargs):
    """Take screenshots of web applications."""
    
    with get_db_session() as session:
        job_repository.update_status(session, job_id, ScanStatus.RUNNING)
    
    log_scan_activity(job_id, "screenshot_scan_started", target=target)
    
    try:
        from automation.logging_config import screenshot_manager
        
        # Get URLs to screenshot
        urls = kwargs.get('urls', [f"http://{target}", f"https://{target}"])
        
        screenshots_taken = 0
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        for url in urls:
            try:
                screenshot_info = loop.run_until_complete(
                    screenshot_manager.take_screenshot(url)
                )
                
                if screenshot_info:
                    # Store screenshot as evidence
                    store_screenshot_evidence(job_id, url, screenshot_info)
                    screenshots_taken += 1
            
            except Exception as e:
                logger.warning(f"Failed to screenshot {url}: {e}")
        
        log_scan_activity(job_id, "screenshot_scan_completed", 
                         screenshots_taken=screenshots_taken)
        
        return {
            'target': target,
            'urls_processed': len(urls),
            'screenshots_taken': screenshots_taken
        }
    
    except Exception as e:
        logger.error(f"Screenshot scan failed for job {job_id}: {e}")
        log_scan_activity(job_id, "screenshot_scan_failed", error=str(e))
        raise


@celery_app.task(bind=True, base=BaseReconTask, name='recon.tasks.run_generic_scan')
def run_generic_scan(self, job_id: str, target: str, **kwargs):
    """Run a generic scan (fallback task)."""
    
    with get_db_session() as session:
        job_repository.update_status(session, job_id, ScanStatus.RUNNING)
    
    log_scan_activity(job_id, "generic_scan_started", target=target)
    
    try:
        # Run basic recon as fallback
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        results = loop.run_until_complete(
            recon_orchestrator.run_recon(target, **kwargs)
        )
        
        log_scan_activity(job_id, "generic_scan_completed")
        
        return results
    
    except Exception as e:
        logger.error(f"Generic scan failed for job {job_id}: {e}")
        log_scan_activity(job_id, "generic_scan_failed", error=str(e))
        raise


@celery_app.task(bind=True, base=BaseReconTask, name='recon.tasks.run_enhanced_recon')
def run_enhanced_recon(self, job_id: str, target: str, **kwargs):
    """Run enhanced Phase B reconnaissance."""
    
    with get_db_session() as session:
        job_repository.update_status(session, job_id, ScanStatus.RUNNING)
    
    log_scan_activity(job_id, "enhanced_recon_started", target=target)
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run enhanced recon collectors
        results = loop.run_until_complete(
            enhanced_recon_orchestrator.run_enhanced_recon(target, **kwargs)
        )
        
        # Process and store results
        findings_count = process_enhanced_recon_results(job_id, target, results)
        
        # Update job with findings count
        with get_db_session() as session:
            job_repository.update(session, job_id, {'findings_count': findings_count})
        
        log_scan_activity(job_id, "enhanced_recon_completed", 
                         results_count=len(results.get('results', {})),
                         findings_count=findings_count)
        
        return results
    
    except Exception as e:
        logger.error(f"Enhanced recon failed for job {job_id}: {e}")
        log_scan_activity(job_id, "enhanced_recon_failed", error=str(e))
        raise


@celery_app.task(bind=True, base=BaseReconTask, name='recon.tasks.run_advanced_subdomain_scan')
def run_advanced_subdomain_scan(self, job_id: str, target: str, **kwargs):
    """Run advanced subdomain discovery with wildcard detection."""
    
    with get_db_session() as session:
        job_repository.update_status(session, job_id, ScanStatus.RUNNING)
    
    log_scan_activity(job_id, "advanced_subdomain_scan_started", target=target)
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run advanced subdomain discovery
        collector = AdvancedSubdomainCollector()
        results = loop.run_until_complete(
            collector.collect(target, **kwargs)
        )
        
        # Process subdomain results
        subdomains_found = process_advanced_subdomain_results(job_id, target, results)
        
        log_scan_activity(job_id, "advanced_subdomain_scan_completed", 
                         subdomains_found=subdomains_found)
        
        return {
            'target': target,
            'results': results,
            'subdomains_found': subdomains_found,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Advanced subdomain scan failed for job {job_id}: {e}")
        log_scan_activity(job_id, "advanced_subdomain_scan_failed", error=str(e))
        raise


@celery_app.task(bind=True, base=BaseReconTask, name='recon.tasks.run_advanced_port_scan')
def run_advanced_port_scan(self, job_id: str, target: str, **kwargs):
    """Run advanced port scanning with service enumeration."""
    
    with get_db_session() as session:
        job_repository.update_status(session, job_id, ScanStatus.RUNNING)
    
    log_scan_activity(job_id, "advanced_port_scan_started", target=target)
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run advanced port scanning
        collector = AdvancedPortScanCollector()
        results = loop.run_until_complete(
            collector.collect(target, **kwargs)
        )
        
        # Process port scan results
        services_found = process_advanced_port_scan_results(job_id, target, results)
        
        log_scan_activity(job_id, "advanced_port_scan_completed", 
                         services_found=services_found)
        
        return {
            'target': target,
            'results': results,
            'services_found': services_found,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Advanced port scan failed for job {job_id}: {e}")
        log_scan_activity(job_id, "advanced_port_scan_failed", error=str(e))
        raise


def process_recon_results(job_id: str, target: str, results: Dict[str, Any]) -> int:
    """Process reconnaissance results and create assets/findings."""
    
    findings_count = 0
    
    try:
        with get_db_session() as session:
            for collector_name, collector_data in results.get('results', {}).items():
                collector_results = collector_data.get('results', [])
                
                for result in collector_results:
                    # Create assets based on result type
                    if result.get('type') == 'subdomain':
                        create_domain_asset(session, result, job_id)
                    
                    elif result.get('type') == 'host':
                        create_host_asset(session, result, job_id)
                        
                        # Check for potential security issues
                        findings_count += check_host_security_issues(session, result, job_id)
                    
                    elif result.get('type') == 'dns_record':
                        create_dns_asset(session, result, job_id)
                    
                    elif result.get('type') == 'wayback_url':
                        create_url_asset(session, result, job_id)
                        
                        # Check for interesting URLs
                        findings_count += check_interesting_urls(session, result, job_id)
    
    except Exception as e:
        logger.error(f"Failed to process recon results: {e}")
    
    return findings_count


def process_subdomain_results(job_id: str, target: str, results: Dict[str, Any]) -> int:
    """Process subdomain discovery results."""
    
    subdomains_found = 0
    
    try:
        with get_db_session() as session:
            for collector_name, collector_data in results.get('results', {}).items():
                collector_results = collector_data.get('results', [])
                
                for result in collector_results:
                    if result.get('type') == 'subdomain':
                        create_domain_asset(session, result, job_id)
                        subdomains_found += 1
    
    except Exception as e:
        logger.error(f"Failed to process subdomain results: {e}")
    
    return subdomains_found


def process_port_scan_results(job_id: str, target: str, scan_result: Dict[str, Any]) -> int:
    """Process port scan results."""
    
    hosts_scanned = 0
    
    try:
        with get_db_session() as session:
            for host_ip, host_data in scan_result.get('scan', {}).items():
                if host_ip == 'nmap':
                    continue  # Skip nmap metadata
                
                # Create host asset
                host_asset_data = {
                    'asset_type': AssetType.HOST.value,
                    'name': host_ip,
                    'data': {
                        'ip': host_ip,
                        'hostname': host_data.get('hostnames', [{}])[0].get('name', ''),
                        'state': host_data.get('status', {}).get('state', ''),
                        'ports': []
                    },
                    'discovered_by': job_id,
                    'active': True
                }
                
                # Process open ports
                tcp_ports = host_data.get('tcp', {})
                for port, port_data in tcp_ports.items():
                    if port_data.get('state') == 'open':
                        host_asset_data['data']['ports'].append({
                            'port': port,
                            'protocol': 'tcp',
                            'service': port_data.get('name', ''),
                            'version': port_data.get('version', ''),
                            'product': port_data.get('product', '')
                        })
                        
                        # Create service asset
                        create_service_asset(session, host_ip, port, port_data, job_id)
                
                asset_repository.create(session, host_asset_data)
                hosts_scanned += 1
    
    except Exception as e:
        logger.error(f"Failed to process port scan results: {e}")
    
    return hosts_scanned


def create_domain_asset(session, result: Dict[str, Any], job_id: str):
    """Create a domain asset from recon result."""
    
    domain = result.get('domain')
    if not domain:
        return
    
    # Check if asset already exists
    existing = asset_repository.find_by_name(session, domain)
    if existing:
        asset_repository.update_last_seen(session, existing.id)
        return
    
    asset_data = {
        'asset_type': AssetType.DOMAIN.value,
        'name': domain,
        'data': {
            'domain': domain,
            'parent_domain': result.get('parent_domain', ''),
            'source': result.get('source', ''),
            'discovery_method': result.get('collector', '')
        },
        'discovered_by': job_id,
        'active': True
    }
    
    asset_repository.create(session, asset_data)


def create_host_asset(session, result: Dict[str, Any], job_id: str):
    """Create a host asset from recon result."""
    
    ip = result.get('ip')
    if not ip:
        return
    
    existing = asset_repository.find_by_name(session, ip)
    if existing:
        asset_repository.update_last_seen(session, existing.id)
        return
    
    asset_data = {
        'asset_type': AssetType.HOST.value,
        'name': ip,
        'data': {
            'ip': ip,
            'port': result.get('port'),
            'service': result.get('service', ''),
            'banner': result.get('banner', ''),
            'hostnames': result.get('hostnames', []),
            'location': result.get('location', {}),
            'org': result.get('org', ''),
            'asn': result.get('asn', '')
        },
        'discovered_by': job_id,
        'active': True
    }
    
    asset_repository.create(session, asset_data)


def create_service_asset(session, host_ip: str, port: int, port_data: Dict[str, Any], job_id: str):
    """Create a service asset from port scan data."""
    
    service_name = f"{host_ip}:{port}"
    
    asset_data = {
        'asset_type': AssetType.SERVICE.value,
        'name': service_name,
        'data': {
            'host_ip': host_ip,
            'port': port,
            'protocol': 'tcp',
            'service_name': port_data.get('name', ''),
            'version': port_data.get('version', ''),
            'product': port_data.get('product', ''),
            'state': port_data.get('state', '')
        },
        'discovered_by': job_id,
        'active': True
    }
    
    asset_repository.create(session, asset_data)


def create_dns_asset(session, result: Dict[str, Any], job_id: str):
    """Create DNS record asset."""
    
    domain = result.get('domain')
    record_type = result.get('record_type')
    
    if not domain or not record_type:
        return
    
    asset_name = f"{domain}_{record_type}"
    
    asset_data = {
        'asset_type': 'dns_record',
        'name': asset_name,
        'data': {
            'domain': domain,
            'record_type': record_type,
            'value': result.get('value', ''),
            'ttl': result.get('ttl')
        },
        'discovered_by': job_id,
        'active': True
    }
    
    asset_repository.create(session, asset_data)


def create_url_asset(session, result: Dict[str, Any], job_id: str):
    """Create URL asset from Wayback results."""
    
    url = result.get('url')
    if not url:
        return
    
    asset_data = {
        'asset_type': AssetType.ENDPOINT.value,
        'name': url,
        'data': {
            'url': url,
            'timestamp': result.get('timestamp', ''),
            'source': 'wayback_machine'
        },
        'discovered_by': job_id,
        'active': True
    }
    
    asset_repository.create(session, asset_data)


def check_host_security_issues(session, result: Dict[str, Any], job_id: str) -> int:
    """Check for potential security issues in host data."""
    
    findings_count = 0
    
    # Check for common vulnerable services
    service = result.get('service', '').lower()
    port = result.get('port')
    
    vulnerable_services = {
        'ftp': 21,
        'telnet': 23,
        'smtp': 25,
        'dns': 53,
        'http': 80,
        'pop3': 110,
        'rpcbind': 111,
        'netbios': 139,
        'snmp': 161,
        'https': 443,
        'smb': 445,
        'mysql': 3306,
        'rdp': 3389,
        'postgresql': 5432
    }
    
    if service in vulnerable_services or port in vulnerable_services.values():
        # Create informational finding
        finding_data = {
            'title': f"Exposed Service: {service or 'Unknown'} on port {port}",
            'description': f"Service {service} detected on {result.get('ip')}:{port}",
            'severity': SeverityLevel.INFO,
            'vulnerability_type': VulnerabilityType.INFO_DISCLOSURE,
            'confidence': 0.8,
            'asset_type': AssetType.HOST,
            'asset_id': result.get('ip', ''),
            'affected_url': f"http://{result.get('ip')}:{port}" if port else None,
            'job_id': job_id
        }
        
        finding_repository.create(session, finding_data)
        findings_count += 1
    
    return findings_count


def check_interesting_urls(session, result: Dict[str, Any], job_id: str) -> int:
    """Check for interesting URLs from Wayback data."""
    
    findings_count = 0
    url = result.get('url', '')
    
    # Check for potentially interesting paths
    interesting_patterns = [
        '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
        '/config', '/backup', '/test', '/dev', '/staging',
        '.env', '.git', '.svn', 'web.config', '.htaccess'
    ]
    
    for pattern in interesting_patterns:
        if pattern in url.lower():
            finding_data = {
                'title': f"Interesting URL Found: {pattern}",
                'description': f"Potentially interesting URL discovered: {url}",
                'severity': SeverityLevel.INFO,
                'vulnerability_type': VulnerabilityType.INFO_DISCLOSURE,
                'confidence': 0.6,
                'asset_type': AssetType.ENDPOINT,
                'asset_id': url,
                'affected_url': url,
                'job_id': job_id
            }
            
            finding_repository.create(session, finding_data)
            findings_count += 1
            break  # Only create one finding per URL
    
    return findings_count


def store_screenshot_evidence(job_id: str, url: str, screenshot_info: Dict[str, Any]):
    """Store screenshot as evidence linked to job."""
    
    try:
        with get_db_session() as session:
            # Create an informational finding for the screenshot
            finding_data = {
                'title': f"Screenshot: {url}",
                'description': f"Screenshot captured for {url}",
                'severity': SeverityLevel.INFO,
                'vulnerability_type': VulnerabilityType.INFO_DISCLOSURE,
                'confidence': 1.0,
                'asset_type': AssetType.APPLICATION,
                'asset_id': url,
                'affected_url': url,
                'evidence': [{
                    'type': 'screenshot',
                    'path': screenshot_info['file_path'],
                    'description': f"Screenshot of {url}",
                    'timestamp': screenshot_info['timestamp']
                }],
                'job_id': job_id
            }
            
            finding_repository.create(session, finding_data)
    
    except Exception as e:
        logger.error(f"Failed to store screenshot evidence: {e}")


def process_enhanced_recon_results(job_id: str, target: str, results: Dict[str, Any]) -> int:
    """Process enhanced reconnaissance results from Phase B collectors."""
    
    findings_count = 0
    
    try:
        with get_db_session() as session:
            for collector_name, collector_data in results.get('results', {}).items():
                collector_results = collector_data.get('results', [])
                
                for result in collector_results:
                    # Process ASN results
                    if result.get('type') == 'asn':
                        create_asn_asset(session, result, job_id)
                    
                    elif result.get('type') == 'netblock':
                        create_netblock_asset(session, result, job_id)
                    
                    elif result.get('type') == 'acquisition':
                        create_acquisition_finding(session, result, job_id)
                        findings_count += 1
                    
                    elif result.get('type') == 'certificate_pattern_unusual_issuer':
                        create_certificate_finding(session, result, job_id)
                        findings_count += 1
                    
                    elif result.get('type') == 'organization':
                        create_organization_asset(session, result, job_id)
    
    except Exception as e:
        logger.error(f"Failed to process enhanced recon results: {e}")
    
    return findings_count


def process_advanced_subdomain_results(job_id: str, target: str, results: List[Dict[str, Any]]) -> int:
    """Process advanced subdomain discovery results."""
    
    subdomains_found = 0
    
    try:
        with get_db_session() as session:
            for result in results:
                if result.get('type') == 'subdomain_validated':
                    create_advanced_subdomain_asset(session, result, job_id)
                    subdomains_found += 1
                
                elif result.get('type') == 'wildcard_detection':
                    create_wildcard_finding(session, result, job_id)
    
    except Exception as e:
        logger.error(f"Failed to process advanced subdomain results: {e}")
    
    return subdomains_found


def process_advanced_port_scan_results(job_id: str, target: str, results: List[Dict[str, Any]]) -> int:
    """Process advanced port scanning results."""
    
    services_found = 0
    
    try:
        with get_db_session() as session:
            for result in results:
                if result.get('type') == 'service_enumeration':
                    create_advanced_service_asset(session, result, job_id)
                    services_found += 1
                
                elif result.get('type') == 'service_screenshot':
                    store_service_screenshot_evidence(session, result, job_id)
    
    except Exception as e:
        logger.error(f"Failed to process advanced port scan results: {e}")
    
    return services_found


def create_asn_asset(session, result: Dict[str, Any], job_id: str):
    """Create ASN asset from enhanced recon result."""
    
    asn = result.get('asn')
    if not asn:
        return
    
    asset_data = {
        'asset_type': 'asn',
        'name': f"AS{asn}",
        'data': {
            'asn': asn,
            'name': result.get('name', ''),
            'description': result.get('description', ''),
            'country': result.get('country', ''),
            'rir': result.get('rir', ''),
            'allocation_date': result.get('allocation_date', ''),
            'website': result.get('website', ''),
            'email_contacts': result.get('email_contacts', []),
            'abuse_contacts': result.get('abuse_contacts', [])
        },
        'discovered_by': job_id,
        'active': True
    }
    
    asset_repository.create(session, asset_data)


def create_netblock_asset(session, result: Dict[str, Any], job_id: str):
    """Create netblock asset from ASN analysis."""
    
    prefix = result.get('prefix')
    if not prefix:
        return
    
    asset_data = {
        'asset_type': 'netblock',
        'name': prefix,
        'data': {
            'prefix': prefix,
            'asn': result.get('asn'),
            'ip_version': result.get('ip_version', 4),
            'name': result.get('name', ''),
            'description': result.get('description', ''),
            'country': result.get('country', '')
        },
        'discovered_by': job_id,
        'active': True
    }
    
    asset_repository.create(session, asset_data)


def create_acquisition_finding(session, result: Dict[str, Any], job_id: str):
    """Create finding for corporate acquisition information."""
    
    finding_data = {
        'title': f"Corporate Acquisition: {result.get('acquired', '')} acquired by {result.get('acquirer', '')}",
        'description': f"Acquisition relationship discovered: {result.get('acquirer', '')} acquired {result.get('acquired', '')}",
        'severity': SeverityLevel.INFO,
        'vulnerability_type': VulnerabilityType.INFO_DISCLOSURE,
        'confidence': 0.8,
        'asset_type': AssetType.DOMAIN,
        'asset_id': result.get('acquired', ''),
        'evidence': [{
            'type': 'acquisition_data',
            'description': f"Acquisition date: {result.get('acquisition_date', 'Unknown')}",
            'details': f"Price: {result.get('price', 'Unknown')}",
            'source': result.get('source', ''),
            'timestamp': datetime.utcnow().isoformat()
        }],
        'job_id': job_id
    }
    
    finding_repository.create(session, finding_data)


def create_certificate_finding(session, result: Dict[str, Any], job_id: str):
    """Create finding for unusual certificate patterns."""
    
    finding_data = {
        'title': f"Unusual Certificate Issuer Pattern: {result.get('domain', '')}",
        'description': f"Unusual certificate issuers detected for {result.get('domain', '')}",
        'severity': SeverityLevel.LOW,
        'vulnerability_type': VulnerabilityType.MISCONFIGURATION,
        'confidence': 0.6,
        'asset_type': AssetType.DOMAIN,
        'asset_id': result.get('domain', ''),
        'evidence': [{
            'type': 'certificate_analysis',
            'description': f"Unusual issuers: {', '.join(result.get('unusual_issuers', []))}",
            'count': result.get('unusual_issuer_count', 0),
            'timestamp': datetime.utcnow().isoformat()
        }],
        'job_id': job_id
    }
    
    finding_repository.create(session, finding_data)


def create_organization_asset(session, result: Dict[str, Any], job_id: str):
    """Create organization asset from corporate data."""
    
    name = result.get('name')
    if not name:
        return
    
    asset_data = {
        'asset_type': 'organization',
        'name': name,
        'data': {
            'name': name,
            'legal_name': result.get('legal_name', ''),
            'website': result.get('website', ''),
            'description': result.get('description', ''),
            'founded_date': result.get('founded_date', ''),
            'categories': result.get('categories', []),
            'headquarters': result.get('headquarters', [])
        },
        'discovered_by': job_id,
        'active': True
    }
    
    asset_repository.create(session, asset_data)


def create_advanced_subdomain_asset(session, result: Dict[str, Any], job_id: str):
    """Create subdomain asset from advanced discovery."""
    
    subdomain = result.get('subdomain')
    if not subdomain:
        return
    
    asset_data = {
        'asset_type': AssetType.DOMAIN.value,
        'name': subdomain,
        'data': {
            'subdomain': subdomain,
            'parent_domain': result.get('parent_domain', ''),
            'resolved_ips': result.get('resolved_ips', []),
            'is_wildcard_response': result.get('is_wildcard_response', False),
            'resolution_time': result.get('resolution_time', ''),
            'discovery_method': 'advanced_subdomain_scan'
        },
        'discovered_by': job_id,
        'active': True
    }
    
    asset_repository.create(session, asset_data)


def create_wildcard_finding(session, result: Dict[str, Any], job_id: str):
    """Create finding for wildcard DNS detection."""
    
    if not result.get('has_wildcard'):
        return
    
    finding_data = {
        'title': f"Wildcard DNS Detected: {result.get('domain', '')}",
        'description': f"Wildcard DNS configuration detected for {result.get('domain', '')}",
        'severity': SeverityLevel.INFO,
        'vulnerability_type': VulnerabilityType.MISCONFIGURATION,
        'confidence': result.get('confidence', 0.5),
        'asset_type': AssetType.DOMAIN,
        'asset_id': result.get('domain', ''),
        'evidence': [{
            'type': 'wildcard_detection',
            'description': f"Wildcard IPs: {', '.join(result.get('wildcard_ips', []))}",
            'test_subdomains': result.get('test_subdomains', []),
            'confidence': result.get('confidence', 0.5),
            'timestamp': datetime.utcnow().isoformat()
        }],
        'job_id': job_id
    }
    
    finding_repository.create(session, finding_data)


def create_advanced_service_asset(session, result: Dict[str, Any], job_id: str):
    """Create service asset from advanced port scanning."""
    
    service_data = result.get('service', {})
    host = service_data.get('host')
    port = service_data.get('port')
    
    if not host or not port:
        return
    
    service_name = f"{host}:{port}"
    
    asset_data = {
        'asset_type': AssetType.SERVICE.value,
        'name': service_name,
        'data': {
            'host': host,
            'port': port,
            'protocol': service_data.get('protocol', 'tcp'),
            'service_name': service_data.get('service_name', ''),
            'service_type': service_data.get('service_type', ''),
            'url': service_data.get('url', ''),
            'headers': service_data.get('headers', {}),
            'title': service_data.get('title', ''),
            'server': service_data.get('server', ''),
            'powered_by': service_data.get('powered_by', ''),
            'accessible_paths': service_data.get('accessible_paths', []),
            'enumeration_time': service_data.get('enumeration_time', '')
        },
        'discovered_by': job_id,
        'active': True
    }
    
    asset_repository.create(session, asset_data)


def store_service_screenshot_evidence(session, result: Dict[str, Any], job_id: str):
    """Store screenshot evidence for a service."""
    
    screenshot_info = result.get('screenshot_info', {})
    service = screenshot_info.get('service', {})
    screenshot_data = screenshot_info.get('screenshot', {})
    
    if not screenshot_data:
        return
    
    finding_data = {
        'title': f"Service Screenshot: {screenshot_info.get('url', '')}",
        'description': f"Screenshot captured for service on {service.get('host', '')}:{service.get('port', '')}",
        'severity': SeverityLevel.INFO,
        'vulnerability_type': VulnerabilityType.INFO_DISCLOSURE,
        'confidence': 1.0,
        'asset_type': AssetType.SERVICE,
        'asset_id': f"{service.get('host', '')}:{service.get('port', '')}",
        'affected_url': screenshot_info.get('url', ''),
        'evidence': [{
            'type': 'screenshot',
            'path': screenshot_data.get('file_path', ''),
            'description': f"Screenshot of {screenshot_info.get('url', '')}",
            'timestamp': screenshot_data.get('timestamp', '')
        }],
        'job_id': job_id
    }
    
    finding_repository.create(session, finding_data)
