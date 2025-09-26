"""
Celery tasks for content discovery and application analysis.

This module defines tasks for discovering web content, analyzing applications,
and identifying potential attack surfaces.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
import re

from celery import Task
from automation.orchestrator import celery_app
from automation.database import get_db_session, job_repository, finding_repository, asset_repository
from automation.logging_config import audit_logger, log_scan_activity
from data.schemas import ScanStatus, AssetType, SeverityLevel, VulnerabilityType, FindingStatus
from analysis.content_discovery import ContentDiscoveryCollector
from analysis.bruteforce_engine import BruteforceCollector
from analysis.technology_profiling import TechnologyProfilingCollector
import httpx
import asyncio
from bs4 import BeautifulSoup


logger = logging.getLogger(__name__)


class BaseAnalysisTask(Task):
    """Base class for analysis tasks."""
    
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
    
    def _update_job_status(self, job_id: str, status: ScanStatus, results: Optional[Dict] = None, error: Optional[str] = None):
        """Update job status in database."""
        try:
            with get_db_session() as session:
                update_data = {'status': status}
                
                if results:
                    update_data['results_count'] = results.get('endpoints_found', 0)
                    update_data['findings_count'] = results.get('findings_count', 0)
                
                if error:
                    update_data['error_message'] = error
                
                job_repository.update(session, job_id, update_data)
        
        except Exception as e:
            logger.error(f"Failed to update job status: {e}")


@celery_app.task(bind=True, base=BaseAnalysisTask, name='analysis.tasks.run_content_discovery')
def run_content_discovery(self, job_id: str, target: str, **kwargs):
    """Run content discovery on target application."""
    
    with get_db_session() as session:
        job_repository.update_status(session, job_id, ScanStatus.RUNNING)
    
    log_scan_activity(job_id, "content_discovery_started", target=target)
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run content discovery
        results = loop.run_until_complete(
            discover_content(target, **kwargs)
        )
        
        # Process results and create findings
        findings_count = process_content_discovery_results(job_id, target, results)
        
        results['findings_count'] = findings_count
        
        log_scan_activity(job_id, "content_discovery_completed", 
                         endpoints_found=results.get('endpoints_found', 0),
                         findings_count=findings_count)
        
        return results
    
    except Exception as e:
        logger.error(f"Content discovery failed for job {job_id}: {e}")
        log_scan_activity(job_id, "content_discovery_failed", error=str(e))
        raise


@celery_app.task(bind=True, base=BaseAnalysisTask, name='analysis.tasks.run_tech_fingerprinting')
def run_tech_fingerprinting(self, job_id: str, target: str, **kwargs):
    """Run technology fingerprinting on target."""
    
    with get_db_session() as session:
        job_repository.update_status(session, job_id, ScanStatus.RUNNING)
    
    log_scan_activity(job_id, "tech_fingerprinting_started", target=target)
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run technology fingerprinting
        results = loop.run_until_complete(
            fingerprint_technology(target, **kwargs)
        )
        
        # Store technology information
        store_technology_info(job_id, target, results)
        
        log_scan_activity(job_id, "tech_fingerprinting_completed", 
                         technologies_found=len(results.get('technologies', [])))
        
        return results
    
    except Exception as e:
        logger.error(f"Technology fingerprinting failed for job {job_id}: {e}")
        log_scan_activity(job_id, "tech_fingerprinting_failed", error=str(e))
        raise


@celery_app.task(bind=True, base=BaseAnalysisTask, name='analysis.tasks.run_advanced_content_discovery')
def run_advanced_content_discovery(self, job_id: str, target: str, **kwargs):
    """Run advanced content discovery with intelligent crawling."""
    
    with get_db_session() as session:
        job_repository.update_status(session, job_id, ScanStatus.RUNNING)
    
    log_scan_activity(job_id, "advanced_content_discovery_started", target=target)
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run advanced content discovery
        collector = ContentDiscoveryCollector()
        results = loop.run_until_complete(
            collector.collect(target, **kwargs)
        )
        
        # Process results
        findings_count = process_content_discovery_results_advanced(job_id, target, results)
        
        log_scan_activity(job_id, "advanced_content_discovery_completed", 
                         endpoints_found=len([r for r in results if r.get('type') == 'endpoint_discovered']),
                         findings_count=findings_count)
        
        return {
            'target': target,
            'results': results,
            'findings_count': findings_count,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Advanced content discovery failed for job {job_id}: {e}")
        log_scan_activity(job_id, "advanced_content_discovery_failed", error=str(e))
        raise


@celery_app.task(bind=True, base=BaseAnalysisTask, name='analysis.tasks.run_bruteforce_discovery')
def run_bruteforce_discovery(self, job_id: str, target: str, **kwargs):
    """Run intelligent bruteforce directory and file discovery."""
    
    with get_db_session() as session:
        job_repository.update_status(session, job_id, ScanStatus.RUNNING)
    
    log_scan_activity(job_id, "bruteforce_discovery_started", target=target)
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run bruteforce discovery
        collector = BruteforceCollector()
        results = loop.run_until_complete(
            collector.collect(target, **kwargs)
        )
        
        # Process results
        findings_count = process_bruteforce_discovery_results(job_id, target, results)
        
        log_scan_activity(job_id, "bruteforce_discovery_completed", 
                         paths_found=len([r for r in results if r.get('type') == 'path_discovered']),
                         findings_count=findings_count)
        
        return {
            'target': target,
            'results': results,
            'findings_count': findings_count,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Bruteforce discovery failed for job {job_id}: {e}")
        log_scan_activity(job_id, "bruteforce_discovery_failed", error=str(e))
        raise


@celery_app.task(bind=True, base=BaseAnalysisTask, name='analysis.tasks.run_technology_profiling')
def run_technology_profiling(self, job_id: str, target: str, **kwargs):
    """Run comprehensive technology profiling and fingerprinting."""
    
    with get_db_session() as session:
        job_repository.update_status(session, job_id, ScanStatus.RUNNING)
    
    log_scan_activity(job_id, "technology_profiling_started", target=target)
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run technology profiling
        collector = TechnologyProfilingCollector()
        results = loop.run_until_complete(
            collector.collect(target, **kwargs)
        )
        
        # Process results
        findings_count = process_technology_profiling_results(job_id, target, results)
        
        log_scan_activity(job_id, "technology_profiling_completed", 
                         technologies_found=len([r for r in results if r.get('type') == 'technology_detected']),
                         findings_count=findings_count)
        
        return {
            'target': target,
            'results': results,
            'findings_count': findings_count,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Technology profiling failed for job {job_id}: {e}")
        log_scan_activity(job_id, "technology_profiling_failed", error=str(e))
        raise


async def discover_content(target: str, **kwargs) -> Dict[str, Any]:
    """Discover content and endpoints on target application."""
    
    # Ensure target has protocol
    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"
    
    discovered_endpoints = []
    discovered_parameters = []
    interesting_files = []
    
    async with httpx.AsyncClient(
        timeout=30.0,
        follow_redirects=True,
        verify=False  # For testing environments
    ) as client:
        
        # 1. Crawl the main page
        try:
            response = await client.get(target)
            if response.status_code == 200:
                endpoints, params = extract_links_and_params(target, response.text)
                discovered_endpoints.extend(endpoints)
                discovered_parameters.extend(params)
        except Exception as e:
            logger.warning(f"Failed to crawl main page {target}: {e}")
        
        # 2. Check common files
        common_files = [
            'robots.txt', 'sitemap.xml', '.well-known/security.txt',
            'crossdomain.xml', 'clientaccesspolicy.xml',
            'favicon.ico', 'humans.txt', 'ads.txt'
        ]
        
        for file_path in common_files:
            try:
                url = urljoin(target, file_path)
                response = await client.get(url)
                if response.status_code == 200:
                    interesting_files.append({
                        'url': url,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'content_type': response.headers.get('content-type', '')
                    })
            except Exception:
                pass  # File doesn't exist, continue
        
        # 3. Directory bruteforcing (basic)
        common_dirs = [
            'admin', 'administrator', 'wp-admin', 'phpmyadmin',
            'config', 'backup', 'test', 'dev', 'staging',
            'api', 'v1', 'v2', 'docs', 'documentation',
            'uploads', 'files', 'images', 'assets'
        ]
        
        for directory in common_dirs:
            try:
                url = urljoin(target, f"{directory}/")
                response = await client.get(url)
                if response.status_code in [200, 301, 302, 403]:
                    discovered_endpoints.append({
                        'url': url,
                        'status_code': response.status_code,
                        'method': 'GET',
                        'type': 'directory'
                    })
            except Exception:
                pass
        
        # 4. API endpoint discovery
        api_endpoints = [
            'api', 'api/v1', 'api/v2', 'rest', 'graphql',
            'swagger.json', 'openapi.json', 'api-docs'
        ]
        
        for endpoint in api_endpoints:
            try:
                url = urljoin(target, endpoint)
                response = await client.get(url)
                if response.status_code == 200:
                    discovered_endpoints.append({
                        'url': url,
                        'status_code': response.status_code,
                        'method': 'GET',
                        'type': 'api',
                        'content_type': response.headers.get('content-type', '')
                    })
                    
                    # If it's an API documentation, extract more endpoints
                    if 'json' in response.headers.get('content-type', ''):
                        try:
                            api_data = response.json()
                            api_endpoints_from_doc = extract_api_endpoints(target, api_data)
                            discovered_endpoints.extend(api_endpoints_from_doc)
                        except Exception:
                            pass
            except Exception:
                pass
    
    return {
        'target': target,
        'endpoints_found': len(discovered_endpoints),
        'endpoints': discovered_endpoints,
        'parameters': discovered_parameters,
        'interesting_files': interesting_files,
        'timestamp': datetime.utcnow().isoformat()
    }


def extract_links_and_params(base_url: str, html_content: str) -> tuple:
    """Extract links and parameters from HTML content."""
    
    endpoints = []
    parameters = set()
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract links
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith(('http://', 'https://')):
                full_url = href
            else:
                full_url = urljoin(base_url, href)
            
            # Parse URL to extract parameters
            parsed = urlparse(full_url)
            if parsed.query:
                query_params = parsed.query.split('&')
                for param in query_params:
                    if '=' in param:
                        param_name = param.split('=')[0]
                        parameters.add(param_name)
            
            endpoints.append({
                'url': full_url,
                'method': 'GET',
                'type': 'link',
                'source': 'html_crawl'
            })
        
        # Extract forms and their parameters
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            
            if action:
                if action.startswith(('http://', 'https://')):
                    form_url = action
                else:
                    form_url = urljoin(base_url, action)
            else:
                form_url = base_url
            
            # Extract form parameters
            form_params = []
            for input_tag in form.find_all(['input', 'select', 'textarea']):
                name = input_tag.get('name')
                if name:
                    parameters.add(name)
                    form_params.append(name)
            
            endpoints.append({
                'url': form_url,
                'method': method,
                'type': 'form',
                'parameters': form_params,
                'source': 'html_crawl'
            })
        
        # Extract JavaScript endpoints (basic)
        for script in soup.find_all('script'):
            if script.string:
                # Look for URL patterns in JavaScript
                url_patterns = re.findall(r'["\']([/\w\-\.]+\.(?:php|asp|aspx|jsp|do|action))["\']', script.string)
                for pattern in url_patterns:
                    full_url = urljoin(base_url, pattern)
                    endpoints.append({
                        'url': full_url,
                        'method': 'GET',
                        'type': 'javascript',
                        'source': 'js_extraction'
                    })
    
    except Exception as e:
        logger.warning(f"Failed to parse HTML content: {e}")
    
    return endpoints, list(parameters)


def extract_api_endpoints(base_url: str, api_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract endpoints from API documentation (Swagger/OpenAPI)."""
    
    endpoints = []
    
    try:
        # Handle Swagger/OpenAPI format
        if 'paths' in api_data:
            for path, methods in api_data['paths'].items():
                for method, details in methods.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        full_url = urljoin(base_url, path.lstrip('/'))
                        
                        # Extract parameters
                        parameters = []
                        if 'parameters' in details:
                            for param in details['parameters']:
                                if 'name' in param:
                                    parameters.append(param['name'])
                        
                        endpoints.append({
                            'url': full_url,
                            'method': method.upper(),
                            'type': 'api',
                            'parameters': parameters,
                            'source': 'api_documentation',
                            'summary': details.get('summary', ''),
                            'tags': details.get('tags', [])
                        })
    
    except Exception as e:
        logger.warning(f"Failed to extract API endpoints: {e}")
    
    return endpoints


async def fingerprint_technology(target: str, **kwargs) -> Dict[str, Any]:
    """Fingerprint technologies used by the target application."""
    
    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"
    
    technologies = []
    headers_info = {}
    
    async with httpx.AsyncClient(
        timeout=30.0,
        follow_redirects=True,
        verify=False
    ) as client:
        
        try:
            response = await client.get(target)
            headers_info = dict(response.headers)
            
            # Analyze response headers
            tech_from_headers = analyze_headers(headers_info)
            technologies.extend(tech_from_headers)
            
            # Analyze HTML content
            if response.status_code == 200:
                tech_from_html = analyze_html_content(response.text)
                technologies.extend(tech_from_html)
        
        except Exception as e:
            logger.warning(f"Failed to fingerprint {target}: {e}")
    
    return {
        'target': target,
        'technologies': technologies,
        'headers': headers_info,
        'timestamp': datetime.utcnow().isoformat()
    }


def analyze_headers(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Analyze HTTP headers to identify technologies."""
    
    technologies = []
    
    # Server header analysis
    server = headers.get('server', '').lower()
    if server:
        if 'apache' in server:
            technologies.append({'name': 'Apache', 'category': 'Web Server', 'confidence': 0.9})
        elif 'nginx' in server:
            technologies.append({'name': 'Nginx', 'category': 'Web Server', 'confidence': 0.9})
        elif 'iis' in server:
            technologies.append({'name': 'IIS', 'category': 'Web Server', 'confidence': 0.9})
        elif 'cloudflare' in server:
            technologies.append({'name': 'Cloudflare', 'category': 'CDN', 'confidence': 0.9})
    
    # X-Powered-By header
    powered_by = headers.get('x-powered-by', '').lower()
    if powered_by:
        if 'php' in powered_by:
            technologies.append({'name': 'PHP', 'category': 'Programming Language', 'confidence': 0.9})
        elif 'asp.net' in powered_by:
            technologies.append({'name': 'ASP.NET', 'category': 'Framework', 'confidence': 0.9})
        elif 'express' in powered_by:
            technologies.append({'name': 'Express.js', 'category': 'Framework', 'confidence': 0.9})
    
    # Other technology indicators
    if 'x-drupal-cache' in headers:
        technologies.append({'name': 'Drupal', 'category': 'CMS', 'confidence': 0.8})
    
    if 'x-generator' in headers:
        generator = headers['x-generator'].lower()
        if 'wordpress' in generator:
            technologies.append({'name': 'WordPress', 'category': 'CMS', 'confidence': 0.9})
    
    # Security headers (informational)
    security_headers = [
        'strict-transport-security',
        'content-security-policy',
        'x-frame-options',
        'x-content-type-options',
        'x-xss-protection'
    ]
    
    missing_security_headers = []
    for header in security_headers:
        if header not in headers:
            missing_security_headers.append(header)
    
    if missing_security_headers:
        technologies.append({
            'name': 'Missing Security Headers',
            'category': 'Security',
            'confidence': 1.0,
            'details': missing_security_headers
        })
    
    return technologies


def analyze_html_content(html_content: str) -> List[Dict[str, Any]]:
    """Analyze HTML content to identify technologies."""
    
    technologies = []
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Meta generator tag
        generator_meta = soup.find('meta', attrs={'name': 'generator'})
        if generator_meta and generator_meta.get('content'):
            content = generator_meta['content'].lower()
            if 'wordpress' in content:
                technologies.append({'name': 'WordPress', 'category': 'CMS', 'confidence': 0.9})
            elif 'drupal' in content:
                technologies.append({'name': 'Drupal', 'category': 'CMS', 'confidence': 0.9})
            elif 'joomla' in content:
                technologies.append({'name': 'Joomla', 'category': 'CMS', 'confidence': 0.9})
        
        # Script sources
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script['src'].lower()
            if 'jquery' in src:
                technologies.append({'name': 'jQuery', 'category': 'JavaScript Library', 'confidence': 0.8})
            elif 'angular' in src:
                technologies.append({'name': 'AngularJS', 'category': 'JavaScript Framework', 'confidence': 0.8})
            elif 'react' in src:
                technologies.append({'name': 'React', 'category': 'JavaScript Framework', 'confidence': 0.8})
            elif 'vue' in src:
                technologies.append({'name': 'Vue.js', 'category': 'JavaScript Framework', 'confidence': 0.8})
        
        # CSS frameworks
        links = soup.find_all('link', rel='stylesheet')
        for link in links:
            href = link.get('href', '').lower()
            if 'bootstrap' in href:
                technologies.append({'name': 'Bootstrap', 'category': 'CSS Framework', 'confidence': 0.8})
            elif 'foundation' in href:
                technologies.append({'name': 'Foundation', 'category': 'CSS Framework', 'confidence': 0.8})
    
    except Exception as e:
        logger.warning(f"Failed to analyze HTML content: {e}")
    
    return technologies


def process_content_discovery_results(job_id: str, target: str, results: Dict[str, Any]) -> int:
    """Process content discovery results and create findings."""
    
    findings_count = 0
    
    try:
        with get_db_session() as session:
            # Create assets for discovered endpoints
            for endpoint in results.get('endpoints', []):
                create_endpoint_asset(session, endpoint, job_id)
                
                # Check for interesting endpoints
                if is_interesting_endpoint(endpoint):
                    create_interesting_endpoint_finding(session, endpoint, job_id)
                    findings_count += 1
            
            # Create findings for interesting files
            for file_info in results.get('interesting_files', []):
                create_interesting_file_finding(session, file_info, job_id)
                findings_count += 1
    
    except Exception as e:
        logger.error(f"Failed to process content discovery results: {e}")
    
    return findings_count


def store_technology_info(job_id: str, target: str, results: Dict[str, Any]):
    """Store technology fingerprinting information."""
    
    try:
        with get_db_session() as session:
            # Create application asset with technology information
            asset_data = {
                'asset_type': AssetType.APPLICATION.value,
                'name': target,
                'data': {
                    'url': target,
                    'technologies': results.get('technologies', []),
                    'headers': results.get('headers', {}),
                    'fingerprinted_at': results.get('timestamp')
                },
                'discovered_by': job_id,
                'active': True
            }
            
            # Check if asset already exists
            existing = asset_repository.find_by_name(session, target)
            if existing:
                # Update existing asset
                existing_data = existing.data or {}
                existing_data.update(asset_data['data'])
                asset_repository.update(session, existing.id, {'data': existing_data})
            else:
                # Create new asset
                asset_repository.create(session, asset_data)
            
            # Create findings for security issues
            for tech in results.get('technologies', []):
                if tech.get('name') == 'Missing Security Headers':
                    create_security_header_finding(session, target, tech, job_id)
    
    except Exception as e:
        logger.error(f"Failed to store technology info: {e}")


def create_endpoint_asset(session, endpoint: Dict[str, Any], job_id: str):
    """Create an endpoint asset."""
    
    url = endpoint.get('url')
    if not url:
        return
    
    asset_data = {
        'asset_type': AssetType.ENDPOINT.value,
        'name': url,
        'data': {
            'url': url,
            'method': endpoint.get('method', 'GET'),
            'type': endpoint.get('type', 'unknown'),
            'parameters': endpoint.get('parameters', []),
            'source': endpoint.get('source', ''),
            'status_code': endpoint.get('status_code'),
            'content_type': endpoint.get('content_type', '')
        },
        'discovered_by': job_id,
        'active': True
    }
    
    # Check if asset already exists
    existing = asset_repository.find_by_name(session, url)
    if existing:
        asset_repository.update_last_seen(session, existing.id)
    else:
        asset_repository.create(session, asset_data)


def is_interesting_endpoint(endpoint: Dict[str, Any]) -> bool:
    """Check if an endpoint is potentially interesting for security testing."""
    
    url = endpoint.get('url', '').lower()
    
    interesting_patterns = [
        '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
        '/config', '/backup', '/test', '/dev', '/staging',
        '/api', '/graphql', '/swagger', '/openapi',
        '.env', '.git', '.svn', 'web.config', '.htaccess'
    ]
    
    for pattern in interesting_patterns:
        if pattern in url:
            return True
    
    # Check for admin panels by status code
    if endpoint.get('status_code') == 200 and any(admin in url for admin in ['/admin', '/administrator']):
        return True
    
    return False


def create_interesting_endpoint_finding(session, endpoint: Dict[str, Any], job_id: str):
    """Create a finding for an interesting endpoint."""
    
    url = endpoint.get('url')
    
    finding_data = {
        'title': f"Interesting Endpoint Discovered: {url}",
        'description': f"Potentially sensitive endpoint found: {url}",
        'severity': SeverityLevel.INFO,
        'vulnerability_type': VulnerabilityType.INFO_DISCLOSURE,
        'confidence': 0.7,
        'asset_type': AssetType.ENDPOINT,
        'asset_id': url,
        'affected_url': url,
        'job_id': job_id
    }
    
    finding_repository.create(session, finding_data)


def create_interesting_file_finding(session, file_info: Dict[str, Any], job_id: str):
    """Create a finding for an interesting file."""
    
    url = file_info.get('url')
    
    finding_data = {
        'title': f"Interesting File Found: {url}",
        'description': f"Accessible file discovered: {url} (Status: {file_info.get('status_code')})",
        'severity': SeverityLevel.INFO,
        'vulnerability_type': VulnerabilityType.INFO_DISCLOSURE,
        'confidence': 0.8,
        'asset_type': AssetType.ENDPOINT,
        'asset_id': url,
        'affected_url': url,
        'job_id': job_id
    }
    
    finding_repository.create(session, finding_data)


def create_security_header_finding(session, target: str, tech_info: Dict[str, Any], job_id: str):
    """Create a finding for missing security headers."""
    
    missing_headers = tech_info.get('details', [])
    
    finding_data = {
        'title': "Missing Security Headers",
        'description': f"The following security headers are missing: {', '.join(missing_headers)}",
        'severity': SeverityLevel.LOW,
        'vulnerability_type': VulnerabilityType.MISCONFIGURATION,
        'confidence': 1.0,
        'asset_type': AssetType.APPLICATION,
        'asset_id': target,
        'affected_url': target,
        'remediation': "Implement proper security headers to protect against common attacks",
        'job_id': job_id
    }
    
    finding_repository.create(session, finding_data)


def process_content_discovery_results_advanced(job_id: str, target: str, results: List[Dict[str, Any]]) -> int:
    """Process advanced content discovery results."""
    
    findings_count = 0
    
    try:
        with get_db_session() as session:
            for result in results:
                if result.get('type') == 'endpoint_discovered':
                    create_endpoint_asset_advanced(session, result, job_id)
                
                elif result.get('type') == 'api_endpoint_discovered':
                    create_api_endpoint_finding(session, result, job_id)
                    findings_count += 1
                
                elif result.get('type') == 'interesting_file_discovered':
                    create_interesting_file_finding_advanced(session, result, job_id)
                    findings_count += 1
                
                elif result.get('type') == 'form_discovered':
                    create_form_asset(session, result, job_id)
    
    except Exception as e:
        logger.error(f"Failed to process advanced content discovery results: {e}")
    
    return findings_count


def process_bruteforce_discovery_results(job_id: str, target: str, results: List[Dict[str, Any]]) -> int:
    """Process bruteforce discovery results."""
    
    findings_count = 0
    
    try:
        with get_db_session() as session:
            for result in results:
                if result.get('type') == 'path_discovered':
                    create_discovered_path_asset(session, result, job_id)
                
                elif result.get('type') == 'bypass_success':
                    create_bypass_finding(session, result, job_id)
                    findings_count += 1
                
                elif result.get('type') == 'interesting_response':
                    create_interesting_response_finding(session, result, job_id)
                    findings_count += 1
    
    except Exception as e:
        logger.error(f"Failed to process bruteforce discovery results: {e}")
    
    return findings_count


def process_technology_profiling_results(job_id: str, target: str, results: List[Dict[str, Any]]) -> int:
    """Process technology profiling results."""
    
    findings_count = 0
    
    try:
        with get_db_session() as session:
            for result in results:
                if result.get('type') == 'technology_detected':
                    create_technology_asset(session, result, job_id)
                
                elif result.get('type') == 'technology_profile':
                    # Check for security issues in the profile
                    profile_data = result.get('profile_data', {})
                    if profile_data.get('security_score', 100) < 70:
                        create_security_profile_finding(session, result, job_id)
                        findings_count += 1
    
    except Exception as e:
        logger.error(f"Failed to process technology profiling results: {e}")
    
    return findings_count


def create_endpoint_asset_advanced(session, result: Dict[str, Any], job_id: str):
    """Create endpoint asset from advanced content discovery."""
    
    endpoint_data = result.get('endpoint', {})
    url = endpoint_data.get('url')
    
    if not url:
        return
    
    asset_data = {
        'asset_type': AssetType.ENDPOINT.value,
        'name': url,
        'data': {
            'url': url,
            'method': endpoint_data.get('method', 'GET'),
            'source': endpoint_data.get('source', ''),
            'parameters': endpoint_data.get('parameters', []),
            'text': endpoint_data.get('text', ''),
            'discovery_method': 'advanced_content_discovery'
        },
        'discovered_by': job_id,
        'active': True
    }
    
    # Check if asset already exists
    existing = asset_repository.find_by_name(session, url)
    if existing:
        asset_repository.update_last_seen(session, existing.id)
    else:
        asset_repository.create(session, asset_data)


def create_api_endpoint_finding(session, result: Dict[str, Any], job_id: str):
    """Create finding for discovered API endpoint."""
    
    api_endpoint = result.get('api_endpoint', {})
    url = api_endpoint.get('url', '')
    
    finding_data = {
        'title': f"API Endpoint Discovered: {url}",
        'description': f"API endpoint found: {url}",
        'severity': SeverityLevel.INFO,
        'vulnerability_type': VulnerabilityType.INFO_DISCLOSURE,
        'confidence': 0.8,
        'asset_type': AssetType.ENDPOINT,
        'asset_id': url,
        'affected_url': url,
        'evidence': [{
            'type': 'api_endpoint',
            'method': api_endpoint.get('method', 'GET'),
            'response_type': api_endpoint.get('response_type', ''),
            'status_code': api_endpoint.get('status_code', 0),
            'timestamp': datetime.utcnow().isoformat()
        }],
        'job_id': job_id
    }
    
    finding_repository.create(session, finding_data)


def create_interesting_file_finding_advanced(session, result: Dict[str, Any], job_id: str):
    """Create finding for interesting file discovery."""
    
    file_data = result.get('file', {})
    url = file_data.get('url', '')
    
    finding_data = {
        'title': f"Interesting File Discovered: {url}",
        'description': f"Potentially sensitive file found: {url}",
        'severity': SeverityLevel.MEDIUM,
        'vulnerability_type': VulnerabilityType.INFO_DISCLOSURE,
        'confidence': 0.7,
        'asset_type': AssetType.ENDPOINT,
        'asset_id': url,
        'affected_url': url,
        'evidence': [{
            'type': 'file_discovery',
            'file_type': file_data.get('type', ''),
            'size': file_data.get('size', 0),
            'timestamp': datetime.utcnow().isoformat()
        }],
        'job_id': job_id
    }
    
    finding_repository.create(session, finding_data)


def create_form_asset(session, result: Dict[str, Any], job_id: str):
    """Create form asset from content discovery."""
    
    form_data = result.get('form', {})
    action_url = form_data.get('action', '')
    
    if not action_url:
        return
    
    asset_data = {
        'asset_type': AssetType.ENDPOINT.value,
        'name': action_url,
        'data': {
            'url': action_url,
            'method': form_data.get('method', 'GET'),
            'fields': form_data.get('fields', []),
            'enctype': form_data.get('enctype', ''),
            'form_id': form_data.get('id', ''),
            'form_class': form_data.get('class', []),
            'discovery_method': 'form_discovery'
        },
        'discovered_by': job_id,
        'active': True
    }
    
    asset_repository.create(session, asset_data)


def create_discovered_path_asset(session, result: Dict[str, Any], job_id: str):
    """Create asset for discovered path."""
    
    path_data = result.get('path_data', {})
    url = path_data.get('url', '')
    
    if not url:
        return
    
    asset_data = {
        'asset_type': AssetType.ENDPOINT.value,
        'name': url,
        'data': {
            'url': url,
            'path': path_data.get('path', ''),
            'status_code': path_data.get('status_code', 0),
            'content_length': path_data.get('content_length', 0),
            'content_type': path_data.get('content_type', ''),
            'server': path_data.get('server', ''),
            'discovery_method': 'bruteforce_discovery',
            'discovery_time': path_data.get('discovery_time', '')
        },
        'discovered_by': job_id,
        'active': True
    }
    
    asset_repository.create(session, asset_data)


def create_bypass_finding(session, result: Dict[str, Any], job_id: str):
    """Create finding for successful bypass technique."""
    
    bypass_data = result.get('bypass_data', {})
    
    finding_data = {
        'title': f"403 Bypass Successful: {bypass_data.get('method', 'Unknown')}",
        'description': f"Successfully bypassed 403 restriction using {bypass_data.get('method', 'unknown method')}",
        'severity': SeverityLevel.MEDIUM,
        'vulnerability_type': VulnerabilityType.MISCONFIGURATION,
        'confidence': 0.8,
        'asset_type': AssetType.ENDPOINT,
        'asset_id': bypass_data.get('original_response', {}).get('url', ''),
        'affected_url': bypass_data.get('original_response', {}).get('url', ''),
        'evidence': [{
            'type': 'bypass_technique',
            'method': bypass_data.get('method', ''),
            'details': bypass_data,
            'timestamp': datetime.utcnow().isoformat()
        }],
        'job_id': job_id
    }
    
    finding_repository.create(session, finding_data)


def create_interesting_response_finding(session, result: Dict[str, Any], job_id: str):
    """Create finding for interesting response."""
    
    response_data = result.get('response_data', {})
    url = response_data.get('url', '')
    
    finding_data = {
        'title': f"Interesting Response: {url}",
        'description': f"Interesting response detected at {url}",
        'severity': SeverityLevel.INFO,
        'vulnerability_type': VulnerabilityType.INFO_DISCLOSURE,
        'confidence': 0.6,
        'asset_type': AssetType.ENDPOINT,
        'asset_id': url,
        'affected_url': url,
        'evidence': [{
            'type': 'interesting_response',
            'status_code': response_data.get('status_code', 0),
            'content_length': response_data.get('content_length', 0),
            'content_type': response_data.get('content_type', ''),
            'timestamp': datetime.utcnow().isoformat()
        }],
        'job_id': job_id
    }
    
    finding_repository.create(session, finding_data)


def create_technology_asset(session, result: Dict[str, Any], job_id: str):
    """Create technology asset from profiling."""
    
    tech_data = result.get('technology', {})
    tech_name = tech_data.get('name', '')
    target = result.get('target', '')
    
    if not tech_name:
        return
    
    asset_data = {
        'asset_type': 'technology',
        'name': f"{target}_{tech_name}",
        'data': {
            'technology_name': tech_name,
            'category': tech_data.get('category', ''),
            'confidence': tech_data.get('confidence', 0.5),
            'detection_method': tech_data.get('method', ''),
            'target': target,
            'evidence': tech_data.get('evidence', '')
        },
        'discovered_by': job_id,
        'active': True
    }
    
    asset_repository.create(session, asset_data)


def create_security_profile_finding(session, result: Dict[str, Any], job_id: str):
    """Create finding for poor security profile."""
    
    profile_data = result.get('profile_data', {})
    target = result.get('target', '')
    security_score = profile_data.get('security_score', 0)
    
    finding_data = {
        'title': f"Poor Security Configuration: {target}",
        'description': f"Security analysis reveals poor configuration (Score: {security_score}/100)",
        'severity': SeverityLevel.MEDIUM if security_score < 50 else SeverityLevel.LOW,
        'vulnerability_type': VulnerabilityType.MISCONFIGURATION,
        'confidence': 0.9,
        'asset_type': AssetType.APPLICATION,
        'asset_id': target,
        'affected_url': target,
        'evidence': [{
            'type': 'security_profile',
            'security_score': security_score,
            'missing_headers': profile_data.get('missing_security_headers', []),
            'timestamp': datetime.utcnow().isoformat()
        }],
        'remediation': "Implement missing security headers and improve security configuration",
        'job_id': job_id
    }
    
    finding_repository.create(session, finding_data)
