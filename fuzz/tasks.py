"""
Celery tasks for vulnerability scanning and fuzzing.

This module defines tasks for automated vulnerability detection,
fuzzing, and security testing of discovered endpoints.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs
import re
import json

from celery import Task
from automation.orchestrator import celery_app
from automation.database import get_db_session, job_repository, finding_repository, asset_repository
from automation.logging_config import audit_logger, log_scan_activity
from automation.ai_services import analyze_vulnerability
from data.schemas import ScanStatus, AssetType, SeverityLevel, VulnerabilityType, FindingStatus
import httpx
import asyncio


logger = logging.getLogger(__name__)


class BaseFuzzTask(Task):
    """Base class for fuzzing tasks."""
    
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
                    update_data['results_count'] = results.get('requests_made', 0)
                    update_data['findings_count'] = results.get('vulnerabilities_found', 0)
                
                if error:
                    update_data['error_message'] = error
                
                job_repository.update(session, job_id, update_data)
        
        except Exception as e:
            logger.error(f"Failed to update job status: {e}")


@celery_app.task(bind=True, base=BaseFuzzTask, name='fuzz.tasks.run_vulnerability_scan')
def run_vulnerability_scan(self, job_id: str, target: str, **kwargs):
    """Run comprehensive vulnerability scanning."""
    
    with get_db_session() as session:
        job_repository.update_status(session, job_id, ScanStatus.RUNNING)
    
    log_scan_activity(job_id, "vulnerability_scan_started", target=target)
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run vulnerability scanning
        results = loop.run_until_complete(
            scan_vulnerabilities(target, **kwargs)
        )
        
        # Process results and create findings
        findings_count = process_vulnerability_results(job_id, target, results)
        
        results['vulnerabilities_found'] = findings_count
        
        log_scan_activity(job_id, "vulnerability_scan_completed", 
                         requests_made=results.get('requests_made', 0),
                         vulnerabilities_found=findings_count)
        
        return results
    
    except Exception as e:
        logger.error(f"Vulnerability scan failed for job {job_id}: {e}")
        log_scan_activity(job_id, "vulnerability_scan_failed", error=str(e))
        raise


@celery_app.task(bind=True, base=BaseFuzzTask, name='fuzz.tasks.run_fuzzing_scan')
def run_fuzzing_scan(self, job_id: str, target: str, **kwargs):
    """Run parameter fuzzing on target endpoints."""
    
    with get_db_session() as session:
        job_repository.update_status(session, job_id, ScanStatus.RUNNING)
    
    log_scan_activity(job_id, "fuzzing_scan_started", target=target)
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run fuzzing
        results = loop.run_until_complete(
            fuzz_parameters(target, **kwargs)
        )
        
        # Process results
        findings_count = process_fuzzing_results(job_id, target, results)
        
        results['vulnerabilities_found'] = findings_count
        
        log_scan_activity(job_id, "fuzzing_scan_completed", 
                         requests_made=results.get('requests_made', 0),
                         vulnerabilities_found=findings_count)
        
        return results
    
    except Exception as e:
        logger.error(f"Fuzzing scan failed for job {job_id}: {e}")
        log_scan_activity(job_id, "fuzzing_scan_failed", error=str(e))
        raise


async def scan_vulnerabilities(target: str, **kwargs) -> Dict[str, Any]:
    """Scan for common vulnerabilities."""
    
    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"
    
    vulnerabilities = []
    requests_made = 0
    
    async with httpx.AsyncClient(
        timeout=30.0,
        follow_redirects=False,
        verify=False
    ) as client:
        
        # 1. Check for common files and directories
        common_vulns = await check_common_vulnerabilities(client, target)
        vulnerabilities.extend(common_vulns['vulnerabilities'])
        requests_made += common_vulns['requests_made']
        
        # 2. Check for SQL injection
        sqli_vulns = await check_sql_injection(client, target)
        vulnerabilities.extend(sqli_vulns['vulnerabilities'])
        requests_made += sqli_vulns['requests_made']
        
        # 3. Check for XSS
        xss_vulns = await check_xss_vulnerabilities(client, target)
        vulnerabilities.extend(xss_vulns['vulnerabilities'])
        requests_made += xss_vulns['requests_made']
        
        # 4. Check for SSRF
        ssrf_vulns = await check_ssrf_vulnerabilities(client, target)
        vulnerabilities.extend(ssrf_vulns['vulnerabilities'])
        requests_made += ssrf_vulns['requests_made']
        
        # 5. Check for directory traversal
        lfi_vulns = await check_directory_traversal(client, target)
        vulnerabilities.extend(lfi_vulns['vulnerabilities'])
        requests_made += lfi_vulns['requests_made']
    
    return {
        'target': target,
        'vulnerabilities': vulnerabilities,
        'requests_made': requests_made,
        'timestamp': datetime.utcnow().isoformat()
    }


async def check_common_vulnerabilities(client: httpx.AsyncClient, target: str) -> Dict[str, Any]:
    """Check for common vulnerability indicators."""
    
    vulnerabilities = []
    requests_made = 0
    
    # Common vulnerable files and directories
    vulnerable_paths = [
        '.env', '.git/config', '.svn/entries', 'web.config',
        '.htaccess', 'phpinfo.php', 'info.php', 'test.php',
        'backup.sql', 'database.sql', 'dump.sql',
        'admin.php', 'admin/', 'administrator/',
        'wp-config.php', 'wp-config.php.bak',
        'config.php', 'config.inc.php', 'configuration.php'
    ]
    
    for path in vulnerable_paths:
        try:
            url = urljoin(target, path)
            response = await client.get(url)
            requests_made += 1
            
            if response.status_code == 200:
                # Check content for sensitive information
                content = response.text.lower()
                
                if path == '.env' and ('password' in content or 'secret' in content):
                    vulnerabilities.append({
                        'type': 'info_disclosure',
                        'severity': 'high',
                        'url': url,
                        'description': 'Environment file exposed with potential secrets',
                        'evidence': response.text[:500]
                    })
                
                elif path.endswith('.sql') and ('insert into' in content or 'create table' in content):
                    vulnerabilities.append({
                        'type': 'info_disclosure',
                        'severity': 'high',
                        'url': url,
                        'description': 'Database dump file exposed',
                        'evidence': response.text[:500]
                    })
                
                elif 'phpinfo()' in content:
                    vulnerabilities.append({
                        'type': 'info_disclosure',
                        'severity': 'medium',
                        'url': url,
                        'description': 'PHP info page exposed',
                        'evidence': 'phpinfo() output detected'
                    })
                
                elif path.startswith('.git') and 'repositoryformatversion' in content:
                    vulnerabilities.append({
                        'type': 'info_disclosure',
                        'severity': 'high',
                        'url': url,
                        'description': 'Git repository exposed',
                        'evidence': 'Git configuration file accessible'
                    })
        
        except Exception:
            pass  # Continue with next path
    
    return {
        'vulnerabilities': vulnerabilities,
        'requests_made': requests_made
    }


async def check_sql_injection(client: httpx.AsyncClient, target: str) -> Dict[str, Any]:
    """Check for SQL injection vulnerabilities."""
    
    vulnerabilities = []
    requests_made = 0
    
    # SQL injection payloads
    sql_payloads = [
        "'", "''", "1'", "1' OR '1'='1", "1' OR '1'='1' --",
        "1' OR '1'='1' /*", "'; DROP TABLE users; --",
        "1' UNION SELECT 1,2,3 --", "1' AND 1=1 --", "1' AND 1=2 --"
    ]
    
    # Error patterns that indicate SQL injection
    error_patterns = [
        r"mysql_fetch_array\(\)",
        r"ORA-\d{5}",
        r"Microsoft.*ODBC.*SQL Server",
        r"PostgreSQL.*ERROR",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"OLE DB.*SQL Server",
        r"(\[SQL Server\])",
        r"(\[Microsoft\]\[ODBC SQL Server Driver\])",
        r"(\[SQLServer JDBC Driver\])",
        r"(\[SqlException",
        r"System\.Data\.SqlClient\.SqlException",
        r"Unclosed quotation mark after the character string",
        r"'80040e14'",
        r"mssql_query\(\)",
        r"odbc_exec\(\)",
        r"Microsoft Access Driver",
        r"JET Database Engine",
        r"Access Database Engine"
    ]
    
    # Test common parameters
    test_params = ['id', 'user', 'username', 'email', 'search', 'q', 'query', 'name']
    
    for param in test_params:
        for payload in sql_payloads:
            try:
                # Test GET parameter
                url = f"{target}?{param}={payload}"
                response = await client.get(url)
                requests_made += 1
                
                # Check for SQL error patterns
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'sqli',
                            'severity': 'high',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'description': f'SQL injection detected in parameter "{param}"',
                            'evidence': f'Error pattern matched: {pattern}',
                            'method': 'GET'
                        })
                        break
                
                # Test POST parameter
                try:
                    response = await client.post(target, data={param: payload})
                    requests_made += 1
                    
                    for pattern in error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerabilities.append({
                                'type': 'sqli',
                                'severity': 'high',
                                'url': target,
                                'parameter': param,
                                'payload': payload,
                                'description': f'SQL injection detected in POST parameter "{param}"',
                                'evidence': f'Error pattern matched: {pattern}',
                                'method': 'POST'
                            })
                            break
                except Exception:
                    pass
            
            except Exception:
                pass
    
    return {
        'vulnerabilities': vulnerabilities,
        'requests_made': requests_made
    }


async def check_xss_vulnerabilities(client: httpx.AsyncClient, target: str) -> Dict[str, Any]:
    """Check for XSS vulnerabilities."""
    
    vulnerabilities = []
    requests_made = 0
    
    # XSS payloads
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<iframe src=javascript:alert('XSS')></iframe>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>"
    ]
    
    # Test parameters
    test_params = ['q', 'search', 'query', 'name', 'comment', 'message', 'text']
    
    for param in test_params:
        for payload in xss_payloads:
            try:
                # Test GET parameter
                url = f"{target}?{param}={payload}"
                response = await client.get(url)
                requests_made += 1
                
                # Check if payload is reflected in response
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'xss',
                        'severity': 'medium',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'description': f'Reflected XSS detected in parameter "{param}"',
                        'evidence': f'Payload reflected in response: {payload}',
                        'method': 'GET'
                    })
                
                # Test POST parameter
                try:
                    response = await client.post(target, data={param: payload})
                    requests_made += 1
                    
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'xss',
                            'severity': 'medium',
                            'url': target,
                            'parameter': param,
                            'payload': payload,
                            'description': f'Reflected XSS detected in POST parameter "{param}"',
                            'evidence': f'Payload reflected in response: {payload}',
                            'method': 'POST'
                        })
                except Exception:
                    pass
            
            except Exception:
                pass
    
    return {
        'vulnerabilities': vulnerabilities,
        'requests_made': requests_made
    }


async def check_ssrf_vulnerabilities(client: httpx.AsyncClient, target: str) -> Dict[str, Any]:
    """Check for SSRF vulnerabilities."""
    
    vulnerabilities = []
    requests_made = 0
    
    # SSRF payloads
    ssrf_payloads = [
        "http://127.0.0.1:80",
        "http://localhost:80",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
        "file:///etc/passwd",
        "file:///c:/windows/system32/drivers/etc/hosts",
        "http://0.0.0.0:22",
        "http://[::1]:80",
        "gopher://127.0.0.1:25/"
    ]
    
    # Parameters that might be vulnerable to SSRF
    ssrf_params = ['url', 'uri', 'path', 'continue', 'dest', 'redirect', 'return_to', 'go', 'file']
    
    for param in ssrf_params:
        for payload in ssrf_payloads:
            try:
                # Test GET parameter
                url = f"{target}?{param}={payload}"
                response = await client.get(url, timeout=10)
                requests_made += 1
                
                # Check for SSRF indicators
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    # Check for internal service responses
                    if any(indicator in content for indicator in [
                        'root:x:', 'daemon:x:', 'bin:x:',  # /etc/passwd
                        'localhost', '127.0.0.1',
                        'instance-id', 'ami-id',  # AWS metadata
                        'computemetadata'  # GCP metadata
                    ]):
                        vulnerabilities.append({
                            'type': 'ssrf',
                            'severity': 'high',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'description': f'SSRF detected in parameter "{param}"',
                            'evidence': 'Internal service response detected',
                            'method': 'GET'
                        })
            
            except Exception:
                pass
    
    return {
        'vulnerabilities': vulnerabilities,
        'requests_made': requests_made
    }


async def check_directory_traversal(client: httpx.AsyncClient, target: str) -> Dict[str, Any]:
    """Check for directory traversal vulnerabilities."""
    
    vulnerabilities = []
    requests_made = 0
    
    # Directory traversal payloads
    traversal_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
    ]
    
    # Parameters that might be vulnerable
    file_params = ['file', 'path', 'include', 'page', 'template', 'document', 'filename']
    
    for param in file_params:
        for payload in traversal_payloads:
            try:
                url = f"{target}?{param}={payload}"
                response = await client.get(url)
                requests_made += 1
                
                # Check for file content indicators
                content = response.text.lower()
                if any(indicator in content for indicator in [
                    'root:x:', 'daemon:x:', 'bin:x:',  # /etc/passwd
                    '# localhost', '127.0.0.1',  # hosts file
                    '[boot loader]', '[operating systems]'  # Windows boot.ini
                ]):
                    vulnerabilities.append({
                        'type': 'directory_traversal',
                        'severity': 'high',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'description': f'Directory traversal detected in parameter "{param}"',
                        'evidence': 'System file content detected',
                        'method': 'GET'
                    })
            
            except Exception:
                pass
    
    return {
        'vulnerabilities': vulnerabilities,
        'requests_made': requests_made
    }


async def fuzz_parameters(target: str, **kwargs) -> Dict[str, Any]:
    """Fuzz parameters for various vulnerability types."""
    
    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"
    
    vulnerabilities = []
    requests_made = 0
    
    # Get endpoints to fuzz from database
    endpoints = get_endpoints_for_fuzzing(target)
    
    async with httpx.AsyncClient(
        timeout=30.0,
        follow_redirects=False,
        verify=False
    ) as client:
        
        for endpoint in endpoints:
            endpoint_vulns = await fuzz_endpoint(client, endpoint)
            vulnerabilities.extend(endpoint_vulns['vulnerabilities'])
            requests_made += endpoint_vulns['requests_made']
    
    return {
        'target': target,
        'vulnerabilities': vulnerabilities,
        'requests_made': requests_made,
        'endpoints_fuzzed': len(endpoints),
        'timestamp': datetime.utcnow().isoformat()
    }


def get_endpoints_for_fuzzing(target: str) -> List[Dict[str, Any]]:
    """Get endpoints from database for fuzzing."""
    
    endpoints = []
    
    try:
        with get_db_session() as session:
            # Get endpoints for this target
            assets = session.query(asset_repository.model_class).filter(
                asset_repository.model_class.asset_type == AssetType.ENDPOINT.value,
                asset_repository.model_class.name.like(f"{target}%"),
                asset_repository.model_class.active == True
            ).limit(50).all()  # Limit to prevent overwhelming
            
            for asset in assets:
                endpoints.append({
                    'url': asset.name,
                    'method': asset.data.get('method', 'GET'),
                    'parameters': asset.data.get('parameters', [])
                })
    
    except Exception as e:
        logger.error(f"Failed to get endpoints for fuzzing: {e}")
    
    return endpoints


async def fuzz_endpoint(client: httpx.AsyncClient, endpoint: Dict[str, Any]) -> Dict[str, Any]:
    """Fuzz a specific endpoint."""
    
    vulnerabilities = []
    requests_made = 0
    
    url = endpoint['url']
    method = endpoint.get('method', 'GET')
    parameters = endpoint.get('parameters', [])
    
    # Basic fuzzing payloads
    fuzz_payloads = [
        "' OR '1'='1",  # SQL injection
        "<script>alert(1)</script>",  # XSS
        "../../../etc/passwd",  # Directory traversal
        "http://127.0.0.1:80",  # SSRF
        "{{7*7}}",  # Template injection
        "${7*7}",  # Expression injection
        "A" * 1000,  # Buffer overflow
        "\x00",  # Null byte injection
        "%00",  # URL encoded null byte
    ]
    
    for param in parameters:
        for payload in fuzz_payloads:
            try:
                if method.upper() == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    response = await client.get(test_url)
                else:
                    response = await client.post(url, data={param: payload})
                
                requests_made += 1
                
                # Analyze response for vulnerabilities
                vuln = analyze_fuzz_response(url, param, payload, response, method)
                if vuln:
                    vulnerabilities.append(vuln)
            
            except Exception:
                pass
    
    return {
        'vulnerabilities': vulnerabilities,
        'requests_made': requests_made
    }


def analyze_fuzz_response(url: str, param: str, payload: str, response: httpx.Response, method: str) -> Optional[Dict[str, Any]]:
    """Analyze fuzzing response for vulnerabilities."""
    
    content = response.text
    
    # SQL injection detection
    sql_errors = [
        "mysql_fetch_array", "ORA-", "SQL Server", "PostgreSQL ERROR",
        "mysql_", "SqlException", "OLE DB", "ODBC SQL Server Driver"
    ]
    
    for error in sql_errors:
        if error.lower() in content.lower():
            return {
                'type': 'sqli',
                'severity': 'high',
                'url': url,
                'parameter': param,
                'payload': payload,
                'description': f'SQL injection detected in parameter "{param}"',
                'evidence': f'SQL error detected: {error}',
                'method': method
            }
    
    # XSS detection
    if payload in content and '<script>' in payload:
        return {
            'type': 'xss',
            'severity': 'medium',
            'url': url,
            'parameter': param,
            'payload': payload,
            'description': f'XSS detected in parameter "{param}"',
            'evidence': 'Payload reflected in response',
            'method': method
        }
    
    # Directory traversal detection
    if any(indicator in content.lower() for indicator in ['root:x:', 'daemon:x:', 'bin:x:']):
        return {
            'type': 'directory_traversal',
            'severity': 'high',
            'url': url,
            'parameter': param,
            'payload': payload,
            'description': f'Directory traversal detected in parameter "{param}"',
            'evidence': 'System file content detected',
            'method': method
        }
    
    # Template injection detection
    if payload in ["{{7*7}}", "${7*7}"] and "49" in content:
        return {
            'type': 'template_injection',
            'severity': 'high',
            'url': url,
            'parameter': param,
            'payload': payload,
            'description': f'Template injection detected in parameter "{param}"',
            'evidence': 'Mathematical expression evaluated',
            'method': method
        }
    
    return None


def process_vulnerability_results(job_id: str, target: str, results: Dict[str, Any]) -> int:
    """Process vulnerability scan results and create findings."""
    
    findings_count = 0
    
    try:
        with get_db_session() as session:
            for vuln in results.get('vulnerabilities', []):
                create_vulnerability_finding(session, vuln, job_id)
                findings_count += 1
    
    except Exception as e:
        logger.error(f"Failed to process vulnerability results: {e}")
    
    return findings_count


def process_fuzzing_results(job_id: str, target: str, results: Dict[str, Any]) -> int:
    """Process fuzzing results and create findings."""
    
    findings_count = 0
    
    try:
        with get_db_session() as session:
            for vuln in results.get('vulnerabilities', []):
                create_vulnerability_finding(session, vuln, job_id)
                findings_count += 1
    
    except Exception as e:
        logger.error(f"Failed to process fuzzing results: {e}")
    
    return findings_count


def create_vulnerability_finding(session, vuln: Dict[str, Any], job_id: str):
    """Create a vulnerability finding in the database."""
    
    # Map vulnerability types
    vuln_type_mapping = {
        'sqli': VulnerabilityType.SQLI,
        'xss': VulnerabilityType.XSS,
        'ssrf': VulnerabilityType.SSRF,
        'directory_traversal': VulnerabilityType.FILE_UPLOAD,  # Close enough
        'template_injection': VulnerabilityType.LOGIC_FLAW,
        'info_disclosure': VulnerabilityType.INFO_DISCLOSURE
    }
    
    # Map severity levels
    severity_mapping = {
        'critical': SeverityLevel.CRITICAL,
        'high': SeverityLevel.HIGH,
        'medium': SeverityLevel.MEDIUM,
        'low': SeverityLevel.LOW,
        'info': SeverityLevel.INFO
    }
    
    vuln_type = vuln_type_mapping.get(vuln.get('type'), VulnerabilityType.LOGIC_FLAW)
    severity = severity_mapping.get(vuln.get('severity'), SeverityLevel.MEDIUM)
    
    finding_data = {
        'title': vuln.get('description', f"{vuln.get('type', 'Unknown')} vulnerability detected"),
        'description': vuln.get('description', ''),
        'severity': severity,
        'vulnerability_type': vuln_type,
        'confidence': 0.8,  # High confidence for automated detection
        'asset_type': AssetType.ENDPOINT,
        'asset_id': vuln.get('url', ''),
        'affected_url': vuln.get('url'),
        'affected_parameter': vuln.get('parameter'),
        'evidence': [{
            'type': 'http_request',
            'description': f"Payload: {vuln.get('payload', '')}",
            'details': vuln.get('evidence', ''),
            'timestamp': datetime.utcnow().isoformat()
        }],
        'job_id': job_id
    }
    
    finding_repository.create(session, finding_data)
