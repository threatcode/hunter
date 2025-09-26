"""
CVE scanner integration with Nuclei and custom vulnerability detection.

This module implements integration with Nuclei templates and custom
CVE detection for comprehensive vulnerability scanning.
"""

import asyncio
import logging
import json
import subprocess
import tempfile
import os
from datetime import datetime
from typing import Dict, List, Optional, Set, Any, Tuple
from pathlib import Path
import aiohttp
import yaml

from recon.collectors import BaseCollector


logger = logging.getLogger(__name__)


class NucleiIntegration:
    """Integration with Nuclei vulnerability scanner."""
    
    def __init__(self):
        self.nuclei_path = self._find_nuclei_binary()
        self.templates_path = self._get_templates_path()
        self.custom_templates = []
    
    def _find_nuclei_binary(self) -> Optional[str]:
        """Find Nuclei binary in system PATH."""
        try:
            result = subprocess.run(['which', 'nuclei'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        # Check common installation paths
        common_paths = [
            '/usr/local/bin/nuclei',
            '/usr/bin/nuclei',
            '/opt/nuclei/nuclei',
            os.path.expanduser('~/go/bin/nuclei')
        ]
        
        for path in common_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path
        
        logger.warning("Nuclei binary not found. Please install Nuclei for CVE scanning.")
        return None
    
    def _get_templates_path(self) -> Optional[str]:
        """Get Nuclei templates directory."""
        try:
            # Try to get templates path from nuclei config
            result = subprocess.run(['nuclei', '-version'], capture_output=True, text=True)
            if result.returncode == 0:
                # Default templates path
                templates_path = os.path.expanduser('~/nuclei-templates')
                if os.path.exists(templates_path):
                    return templates_path
        except:
            pass
        
        return None
    
    async def install_nuclei(self) -> bool:
        """Install Nuclei if not present."""
        if self.nuclei_path:
            return True
        
        try:
            logger.info("Installing Nuclei...")
            
            # Install via go
            install_cmd = [
                'go', 'install', '-v', 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *install_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                self.nuclei_path = os.path.expanduser('~/go/bin/nuclei')
                logger.info("Nuclei installed successfully")
                return True
            else:
                logger.error(f"Failed to install Nuclei: {stderr.decode()}")
                return False
        
        except Exception as e:
            logger.error(f"Error installing Nuclei: {e}")
            return False
    
    async def update_templates(self) -> bool:
        """Update Nuclei templates."""
        if not self.nuclei_path:
            return False
        
        try:
            logger.info("Updating Nuclei templates...")
            
            update_cmd = [self.nuclei_path, '-update-templates']
            
            process = await asyncio.create_subprocess_exec(
                *update_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.info("Nuclei templates updated successfully")
                return True
            else:
                logger.warning(f"Template update warning: {stderr.decode()}")
                return True  # Templates might already be up to date
        
        except Exception as e:
            logger.error(f"Error updating templates: {e}")
            return False
    
    async def run_nuclei_scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run Nuclei scan against target."""
        
        if not self.nuclei_path:
            logger.error("Nuclei not available for scanning")
            return {'error': 'Nuclei not installed'}
        
        scan_results = {
            'target': target,
            'vulnerabilities': [],
            'scan_stats': {
                'templates_loaded': 0,
                'requests_made': 0,
                'findings_count': 0
            },
            'scan_time': 0,
            'nuclei_version': ''
        }
        
        try:
            # Create temporary output file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                output_file = temp_file.name
            
            # Build Nuclei command
            nuclei_cmd = [
                self.nuclei_path,
                '-target', target,
                '-json',
                '-output', output_file,
                '-stats',
                '-silent'
            ]
            
            # Add template filters
            severity = kwargs.get('severity', ['critical', 'high', 'medium'])
            if severity:
                nuclei_cmd.extend(['-severity', ','.join(severity)])
            
            tags = kwargs.get('tags', [])
            if tags:
                nuclei_cmd.extend(['-tags', ','.join(tags)])
            
            templates = kwargs.get('templates', [])
            if templates:
                nuclei_cmd.extend(['-templates', ','.join(templates)])
            
            # Rate limiting
            rate_limit = kwargs.get('rate_limit', 150)
            nuclei_cmd.extend(['-rate-limit', str(rate_limit)])
            
            # Timeout
            timeout = kwargs.get('timeout', 30)
            nuclei_cmd.extend(['-timeout', str(timeout)])
            
            # Run Nuclei
            start_time = asyncio.get_event_loop().time()
            
            process = await asyncio.create_subprocess_exec(
                *nuclei_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            scan_time = asyncio.get_event_loop().time() - start_time
            scan_results['scan_time'] = scan_time
            
            # Parse results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            result = json.loads(line.strip())
                            vulnerability = self._parse_nuclei_result(result)
                            if vulnerability:
                                scan_results['vulnerabilities'].append(vulnerability)
                        except json.JSONDecodeError:
                            continue
                
                # Clean up
                os.unlink(output_file)
            
            # Parse stats from stderr
            stderr_text = stderr.decode()
            scan_results['scan_stats'] = self._parse_nuclei_stats(stderr_text)
            scan_results['scan_stats']['findings_count'] = len(scan_results['vulnerabilities'])
            
            logger.info(f"Nuclei scan completed: {len(scan_results['vulnerabilities'])} vulnerabilities found")
            
        except Exception as e:
            logger.error(f"Error running Nuclei scan: {e}")
            scan_results['error'] = str(e)
        
        return scan_results
    
    def _parse_nuclei_result(self, result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse individual Nuclei result."""
        
        try:
            vulnerability = {
                'template_id': result.get('template-id', ''),
                'template_name': result.get('info', {}).get('name', ''),
                'severity': result.get('info', {}).get('severity', 'unknown'),
                'description': result.get('info', {}).get('description', ''),
                'reference': result.get('info', {}).get('reference', []),
                'classification': result.get('info', {}).get('classification', {}),
                'tags': result.get('info', {}).get('tags', []),
                'matched_at': result.get('matched-at', ''),
                'extracted_results': result.get('extracted-results', []),
                'request': result.get('request', ''),
                'response': result.get('response', ''),
                'curl_command': result.get('curl-command', ''),
                'timestamp': result.get('timestamp', datetime.utcnow().isoformat())
            }
            
            # Extract CVE information
            cve_ids = []
            classification = vulnerability['classification']
            if 'cve-id' in classification:
                cve_ids = classification['cve-id']
            elif 'cve' in classification:
                cve_ids = classification['cve']
            
            vulnerability['cve_ids'] = cve_ids if isinstance(cve_ids, list) else [cve_ids] if cve_ids else []
            
            # Extract CVSS score
            cvss_score = classification.get('cvss-score', 0.0)
            vulnerability['cvss_score'] = float(cvss_score) if cvss_score else 0.0
            
            return vulnerability
        
        except Exception as e:
            logger.debug(f"Error parsing Nuclei result: {e}")
            return None
    
    def _parse_nuclei_stats(self, stderr_text: str) -> Dict[str, int]:
        """Parse Nuclei statistics from stderr."""
        
        stats = {
            'templates_loaded': 0,
            'requests_made': 0,
            'errors': 0
        }
        
        try:
            import re
            
            # Parse templates loaded
            templates_match = re.search(r'(\d+)\s+templates\s+loaded', stderr_text)
            if templates_match:
                stats['templates_loaded'] = int(templates_match.group(1))
            
            # Parse requests made
            requests_match = re.search(r'(\d+)\s+requests\s+made', stderr_text)
            if requests_match:
                stats['requests_made'] = int(requests_match.group(1))
            
            # Parse errors
            errors_match = re.search(r'(\d+)\s+errors?', stderr_text)
            if errors_match:
                stats['errors'] = int(errors_match.group(1))
        
        except Exception as e:
            logger.debug(f"Error parsing Nuclei stats: {e}")
        
        return stats


class CustomCVEDatabase:
    """Custom CVE database and detection rules."""
    
    def __init__(self):
        self.cve_database = self._load_cve_database()
        self.custom_rules = self._load_custom_rules()
    
    def _load_cve_database(self) -> Dict[str, Any]:
        """Load custom CVE database."""
        return {
            'CVE-2023-46604': {
                'description': 'Apache ActiveMQ RCE',
                'severity': 'critical',
                'cvss_score': 10.0,
                'detection_rules': [
                    {
                        'path': '/admin/queues.jsp',
                        'method': 'GET',
                        'indicators': ['ActiveMQ', 'Queues']
                    }
                ]
            },
            'CVE-2023-22515': {
                'description': 'Atlassian Confluence Privilege Escalation',
                'severity': 'critical',
                'cvss_score': 10.0,
                'detection_rules': [
                    {
                        'path': '/setup/setupadministrator.action',
                        'method': 'GET',
                        'indicators': ['Confluence', 'Administrator Setup']
                    }
                ]
            },
            'CVE-2023-34362': {
                'description': 'MOVEit Transfer SQL Injection',
                'severity': 'critical',
                'cvss_score': 9.8,
                'detection_rules': [
                    {
                        'path': '/human.aspx',
                        'method': 'GET',
                        'indicators': ['MOVEit', 'Transfer']
                    }
                ]
            },
            'CVE-2023-20198': {
                'description': 'Cisco ASA/FTD Path Traversal',
                'severity': 'critical',
                'cvss_score': 10.0,
                'detection_rules': [
                    {
                        'path': '/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../../../../../../../../../etc/passwd%00',
                        'method': 'GET',
                        'indicators': ['root:', 'daemon:']
                    }
                ]
            },
            'CVE-2022-47966': {
                'description': 'Zoho ManageEngine SAML SSO Authentication Bypass',
                'severity': 'critical',
                'cvss_score': 9.8,
                'detection_rules': [
                    {
                        'path': '/saml/SSO',
                        'method': 'GET',
                        'indicators': ['ManageEngine', 'SAML']
                    }
                ]
            }
        }
    
    def _load_custom_rules(self) -> List[Dict[str, Any]]:
        """Load custom detection rules."""
        return [
            {
                'name': 'Exposed Git Directory',
                'severity': 'medium',
                'paths': ['/.git/', '/.git/config', '/.git/HEAD'],
                'indicators': ['[core]', 'repositoryformatversion', 'ref: refs/heads/']
            },
            {
                'name': 'Exposed SVN Directory',
                'severity': 'medium',
                'paths': ['/.svn/', '/.svn/entries'],
                'indicators': ['svn:special', 'svn:externals']
            },
            {
                'name': 'Exposed Environment Files',
                'severity': 'high',
                'paths': ['/.env', '/.env.local', '/.env.production'],
                'indicators': ['API_KEY', 'SECRET', 'PASSWORD', 'DATABASE_URL']
            },
            {
                'name': 'Exposed Backup Files',
                'severity': 'medium',
                'paths': ['/backup.sql', '/database.sql', '/dump.sql', '/backup.zip'],
                'indicators': ['CREATE TABLE', 'INSERT INTO', 'DROP TABLE']
            },
            {
                'name': 'Admin Panel Exposure',
                'severity': 'medium',
                'paths': ['/admin/', '/administrator/', '/wp-admin/', '/phpmyadmin/'],
                'indicators': ['login', 'password', 'username', 'admin']
            }
        ]
    
    async def scan_custom_cves(self, target: str) -> List[Dict[str, Any]]:
        """Scan for custom CVE patterns."""
        
        vulnerabilities = []
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            
            # Test CVE-specific patterns
            for cve_id, cve_data in self.cve_database.items():
                for rule in cve_data['detection_rules']:
                    vuln = await self._test_cve_rule(session, target, cve_id, cve_data, rule)
                    if vuln:
                        vulnerabilities.append(vuln)
            
            # Test custom rules
            for rule in self.custom_rules:
                vuln = await self._test_custom_rule(session, target, rule)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_cve_rule(self, session: aiohttp.ClientSession, target: str,
                           cve_id: str, cve_data: Dict[str, Any], rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test a specific CVE detection rule."""
        
        try:
            url = f"{target.rstrip('/')}{rule['path']}"
            method = rule.get('method', 'GET')
            
            if method == 'GET':
                async with session.get(url) as response:
                    content = await response.text()
            else:
                async with session.request(method, url) as response:
                    content = await response.text()
            
            # Check for indicators
            indicators_found = []
            for indicator in rule.get('indicators', []):
                if indicator in content:
                    indicators_found.append(indicator)
            
            if indicators_found:
                return {
                    'cve_id': cve_id,
                    'description': cve_data['description'],
                    'severity': cve_data['severity'],
                    'cvss_score': cve_data['cvss_score'],
                    'url': url,
                    'method': method,
                    'indicators_found': indicators_found,
                    'response_status': response.status,
                    'detection_type': 'custom_cve',
                    'timestamp': datetime.utcnow().isoformat()
                }
        
        except Exception as e:
            logger.debug(f"Error testing CVE rule {cve_id}: {e}")
        
        return None
    
    async def _test_custom_rule(self, session: aiohttp.ClientSession, target: str,
                              rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test a custom detection rule."""
        
        for path in rule.get('paths', []):
            try:
                url = f"{target.rstrip('/')}{path}"
                
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for indicators
                        indicators_found = []
                        for indicator in rule.get('indicators', []):
                            if indicator in content:
                                indicators_found.append(indicator)
                        
                        if indicators_found:
                            return {
                                'rule_name': rule['name'],
                                'severity': rule['severity'],
                                'url': url,
                                'indicators_found': indicators_found,
                                'response_status': response.status,
                                'detection_type': 'custom_rule',
                                'timestamp': datetime.utcnow().isoformat()
                            }
            
            except Exception as e:
                logger.debug(f"Error testing custom rule {rule['name']}: {e}")
                continue
        
        return None


class CVEScannerCollector(BaseCollector):
    """CVE scanner collector integrating Nuclei and custom detection."""
    
    def __init__(self):
        super().__init__("cve_scanner")
        self.nuclei_integration = NucleiIntegration()
        self.custom_cve_db = CustomCVEDatabase()
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Perform comprehensive CVE scanning."""
        
        # Ensure target is a full URL
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # Run Nuclei scan if available
        nuclei_results = await self.nuclei_integration.run_nuclei_scan(target, **kwargs)
        
        # Store Nuclei results
        self.add_result({
            'type': 'nuclei_scan_results',
            'target': target,
            'nuclei_data': nuclei_results
        })
        
        # Process Nuclei vulnerabilities
        for vulnerability in nuclei_results.get('vulnerabilities', []):
            self.add_result({
                'type': 'nuclei_vulnerability',
                'target': target,
                'vulnerability': vulnerability
            })
        
        # Run custom CVE detection
        custom_vulnerabilities = await self.custom_cve_db.scan_custom_cves(target)
        
        # Process custom vulnerabilities
        for vulnerability in custom_vulnerabilities:
            self.add_result({
                'type': 'custom_cve_vulnerability',
                'target': target,
                'vulnerability': vulnerability
            })
        
        return self.results


# Standalone usage
if __name__ == "__main__":
    async def test_cve_scanner():
        collector = CVEScannerCollector()
        results = await collector.collect(
            "https://httpbin.org",
            severity=['critical', 'high'],
            rate_limit=100
        )
        
        print(f"CVE scanning completed with {len(results)} results")
        for result in results[:5]:
            print(f"- {result.get('type')}: {result}")
    
    asyncio.run(test_cve_scanner())
