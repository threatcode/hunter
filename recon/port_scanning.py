"""
Advanced port scanning and screenshotting pipeline.

This module implements comprehensive port scanning with service detection,
automated screenshotting, and service enumeration capabilities.
"""

import asyncio
import logging
import subprocess
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Set, Any, Tuple
import aiohttp
from pathlib import Path

from recon.collectors import BaseCollector
from automation.logging_config import screenshot_manager, evidence_store


logger = logging.getLogger(__name__)


class PortScanner:
    """Advanced port scanning with multiple techniques."""
    
    def __init__(self):
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017
        ]
        
        self.top_1000_ports = list(range(1, 1001))
        
        self.service_signatures = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            111: 'rpcbind',
            135: 'msrpc',
            139: 'netbios-ssn',
            143: 'imap',
            443: 'https',
            993: 'imaps',
            995: 'pop3s',
            1723: 'pptp',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            5900: 'vnc',
            6379: 'redis',
            8080: 'http-proxy',
            8443: 'https-alt',
            8888: 'http-alt',
            9200: 'elasticsearch',
            27017: 'mongodb'
        }
    
    async def scan_host(self, target: str, scan_type: str = 'common', **kwargs) -> Dict[str, Any]:
        """Scan a single host for open ports."""
        
        scan_results = {
            'target': target,
            'scan_type': scan_type,
            'open_ports': [],
            'filtered_ports': [],
            'closed_ports': [],
            'scan_time': datetime.utcnow().isoformat(),
            'scan_duration': 0
        }
        
        start_time = datetime.utcnow()
        
        try:
            if scan_type == 'nmap':
                scan_results = await self._nmap_scan(target, **kwargs)
            elif scan_type == 'masscan':
                scan_results = await self._masscan_scan(target, **kwargs)
            else:
                scan_results = await self._python_scan(target, scan_type, **kwargs)
            
            scan_results['scan_duration'] = (datetime.utcnow() - start_time).total_seconds()
        
        except Exception as e:
            logger.error(f"Port scan failed for {target}: {e}")
            scan_results['error'] = str(e)
        
        return scan_results
    
    async def _nmap_scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform nmap scan."""
        
        # Build nmap command
        nmap_args = ['nmap', '-sS', '-T4', '--open']
        
        # Port specification
        ports = kwargs.get('ports', 'common')
        if ports == 'common':
            nmap_args.extend(['-p', ','.join(map(str, self.common_ports))])
        elif ports == 'top1000':
            nmap_args.append('--top-ports=1000')
        elif ports == 'all':
            nmap_args.extend(['-p', '1-65535'])
        else:
            nmap_args.extend(['-p', str(ports)])
        
        # Service detection
        if kwargs.get('service_detection', True):
            nmap_args.extend(['-sV', '--version-intensity=5'])
        
        # OS detection
        if kwargs.get('os_detection', False):
            nmap_args.append('-O')
        
        # Script scanning
        scripts = kwargs.get('scripts', [])
        if scripts:
            nmap_args.extend(['--script', ','.join(scripts)])
        
        # Output format
        nmap_args.extend(['-oX', '-'])  # XML output to stdout
        nmap_args.append(target)
        
        try:
            # Run nmap
            process = await asyncio.create_subprocess_exec(
                *nmap_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return self._parse_nmap_xml(stdout.decode())
            else:
                raise Exception(f"Nmap failed: {stderr.decode()}")
        
        except FileNotFoundError:
            raise Exception("Nmap not found. Please install nmap.")
    
    async def _masscan_scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform masscan scan for high-speed scanning."""
        
        # Build masscan command
        masscan_args = ['masscan']
        
        # Port specification
        ports = kwargs.get('ports', 'common')
        if ports == 'common':
            masscan_args.extend(['-p', ','.join(map(str, self.common_ports))])
        elif ports == 'top1000':
            masscan_args.extend(['-p', '1-1000'])
        elif ports == 'all':
            masscan_args.extend(['-p', '1-65535'])
        else:
            masscan_args.extend(['-p', str(ports)])
        
        # Rate limiting
        rate = kwargs.get('rate', '1000')
        masscan_args.extend(['--rate', str(rate)])
        
        # Output format
        masscan_args.extend(['-oJ', '-'])  # JSON output to stdout
        masscan_args.append(target)
        
        try:
            # Run masscan
            process = await asyncio.create_subprocess_exec(
                *masscan_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return self._parse_masscan_json(stdout.decode())
            else:
                raise Exception(f"Masscan failed: {stderr.decode()}")
        
        except FileNotFoundError:
            raise Exception("Masscan not found. Please install masscan.")
    
    async def _python_scan(self, target: str, scan_type: str, **kwargs) -> Dict[str, Any]:
        """Perform Python-based port scan."""
        
        if scan_type == 'common':
            ports_to_scan = self.common_ports
        elif scan_type == 'top1000':
            ports_to_scan = self.top_1000_ports
        else:
            ports_to_scan = kwargs.get('port_list', self.common_ports)
        
        open_ports = []
        
        # Scan ports concurrently
        semaphore = asyncio.Semaphore(50)  # Limit concurrent connections
        
        async def scan_port(port):
            async with semaphore:
                return await self._test_port_connection(target, port)
        
        tasks = [scan_port(port) for port in ports_to_scan]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for port, result in zip(ports_to_scan, results):
            if isinstance(result, dict) and result.get('open'):
                open_ports.append({
                    'port': port,
                    'protocol': 'tcp',
                    'service': self.service_signatures.get(port, 'unknown'),
                    'banner': result.get('banner', ''),
                    'response_time': result.get('response_time', 0)
                })
        
        return {
            'target': target,
            'scan_type': scan_type,
            'open_ports': open_ports,
            'total_ports_scanned': len(ports_to_scan)
        }
    
    async def _test_port_connection(self, host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
        """Test connection to a specific port."""
        
        start_time = asyncio.get_event_loop().time()
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            response_time = asyncio.get_event_loop().time() - start_time
            
            # Try to grab banner
            banner = ''
            try:
                # Wait briefly for banner
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner = banner_data.decode('utf-8', errors='ignore').strip()
            except:
                pass
            
            writer.close()
            await writer.wait_closed()
            
            return {
                'open': True,
                'banner': banner,
                'response_time': response_time
            }
        
        except:
            return {'open': False}
    
    def _parse_nmap_xml(self, xml_output: str) -> Dict[str, Any]:
        """Parse nmap XML output."""
        
        try:
            root = ET.fromstring(xml_output)
            
            scan_results = {
                'open_ports': [],
                'scan_info': {}
            }
            
            # Parse scan info
            scaninfo = root.find('scaninfo')
            if scaninfo is not None:
                scan_results['scan_info'] = {
                    'type': scaninfo.get('type'),
                    'protocol': scaninfo.get('protocol'),
                    'numservices': scaninfo.get('numservices')
                }
            
            # Parse hosts
            for host in root.findall('host'):
                # Get host address
                address = host.find('address')
                if address is not None:
                    host_addr = address.get('addr')
                
                # Parse ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_id = int(port.get('portid'))
                        protocol = port.get('protocol')
                        
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            
                            # Get service info
                            service = port.find('service')
                            service_info = {}
                            if service is not None:
                                service_info = {
                                    'name': service.get('name', ''),
                                    'product': service.get('product', ''),
                                    'version': service.get('version', ''),
                                    'extrainfo': service.get('extrainfo', '')
                                }
                            
                            scan_results['open_ports'].append({
                                'port': port_id,
                                'protocol': protocol,
                                'service': service_info,
                                'host': host_addr
                            })
            
            return scan_results
        
        except ET.ParseError as e:
            raise Exception(f"Failed to parse nmap XML: {e}")
    
    def _parse_masscan_json(self, json_output: str) -> Dict[str, Any]:
        """Parse masscan JSON output."""
        
        scan_results = {'open_ports': []}
        
        try:
            for line in json_output.strip().split('\n'):
                if line.strip():
                    data = json.loads(line)
                    
                    if 'ports' in data:
                        for port_info in data['ports']:
                            scan_results['open_ports'].append({
                                'port': port_info['port'],
                                'protocol': port_info['proto'],
                                'service': self.service_signatures.get(port_info['port'], 'unknown'),
                                'host': data['ip'],
                                'timestamp': data.get('timestamp')
                            })
        
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse masscan JSON: {e}")
        
        return scan_results


class ServiceEnumerator:
    """Enumerate and fingerprint services on open ports."""
    
    def __init__(self):
        self.http_ports = [80, 443, 8080, 8443, 8888, 9200]
        self.database_ports = [3306, 5432, 6379, 27017, 1433, 1521]
        self.remote_access_ports = [22, 23, 3389, 5900]
    
    async def enumerate_services(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enumerate services found in port scan results."""
        
        services = []
        
        for port_info in scan_results.get('open_ports', []):
            port = port_info['port']
            host = scan_results.get('target', port_info.get('host', ''))
            
            service_info = await self._enumerate_service(host, port, port_info)
            if service_info:
                services.append(service_info)
        
        return services
    
    async def _enumerate_service(self, host: str, port: int, port_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Enumerate a specific service."""
        
        service_data = {
            'host': host,
            'port': port,
            'protocol': port_info.get('protocol', 'tcp'),
            'service_name': port_info.get('service', 'unknown'),
            'enumeration_time': datetime.utcnow().isoformat()
        }
        
        try:
            if port in self.http_ports:
                http_info = await self._enumerate_http_service(host, port)
                service_data.update(http_info)
            
            elif port in self.database_ports:
                db_info = await self._enumerate_database_service(host, port)
                service_data.update(db_info)
            
            elif port in self.remote_access_ports:
                remote_info = await self._enumerate_remote_access_service(host, port)
                service_data.update(remote_info)
            
            else:
                # Generic service enumeration
                generic_info = await self._enumerate_generic_service(host, port)
                service_data.update(generic_info)
        
        except Exception as e:
            service_data['enumeration_error'] = str(e)
        
        return service_data
    
    async def _enumerate_http_service(self, host: str, port: int) -> Dict[str, Any]:
        """Enumerate HTTP/HTTPS service."""
        
        http_info = {}
        
        # Determine protocol
        protocol = 'https' if port in [443, 8443] else 'http'
        base_url = f"{protocol}://{host}:{port}"
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10),
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                
                # Get main page
                async with session.get(base_url) as response:
                    http_info.update({
                        'url': base_url,
                        'status_code': response.status,
                        'headers': dict(response.headers),
                        'content_length': response.headers.get('content-length', 0),
                        'server': response.headers.get('server', ''),
                        'powered_by': response.headers.get('x-powered-by', ''),
                        'content_type': response.headers.get('content-type', '')
                    })
                    
                    # Get page title
                    if response.status == 200:
                        content = await response.text()
                        title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                        if title_match:
                            http_info['title'] = title_match.group(1).strip()
                
                # Check common paths
                common_paths = [
                    '/robots.txt', '/sitemap.xml', '/admin', '/login',
                    '/api', '/swagger.json', '/openapi.json'
                ]
                
                accessible_paths = []
                for path in common_paths:
                    try:
                        async with session.get(f"{base_url}{path}") as resp:
                            if resp.status == 200:
                                accessible_paths.append(path)
                    except:
                        pass
                
                http_info['accessible_paths'] = accessible_paths
        
        except Exception as e:
            http_info['http_error'] = str(e)
        
        return http_info
    
    async def _enumerate_database_service(self, host: str, port: int) -> Dict[str, Any]:
        """Enumerate database service."""
        
        db_info = {'service_type': 'database'}
        
        # Database-specific enumeration would go here
        # This is a placeholder for database fingerprinting
        
        if port == 3306:  # MySQL
            db_info['database_type'] = 'mysql'
        elif port == 5432:  # PostgreSQL
            db_info['database_type'] = 'postgresql'
        elif port == 6379:  # Redis
            db_info['database_type'] = 'redis'
        elif port == 27017:  # MongoDB
            db_info['database_type'] = 'mongodb'
        
        return db_info
    
    async def _enumerate_remote_access_service(self, host: str, port: int) -> Dict[str, Any]:
        """Enumerate remote access service."""
        
        remote_info = {'service_type': 'remote_access'}
        
        if port == 22:  # SSH
            remote_info['access_type'] = 'ssh'
        elif port == 23:  # Telnet
            remote_info['access_type'] = 'telnet'
        elif port == 3389:  # RDP
            remote_info['access_type'] = 'rdp'
        elif port == 5900:  # VNC
            remote_info['access_type'] = 'vnc'
        
        return remote_info
    
    async def _enumerate_generic_service(self, host: str, port: int) -> Dict[str, Any]:
        """Generic service enumeration."""
        
        return {'service_type': 'generic'}


class ScreenshottingPipeline:
    """Automated screenshotting pipeline for web services."""
    
    def __init__(self):
        self.screenshot_manager = screenshot_manager
    
    async def screenshot_services(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Take screenshots of web services."""
        
        screenshot_results = []
        
        for service in services:
            if self._is_web_service(service):
                screenshot_info = await self._screenshot_service(service)
                if screenshot_info:
                    screenshot_results.append(screenshot_info)
        
        return screenshot_results
    
    def _is_web_service(self, service: Dict[str, Any]) -> bool:
        """Check if service is a web service that can be screenshotted."""
        
        port = service.get('port')
        service_name = service.get('service_name', '').lower()
        
        # Check for HTTP ports or HTTP service names
        return (
            port in [80, 443, 8080, 8443, 8888, 9200] or
            'http' in service_name or
            'web' in service_name or
            service.get('url')
        )
    
    async def _screenshot_service(self, service: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Take screenshot of a web service."""
        
        try:
            # Determine URL
            url = service.get('url')
            if not url:
                host = service['host']
                port = service['port']
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f"{protocol}://{host}:{port}"
            
            # Take screenshot
            screenshot_info = await self.screenshot_manager.take_screenshot(url)
            
            if screenshot_info:
                return {
                    'service': service,
                    'screenshot': screenshot_info,
                    'url': url,
                    'timestamp': datetime.utcnow().isoformat()
                }
        
        except Exception as e:
            logger.error(f"Screenshot failed for service {service}: {e}")
        
        return None


class AdvancedPortScanCollector(BaseCollector):
    """Advanced port scanning collector with service enumeration."""
    
    def __init__(self):
        super().__init__("advanced_port_scan")
        self.port_scanner = PortScanner()
        self.service_enumerator = ServiceEnumerator()
        self.screenshot_pipeline = ScreenshottingPipeline()
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Perform comprehensive port scanning and service enumeration."""
        
        # 1. Port scanning
        scan_type = kwargs.get('scan_type', 'common')
        scan_results = await self.port_scanner.scan_host(target, scan_type, **kwargs)
        
        self.add_result({
            'type': 'port_scan_results',
            'target': target,
            'scan_results': scan_results
        })
        
        # 2. Service enumeration
        if scan_results.get('open_ports'):
            services = await self.service_enumerator.enumerate_services(scan_results)
            
            for service in services:
                self.add_result({
                    'type': 'service_enumeration',
                    'target': target,
                    'service': service
                })
            
            # 3. Screenshots
            if kwargs.get('take_screenshots', True):
                screenshots = await self.screenshot_pipeline.screenshot_services(services)
                
                for screenshot_info in screenshots:
                    self.add_result({
                        'type': 'service_screenshot',
                        'target': target,
                        'screenshot_info': screenshot_info
                    })
        
        return self.results


# Integration function
def add_port_scanning_collector():
    """Add advanced port scanning collector to existing orchestrator."""
    from recon.collectors import recon_orchestrator
    
    recon_orchestrator.collectors['advanced_port_scan'] = AdvancedPortScanCollector()
    
    return recon_orchestrator


# Standalone usage
if __name__ == "__main__":
    async def test_port_scanning():
        collector = AdvancedPortScanCollector()
        results = await collector.collect("scanme.nmap.org", scan_type='common', take_screenshots=True)
        
        print(f"Port scan completed with {len(results)} results")
        for result in results:
            print(f"- {result.get('type')}: {result.get('target')}")
    
    asyncio.run(test_port_scanning())
