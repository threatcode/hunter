"""
Advanced bruteforce and wordlist engine for directory and file discovery.

This module implements intelligent bruteforcing with technology-specific wordlists,
recursive discovery, and 403 bypass techniques.
"""

import asyncio
import logging
import random
from datetime import datetime
from typing import Dict, List, Optional, Set, Any, Tuple
from urllib.parse import urljoin, urlparse
from pathlib import Path
import aiohttp
import aiofiles

from recon.collectors import BaseCollector


logger = logging.getLogger(__name__)


class WordlistManager:
    """Manages wordlists for different technologies and contexts."""
    
    def __init__(self):
        self.base_wordlists = {
            'common': [
                'admin', 'administrator', 'login', 'dashboard', 'panel',
                'config', 'configuration', 'settings', 'setup',
                'backup', 'backups', 'bak', 'old', 'tmp', 'temp',
                'test', 'testing', 'dev', 'development', 'staging',
                'api', 'v1', 'v2', 'rest', 'graphql', 'swagger',
                'docs', 'documentation', 'help', 'support',
                'upload', 'uploads', 'files', 'images', 'assets',
                'static', 'public', 'private', 'secure',
                'data', 'database', 'db', 'sql', 'mysql',
                'logs', 'log', 'debug', 'error', 'access'
            ],
            
            'files': [
                'robots.txt', 'sitemap.xml', 'crossdomain.xml',
                'clientaccesspolicy.xml', 'security.txt', 'humans.txt',
                'ads.txt', 'favicon.ico', 'apple-touch-icon.png',
                '.htaccess', '.htpasswd', 'web.config', '.env',
                'config.php', 'config.inc.php', 'configuration.php',
                'wp-config.php', 'wp-config.php.bak', 'database.php',
                'settings.php', 'local_settings.py', 'settings.py',
                'config.json', 'config.yaml', 'config.yml',
                'package.json', 'composer.json', 'requirements.txt',
                'Dockerfile', 'docker-compose.yml', '.dockerignore',
                '.gitignore', '.git/config', '.svn/entries',
                'backup.sql', 'dump.sql', 'database.sql',
                'phpinfo.php', 'info.php', 'test.php'
            ],
            
            'api': [
                'api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'restapi',
                'graphql', 'swagger', 'swagger.json', 'swagger.yaml',
                'openapi.json', 'openapi.yaml', 'api-docs',
                'docs/api', 'documentation/api', 'api/docs',
                'api/swagger', 'api/openapi', 'api/graphql',
                'webhooks', 'callback', 'oauth', 'auth',
                'token', 'tokens', 'session', 'sessions'
            ],
            
            'admin': [
                'admin', 'administrator', 'administration', 'manage',
                'manager', 'management', 'control', 'controlpanel',
                'cpanel', 'panel', 'dashboard', 'console',
                'backend', 'backoffice', 'cms', 'wp-admin',
                'phpmyadmin', 'adminer', 'pgadmin', 'myadmin',
                'admin.php', 'admin.html', 'admin.asp', 'admin.aspx',
                'login', 'signin', 'auth', 'authenticate'
            ]
        }
        
        self.technology_wordlists = {
            'wordpress': [
                'wp-admin', 'wp-content', 'wp-includes', 'wp-json',
                'wp-login.php', 'wp-config.php', 'wp-config.php.bak',
                'wp-content/themes', 'wp-content/plugins', 'wp-content/uploads',
                'xmlrpc.php', 'readme.html', 'license.txt'
            ],
            
            'drupal': [
                'admin', 'user', 'node', 'sites/default/files',
                'sites/default/settings.php', 'modules', 'themes',
                'core', 'vendor', 'autoload.php', 'update.php',
                'install.php', 'cron.php', 'authorize.php'
            ],
            
            'joomla': [
                'administrator', 'components', 'modules', 'plugins',
                'templates', 'media', 'cache', 'logs',
                'configuration.php', 'htaccess.txt', 'web.config.txt'
            ],
            
            'php': [
                'index.php', 'config.php', 'config.inc.php', 'common.php',
                'functions.php', 'includes', 'inc', 'lib', 'libs',
                'classes', 'vendor', 'composer.json', 'composer.lock',
                'phpinfo.php', 'info.php', 'test.php', 'debug.php'
            ],
            
            'asp': [
                'default.asp', 'default.aspx', 'index.asp', 'index.aspx',
                'web.config', 'global.asax', 'app_data', 'app_code',
                'bin', 'obj', 'packages.config', 'web.debug.config'
            ],
            
            'java': [
                'WEB-INF', 'META-INF', 'classes', 'lib', 'web.xml',
                'struts.xml', 'spring', 'hibernate', 'log4j.properties',
                'application.properties', 'config.properties'
            ],
            
            'node': [
                'package.json', 'package-lock.json', 'node_modules',
                'app.js', 'server.js', 'index.js', 'main.js',
                '.env', '.env.local', '.env.production', 'config'
            ],
            
            'python': [
                'requirements.txt', 'setup.py', 'manage.py', 'wsgi.py',
                'settings.py', 'local_settings.py', 'config.py',
                'app.py', 'main.py', '__pycache__', '.pyc'
            ]
        }
        
        self.file_extensions = {
            'web': ['.php', '.asp', '.aspx', '.jsp', '.do', '.action'],
            'config': ['.config', '.conf', '.ini', '.yaml', '.yml', '.json'],
            'backup': ['.bak', '.backup', '.old', '.orig', '.save', '.tmp'],
            'data': ['.sql', '.db', '.sqlite', '.mdb', '.csv', '.xml'],
            'log': ['.log', '.logs', '.out', '.err', '.debug'],
            'archive': ['.zip', '.rar', '.tar', '.gz', '.7z', '.bz2']
        }
    
    def get_wordlist(self, category: str, technology: Optional[str] = None) -> List[str]:
        """Get wordlist for specific category and technology."""
        
        wordlist = []
        
        # Add base wordlist
        if category in self.base_wordlists:
            wordlist.extend(self.base_wordlists[category])
        
        # Add technology-specific wordlist
        if technology and technology in self.technology_wordlists:
            wordlist.extend(self.technology_wordlists[technology])
        
        return list(set(wordlist))  # Remove duplicates
    
    def generate_permutations(self, base_words: List[str], max_permutations: int = 500) -> List[str]:
        """Generate permutations of base words."""
        
        permutations = set(base_words)
        
        # Add common prefixes and suffixes
        prefixes = ['old', 'new', 'backup', 'test', 'dev', 'staging', 'prod']
        suffixes = ['old', 'new', 'backup', 'test', 'dev', 'staging', 'prod', '1', '2', '3']
        
        for word in base_words:
            # Add prefixes
            for prefix in prefixes:
                permutations.add(f"{prefix}_{word}")
                permutations.add(f"{prefix}-{word}")
                permutations.add(f"{prefix}{word}")
            
            # Add suffixes
            for suffix in suffixes:
                permutations.add(f"{word}_{suffix}")
                permutations.add(f"{word}-{suffix}")
                permutations.add(f"{word}{suffix}")
        
        # Add file extensions
        for word in list(permutations):
            for ext_category, extensions in self.file_extensions.items():
                for ext in extensions:
                    permutations.add(f"{word}{ext}")
        
        # Limit results
        permutation_list = list(permutations)
        if len(permutation_list) > max_permutations:
            # Prioritize shorter, more common paths
            permutation_list.sort(key=len)
            permutation_list = permutation_list[:max_permutations]
        
        return permutation_list


class BypassTechniques:
    """Implements various 403 bypass techniques."""
    
    def __init__(self):
        self.bypass_methods = [
            self._header_bypass,
            self._case_bypass,
            self._encoding_bypass,
            self._path_bypass,
            self._method_bypass
        ]
    
    async def attempt_bypasses(self, session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
        """Attempt various bypass techniques on a 403 response."""
        
        bypass_results = []
        
        for bypass_method in self.bypass_methods:
            try:
                result = await bypass_method(session, url)
                if result:
                    bypass_results.append(result)
            except Exception as e:
                logger.debug(f"Bypass method failed for {url}: {e}")
        
        return bypass_results
    
    async def _header_bypass(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict[str, Any]]:
        """Try header-based bypass techniques."""
        
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Rewrite-URL': '/'},
            {'X-Original-URL': '/'},
            {'Referer': url},
            {'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)'}
        ]
        
        for headers in bypass_headers:
            try:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        return {
                            'method': 'header_bypass',
                            'headers': headers,
                            'status_code': response.status,
                            'content_length': len(await response.text())
                        }
            except:
                continue
        
        return None
    
    async def _case_bypass(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict[str, Any]]:
        """Try case variation bypass techniques."""
        
        parsed_url = urlparse(url)
        path = parsed_url.path
        
        case_variations = [
            path.upper(),
            path.lower(),
            path.capitalize(),
            path.swapcase()
        ]
        
        for variation in case_variations:
            if variation != path:
                test_url = url.replace(path, variation)
                try:
                    async with session.get(test_url) as response:
                        if response.status == 200:
                            return {
                                'method': 'case_bypass',
                                'original_path': path,
                                'bypass_path': variation,
                                'status_code': response.status
                            }
                except:
                    continue
        
        return None
    
    async def _encoding_bypass(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict[str, Any]]:
        """Try URL encoding bypass techniques."""
        
        parsed_url = urlparse(url)
        path = parsed_url.path
        
        encoding_variations = [
            path.replace('/', '%2f'),
            path.replace('/', '%2F'),
            path.replace('/', '//'),
            path.replace('/', '/./'),
            path.replace('/', '/../'),
            path + '/',
            path + '%20',
            path + '?',
            path + '#'
        ]
        
        for variation in encoding_variations:
            test_url = url.replace(path, variation)
            try:
                async with session.get(test_url) as response:
                    if response.status == 200:
                        return {
                            'method': 'encoding_bypass',
                            'original_path': path,
                            'bypass_path': variation,
                            'status_code': response.status
                        }
            except:
                continue
        
        return None
    
    async def _path_bypass(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict[str, Any]]:
        """Try path manipulation bypass techniques."""
        
        parsed_url = urlparse(url)
        path = parsed_url.path
        
        path_variations = [
            f"{path}/",
            f"{path}/..",
            f"{path}/.",
            f"/{path}",
            f".{path}",
            f"{path}.html",
            f"{path}.php",
            f"{path}.asp"
        ]
        
        for variation in path_variations:
            test_url = url.replace(path, variation)
            try:
                async with session.get(test_url) as response:
                    if response.status == 200:
                        return {
                            'method': 'path_bypass',
                            'original_path': path,
                            'bypass_path': variation,
                            'status_code': response.status
                        }
            except:
                continue
        
        return None
    
    async def _method_bypass(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict[str, Any]]:
        """Try HTTP method bypass techniques."""
        
        methods = ['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE']
        
        for method in methods:
            try:
                async with session.request(method, url) as response:
                    if response.status == 200:
                        return {
                            'method': 'http_method_bypass',
                            'http_method': method,
                            'status_code': response.status
                        }
            except:
                continue
        
        return None


class BruteforceEngine:
    """Advanced bruteforce engine with intelligent discovery."""
    
    def __init__(self):
        self.wordlist_manager = WordlistManager()
        self.bypass_techniques = BypassTechniques()
        self.discovered_paths = set()
        self.interesting_responses = []
    
    async def bruteforce_directories(self, base_url: str, **kwargs) -> Dict[str, Any]:
        """Bruteforce directories and files on target."""
        
        bruteforce_results = {
            'base_url': base_url,
            'discovered_paths': [],
            'bypass_successes': [],
            'interesting_responses': [],
            'statistics': {
                'total_requests': 0,
                'successful_requests': 0,
                'bypass_attempts': 0,
                'bypass_successes': 0
            }
        }
        
        # Get wordlists
        technology = kwargs.get('technology', 'common')
        categories = kwargs.get('categories', ['common', 'files', 'admin'])
        max_depth = kwargs.get('max_depth', 2)
        max_requests = kwargs.get('max_requests', 1000)
        
        # Build comprehensive wordlist
        wordlist = []
        for category in categories:
            wordlist.extend(self.wordlist_manager.get_wordlist(category, technology))
        
        # Add permutations
        if kwargs.get('enable_permutations', True):
            permutations = self.wordlist_manager.generate_permutations(
                wordlist[:50],  # Limit base words for permutations
                max_permutations=kwargs.get('max_permutations', 500)
            )
            wordlist.extend(permutations)
        
        # Remove duplicates and limit
        wordlist = list(set(wordlist))[:max_requests]
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=aiohttp.TCPConnector(ssl=False, limit=100)
        ) as session:
            
            # Initial bruteforce
            await self._bruteforce_wordlist(session, base_url, wordlist, bruteforce_results)
            
            # Recursive discovery
            if max_depth > 1:
                await self._recursive_discovery(session, base_url, max_depth - 1, bruteforce_results)
        
        return bruteforce_results
    
    async def _bruteforce_wordlist(self, session: aiohttp.ClientSession, base_url: str, 
                                 wordlist: List[str], results: Dict[str, Any]):
        """Bruteforce a wordlist against the target."""
        
        # Create semaphore for rate limiting
        semaphore = asyncio.Semaphore(50)
        
        async def test_path(path: str):
            async with semaphore:
                return await self._test_single_path(session, base_url, path, results)
        
        # Test all paths concurrently
        tasks = [test_path(path) for path in wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _test_single_path(self, session: aiohttp.ClientSession, base_url: str, 
                              path: str, results: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test a single path and handle response."""
        
        url = urljoin(base_url, path)
        
        if url in self.discovered_paths:
            return None
        
        try:
            async with session.get(url) as response:
                results['statistics']['total_requests'] += 1
                
                response_data = {
                    'url': url,
                    'path': path,
                    'status_code': response.status,
                    'content_length': len(await response.text()),
                    'content_type': response.headers.get('content-type', ''),
                    'server': response.headers.get('server', ''),
                    'last_modified': response.headers.get('last-modified', ''),
                    'discovery_time': datetime.utcnow().isoformat()
                }
                
                # Handle different response codes
                if response.status == 200:
                    results['statistics']['successful_requests'] += 1
                    self.discovered_paths.add(url)
                    results['discovered_paths'].append(response_data)
                    
                    # Check if response is interesting
                    if self._is_interesting_response(response_data):
                        results['interesting_responses'].append(response_data)
                
                elif response.status == 403:
                    # Attempt bypass techniques
                    results['statistics']['bypass_attempts'] += 1
                    bypass_results = await self.bypass_techniques.attempt_bypasses(session, url)
                    
                    if bypass_results:
                        results['statistics']['bypass_successes'] += len(bypass_results)
                        for bypass_result in bypass_results:
                            bypass_result['original_response'] = response_data
                            results['bypass_successes'].append(bypass_result)
                
                elif response.status in [301, 302, 307, 308]:
                    # Follow redirects manually for analysis
                    location = response.headers.get('location', '')
                    if location:
                        response_data['redirect_location'] = location
                        results['discovered_paths'].append(response_data)
                
                elif response.status == 401:
                    # Authentication required - interesting
                    response_data['requires_auth'] = True
                    results['interesting_responses'].append(response_data)
                
                return response_data
        
        except Exception as e:
            logger.debug(f"Error testing path {url}: {e}")
            return None
    
    async def _recursive_discovery(self, session: aiohttp.ClientSession, base_url: str, 
                                 max_depth: int, results: Dict[str, Any]):
        """Perform recursive discovery on found directories."""
        
        if max_depth <= 0:
            return
        
        # Get discovered directories
        directories = [
            item for item in results['discovered_paths']
            if item['status_code'] == 200 and (
                item['path'].endswith('/') or 
                '.' not in item['path'].split('/')[-1]
            )
        ]
        
        # Recursive wordlist (smaller for performance)
        recursive_wordlist = self.wordlist_manager.get_wordlist('common')[:100]
        
        for directory in directories:
            dir_url = directory['url']
            if not dir_url.endswith('/'):
                dir_url += '/'
            
            # Test recursive paths
            for word in recursive_wordlist:
                recursive_path = f"{directory['path'].rstrip('/')}/{word}"
                await self._test_single_path(session, base_url, recursive_path, results)
    
    def _is_interesting_response(self, response_data: Dict[str, Any]) -> bool:
        """Determine if a response is particularly interesting."""
        
        # Large files might contain interesting content
        if response_data['content_length'] > 10000:
            return True
        
        # Certain content types are interesting
        content_type = response_data['content_type'].lower()
        interesting_types = [
            'application/json', 'application/xml', 'text/xml',
            'application/sql', 'text/plain'
        ]
        
        if any(itype in content_type for itype in interesting_types):
            return True
        
        # Certain paths are always interesting
        path = response_data['path'].lower()
        interesting_paths = [
            'admin', 'config', 'backup', 'database', 'api',
            'swagger', 'phpinfo', '.env', 'web.config'
        ]
        
        if any(ipath in path for ipath in interesting_paths):
            return True
        
        return False


class BruteforceCollector(BaseCollector):
    """Bruteforce collector for directory and file discovery."""
    
    def __init__(self):
        super().__init__("bruteforce_discovery")
        self.bruteforce_engine = BruteforceEngine()
    
    async def collect(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Perform bruteforce discovery on target."""
        
        # Ensure target is a full URL
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # Run bruteforce discovery
        bruteforce_results = await self.bruteforce_engine.bruteforce_directories(target, **kwargs)
        
        # Store main results
        self.add_result({
            'type': 'bruteforce_results',
            'target': target,
            'bruteforce_data': bruteforce_results
        })
        
        # Process individual discoveries
        await self._process_bruteforce_results(target, bruteforce_results)
        
        return self.results
    
    async def _process_bruteforce_results(self, target: str, bruteforce_results: Dict[str, Any]):
        """Process and categorize bruteforce results."""
        
        # Process discovered paths
        for path_data in bruteforce_results.get('discovered_paths', []):
            self.add_result({
                'type': 'path_discovered',
                'target': target,
                'path_data': path_data
            })
        
        # Process bypass successes
        for bypass_data in bruteforce_results.get('bypass_successes', []):
            self.add_result({
                'type': 'bypass_success',
                'target': target,
                'bypass_data': bypass_data
            })
        
        # Process interesting responses
        for interesting_data in bruteforce_results.get('interesting_responses', []):
            self.add_result({
                'type': 'interesting_response',
                'target': target,
                'response_data': interesting_data
            })


# Standalone usage
if __name__ == "__main__":
    async def test_bruteforce():
        collector = BruteforceCollector()
        results = await collector.collect("https://httpbin.org", 
                                         technology='common',
                                         categories=['common', 'files'],
                                         max_requests=100)
        
        print(f"Bruteforce discovery completed with {len(results)} results")
        for result in results[:10]:  # Show first 10
            print(f"- {result.get('type')}: {result}")
    
    asyncio.run(test_bruteforce())
