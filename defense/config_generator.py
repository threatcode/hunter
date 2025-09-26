"""
Automated security configuration generation engine.

This module generates secure configuration files for various services
(e.g., Nginx, Docker) based on the findings from the AI Bug Hunter framework.
"""

import logging
from typing import Dict, List, Any

from data.schemas import Finding, VulnerabilityType


logger = logging.getLogger(__name__)


class ConfigGenerator:
    """Generates secure configurations based on security findings."""
    
    def __init__(self, finding: Finding):
        self.finding = finding
    
    def generate_nginx_config(self) -> str or None:
        """Generate a secure Nginx configuration snippet."""
        
        configs = []
        
        # Add security headers for common web vulnerabilities
        if self.finding.vulnerability_type in [VulnerabilityType.XSS, VulnerabilityType.CLICKJACKING]:
            configs.append("add_header X-Frame-Options \"SAMEORIGIN\";")
            configs.append("add_header X-Content-Type-Options \"nosniff\";")
            configs.append("add_header X-XSS-Protection \"1; mode=block\";")
            configs.append("add_header Content-Security-Policy \"default-src 'self'\";")
        
        # Add rate limiting for bruteforce or denial of service
        if self.finding.vulnerability_type == VulnerabilityType.BRUTEFORCE:
            configs.append("limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;")
            configs.append("limit_req zone=mylimit burst=20 nodelay;")
        
        if not configs:
            return None
        
        return "\n".join(configs)

    def generate_dockerfile(self) -> str or None:
        """Generate a hardened Dockerfile snippet."""
        
        configs = []
        
        # Recommend non-root user for container security
        if 'container' in self.finding.asset_id.lower():
            configs.append("RUN addgroup -S appgroup && adduser -S appuser -G appgroup")
            configs.append("USER appuser")
        
        if not configs:
            return None
        
        return "\n".join(configs)

    def generate_all_configs(self) -> Dict[str, str]:
        """Generate all applicable secure configurations."""
        
        all_configs = {}
        
        nginx_config = self.generate_nginx_config()
        if nginx_config:
            all_configs['nginx'] = nginx_config
        
        dockerfile = self.generate_dockerfile()
        if dockerfile:
            all_configs['dockerfile'] = dockerfile
            
        return all_configs


# Standalone usage
if __name__ == "__main__":
    def test_config_generation():
        from data.schemas import SeverityLevel, FindingStatus
        
        mock_finding_xss = Finding(
            id='test-finding-xss-456',
            title='Missing Security Headers',
            vulnerability_type=VulnerabilityType.XSS,
            severity=SeverityLevel.MEDIUM,
            status=FindingStatus.OPEN,
            asset_id='https://example.com',
            description='The application is missing key security headers.',
            remediation='Add security headers to the web server configuration.',
            evidence=[]
        )
        
        generator = ConfigGenerator(mock_finding_xss)
        
        print("--- Secure Nginx Config Snippet ---")
        nginx_config = generator.generate_nginx_config()
        if nginx_config:
            print(nginx_config)
        else:
            print("No Nginx config generated.")

    # test_config_generation()
