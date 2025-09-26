"""
AI-generated detection rule engine.

This module generates detection rules for security tools like WAFs and SIEMs
based on the findings from the AI Bug Hunter framework.
"""

import logging
from typing import Dict, List, Any
import re

from data.schemas import Finding


logger = logging.getLogger(__name__)


class DetectionRuleGenerator:
    """Generates detection rules from security findings."""
    
    def __init__(self, finding: Finding):
        self.finding = finding
    
    def generate_snort_rule(self) -> str or None:
        """Generate a Snort rule for the finding."""
        
        try:
            payload = self._extract_payload()
            if not payload:
                return None
            
            # Sanitize payload for use in the rule
            sanitized_payload = re.sub(r'(["|;])', r'\\\1', payload)
            
            rule = (
                f'alert tcp any any -> any any ('
                f'msg:"AI Bug Hunter: Potential {self.finding.vulnerability_type.value} attack detected"; '
                f'flow:to_server,established; '
                f'content:"{sanitized_payload}"; nocase; http_uri; '
                f'classtype:web-application-attack; '
                f'sid:{self._generate_sid()}; rev:1;'
                f')'
            )
            return rule
        
        except Exception as e:
            logger.error(f"Failed to generate Snort rule: {e}")
            return None

    def generate_sigma_rule(self) -> Dict[str, Any] or None:
        """Generate a Sigma rule for the finding."""
        
        try:
            payload = self._extract_payload()
            if not payload:
                return None
            
            rule = {
                'title': f'Potential {self.finding.vulnerability_type.value} Attack Detected',
                'id': f'sigma-rule-{self.finding.id}',
                'status': 'experimental',
                'description': f'Detects a potential {self.finding.vulnerability_type.value} attack based on a finding from the AI Bug Hunter.',
                'logsource': {
                    'category': 'webserver',
                },
                'detection': {
                    'selection': {
                        'c-uri|contains': payload
                    },
                    'condition': 'selection'
                },
                'falsepositives': ['low'],
                'level': self._map_severity_to_sigma_level(self.finding.severity.value)
            }
            return rule
        
        except Exception as e:
            logger.error(f"Failed to generate Sigma rule: {e}")
            return None

    def _extract_payload(self) -> str or None:
        """Extract a representative payload from the finding's evidence."""
        
        if not self.finding.evidence or not isinstance(self.finding.evidence, list):
            return None
        
        for evidence_item in self.finding.evidence:
            if isinstance(evidence_item, dict) and 'payload' in evidence_item:
                return str(evidence_item['payload'])
        
        return None

    def _generate_sid(self) -> int:
        """Generate a unique SID for the Snort rule."""
        # In a real system, this should be managed to avoid collisions.
        # For this example, we'll use a hash of the finding ID.
        return 1000000 + (hash(self.finding.id) % 100000)

    def _map_severity_to_sigma_level(self, severity: str) -> str:
        """Map our severity to Sigma's level."""
        
        mapping = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low',
            'INFORMATIONAL': 'informational'
        }
        
        return mapping.get(severity.upper(), 'medium')


# Standalone usage
if __name__ == "__main__":
    def test_rule_generation():
        from data.schemas import SeverityLevel, VulnerabilityType, FindingStatus
        
        mock_finding = Finding(
            id='test-finding-xss-123',
            title='XSS in Search Query',
            vulnerability_type=VulnerabilityType.XSS,
            severity=SeverityLevel.HIGH,
            evidence=[{'type': 'payload', 'payload': '<script>alert(1)</script>'}],
            status=FindingStatus.OPEN,
            asset_id='https://example.com',
            description='A test finding',
            remediation='Fix it.'
        )
        
        generator = DetectionRuleGenerator(mock_finding)
        
        print("--- Snort Rule ---")
        snort_rule = generator.generate_snort_rule()
        if snort_rule:
            print(snort_rule)
        else:
            print("Failed to generate Snort rule.")
        
        print("\n--- Sigma Rule ---")
        sigma_rule = generator.generate_sigma_rule()
        if sigma_rule:
            import yaml
            print(yaml.dump(sigma_rule, default_flow_style=False))
        else:
            print("Failed to generate Sigma rule.")

    # test_rule_generation()
