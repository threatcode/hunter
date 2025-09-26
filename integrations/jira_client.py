"""
Jira integration client.

This module provides a client for interacting with the Jira API to create
issues from security findings.
"""

import logging
from jira import JIRA, JIRAError

from data.schemas import Finding


logger = logging.getLogger(__name__)


# IMPORTANT: Replace these with your actual Jira configuration
JIRA_SERVER = 'https://your-jira-instance.atlassian.net'
JIRA_USERNAME = 'your-email@example.com'
JIRA_API_TOKEN = 'your_jira_api_token'
JIRA_PROJECT_KEY = 'YOUR_PROJECT_KEY'


class JiraClient:
    """A client for creating Jira issues from findings."""
    
    def __init__(self, server_url=JIRA_SERVER, username=JIRA_USERNAME, api_token=JIRA_API_TOKEN):
        try:
            self.client = JIRA(
                server=server_url,
                basic_auth=(username, api_token)
            )
            logger.info(f"Successfully connected to Jira server at {server_url}")
        
        except JIRAError as e:
            logger.error(f"Failed to connect to Jira: {e.status_code} {e.text}")
            raise
    
    def create_issue_from_finding(self, finding: Finding, project_key: str = JIRA_PROJECT_KEY) -> str:
        """Create a Jira issue from a Finding object."""
        
        issue_summary = f"Security Finding: {finding.title}"
        
        issue_description = f"""\
        h2. Vulnerability Details

        *Severity:* {finding.severity.value}
        *Vulnerability Type:* {finding.vulnerability_type.value}
        *Asset:* `{finding.asset_id}`
        *Status:* {finding.status.value}

        h2. Description

        {finding.description}

        h2. Evidence

        {{code:json}}
        {finding.evidence}
        {{code}}

        h2. Remediation

        {finding.remediation}
        """
        
        issue_dict = {
            'project': {'key': project_key},
            'summary': issue_summary,
            'description': issue_description,
            'issuetype': {'name': 'Task'}, # Or 'Bug', depending on your project config
            'priority': {'name': self._map_severity_to_priority(finding.severity.value)}
        }
        
        try:
            new_issue = self.client.create_issue(fields=issue_dict)
            logger.info(f"Successfully created Jira issue {new_issue.key} for finding {finding.id}")
            return new_issue.key
        
        except JIRAError as e:
            logger.error(f"Failed to create Jira issue: {e.status_code} {e.text}")
            raise
    
    def _map_severity_to_priority(self, severity: str) -> str:
        """Map our severity levels to Jira priorities."""
        
        mapping = {
            'CRITICAL': 'Highest',
            'HIGH': 'High',
            'MEDIUM': 'Medium',
            'LOW': 'Low',
            'INFORMATIONAL': 'Lowest'
        }
        
        return mapping.get(severity.upper(), 'Medium')


# Standalone usage
if __name__ == "__main__":
    def test_jira_integration():
        # This is a mock finding for testing purposes
        from data.schemas import SeverityLevel, VulnerabilityType, FindingStatus
        
        mock_finding = Finding(
            id='test-finding-123',
            title='Cross-Site Scripting (XSS) in Search Bar',
            description='A reflected XSS vulnerability was found in the main search bar.',
            severity=SeverityLevel.HIGH,
            vulnerability_type=VulnerabilityType.XSS,
            status=FindingStatus.OPEN,
            asset_id='https://example.com/search?q=<script>alert(1)</script>',
            evidence=[{'type': 'request', 'payload': '<script>alert(1)</script>'}],
            remediation='Implement proper output encoding and input validation.'
        )
        
        print("Testing Jira integration...")
        
        try:
            jira_client = JiraClient()
            issue_key = jira_client.create_issue_from_finding(mock_finding)
            print(f"Successfully created Jira issue: {issue_key}")
        
        except Exception as e:
            print(f"Jira integration test failed: {e}")
            print("Please ensure your Jira credentials and server URL are correctly configured.")
    
    # To run this test, you need to have a Jira instance and valid credentials.
    # test_jira_integration()
