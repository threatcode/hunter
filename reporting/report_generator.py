"""
Automated report generation engine.

This module provides capabilities for generating professional penetration testing
reports in various formats (Markdown, PDF, HTML).
"""

import logging
from datetime import datetime
from typing import Dict, List, Any

from jinja2 import Environment, FileSystemLoader

from automation.database import get_db_session, job_repository, finding_repository, asset_repository
from data.schemas import ScanJob, Finding


logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates comprehensive penetration testing reports."""
    
    def __init__(self, job_id: str):
        self.job_id = job_id
        self.report_data = {}
        self.env = Environment(loader=FileSystemLoader('reporting/templates/'))
    
    def _fetch_data(self):
        """Fetch all necessary data from the database for the report."""
        
        with get_db_session() as session:
            job = job_repository.get_by_id(session, self.job_id)
            if not job:
                raise ValueError(f"Job with ID {self.job_id} not found.")
            
            findings = finding_repository.get_by_job_id(session, self.job_id)
            
            # Collect unique assets from findings
            asset_ids = {f.asset_id for f in findings if f.asset_id}
            assets = [asset_repository.get_by_id(session, asset_id) for asset_id in asset_ids]
            
            self.report_data = {
                'job': job,
                'findings': findings,
                'assets': [asset for asset in assets if asset],
                'generation_date': datetime.utcnow().isoformat(),
                'summary': self._generate_summary(findings)
            }
    
    def _generate_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate a summary of the findings."""
        
        summary = {
            'total_findings': len(findings),
            'severity_counts': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'informational': 0
            },
            'top_vulnerability_types': {}
        }
        
        for finding in findings:
            severity = finding.severity.value.lower()
            if severity in summary['severity_counts']:
                summary['severity_counts'][severity] += 1
            
            vuln_type = finding.vulnerability_type.value
            summary['top_vulnerability_types'][vuln_type] = summary['top_vulnerability_types'].get(vuln_type, 0) + 1
        
        # Sort top vulnerability types
        summary['top_vulnerability_types'] = dict(sorted(
            summary['top_vulnerability_types'].items(), 
            key=lambda item: item[1], 
            reverse=True
        )[:5])
        
        return summary

    def generate_markdown_report(self) -> str:
        """Generate a report in Markdown format."""
        
        try:
            self._fetch_data()
            template = self.env.get_template('markdown_report.md.j2')
            markdown_content = template.render(self.report_data)
            return markdown_content
        
        except Exception as e:
            logger.error(f"Failed to generate Markdown report: {e}")
            return f"# Report Generation Failed\n\nError: {e}"
    
    def save_markdown_report(self, file_path: str) -> bool:
        """Save the Markdown report to a file."""
        
        markdown_content = self.generate_markdown_report()
        
        try:
            with open(file_path, 'w') as f:
                f.write(markdown_content)
            logger.info(f"Report saved to {file_path}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to save report to {file_path}: {e}")
            return False


# Standalone usage
if __name__ == "__main__":
    def test_report_generation():
        # This requires a valid job_id from your database
        # Replace with a real job_id for testing
        test_job_id = "your_test_job_id_here"
        
        print(f"Generating report for job: {test_job_id}")
        
        try:
            report_generator = ReportGenerator(test_job_id)
            report_generator.save_markdown_report(f"/tmp/report_{test_job_id}.md")
            print(f"Report generated successfully.")
        
        except Exception as e:
            print(f"Report generation failed: {e}")
    
    # To run this test, you need to have a database with scan results.
    # test_report_generation()
