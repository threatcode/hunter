"""
Reporting and integration tasks.

This module contains Celery tasks for generating reports and handling
integrations with external systems.
"""

import logging
from datetime import datetime

from celery import Task
from automation.orchestrator import celery_app
from reporting.report_generator import ReportGenerator


logger = logging.getLogger(__name__)


class BaseReportingTask(Task):
    """Base class for reporting tasks."""
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        logger.error(f"Reporting task {task_id} failed: {exc}")
    
    def on_success(self, retval, task_id, args, kwargs):
        logger.info(f"Reporting task {task_id} completed successfully")


@celery_app.task(bind=True, base=BaseReportingTask, name='reporting.tasks.generate_report')
def generate_report(self, job_id: str, output_path: str, report_type: str = 'markdown'):
    """Generate a penetration testing report."""
    
    log_message = f"Starting report generation for job {job_id} to {output_path}"
    logger.info(log_message)
    
    try:
        report_generator = ReportGenerator(job_id)
        
        if report_type == 'markdown':
            success = report_generator.save_markdown_report(output_path)
        elif report_type == 'html':
            success = report_generator.save_html_report(output_path)
        elif report_type == 'pdf':
            success = report_generator.save_pdf_report(output_path)
        else:
            raise ValueError(f"Unsupported report type: {report_type}")
        
        if not success:
            raise Exception("Failed to save the report.")
        
        result = {
            'job_id': job_id,
            'report_path': output_path,
            'report_type': report_type,
            'status': 'completed',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        logger.info(f"Report for job {job_id} saved to {output_path}")
        return result
    
    except Exception as e:
        logger.error(f"Report generation failed for job {job_id}: {e}")
        raise
