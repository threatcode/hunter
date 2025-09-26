"""
Integration tasks for external systems.

This module contains Celery tasks for interacting with external platforms
like Jira, Slack, etc.
"""

import logging

from celery import Task
from automation.orchestrator import celery_app
from automation.database import get_db_session, finding_repository
from integrations.jira_client import JiraClient


logger = logging.getLogger(__name__)


class BaseIntegrationTask(Task):
    """Base class for integration tasks."""
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        logger.error(f"Integration task {task_id} failed: {exc}")
    
    def on_success(self, retval, task_id, args, kwargs):
        logger.info(f"Integration task {task_id} completed successfully")


@celery_app.task(bind=True, base=BaseIntegrationTask, name='integrations.tasks.create_jira_ticket')
def create_jira_ticket(self, finding_id: str, project_key: str = None):
    """Create a Jira ticket for a given finding."""
    
    logger.info(f"Starting Jira ticket creation for finding: {finding_id}")
    
    try:
        with get_db_session() as session:
            finding = finding_repository.get_by_id(session, finding_id)
            if not finding:
                raise ValueError(f"Finding with ID {finding_id} not found.")
        
        jira_client = JiraClient()
        
        # Use the provided project_key or the default from the client
        if project_key:
            issue_key = jira_client.create_issue_from_finding(finding, project_key=project_key)
        else:
            issue_key = jira_client.create_issue_from_finding(finding)
        
        # You could optionally update the finding in the database with the Jira issue key here
        
        result = {
            'finding_id': finding_id,
            'jira_issue_key': issue_key,
            'status': 'completed'
        }
        
        logger.info(f"Jira ticket {issue_key} created for finding {finding_id}")
        return result
    
    except Exception as e:
        logger.error(f"Jira ticket creation failed for finding {finding_id}: {e}")
        raise
