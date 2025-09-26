"""
Celery tasks for proactive defense capabilities.

This module contains tasks for generating detection rules, secure configurations,
and other defensive measures in the background.
"""

import logging

from celery import Task
from automation.orchestrator import celery_app
from automation.database import get_db_session, finding_repository
from defense.rule_generator import DetectionRuleGenerator


logger = logging.getLogger(__name__)


class BaseDefenseTask(Task):
    """Base class for defense tasks."""
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        logger.error(f"Defense task {task_id} failed: {exc}")
    
    def on_success(self, retval, task_id, args, kwargs):
        logger.info(f"Defense task {task_id} completed successfully")


@celery_app.task(bind=True, base=BaseDefenseTask, name='defense.tasks.generate_detection_rules')
def generate_detection_rules(self, finding_id: str):
    """Generate detection rules for a given finding."""
    
    logger.info(f"Starting detection rule generation for finding: {finding_id}")
    
    try:
        with get_db_session() as session:
            finding = finding_repository.get_by_id(session, finding_id)
            if not finding:
                raise ValueError(f"Finding with ID {finding_id} not found.")
        
        generator = DetectionRuleGenerator(finding)
        
        snort_rule = generator.generate_snort_rule()
        sigma_rule = generator.generate_sigma_rule()
        
        result = {
            'finding_id': finding_id,
            'snort_rule': snort_rule,
            'sigma_rule': sigma_rule,
            'status': 'completed'
        }
        
        logger.info(f"Successfully generated detection rules for finding {finding_id}")
        return result

    except Exception as e:
        logger.error(f"Detection rule generation failed for finding {finding_id}: {e}")
        raise
