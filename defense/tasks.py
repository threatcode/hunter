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
from defense.config_generator import ConfigGenerator
from defense.playbook_generator import PlaybookGenerator


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


@celery_app.task(bind=True, base=BaseDefenseTask, name='defense.tasks.generate_secure_configurations')
def generate_secure_configurations(self, finding_id: str):
    """Generate secure configurations for a given finding."""
    
    logger.info(f"Starting secure configuration generation for finding: {finding_id}")
    
    try:
        with get_db_session() as session:
            finding = finding_repository.get_by_id(session, finding_id)
            if not finding:
                raise ValueError(f"Finding with ID {finding_id} not found.")
        
        generator = ConfigGenerator(finding)
        
        configs = generator.generate_all_configs()
        
        result = {
            'finding_id': finding_id,
            'configurations': configs,
            'status': 'completed'
        }
        
        logger.info(f"Successfully generated {len(configs)} secure configurations for finding {finding_id}")
        return result

    except Exception as e:
        logger.error(f"Secure configuration generation failed for finding {finding_id}: {e}")
        raise


@celery_app.task(bind=True, base=BaseDefenseTask, name='defense.tasks.generate_remediation_playbook')
def generate_remediation_playbook(self, finding_id: str):
    """Generate a remediation playbook for a given finding."""
    
    logger.info(f"Starting remediation playbook generation for finding: {finding_id}")
    
    try:
        with get_db_session() as session:
            finding = finding_repository.get_by_id(session, finding_id)
            if not finding:
                raise ValueError(f"Finding with ID {finding_id} not found.")
        
        generator = PlaybookGenerator(finding)
        
        playbook = generator.generate_playbook()
        
        result = {
            'finding_id': finding_id,
            'playbook': playbook,
            'status': 'completed'
        }
        
        logger.info(f"Successfully generated remediation playbook for finding {finding_id}")
        return result

    except Exception as e:
        logger.error(f"Remediation playbook generation failed for finding {finding_id}: {e}")
        raise
