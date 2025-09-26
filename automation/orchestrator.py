"""
Orchestration engine for the AI Bug Hunter framework.

This module handles job scheduling, task distribution, and workflow coordination
using Celery for distributed task processing.
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from celery import Celery
from celery.result import AsyncResult
from sqlalchemy.orm import Session

from data.schemas import ScanJob, ScanType, ScanStatus, ScanRequest
from automation.database import get_db_session, JobRepository


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Celery
celery_app = Celery(
    'bug_hunter',
    broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
    include=[
        'recon.tasks',
        'analysis.tasks',
        'fuzz.tasks',
    ]
)

# Celery configuration
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    task_soft_time_limit=3000,  # 50 minutes soft limit
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
)


class JobOrchestrator:
    """Main orchestrator for managing scan jobs and workflows."""
    
    def __init__(self):
        self.job_repo = JobRepository()
    
    def submit_scan(self, scan_request: ScanRequest) -> str:
        """Submit a new scan job to the queue."""
        try:
            # Create job record
            job = ScanJob(
                name=f"{scan_request.scan_type.value}_{scan_request.target}",
                scan_type=scan_request.scan_type,
                target=scan_request.target,
                parameters=scan_request.config or {},
                status=ScanStatus.PENDING
            )
            
            with get_db_session() as session:
                saved_job = self.job_repo.create(session, job)
                job_id = saved_job.id
            
            # Submit to appropriate task queue based on scan type
            task_name = self._get_task_name(scan_request.scan_type)
            
            celery_task = celery_app.send_task(
                task_name,
                args=[job_id, scan_request.target],
                kwargs=scan_request.config or {},
                priority=scan_request.priority
            )
            
            # Update job with Celery task ID
            with get_db_session() as session:
                self.job_repo.update_task_id(session, job_id, celery_task.id)
            
            logger.info(f"Submitted scan job {job_id} for target {scan_request.target}")
            return job_id
            
        except Exception as e:
            logger.error(f"Failed to submit scan: {e}")
            raise
    
    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """Get the current status of a job."""
        with get_db_session() as session:
            job = self.job_repo.get_by_id(session, job_id)
            if not job:
                raise ValueError(f"Job {job_id} not found")
            
            # Get Celery task status if available
            celery_status = None
            if job.metadata.get('celery_task_id'):
                task = AsyncResult(job.metadata['celery_task_id'], app=celery_app)
                celery_status = {
                    'state': task.state,
                    'info': task.info,
                    'traceback': task.traceback
                }
            
            return {
                'job_id': job.id,
                'name': job.name,
                'status': job.status,
                'scan_type': job.scan_type,
                'target': job.target,
                'created_at': job.created_at,
                'started_at': job.started_at,
                'completed_at': job.completed_at,
                'results_count': job.results_count,
                'findings_count': job.findings_count,
                'error_message': job.error_message,
                'celery_status': celery_status
            }
    
    def cancel_job(self, job_id: str) -> bool:
        """Cancel a running job."""
        try:
            with get_db_session() as session:
                job = self.job_repo.get_by_id(session, job_id)
                if not job:
                    return False
                
                # Cancel Celery task if it exists
                if job.metadata.get('celery_task_id'):
                    celery_app.control.revoke(
                        job.metadata['celery_task_id'],
                        terminate=True
                    )
                
                # Update job status
                self.job_repo.update_status(
                    session, job_id, ScanStatus.CANCELLED
                )
                
            logger.info(f"Cancelled job {job_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cancel job {job_id}: {e}")
            return False
    
    def list_jobs(
        self,
        status: Optional[ScanStatus] = None,
        scan_type: Optional[ScanType] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List jobs with optional filtering."""
        with get_db_session() as session:
            jobs = self.job_repo.list_jobs(
                session, status=status, scan_type=scan_type,
                limit=limit, offset=offset
            )
            
            return [
                {
                    'job_id': job.id,
                    'name': job.name,
                    'status': job.status,
                    'scan_type': job.scan_type,
                    'target': job.target,
                    'created_at': job.created_at,
                    'results_count': job.results_count,
                    'findings_count': job.findings_count
                }
                for job in jobs
            ]
    
    def cleanup_old_jobs(self, days: int = 30) -> int:
        """Clean up completed jobs older than specified days."""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        with get_db_session() as session:
            deleted_count = self.job_repo.cleanup_old_jobs(session, cutoff_date)
            
        logger.info(f"Cleaned up {deleted_count} old jobs")
        return deleted_count
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """Get statistics about the job queues."""
        inspect = celery_app.control.inspect()
        
        # Get active tasks
        active_tasks = inspect.active()
        scheduled_tasks = inspect.scheduled()
        reserved_tasks = inspect.reserved()
        
        # Count tasks by type
        task_counts = {}
        for worker_tasks in (active_tasks or {}).values():
            for task in worker_tasks:
                task_name = task['name']
                task_counts[task_name] = task_counts.get(task_name, 0) + 1
        
        # Get queue lengths
        queue_lengths = {}
        try:
            from celery.app.control import Inspect
            i = Inspect(app=celery_app)
            queue_lengths = i.active_queues() or {}
        except Exception as e:
            logger.warning(f"Could not get queue lengths: {e}")
        
        return {
            'active_tasks': len(sum((active_tasks or {}).values(), [])),
            'scheduled_tasks': len(sum((scheduled_tasks or {}).values(), [])),
            'reserved_tasks': len(sum((reserved_tasks or {}).values(), [])),
            'task_counts': task_counts,
            'queue_lengths': queue_lengths
        }
    
    def _get_task_name(self, scan_type: ScanType) -> str:
        """Map scan type to Celery task name."""
        task_mapping = {
            ScanType.RECON: 'recon.tasks.run_recon_scan',
            ScanType.SUBDOMAIN: 'recon.tasks.run_subdomain_scan',
            ScanType.PORT_SCAN: 'recon.tasks.run_port_scan',
            ScanType.CONTENT_DISCOVERY: 'analysis.tasks.run_content_discovery',
            ScanType.VULNERABILITY_SCAN: 'fuzz.tasks.run_vulnerability_scan',
            ScanType.SCREENSHOT: 'recon.tasks.run_screenshot_scan',
            ScanType.FUZZING: 'fuzz.tasks.run_fuzzing_scan'
        }
        
        return task_mapping.get(scan_type, 'recon.tasks.run_generic_scan')
    
    def submit_enhanced_scan(self, scan_type: str, target: str, **kwargs) -> str:
        """Submit enhanced Phase B scan jobs."""
        
        enhanced_task_mapping = {
            'enhanced_recon': 'recon.tasks.run_enhanced_recon',
            'advanced_subdomain': 'recon.tasks.run_advanced_subdomain_scan',
            'advanced_port_scan': 'recon.tasks.run_advanced_port_scan'
        }
        
        task_name = enhanced_task_mapping.get(scan_type)
        if not task_name:
            raise ValueError(f"Unknown enhanced scan type: {scan_type}")
        
        try:
            # Create job record
            from data.schemas import ScanJob, ScanStatus
            job = ScanJob(
                name=f"{scan_type}_{target}",
                scan_type=scan_type,
                target=target,
                parameters=kwargs,
                status=ScanStatus.PENDING
            )
            
            with get_db_session() as session:
                saved_job = job_repository.create(session, job)
                job_id = saved_job.id
            
            # Submit to Celery
            celery_task = celery_app.send_task(
                task_name,
                args=[job_id, target],
                kwargs=kwargs,
                priority=kwargs.get('priority', 5)
            )
            
            # Update job with Celery task ID
            with get_db_session() as session:
                job_repository.update_task_id(session, job_id, celery_task.id)
            
            logger.info(f"Submitted enhanced scan {scan_type} for target {target}")
            return job_id
            
        except Exception as e:
            logger.error(f"Failed to submit enhanced scan: {e}")
            raise


# Workflow definitions
class WorkflowOrchestrator:
    """Orchestrator for complex multi-stage workflows."""
    
    def __init__(self):
        self.job_orchestrator = JobOrchestrator()
    
    def run_full_recon_workflow(self, target: str) -> str:
        """Run a complete reconnaissance workflow."""
        workflow_id = f"workflow_{target}_{datetime.utcnow().isoformat()}"
        
        # Stage 1: Basic recon
        recon_job = self.job_orchestrator.submit_scan(
            ScanRequest(
                target=target,
                scan_type=ScanType.RECON,
                priority=8
            )
        )
        
        # Stage 2: Subdomain discovery (depends on stage 1)
        subdomain_job = self.job_orchestrator.submit_scan(
            ScanRequest(
                target=target,
                scan_type=ScanType.SUBDOMAIN,
                priority=7
            )
        )
        
        # Stage 3: Port scanning (depends on stage 2)
        # This would be implemented with Celery chains/groups
        
        logger.info(f"Started full recon workflow {workflow_id} for {target}")
        return workflow_id
    
    def run_vulnerability_assessment_workflow(self, target: str) -> str:
        """Run a complete vulnerability assessment workflow."""
        workflow_id = f"vuln_workflow_{target}_{datetime.utcnow().isoformat()}"
        
        # This would implement a complex workflow with dependencies
        # between different scan types
        
        logger.info(f"Started vulnerability assessment workflow {workflow_id} for {target}")
        return workflow_id


# Global orchestrator instance
orchestrator = JobOrchestrator()
workflow_orchestrator = WorkflowOrchestrator()


# Health check functions
def health_check() -> Dict[str, Any]:
    """Check the health of the orchestration system."""
    try:
        # Check Celery connection
        celery_status = celery_app.control.inspect().ping()
        celery_healthy = bool(celery_status)
        
        # Check database connection
        db_healthy = False
        try:
            with get_db_session() as session:
                session.execute("SELECT 1")
                db_healthy = True
        except Exception:
            pass
        
        # Get queue stats
        queue_stats = orchestrator.get_queue_stats()
        
        return {
            'status': 'healthy' if (celery_healthy and db_healthy) else 'unhealthy',
            'celery_healthy': celery_healthy,
            'database_healthy': db_healthy,
            'queue_stats': queue_stats,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        return {
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }
