"""
FastAPI web interface for the AI Bug Hunter framework.

This module provides REST API endpoints for managing scans, findings,
and assets through a web interface.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn

from data.schemas import (
    ScanRequest, ScanResponse, ScanJob, ScanType, ScanStatus,
    Finding, FindingStatus, SeverityLevel, VulnerabilityType,
    FindingsResponse, AssetResponse
)
from automation.orchestrator import orchestrator, workflow_orchestrator, health_check
from automation.database import get_db_session, finding_repository, job_repository, asset_repository
from automation.logging_config import audit_logger
from automation.api_manager import api_manager
from automation.ai_services import triage_finding_ai, generate_finding_poc


logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="AI Bug Hunter API",
    description="REST API for the AI Bug Hunter security testing framework",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request/Response Models
class ScanSubmissionRequest(BaseModel):
    target: str
    scan_type: ScanType
    config: Optional[Dict[str, Any]] = None
    priority: int = 5


class FindingUpdateRequest(BaseModel):
    status: Optional[FindingStatus] = None
    assigned_to: Optional[str] = None
    remediation: Optional[str] = None
    notes: Optional[str] = None


class TriageRequest(BaseModel):
    finding_id: str
    action: str  # "verify", "false_positive", "duplicate", "resolve"
    notes: Optional[str] = None
    user: Optional[str] = None


# Health Check Endpoints
@app.get("/health")
async def health_status():
    """Get system health status."""
    return health_check()


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "AI Bug Hunter API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "health": "/health"
    }


# Scan Management Endpoints
@app.post("/scans", response_model=ScanResponse)
async def submit_scan(
    scan_request: ScanSubmissionRequest,
    background_tasks: BackgroundTasks
):
    """Submit a new scan job."""
    try:
        # Convert to internal format
        internal_request = ScanRequest(
            target=scan_request.target,
            scan_type=scan_request.scan_type,
            config=scan_request.config,
            priority=scan_request.priority
        )
        
        # Submit scan
        job_id = orchestrator.submit_scan(internal_request)
        
        # Log scan submission
        audit_logger.log_scan_start(
            job_id=job_id,
            target=scan_request.target,
            scan_type=scan_request.scan_type.value
        )
        
        return ScanResponse(
            job_id=job_id,
            status=ScanStatus.PENDING,
            message=f"Scan submitted successfully for target: {scan_request.target}"
        )
    
    except Exception as e:
        logger.error(f"Failed to submit scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scans/{job_id}")
async def get_scan_status(job_id: str):
    """Get scan job status."""
    try:
        status = orchestrator.get_job_status(job_id)
        return status
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to get scan status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scans")
async def list_scans(
    status: Optional[ScanStatus] = None,
    scan_type: Optional[ScanType] = None,
    limit: int = Query(50, le=100),
    offset: int = Query(0, ge=0)
):
    """List scan jobs with optional filtering."""
    try:
        jobs = orchestrator.list_jobs(
            status=status,
            scan_type=scan_type,
            limit=limit,
            offset=offset
        )
        return {"jobs": jobs, "total": len(jobs)}
    except Exception as e:
        logger.error(f"Failed to list scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/scans/{job_id}")
async def cancel_scan(job_id: str):
    """Cancel a scan job."""
    try:
        success = orchestrator.cancel_job(job_id)
        if success:
            return {"message": f"Scan {job_id} cancelled successfully"}
        else:
            raise HTTPException(status_code=404, detail="Scan job not found")
    except Exception as e:
        logger.error(f"Failed to cancel scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Workflow Endpoints
@app.post("/workflows/recon")
async def start_recon_workflow(target: str):
    """Start a full reconnaissance workflow."""
    try:
        workflow_id = workflow_orchestrator.run_full_recon_workflow(target)
        return {
            "workflow_id": workflow_id,
            "message": f"Reconnaissance workflow started for {target}"
        }
    except Exception as e:
        logger.error(f"Failed to start recon workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/workflows/vulnerability-assessment")
async def start_vuln_assessment_workflow(target: str):
    """Start a vulnerability assessment workflow."""
    try:
        workflow_id = workflow_orchestrator.run_vulnerability_assessment_workflow(target)
        return {
            "workflow_id": workflow_id,
            "message": f"Vulnerability assessment workflow started for {target}"
        }
    except Exception as e:
        logger.error(f"Failed to start vulnerability assessment workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Phase B Enhanced Scan Endpoints
@app.post("/scans/enhanced")
async def submit_enhanced_scan(
    scan_type: str,
    target: str,
    config: Optional[Dict[str, Any]] = None,
    priority: int = 5
):
    """Submit an enhanced Phase B scan."""
    try:
        job_id = orchestrator.submit_enhanced_scan(
            scan_type=scan_type,
            target=target,
            priority=priority,
            **(config or {})
        )
        
        # Log scan submission
        audit_logger.log_scan_start(
            job_id=job_id,
            target=target,
            scan_type=scan_type
        )
        
        return {
            "job_id": job_id,
            "scan_type": scan_type,
            "target": target,
            "message": f"Enhanced {scan_type} scan submitted for {target}"
        }
    
    except Exception as e:
        logger.error(f"Failed to submit enhanced scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scans/enhanced-recon")
async def submit_enhanced_recon(
    target: str,
    collectors: Optional[List[str]] = None,
    priority: int = 8
):
    """Submit enhanced reconnaissance with ASN analysis and corporate data."""
    try:
        config = {}
        if collectors:
            config['collectors'] = collectors
        
        job_id = orchestrator.submit_enhanced_scan(
            scan_type='enhanced_recon',
            target=target,
            priority=priority,
            **config
        )
        
        return {
            "job_id": job_id,
            "message": f"Enhanced reconnaissance started for {target}",
            "collectors": collectors or ["asn_analysis", "corporate_acquisitions", "advanced_certificate"]
        }
    
    except Exception as e:
        logger.error(f"Failed to submit enhanced recon: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scans/advanced-subdomain")
async def submit_advanced_subdomain_scan(
    target: str,
    enable_bruteforce: bool = True,
    max_permutations: int = 1000,
    priority: int = 7
):
    """Submit advanced subdomain discovery with wildcard detection."""
    try:
        job_id = orchestrator.submit_enhanced_scan(
            scan_type='advanced_subdomain',
            target=target,
            priority=priority,
            enable_bruteforce=enable_bruteforce,
            max_permutations=max_permutations
        )
        
        return {
            "job_id": job_id,
            "message": f"Advanced subdomain discovery started for {target}",
            "bruteforce_enabled": enable_bruteforce,
            "max_permutations": max_permutations
        }
    
    except Exception as e:
        logger.error(f"Failed to submit advanced subdomain scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scans/advanced-port-scan")
async def submit_advanced_port_scan(
    target: str,
    scan_type: str = "common",
    take_screenshots: bool = True,
    service_detection: bool = True,
    priority: int = 6
):
    """Submit advanced port scanning with service enumeration."""
    try:
        job_id = orchestrator.submit_enhanced_scan(
            scan_type='advanced_port_scan',
            target=target,
            priority=priority,
            scan_type=scan_type,
            take_screenshots=take_screenshots,
            service_detection=service_detection
        )
        
        return {
            "job_id": job_id,
            "message": f"Advanced port scan started for {target}",
            "port_scan_type": scan_type,
            "screenshots_enabled": take_screenshots,
            "service_detection": service_detection
        }
    
    except Exception as e:
        logger.error(f"Failed to submit advanced port scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Phase C Content Discovery & Application Analysis Endpoints
@app.post("/scans/content-discovery")
async def submit_content_discovery(
    target: str,
    max_depth: int = 3,
    max_pages: int = 100,
    priority: int = 7
):
    """Submit advanced content discovery with intelligent crawling."""
    try:
        job_id = orchestrator.submit_job(
            scan_type=ScanType.CONTENT_DISCOVERY,
            target=target,
            priority=priority,
            max_depth=max_depth,
            max_pages=max_pages
        )
        
        return {
            "job_id": job_id,
            "message": f"Advanced content discovery started for {target}",
            "max_depth": max_depth,
            "max_pages": max_pages
        }
    
    except Exception as e:
        logger.error(f"Failed to submit content discovery: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scans/bruteforce-discovery")
async def submit_bruteforce_discovery(
    target: str,
    technology: str = "common",
    categories: List[str] = ["common", "files", "admin"],
    max_requests: int = 1000,
    enable_permutations: bool = True,
    priority: int = 6
):
    """Submit intelligent bruteforce directory and file discovery."""
    try:
        # Use analysis task directly for bruteforce
        from automation.orchestrator import celery_app
        
        # Create job record
        job = ScanJob(
            name=f"bruteforce_{target}",
            scan_type="bruteforce_discovery",
            target=target,
            parameters={
                "technology": technology,
                "categories": categories,
                "max_requests": max_requests,
                "enable_permutations": enable_permutations
            },
            status=ScanStatus.PENDING
        )
        
        with get_db_session() as session:
            saved_job = job_repository.create(session, job)
            job_id = saved_job.id
        
        # Submit to Celery
        celery_task = celery_app.send_task(
            'analysis.tasks.run_bruteforce_discovery',
            args=[job_id, target],
            kwargs={
                "technology": technology,
                "categories": categories,
                "max_requests": max_requests,
                "enable_permutations": enable_permutations
            },
            priority=priority
        )
        
        # Update job with Celery task ID
        with get_db_session() as session:
            job_repository.update_task_id(session, job_id, celery_task.id)
        
        return {
            "job_id": job_id,
            "message": f"Bruteforce discovery started for {target}",
            "technology": technology,
            "categories": categories,
            "max_requests": max_requests
        }
    
    except Exception as e:
        logger.error(f"Failed to submit bruteforce discovery: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scans/technology-profiling")
async def submit_technology_profiling(
    target: str,
    priority: int = 7
):
    """Submit comprehensive technology profiling and fingerprinting."""
    try:
        # Use analysis task directly for technology profiling
        from automation.orchestrator import celery_app
        
        # Create job record
        job = ScanJob(
            name=f"tech_profiling_{target}",
            scan_type="technology_profiling",
            target=target,
            parameters={},
            status=ScanStatus.PENDING
        )
        
        with get_db_session() as session:
            saved_job = job_repository.create(session, job)
            job_id = saved_job.id
        
        # Submit to Celery
        celery_task = celery_app.send_task(
            'analysis.tasks.run_technology_profiling',
            args=[job_id, target],
            kwargs={},
            priority=priority
        )
        
        # Update job with Celery task ID
        with get_db_session() as session:
            job_repository.update_task_id(session, job_id, celery_task.id)
        
        return {
            "job_id": job_id,
            "message": f"Technology profiling started for {target}"
        }
    
    except Exception as e:
        logger.error(f"Failed to submit technology profiling: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Phase D Vulnerability Detection & Fuzzing Endpoints
@app.post("/scans/advanced-fuzzing")
async def submit_advanced_fuzzing(
    target: str,
    endpoints: List[Dict[str, Any]] = [],
    vulnerability_types: List[str] = ["xss", "sqli", "ssrf", "lfi", "rce"],
    max_payloads_per_type: int = 20,
    priority: int = 8
):
    """Submit advanced fuzzing with payload generation and mutation."""
    try:
        from automation.orchestrator import celery_app
        
        # Create job record
        job = ScanJob(
            name=f"advanced_fuzzing_{target}",
            scan_type="advanced_fuzzing",
            target=target,
            parameters={
                "endpoints": endpoints,
                "vulnerability_types": vulnerability_types,
                "max_payloads_per_type": max_payloads_per_type
            },
            status=ScanStatus.PENDING
        )
        
        with get_db_session() as session:
            saved_job = job_repository.create(session, job)
            job_id = saved_job.id
        
        # Submit to Celery
        celery_task = celery_app.send_task(
            'fuzz.tasks.run_advanced_fuzzing',
            args=[job_id, target],
            kwargs={
                "endpoints": endpoints,
                "vulnerability_types": vulnerability_types,
                "max_payloads_per_type": max_payloads_per_type
            },
            priority=priority
        )
        
        # Update job with Celery task ID
        with get_db_session() as session:
            job_repository.update_task_id(session, job_id, celery_task.id)
        
        return {
            "job_id": job_id,
            "message": f"Advanced fuzzing started for {target}",
            "vulnerability_types": vulnerability_types,
            "max_payloads_per_type": max_payloads_per_type
        }
    
    except Exception as e:
        logger.error(f"Failed to submit advanced fuzzing: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scans/cve-scanning")
async def submit_cve_scanning(
    target: str,
    severity: List[str] = ["critical", "high", "medium"],
    tags: List[str] = [],
    templates: List[str] = [],
    rate_limit: int = 150,
    priority: int = 8
):
    """Submit CVE scanning with Nuclei and custom detection."""
    try:
        from automation.orchestrator import celery_app
        
        # Create job record
        job = ScanJob(
            name=f"cve_scanning_{target}",
            scan_type="cve_scanning",
            target=target,
            parameters={
                "severity": severity,
                "tags": tags,
                "templates": templates,
                "rate_limit": rate_limit
            },
            status=ScanStatus.PENDING
        )
        
        with get_db_session() as session:
            saved_job = job_repository.create(session, job)
            job_id = saved_job.id
        
        # Submit to Celery
        celery_task = celery_app.send_task(
            'fuzz.tasks.run_cve_scanning',
            args=[job_id, target],
            kwargs={
                "severity": severity,
                "tags": tags,
                "templates": templates,
                "rate_limit": rate_limit
            },
            priority=priority
        )
        
        # Update job with Celery task ID
        with get_db_session() as session:
            job_repository.update_task_id(session, job_id, celery_task.id)
        
        return {
            "job_id": job_id,
            "message": f"CVE scanning started for {target}",
            "severity": severity,
            "rate_limit": rate_limit
        }
    
    except Exception as e:
        logger.error(f"Failed to submit CVE scanning: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scans/class-specific-scanning")
async def submit_class_specific_scanning(
    target: str,
    endpoints: List[Dict[str, Any]] = [],
    vulnerability_types: List[str] = ["xss", "sqli", "ssrf"],
    priority: int = 7
):
    """Submit class-specific vulnerability scanning (XSS, SQLi, SSRF, etc.)."""
    try:
        from automation.orchestrator import celery_app
        
        # Create job record
        job = ScanJob(
            name=f"class_specific_{target}",
            scan_type="class_specific_scanning",
            target=target,
            parameters={
                "endpoints": endpoints,
                "vulnerability_types": vulnerability_types
            },
            status=ScanStatus.PENDING
        )
        
        with get_db_session() as session:
            saved_job = job_repository.create(session, job)
            job_id = saved_job.id
        
        # Submit to Celery
        celery_task = celery_app.send_task(
            'fuzz.tasks.run_class_specific_scanning',
            args=[job_id, target],
            kwargs={
                "endpoints": endpoints,
                "vulnerability_types": vulnerability_types
            },
            priority=priority
        )
        
        # Update job with Celery task ID
        with get_db_session() as session:
            job_repository.update_task_id(session, job_id, celery_task.id)
        
        return {
            "job_id": job_id,
            "message": f"Class-specific scanning started for {target}",
            "vulnerability_types": vulnerability_types
        }
    
    except Exception as e:
        logger.error(f"Failed to submit class-specific scanning: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Phase E Exploitation & Post-Exploitation Endpoints
@app.post("/scans/exploitation-framework")
async def submit_exploitation_framework(
    target: str,
    vulnerabilities: List[Dict[str, Any]] = [],
    validate_exploit: bool = False,
    priority: int = 9
):
    """Submit exploitation framework with proof-of-concept generation."""
    try:
        from automation.orchestrator import celery_app
        
        # Create job record
        job = ScanJob(
            name=f"exploitation_{target}",
            scan_type="exploitation_framework",
            target=target,
            parameters={
                "vulnerabilities": vulnerabilities,
                "validate_exploit": validate_exploit
            },
            status=ScanStatus.PENDING
        )
        
        with get_db_session() as session:
            saved_job = job_repository.create(session, job)
            job_id = saved_job.id
        
        # Submit to Celery
        celery_task = celery_app.send_task(
            'exploit.tasks.run_exploitation_framework',
            args=[job_id, target],
            kwargs={
                "vulnerabilities": vulnerabilities,
                "validate_exploit": validate_exploit
            },
            priority=priority
        )
        
        # Update job with Celery task ID
        with get_db_session() as session:
            job_repository.update_task_id(session, job_id, celery_task.id)
        
        return {
            "job_id": job_id,
            "message": f"Exploitation framework started for {target}",
            "vulnerabilities_count": len(vulnerabilities),
            "validate_exploit": validate_exploit
        }
    
    except Exception as e:
        logger.error(f"Failed to submit exploitation framework: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scans/payload-delivery")
async def submit_payload_delivery(
    target: str,
    payload_configs: List[Dict[str, Any]] = [],
    monitor_execution: bool = False,
    priority: int = 9
):
    """Submit payload delivery and execution operations."""
    try:
        from automation.orchestrator import celery_app
        
        # Create job record
        job = ScanJob(
            name=f"payload_delivery_{target}",
            scan_type="payload_delivery",
            target=target,
            parameters={
                "payload_configs": payload_configs,
                "monitor_execution": monitor_execution
            },
            status=ScanStatus.PENDING
        )
        
        with get_db_session() as session:
            saved_job = job_repository.create(session, job)
            job_id = saved_job.id
        
        # Submit to Celery
        celery_task = celery_app.send_task(
            'exploit.tasks.run_payload_delivery',
            args=[job_id, target],
            kwargs={
                "payload_configs": payload_configs,
                "monitor_execution": monitor_execution
            },
            priority=priority
        )
        
        # Update job with Celery task ID
        with get_db_session() as session:
            job_repository.update_task_id(session, job_id, celery_task.id)
        
        return {
            "job_id": job_id,
            "message": f"Payload delivery started for {target}",
            "payloads_count": len(payload_configs),
            "monitor_execution": monitor_execution
        }
    
    except Exception as e:
        logger.error(f"Failed to submit payload delivery: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scans/post-exploitation")
async def submit_post_exploitation(
    target: str,
    session_configs: List[Dict[str, Any]] = [],
    priority: int = 9
):
    """Submit post-exploitation enumeration and persistence operations."""
    try:
        from automation.orchestrator import celery_app
        
        # Create job record
        job = ScanJob(
            name=f"post_exploitation_{target}",
            scan_type="post_exploitation",
            target=target,
            parameters={
                "session_configs": session_configs
            },
            status=ScanStatus.PENDING
        )
        
        with get_db_session() as session:
            saved_job = job_repository.create(session, job)
            job_id = saved_job.id
        
        # Submit to Celery
        celery_task = celery_app.send_task(
            'exploit.tasks.run_post_exploitation',
            args=[job_id, target],
            kwargs={
                "session_configs": session_configs
            },
            priority=priority
        )
        
        # Update job with Celery task ID
        with get_db_session() as session:
            job_repository.update_task_id(session, job_id, celery_task.id)
        
        return {
            "job_id": job_id,
            "message": f"Post-exploitation started for {target}",
            "sessions_count": len(session_configs)
        }
    
    except Exception as e:
        logger.error(f"Failed to submit post-exploitation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Report Generation Endpoints
@app.post("/reports/generate")
async def submit_report_generation(
    job_id: str,
    report_type: str = Query('markdown', enum=['markdown', 'html', 'pdf']),
    priority: int = 1
):
    """Submit a job to generate a penetration testing report."""
    try:
        from automation.orchestrator import celery_app
        
        # Define output path
        output_path = f"/tmp/report_{job_id}.{report_type}"
        
        # Create a job record for the report generation
        report_job = ScanJob(
            name=f"report_{job_id}",
            scan_type="report_generation",
            target=job_id, # Target is the job_id for which we generate the report
            parameters={
                "original_job_id": job_id,
                "report_type": report_type,
                "output_path": output_path
            },
            status=ScanStatus.PENDING
        )
        
        with get_db_session() as session:
            saved_job = job_repository.create(session, report_job)
            report_job_id = saved_job.id
        
        # Submit to Celery
        celery_task = celery_app.send_task(
            'reporting.tasks.generate_report',
            args=[job_id, output_path, report_type],
            priority=priority
        )
        
        # Update job with Celery task ID
        with get_db_session() as session:
            job_repository.update_task_id(session, report_job_id, celery_task.id)
        
        return {
            "job_id": report_job_id,
            "message": f"Report generation started for job {job_id}",
            "output_path": output_path
        }
    
    except Exception as e:
        logger.error(f"Failed to submit report generation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Finding Management Endpoints
@app.get("/findings", response_model=FindingsResponse)
async def list_findings(
    status: Optional[FindingStatus] = None,
    severity: Optional[SeverityLevel] = None,
    vulnerability_type: Optional[VulnerabilityType] = None,
    asset_id: Optional[str] = None,
    limit: int = Query(50, le=100),
    offset: int = Query(0, ge=0)
):
    """List findings with optional filtering."""
    try:
        with get_db_session() as session:
            # Build query filters
            query = session.query(finding_repository.model_class)
            
            if status:
                query = query.filter(finding_repository.model_class.status == status)
            if severity:
                query = query.filter(finding_repository.model_class.severity == severity)
            if vulnerability_type:
                query = query.filter(finding_repository.model_class.vulnerability_type == vulnerability_type)
            if asset_id:
                query = query.filter(finding_repository.model_class.asset_id == asset_id)
            
            total = query.count()
            findings = query.order_by(finding_repository.model_class.created_at.desc()).offset(offset).limit(limit).all()
            
            return FindingsResponse(
                findings=[Finding.from_orm(f) for f in findings],
                total=total,
                page=offset // limit + 1,
                per_page=limit
            )
    
    except Exception as e:
        logger.error(f"Failed to list findings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/findings/{finding_id}")
async def get_finding(finding_id: str):
    """Get a specific finding."""
    try:
        with get_db_session() as session:
            finding = finding_repository.get_by_id(session, finding_id)
            if not finding:
                raise HTTPException(status_code=404, detail="Finding not found")
            
            return Finding.from_orm(finding)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get finding: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/findings/{finding_id}")
async def update_finding(finding_id: str, update_request: FindingUpdateRequest):
    """Update a finding."""
    try:
        with get_db_session() as session:
            # Get current finding
            finding = finding_repository.get_by_id(session, finding_id)
            if not finding:
                raise HTTPException(status_code=404, detail="Finding not found")
            
            # Prepare update data
            update_data = {}
            if update_request.status is not None:
                update_data['status'] = update_request.status
            if update_request.assigned_to is not None:
                update_data['assigned_to'] = update_request.assigned_to
            if update_request.remediation is not None:
                update_data['remediation'] = update_request.remediation
            
            # Update finding
            updated_finding = finding_repository.update(session, finding_id, update_data)
            
            # Log update
            for field, value in update_data.items():
                old_value = getattr(finding, field)
                audit_logger.log_finding_updated(
                    finding_id=finding_id,
                    field=field,
                    old_value=old_value,
                    new_value=value
                )
            
            return Finding.from_orm(updated_finding)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update finding: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/findings/{finding_id}/triage")
async def triage_finding(finding_id: str, triage_request: TriageRequest):
    """Perform triage action on a finding."""
    try:
        with get_db_session() as session:
            finding = finding_repository.get_by_id(session, finding_id)
            if not finding:
                raise HTTPException(status_code=404, detail="Finding not found")
            
            # Convert to Pydantic model for AI analysis
            finding_obj = Finding.from_orm(finding)
            
            # Perform triage action
            update_data = {}
            
            if triage_request.action == "verify":
                update_data['status'] = FindingStatus.VERIFIED
                update_data['verified_by'] = triage_request.user
                update_data['verified_at'] = datetime.utcnow()
            elif triage_request.action == "false_positive":
                update_data['status'] = FindingStatus.FALSE_POSITIVE
            elif triage_request.action == "duplicate":
                update_data['status'] = FindingStatus.DUPLICATE
            elif triage_request.action == "resolve":
                update_data['status'] = FindingStatus.RESOLVED
                update_data['resolved_at'] = datetime.utcnow()
            else:
                raise HTTPException(status_code=400, detail="Invalid triage action")
            
            # Get AI triage recommendation if available
            ai_triage = None
            try:
                ai_triage = await triage_finding_ai(finding_obj)
            except Exception as e:
                logger.warning(f"AI triage failed: {e}")
            
            # Update finding
            updated_finding = finding_repository.update(session, finding_id, update_data)
            
            # Log triage action
            audit_logger.log_security_event(
                "finding_triaged",
                f"Finding {finding_id} triaged with action: {triage_request.action}",
                finding_id=finding_id,
                action=triage_request.action,
                user=triage_request.user
            )
            
            return {
                "finding": Finding.from_orm(updated_finding),
                "ai_recommendation": ai_triage,
                "message": f"Finding {triage_request.action} successfully"
            }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to triage finding: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/findings/{finding_id}/poc")
async def generate_poc(finding_id: str):
    """Generate proof-of-concept for a finding."""
    try:
        with get_db_session() as session:
            finding = finding_repository.get_by_id(session, finding_id)
            if not finding:
                raise HTTPException(status_code=404, detail="Finding not found")
            
            # Convert to Pydantic model
            finding_obj = Finding.from_orm(finding)
            
            # Generate PoC using AI
            poc = await generate_finding_poc(finding_obj)
            
            # Update finding with PoC
            update_data = {'proof_of_concept': poc}
            updated_finding = finding_repository.update(session, finding_id, update_data)
            
            # Log PoC generation
            audit_logger.log_security_event(
                "poc_generated",
                f"PoC generated for finding {finding_id}",
                finding_id=finding_id
            )
            
            return {
                "finding_id": finding_id,
                "poc": poc,
                "message": "PoC generated successfully"
            }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate PoC: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Statistics and Dashboard Endpoints
@app.get("/dashboard/stats")
async def get_dashboard_stats():
    """Get dashboard statistics."""
    try:
        with get_db_session() as session:
            # Get finding statistics
            finding_stats = finding_repository.get_stats(session)
            
            # Get recent scans
            recent_scans = job_repository.list_jobs(session, limit=10)
            
            # Get queue statistics
            queue_stats = orchestrator.get_queue_stats()
            
            # Get API service status
            api_status = api_manager.get_all_status()
            
            return {
                "findings": finding_stats,
                "recent_scans": [
                    {
                        "job_id": job.id,
                        "target": job.target,
                        "scan_type": job.scan_type,
                        "status": job.status,
                        "created_at": job.created_at.isoformat()
                    }
                    for job in recent_scans
                ],
                "queue": queue_stats,
                "api_services": api_status,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    except Exception as e:
        logger.error(f"Failed to get dashboard stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Asset Management Endpoints
@app.get("/assets")
async def list_assets(
    asset_type: Optional[str] = None,
    limit: int = Query(50, le=100),
    offset: int = Query(0, ge=0)
):
    """List discovered assets."""
    try:
        with get_db_session() as session:
            if asset_type:
                assets = asset_repository.list_by_type(session, asset_type, limit, offset)
            else:
                # Get all assets
                query = session.query(asset_repository.model_class)
                total = query.count()
                assets = query.order_by(asset_repository.model_class.first_seen.desc()).offset(offset).limit(limit).all()
            
            return {
                "assets": [
                    {
                        "id": asset.id,
                        "type": asset.asset_type,
                        "name": asset.name,
                        "data": asset.data,
                        "first_seen": asset.first_seen.isoformat(),
                        "last_seen": asset.last_seen.isoformat(),
                        "active": asset.active
                    }
                    for asset in assets
                ],
                "total": len(assets)
            }
    
    except Exception as e:
        logger.error(f"Failed to list assets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Configuration Endpoints
@app.get("/config/api-services")
async def get_api_service_config():
    """Get API service configuration status."""
    return api_manager.get_all_status()


@app.get("/config/collectors")
async def get_available_collectors():
    """Get available reconnaissance collectors."""
    from recon.collectors import recon_orchestrator
    return {
        "collectors": recon_orchestrator.get_available_collectors(),
        "description": "Available reconnaissance collectors"
    }


# Error Handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={"error": "Resource not found", "detail": str(exc.detail) if hasattr(exc, 'detail') else str(exc)}
    )


@app.exception_handler(500)
async def internal_error_handler(request, exc):
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": "An unexpected error occurred"}
    )


# Startup and Shutdown Events
@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    logger.info("AI Bug Hunter API starting up...")
    
    # Initialize database tables
    from automation.database import create_tables
    create_tables()
    
    logger.info("AI Bug Hunter API started successfully")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("AI Bug Hunter API shutting down...")


if __name__ == "__main__":
    uvicorn.run(
        "ui.api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
