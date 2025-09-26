"""
Logging and audit system for the AI Bug Hunter framework.

This module provides structured logging, audit trails, and evidence storage
with immutable logs and comprehensive tracking of all activities.
"""

import os
import json
import logging
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path
import structlog
from structlog.stdlib import LoggerFactory
import boto3
from botocore.exceptions import ClientError


# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)


class AuditLogger:
    """Immutable audit logger for security events."""
    
    def __init__(self, log_dir: str = "logs/audit"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure audit logger
        self.logger = structlog.get_logger("audit")
        
        # Set up file handler for audit logs
        audit_file = self.log_dir / "audit.jsonl"
        file_handler = logging.FileHandler(audit_file, mode='a')
        file_handler.setLevel(logging.INFO)
        
        # Get the root logger and add our handler
        root_logger = logging.getLogger()
        root_logger.addHandler(file_handler)
        root_logger.setLevel(logging.INFO)
    
    def log_scan_start(self, job_id: str, target: str, scan_type: str, user: Optional[str] = None) -> str:
        """Log the start of a scan job."""
        event_id = self._generate_event_id()
        
        self.logger.info(
            "scan_started",
            event_id=event_id,
            job_id=job_id,
            target=target,
            scan_type=scan_type,
            user=user,
            timestamp=datetime.utcnow().isoformat()
        )
        
        return event_id
    
    def log_scan_complete(self, job_id: str, results_count: int, findings_count: int, status: str) -> str:
        """Log the completion of a scan job."""
        event_id = self._generate_event_id()
        
        self.logger.info(
            "scan_completed",
            event_id=event_id,
            job_id=job_id,
            results_count=results_count,
            findings_count=findings_count,
            status=status,
            timestamp=datetime.utcnow().isoformat()
        )
        
        return event_id
    
    def log_finding_created(self, finding_id: str, severity: str, vulnerability_type: str, target: str) -> str:
        """Log the creation of a security finding."""
        event_id = self._generate_event_id()
        
        self.logger.info(
            "finding_created",
            event_id=event_id,
            finding_id=finding_id,
            severity=severity,
            vulnerability_type=vulnerability_type,
            target=target,
            timestamp=datetime.utcnow().isoformat()
        )
        
        return event_id
    
    def log_finding_updated(self, finding_id: str, field: str, old_value: Any, new_value: Any, user: Optional[str] = None) -> str:
        """Log updates to a finding."""
        event_id = self._generate_event_id()
        
        self.logger.info(
            "finding_updated",
            event_id=event_id,
            finding_id=finding_id,
            field=field,
            old_value=str(old_value),
            new_value=str(new_value),
            user=user,
            timestamp=datetime.utcnow().isoformat()
        )
        
        return event_id
    
    def log_api_request(self, service: str, endpoint: str, method: str, status_code: int, user: Optional[str] = None) -> str:
        """Log API requests to external services."""
        event_id = self._generate_event_id()
        
        self.logger.info(
            "api_request",
            event_id=event_id,
            service=service,
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            user=user,
            timestamp=datetime.utcnow().isoformat()
        )
        
        return event_id
    
    def log_evidence_stored(self, evidence_id: str, evidence_type: str, file_path: str, file_hash: str) -> str:
        """Log evidence storage."""
        event_id = self._generate_event_id()
        
        self.logger.info(
            "evidence_stored",
            event_id=event_id,
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            file_path=file_path,
            file_hash=file_hash,
            timestamp=datetime.utcnow().isoformat()
        )
        
        return event_id
    
    def log_security_event(self, event_type: str, description: str, severity: str = "medium", **kwargs) -> str:
        """Log general security events."""
        event_id = self._generate_event_id()
        
        self.logger.warning(
            "security_event",
            event_id=event_id,
            event_type=event_type,
            description=description,
            severity=severity,
            timestamp=datetime.utcnow().isoformat(),
            **kwargs
        )
        
        return event_id
    
    def _generate_event_id(self) -> str:
        """Generate a unique event ID."""
        timestamp = datetime.utcnow().isoformat()
        random_data = os.urandom(16).hex()
        return hashlib.sha256(f"{timestamp}{random_data}".encode()).hexdigest()[:16]


class EvidenceStore:
    """Secure storage for evidence files (screenshots, pcaps, etc.)."""
    
    def __init__(self, storage_type: str = "local", **kwargs):
        self.storage_type = storage_type
        self.audit_logger = AuditLogger()
        
        if storage_type == "local":
            self.base_path = Path(kwargs.get("base_path", "evidence"))
            self.base_path.mkdir(parents=True, exist_ok=True)
        elif storage_type == "s3":
            self.s3_client = boto3.client('s3')
            self.bucket_name = kwargs.get("bucket_name", "bug-hunter-evidence")
        else:
            raise ValueError(f"Unsupported storage type: {storage_type}")
    
    def store_evidence(
        self,
        evidence_type: str,
        file_data: bytes,
        file_extension: str = "",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        """Store evidence file and return storage information."""
        
        # Generate evidence ID and file hash
        evidence_id = self._generate_evidence_id()
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        # Create filename
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{evidence_id}{file_extension}"
        
        if self.storage_type == "local":
            file_path = self._store_local(evidence_type, filename, file_data, metadata)
        elif self.storage_type == "s3":
            file_path = self._store_s3(evidence_type, filename, file_data, metadata)
        else:
            raise ValueError(f"Unsupported storage type: {self.storage_type}")
        
        # Log evidence storage
        self.audit_logger.log_evidence_stored(evidence_id, evidence_type, file_path, file_hash)
        
        return {
            "evidence_id": evidence_id,
            "file_path": file_path,
            "file_hash": file_hash,
            "file_size": len(file_data),
            "storage_type": self.storage_type,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _store_local(self, evidence_type: str, filename: str, file_data: bytes, metadata: Optional[Dict[str, Any]]) -> str:
        """Store evidence locally."""
        # Create type-specific directory
        type_dir = self.base_path / evidence_type
        type_dir.mkdir(parents=True, exist_ok=True)
        
        # Write file
        file_path = type_dir / filename
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        # Write metadata if provided
        if metadata:
            metadata_path = type_dir / f"{filename}.metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
        
        return str(file_path)
    
    def _store_s3(self, evidence_type: str, filename: str, file_data: bytes, metadata: Optional[Dict[str, Any]]) -> str:
        """Store evidence in S3."""
        key = f"{evidence_type}/{filename}"
        
        try:
            # Prepare S3 metadata
            s3_metadata = {}
            if metadata:
                # S3 metadata must be strings
                s3_metadata = {k: str(v) for k, v in metadata.items()}
            
            # Upload file
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=file_data,
                Metadata=s3_metadata,
                ServerSideEncryption='AES256'
            )
            
            return f"s3://{self.bucket_name}/{key}"
        
        except ClientError as e:
            raise Exception(f"Failed to store evidence in S3: {e}")
    
    def retrieve_evidence(self, file_path: str) -> bytes:
        """Retrieve evidence file."""
        if self.storage_type == "local":
            with open(file_path, 'rb') as f:
                return f.read()
        elif self.storage_type == "s3":
            # Parse S3 path
            if file_path.startswith("s3://"):
                bucket, key = file_path[5:].split("/", 1)
                response = self.s3_client.get_object(Bucket=bucket, Key=key)
                return response['Body'].read()
            else:
                raise ValueError("Invalid S3 path format")
        else:
            raise ValueError(f"Unsupported storage type: {self.storage_type}")
    
    def _generate_evidence_id(self) -> str:
        """Generate a unique evidence ID."""
        timestamp = datetime.utcnow().isoformat()
        random_data = os.urandom(8).hex()
        return hashlib.sha256(f"{timestamp}{random_data}".encode()).hexdigest()[:12]


class ScreenshotManager:
    """Manager for taking and storing screenshots."""
    
    def __init__(self, evidence_store: EvidenceStore):
        self.evidence_store = evidence_store
        self.logger = structlog.get_logger("screenshot")
    
    async def take_screenshot(self, url: str, **kwargs) -> Optional[Dict[str, str]]:
        """Take a screenshot of a URL and store it."""
        try:
            from playwright.async_api import async_playwright
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                # Set viewport and user agent
                await page.set_viewport_size({"width": 1920, "height": 1080})
                await page.set_extra_http_headers({
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                })
                
                # Navigate to URL
                await page.goto(url, timeout=30000, wait_until="networkidle")
                
                # Take screenshot
                screenshot_data = await page.screenshot(full_page=True, type="png")
                
                await browser.close()
                
                # Store screenshot
                metadata = {
                    "url": url,
                    "timestamp": datetime.utcnow().isoformat(),
                    "viewport_width": 1920,
                    "viewport_height": 1080,
                    "full_page": True
                }
                
                storage_info = self.evidence_store.store_evidence(
                    evidence_type="screenshots",
                    file_data=screenshot_data,
                    file_extension=".png",
                    metadata=metadata
                )
                
                self.logger.info(
                    "screenshot_taken",
                    url=url,
                    evidence_id=storage_info["evidence_id"],
                    file_size=storage_info["file_size"]
                )
                
                return storage_info
        
        except Exception as e:
            self.logger.error("screenshot_failed", url=url, error=str(e))
            return None


class RequestResponseLogger:
    """Logger for HTTP requests and responses."""
    
    def __init__(self, evidence_store: EvidenceStore):
        self.evidence_store = evidence_store
        self.logger = structlog.get_logger("http")
    
    def log_request_response(
        self,
        request_data: Dict[str, Any],
        response_data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        """Log HTTP request/response pair."""
        
        # Create combined data
        log_data = {
            "request": request_data,
            "response": response_data,
            "context": context or {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Store as JSON
        json_data = json.dumps(log_data, indent=2).encode('utf-8')
        
        metadata = {
            "url": request_data.get("url", ""),
            "method": request_data.get("method", ""),
            "status_code": response_data.get("status_code", ""),
            "content_type": response_data.get("content_type", "")
        }
        
        storage_info = self.evidence_store.store_evidence(
            evidence_type="http_logs",
            file_data=json_data,
            file_extension=".json",
            metadata=metadata
        )
        
        self.logger.info(
            "http_logged",
            url=request_data.get("url"),
            method=request_data.get("method"),
            status_code=response_data.get("status_code"),
            evidence_id=storage_info["evidence_id"]
        )
        
        return storage_info


# Global instances
audit_logger = AuditLogger()
evidence_store = EvidenceStore(
    storage_type=os.getenv("EVIDENCE_STORAGE_TYPE", "local"),
    base_path=os.getenv("EVIDENCE_BASE_PATH", "evidence"),
    bucket_name=os.getenv("EVIDENCE_S3_BUCKET", "bug-hunter-evidence")
)
screenshot_manager = ScreenshotManager(evidence_store)
request_logger = RequestResponseLogger(evidence_store)


# Convenience functions
def log_scan_activity(job_id: str, activity: str, **kwargs) -> str:
    """Log scan activity."""
    return audit_logger.logger.info(
        "scan_activity",
        job_id=job_id,
        activity=activity,
        timestamp=datetime.utcnow().isoformat(),
        **kwargs
    )


def log_security_event(event_type: str, description: str, **kwargs) -> str:
    """Log security event."""
    return audit_logger.log_security_event(event_type, description, **kwargs)


def store_evidence_file(evidence_type: str, file_data: bytes, **kwargs) -> Dict[str, str]:
    """Store evidence file."""
    return evidence_store.store_evidence(evidence_type, file_data, **kwargs)
