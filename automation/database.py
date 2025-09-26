"""
Database configuration and repository classes for the AI Bug Hunter framework.

This module provides database connectivity, ORM models, and repository patterns
for managing scan jobs, findings, and assets.
"""

import os
from contextlib import contextmanager
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import (
    create_engine, Column, String, DateTime, Integer, Float, Boolean,
    Text, JSON, Enum as SQLEnum, ForeignKey, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid

from data.schemas import ScanStatus, ScanType, SeverityLevel, FindingStatus, VulnerabilityType


# Database configuration
DATABASE_URL = os.getenv(
    'DATABASE_URL',
    'postgresql://postgres:password@localhost:5432/bug_hunter'
)

engine = create_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=30,
    pool_pre_ping=True,
    echo=os.getenv('SQL_DEBUG', 'false').lower() == 'true'
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Database Models
class JobModel(Base):
    """Database model for scan jobs."""
    __tablename__ = 'scan_jobs'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    scan_type = Column(SQLEnum(ScanType), nullable=False)
    status = Column(SQLEnum(ScanStatus), nullable=False, default=ScanStatus.PENDING)
    target = Column(String, nullable=False)
    parameters = Column(JSON, default={})
    metadata = Column(JSON, default={})
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    results_count = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_scan_jobs_status', 'status'),
        Index('idx_scan_jobs_type', 'scan_type'),
        Index('idx_scan_jobs_target', 'target'),
        Index('idx_scan_jobs_created', 'created_at'),
    )


class FindingModel(Base):
    """Database model for security findings."""
    __tablename__ = 'findings'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(SQLEnum(SeverityLevel), nullable=False)
    status = Column(SQLEnum(FindingStatus), nullable=False, default=FindingStatus.NEW)
    vulnerability_type = Column(SQLEnum(VulnerabilityType), nullable=False)
    confidence = Column(Float, nullable=False)
    
    # Asset relationships
    asset_type = Column(String, nullable=False)
    asset_id = Column(String, nullable=False)
    
    # Technical details
    cve_id = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    affected_url = Column(String, nullable=True)
    affected_parameter = Column(String, nullable=True)
    
    # Evidence and PoC (stored as JSON)
    evidence = Column(JSON, default=[])
    proof_of_concept = Column(JSON, nullable=True)
    
    # Remediation
    remediation = Column(Text, nullable=True)
    references = Column(JSON, default=[])
    
    # Workflow
    assigned_to = Column(String, nullable=True)
    verified_by = Column(String, nullable=True)
    verified_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    
    # Metadata
    tags = Column(JSON, default=[])
    metadata = Column(JSON, default={})
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Foreign key to scan job
    job_id = Column(String, ForeignKey('scan_jobs.id'), nullable=True)
    job = relationship("JobModel", backref="findings")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_findings_severity', 'severity'),
        Index('idx_findings_status', 'status'),
        Index('idx_findings_type', 'vulnerability_type'),
        Index('idx_findings_asset', 'asset_type', 'asset_id'),
        Index('idx_findings_created', 'created_at'),
        Index('idx_findings_job', 'job_id'),
    )


class AssetModel(Base):
    """Database model for discovered assets."""
    __tablename__ = 'assets'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_type = Column(String, nullable=False)  # domain, host, service, application, endpoint
    name = Column(String, nullable=False)  # domain name, IP, URL, etc.
    
    # Asset-specific data (stored as JSON for flexibility)
    data = Column(JSON, default={})
    
    # Relationships
    parent_id = Column(String, ForeignKey('assets.id'), nullable=True)
    parent = relationship("AssetModel", remote_side=[id], backref="children")
    
    # Discovery metadata
    discovered_by = Column(String, nullable=True)  # scan job ID or method
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    # Status
    active = Column(Boolean, default=True)
    verified = Column(Boolean, default=False)
    
    # Metadata
    tags = Column(JSON, default=[])
    metadata = Column(JSON, default={})
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_assets_type', 'asset_type'),
        Index('idx_assets_name', 'name'),
        Index('idx_assets_parent', 'parent_id'),
        Index('idx_assets_active', 'active'),
        Index('idx_assets_discovered', 'discovered_by'),
    )


# Repository Classes
class BaseRepository:
    """Base repository class with common operations."""
    
    def __init__(self, model_class):
        self.model_class = model_class
    
    def create(self, session: Session, obj_data: Dict[str, Any]) -> Any:
        """Create a new object."""
        db_obj = self.model_class(**obj_data)
        session.add(db_obj)
        session.commit()
        session.refresh(db_obj)
        return db_obj
    
    def get_by_id(self, session: Session, obj_id: str) -> Optional[Any]:
        """Get object by ID."""
        return session.query(self.model_class).filter(
            self.model_class.id == obj_id
        ).first()
    
    def update(self, session: Session, obj_id: str, update_data: Dict[str, Any]) -> Optional[Any]:
        """Update an object."""
        db_obj = self.get_by_id(session, obj_id)
        if db_obj:
            for field, value in update_data.items():
                setattr(db_obj, field, value)
            db_obj.updated_at = datetime.utcnow()
            session.commit()
            session.refresh(db_obj)
        return db_obj
    
    def delete(self, session: Session, obj_id: str) -> bool:
        """Delete an object."""
        db_obj = self.get_by_id(session, obj_id)
        if db_obj:
            session.delete(db_obj)
            session.commit()
            return True
        return False


class JobRepository(BaseRepository):
    """Repository for scan jobs."""
    
    def __init__(self):
        super().__init__(JobModel)
    
    def create(self, session: Session, job_data) -> JobModel:
        """Create a new scan job."""
        if hasattr(job_data, 'dict'):
            # Pydantic model
            job_dict = job_data.dict()
        else:
            # Already a dict
            job_dict = job_data
        
        return super().create(session, job_dict)
    
    def update_status(self, session: Session, job_id: str, status: ScanStatus) -> Optional[JobModel]:
        """Update job status."""
        update_data = {'status': status}
        
        if status == ScanStatus.RUNNING:
            update_data['started_at'] = datetime.utcnow()
        elif status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
            update_data['completed_at'] = datetime.utcnow()
        
        return self.update(session, job_id, update_data)
    
    def update_task_id(self, session: Session, job_id: str, task_id: str) -> Optional[JobModel]:
        """Update Celery task ID."""
        job = self.get_by_id(session, job_id)
        if job:
            if not job.metadata:
                job.metadata = {}
            job.metadata['celery_task_id'] = task_id
            job.updated_at = datetime.utcnow()
            session.commit()
            session.refresh(job)
        return job
    
    def update_results(self, session: Session, job_id: str, results_count: int, findings_count: int = 0) -> Optional[JobModel]:
        """Update job results count."""
        return self.update(session, job_id, {
            'results_count': results_count,
            'findings_count': findings_count
        })
    
    def list_jobs(
        self,
        session: Session,
        status: Optional[ScanStatus] = None,
        scan_type: Optional[ScanType] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[JobModel]:
        """List jobs with optional filtering."""
        query = session.query(JobModel)
        
        if status:
            query = query.filter(JobModel.status == status)
        if scan_type:
            query = query.filter(JobModel.scan_type == scan_type)
        
        return query.order_by(JobModel.created_at.desc()).offset(offset).limit(limit).all()
    
    def cleanup_old_jobs(self, session: Session, cutoff_date: datetime) -> int:
        """Delete old completed jobs."""
        deleted = session.query(JobModel).filter(
            JobModel.status.in_([ScanStatus.COMPLETED, ScanStatus.FAILED]),
            JobModel.completed_at < cutoff_date
        ).delete()
        session.commit()
        return deleted


class FindingRepository(BaseRepository):
    """Repository for security findings."""
    
    def __init__(self):
        super().__init__(FindingModel)
    
    def create(self, session: Session, finding_data) -> FindingModel:
        """Create a new finding."""
        if hasattr(finding_data, 'dict'):
            # Pydantic model
            finding_dict = finding_data.dict()
        else:
            # Already a dict
            finding_dict = finding_data
        
        return super().create(session, finding_dict)
    
    def list_by_severity(
        self,
        session: Session,
        severity: SeverityLevel,
        limit: int = 50,
        offset: int = 0
    ) -> List[FindingModel]:
        """List findings by severity."""
        return session.query(FindingModel).filter(
            FindingModel.severity == severity
        ).order_by(FindingModel.created_at.desc()).offset(offset).limit(limit).all()
    
    def list_by_status(
        self,
        session: Session,
        status: FindingStatus,
        limit: int = 50,
        offset: int = 0
    ) -> List[FindingModel]:
        """List findings by status."""
        return session.query(FindingModel).filter(
            FindingModel.status == status
        ).order_by(FindingModel.created_at.desc()).offset(offset).limit(limit).all()
    
    def list_by_asset(
        self,
        session: Session,
        asset_id: str,
        limit: int = 50,
        offset: int = 0
    ) -> List[FindingModel]:
        """List findings for a specific asset."""
        return session.query(FindingModel).filter(
            FindingModel.asset_id == asset_id
        ).order_by(FindingModel.created_at.desc()).offset(offset).limit(limit).all()
    
    def get_stats(self, session: Session) -> Dict[str, Any]:
        """Get finding statistics."""
        from sqlalchemy import func
        
        # Count by severity
        severity_counts = session.query(
            FindingModel.severity,
            func.count(FindingModel.id)
        ).group_by(FindingModel.severity).all()
        
        # Count by status
        status_counts = session.query(
            FindingModel.status,
            func.count(FindingModel.id)
        ).group_by(FindingModel.status).all()
        
        # Count by vulnerability type
        vuln_type_counts = session.query(
            FindingModel.vulnerability_type,
            func.count(FindingModel.id)
        ).group_by(FindingModel.vulnerability_type).all()
        
        return {
            'severity_counts': dict(severity_counts),
            'status_counts': dict(status_counts),
            'vulnerability_type_counts': dict(vuln_type_counts),
            'total_findings': session.query(FindingModel).count()
        }


class AssetRepository(BaseRepository):
    """Repository for discovered assets."""
    
    def __init__(self):
        super().__init__(AssetModel)
    
    def create(self, session: Session, asset_data) -> AssetModel:
        """Create a new asset."""
        if hasattr(asset_data, 'dict'):
            # Pydantic model
            asset_dict = asset_data.dict()
        else:
            # Already a dict
            asset_dict = asset_data
        
        return super().create(session, asset_dict)
    
    def find_by_name(self, session: Session, name: str) -> Optional[AssetModel]:
        """Find asset by name."""
        return session.query(AssetModel).filter(
            AssetModel.name == name
        ).first()
    
    def list_by_type(
        self,
        session: Session,
        asset_type: str,
        limit: int = 50,
        offset: int = 0
    ) -> List[AssetModel]:
        """List assets by type."""
        return session.query(AssetModel).filter(
            AssetModel.asset_type == asset_type,
            AssetModel.active == True
        ).order_by(AssetModel.first_seen.desc()).offset(offset).limit(limit).all()
    
    def update_last_seen(self, session: Session, asset_id: str) -> Optional[AssetModel]:
        """Update last seen timestamp."""
        return self.update(session, asset_id, {'last_seen': datetime.utcnow()})


# Database session management
@contextmanager
def get_db_session():
    """Get a database session with automatic cleanup."""
    session = SessionLocal()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# Database initialization
def create_tables():
    """Create all database tables."""
    Base.metadata.create_all(bind=engine)


def drop_tables():
    """Drop all database tables."""
    Base.metadata.drop_all(bind=engine)


# Repository instances
job_repository = JobRepository()
finding_repository = FindingRepository()
asset_repository = AssetRepository()
