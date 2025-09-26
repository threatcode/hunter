"""
Data schemas for the AI Bug Hunter framework.

This module defines the core data structures for findings, assets, and entities
including domains, hosts, ASNs, organizations, services, and applications.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, HttpUrl
import uuid


class SeverityLevel(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Status of a finding in the triage process."""
    NEW = "new"
    TRIAGED = "triaged"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    RESOLVED = "resolved"


class AssetType(str, Enum):
    """Types of assets that can be discovered."""
    DOMAIN = "domain"
    HOST = "host"
    SERVICE = "service"
    APPLICATION = "application"
    ENDPOINT = "endpoint"


class VulnerabilityType(str, Enum):
    """Common vulnerability types."""
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    IDOR = "idor"
    XXE = "xxe"
    FILE_UPLOAD = "file_upload"
    AUTH_BYPASS = "auth_bypass"
    INFO_DISCLOSURE = "info_disclosure"
    MISCONFIGURATION = "misconfiguration"
    CVE = "cve"
    LOGIC_FLAW = "logic_flaw"


# Base Models
class BaseEntity(BaseModel):
    """Base class for all entities."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Union[str, int, float, bool]] = Field(default_factory=dict)


# Asset Models
class Organization(BaseEntity):
    """Organization/company entity."""
    name: str
    domain: Optional[str] = None
    description: Optional[str] = None
    industry: Optional[str] = None
    size: Optional[str] = None
    subsidiaries: List[str] = Field(default_factory=list)
    acquisitions: List[str] = Field(default_factory=list)
    crunchbase_url: Optional[HttpUrl] = None


class ASN(BaseModel):
    asn: int
    name: str
    route: str
    domain: str
    type: str

class Asset(BaseModel):
    id: str
    asset_type: str
    name: str
    parent_id: Optional[str] = None
    discovered_by: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    active: bool
    verified: bool
    tags: List[str] = []
    extra_data: Dict[str, Any] = {}

    class Config:
        orm_mode = True


class Domain(BaseEntity):
    """Domain entity."""
    name: str
    organization_id: Optional[str] = None
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    nameservers: List[str] = Field(default_factory=list)
    mx_records: List[str] = Field(default_factory=list)
    txt_records: List[str] = Field(default_factory=list)
    subdomains: List[str] = Field(default_factory=list)
    wildcard_detected: bool = False
    takeover_vulnerable: bool = False


class Host(BaseEntity):
    """Host/IP entity."""
    ip: str
    hostname: Optional[str] = None
    domain_id: Optional[str] = None
    asn_id: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    ports: List[int] = Field(default_factory=list)
    os: Optional[str] = None
    last_seen: Optional[datetime] = None


class Service(BaseEntity):
    """Service running on a host."""
    host_id: str
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    ssl_cert: Optional[Dict] = None
    screenshot_path: Optional[str] = None
    response_headers: Dict[str, str] = Field(default_factory=dict)


class Application(BaseEntity):
    """Web application entity."""
    url: HttpUrl
    service_id: Optional[str] = None
    title: Optional[str] = None
    technology_stack: List[str] = Field(default_factory=list)
    cms: Optional[str] = None
    framework: Optional[str] = None
    server: Optional[str] = None
    status_code: Optional[int] = None
    content_length: Optional[int] = None
    screenshot_path: Optional[str] = None
    robots_txt: Optional[str] = None
    sitemap_xml: Optional[str] = None


class Endpoint(BaseEntity):
    """API endpoint or web page."""
    url: HttpUrl
    application_id: str
    method: str = "GET"
    parameters: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    response_code: Optional[int] = None
    response_size: Optional[int] = None
    response_time: Optional[float] = None
    content_type: Optional[str] = None


# Finding Models
class Evidence(BaseModel):
    """Evidence supporting a finding."""
    type: str  # "screenshot", "request", "response", "log", "file"
    path: str  # File path or URL
    description: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ProofOfConcept(BaseModel):
    """Proof of concept for a finding."""
    description: str
    steps: List[str]
    curl_command: Optional[str] = None
    python_script: Optional[str] = None
    playwright_script: Optional[str] = None
    payload: Optional[str] = None
    expected_result: str
    actual_result: str


class Finding(BaseEntity):
    """Security finding/vulnerability."""
    title: str
    description: str
    severity: SeverityLevel
    status: FindingStatus = FindingStatus.NEW
    vulnerability_type: VulnerabilityType
    confidence: float = Field(ge=0.0, le=1.0)  # 0.0 to 1.0
    
    # Asset relationships
    asset_type: AssetType
    asset_id: str
    
    # Technical details
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    affected_url: Optional[HttpUrl] = None
    affected_parameter: Optional[str] = None
    
    # Evidence and PoC
    evidence: List[Evidence] = Field(default_factory=list)
    proof_of_concept: Optional[ProofOfConcept] = None
    
    # Remediation
    remediation: Optional[str] = None
    references: List[HttpUrl] = Field(default_factory=list)
    
    # Workflow
    assigned_to: Optional[str] = None
    verified_by: Optional[str] = None
    verified_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None


# Scan and Job Models
class ScanType(str, Enum):
    """Types of scans that can be performed."""
    RECON = "recon"
    SUBDOMAIN = "subdomain"
    PORT_SCAN = "port_scan"
    CONTENT_DISCOVERY = "content_discovery"
    VULNERABILITY_SCAN = "vulnerability_scan"
    SCREENSHOT = "screenshot"
    FUZZING = "fuzzing"


class ScanStatus(str, Enum):
    """Status of a scan job."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanJob(BaseEntity):
    """Scan job entity."""
    name: str
    scan_type: ScanType
    status: ScanStatus = ScanStatus.PENDING
    target: str  # Domain, IP, URL, etc.
    parameters: Dict[str, Union[str, int, float, bool, List]] = Field(default_factory=dict)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    results_count: int = 0
    findings_count: int = 0


# Configuration Models
class ReconConfig(BaseModel):
    """Configuration for reconnaissance modules."""
    passive_dns_enabled: bool = True
    certificate_transparency: bool = True
    shodan_enabled: bool = False
    censys_enabled: bool = False
    virustotal_enabled: bool = False
    wayback_enabled: bool = True
    github_dorking: bool = True
    google_dorking: bool = True
    subdomain_bruteforce: bool = True
    port_scan_enabled: bool = True
    screenshot_enabled: bool = True
    
    # Rate limiting
    max_concurrent_requests: int = 10
    request_delay: float = 1.0
    
    # Scope
    max_subdomains: int = 1000
    max_ports: int = 1000
    excluded_domains: List[str] = Field(default_factory=list)
    excluded_ips: List[str] = Field(default_factory=list)


class FuzzingConfig(BaseModel):
    """Configuration for fuzzing modules."""
    xss_payloads: bool = True
    sqli_payloads: bool = True
    ssrf_payloads: bool = True
    xxe_payloads: bool = True
    idor_testing: bool = True
    file_upload_testing: bool = True
    
    # Wordlists
    directory_wordlist: str = "common.txt"
    parameter_wordlist: str = "parameters.txt"
    
    # Limits
    max_requests_per_endpoint: int = 100
    request_timeout: int = 30
    max_concurrent_fuzz: int = 5


# API Models for requests/responses
class ScanRequest(BaseModel):
    """Request to start a new scan."""
    target: str
    scan_type: ScanType
    config: Optional[Dict] = None
    priority: int = Field(default=5, ge=1, le=10)


class ScanResponse(BaseModel):
    """Response from scan API."""
    job_id: str
    status: ScanStatus
    message: str


class FindingsResponse(BaseModel):
    """Response containing findings."""
    findings: List[Finding]
    total: int
    page: int
    per_page: int


class AssetResponse(BaseModel):
    """Response containing assets."""
    assets: List[Union[Domain, Host, Service, Application, Endpoint]]
    total: int
    asset_type: AssetType
