from pydantic import BaseModel, Field
from typing import List, Literal, Optional, Dict, Any
from datetime import datetime
import uuid


class Incident(BaseModel):
    """Represents a detected incident from log analysis."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    log_group: str
    severity: Literal["CRITICAL", "WARNING", "INFO", "NOISE"]
    summary: str = Field(description="One line summary of the error")
    root_cause: str = Field(description="Technical diagnosis of what failed")
    recommendation: str = Field(description="Specific suggested fix")
    affected_service: str = "Unknown"
    raw_logs: List[str] = []
    occurrence_count: int = 1
    last_seen: Optional[datetime] = None


class AnalysisRun(BaseModel):
    """Metadata about a single analysis run."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    log_group: str
    start_time: datetime
    end_time: datetime
    total_logs: int
    incidents_found: int
    duration_seconds: float


# ============================================
# Security Analyzer Models
# ============================================

class SecurityFinding(BaseModel):
    """Represents a security finding from security analysis."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    finding_type: str = Field(description="Type of security finding (e.g., OPEN_HIGH_RISK_PORT)")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    resource_type: str = Field(description="AWS resource type (e.g., SecurityGroup, S3Bucket)")
    resource_id: str
    resource_name: Optional[str] = None
    title: str
    description: str
    recommendation: str
    additional_info: Dict[str, Any] = Field(default_factory=dict)
    resolved: bool = False


class SecurityScanRun(BaseModel):
    """Metadata about a security scan run."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_time: datetime = Field(default_factory=datetime.now)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    security_score: int = 100
    services_scanned: List[str] = Field(default_factory=list)


# ============================================
# Performance Analyzer Models
# ============================================

class PerformanceInsight(BaseModel):
    """Represents a performance insight for a resource."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    service: Literal["Lambda", "RDS", "EC2", "APIGateway"]
    resource_id: str
    resource_name: Optional[str] = None
    insight_type: str = Field(description="Type of insight (e.g., COLD_START, HIGH_CPU)")
    severity: Literal["HIGH", "MEDIUM", "LOW", "INFO"]
    metric_name: str
    metric_value: float
    threshold: Optional[float] = None
    message: str
    suggestion: str


class PerformanceAnalysisRun(BaseModel):
    """Metadata about a performance analysis run."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    analysis_time: datetime = Field(default_factory=datetime.now)
    analysis_period_hours: int = 24
    total_resources: int = 0
    resources_with_issues: int = 0
    performance_score: int = 100
    services_analyzed: List[str] = Field(default_factory=list)


# ============================================
# Resource Health Models
# ============================================

class ResourceHealth(BaseModel):
    """Represents health status of a resource."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    service: str = Field(description="AWS service (EC2, RDS, Lambda, etc.)")
    resource_id: str
    resource_name: Optional[str] = None
    status: Literal["HEALTHY", "DEGRADED", "UNHEALTHY", "UNKNOWN", "INITIALIZING", "MAINTENANCE", "INACTIVE"]
    status_reason: Optional[str] = None
    metrics: Dict[str, float] = Field(default_factory=dict)
    events: List[Dict[str, Any]] = Field(default_factory=list)


class HealthCheckRun(BaseModel):
    """Metadata about a health check run."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    check_time: datetime = Field(default_factory=datetime.now)
    overall_score: int = 100
    overall_status: Literal["EXCELLENT", "GOOD", "FAIR", "POOR", "CRITICAL"]
    service_scores: Dict[str, int] = Field(default_factory=dict)
    alarms_in_alarm: int = 0
    resources_unhealthy: int = 0


# ============================================
# Compliance Checker Models
# ============================================

class ComplianceFinding(BaseModel):
    """Represents a compliance finding."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    finding_type: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    pillar: Optional[str] = Field(description="Well-Architected Framework pillar", default=None)
    resource_type: str
    resource_id: str
    resource_name: Optional[str] = None
    title: str
    description: str
    recommendation: str
    compliance_framework: Optional[str] = None


class ComplianceCheckRun(BaseModel):
    """Metadata about a compliance check run."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    check_time: datetime = Field(default_factory=datetime.now)
    overall_score: int = 100
    pillar_scores: Dict[str, int] = Field(default_factory=dict)
    total_findings: int = 0
    tagging_compliance_rate: float = 0.0


# ============================================
# Service Quota Models
# ============================================

class QuotaStatus(BaseModel):
    """Represents status of a service quota."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    service_code: str
    quota_code: Optional[str] = None
    quota_name: str
    quota_value: float
    current_usage: float
    usage_percentage: float
    unit: str = "None"
    adjustable: bool = False
    alert_level: Optional[Literal["CRITICAL", "WARNING", "OK"]] = None


class QuotaCheckRun(BaseModel):
    """Metadata about a quota check run."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    check_time: datetime = Field(default_factory=datetime.now)
    quotas_checked: int = 0
    critical_alerts: int = 0
    warning_alerts: int = 0


# ============================================
# Backup & DR Models
# ============================================

class BackupStatus(BaseModel):
    """Represents backup status of a resource."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    resource_type: str = Field(description="Type (RDS_SNAPSHOT, S3_BUCKET, EC2_AMI, etc.)")
    resource_id: str
    resource_name: Optional[str] = None
    backup_type: Optional[str] = None  # manual, automated, etc.
    status: str
    created: Optional[datetime] = None
    age_days: int = 0
    size_gb: float = 0
    encrypted: bool = False
    cross_region: bool = False


class DRReadinessRun(BaseModel):
    """Metadata about a DR readiness check."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    check_time: datetime = Field(default_factory=datetime.now)
    dr_score: int = 100
    readiness_level: Literal["EXCELLENT", "GOOD", "FAIR", "POOR", "CRITICAL"]
    total_findings: int = 0
    rds_snapshots_count: int = 0
    s3_buckets_with_versioning: int = 0
    cross_region_replications: int = 0


# ============================================
# Unified Scan Result Model
# ============================================

class ScanResult(BaseModel):
    """Unified model for storing any type of scan result."""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    scan_type: Literal["security", "performance", "health", "compliance", "quota", "backup"]
    score: int = 100
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    findings_json: str = "{}"  # JSON string of all findings
    ai_recommendations: Optional[str] = None
    duration_seconds: float = 0.0
