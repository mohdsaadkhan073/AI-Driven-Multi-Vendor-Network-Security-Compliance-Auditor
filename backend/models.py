from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class CommonSecurityModel(BaseModel):
    hostname: str = "Unknown-Device"
    vendor: str = "Unknown"
    model: str = "Generic Network Device"
    os_version: str = "Unknown"
    serial_number: str = "N/A"
    
    # Management & Remote Access
    ssh_enabled: bool = False
    ssh_version: Optional[int] = None
    telnet_disabled: bool = True
    http_server_disabled: bool = True
    https_server_enabled: bool = False
    inactivity_timeout_seconds: Optional[int] = None
    
    # Authentication & Access Control
    password_encryption_enabled: bool = False
    enable_secret_configured: bool = False
    default_credentials_used: bool = False
    aaa_authentication_enabled: bool = False
    login_banner_configured: bool = False
    
    # Logging & Monitoring
    logging_enabled: bool = False
    syslog_servers: List[str] = []
    log_timestamps_enabled: bool = False
    
    # SNMP Security
    snmp_enabled: bool = False
    snmp_v3_enforced: bool = False
    insecure_community_detected: bool = False
    detected_communities: List[str] = []
    
    # Time Synchronization
    ntp_configured: bool = False
    ntp_servers: List[str] = []
    
    # Raw Evidence mapping: control_name -> line_number & raw_text
    evidence_map: Dict[str, Dict[str, Any]] = {}
    
    # Unrecognized / Ambiguous tokens for Adaptive Learning
    unrecognized_commands: List[Dict[str, Any]] = []

class ComplianceFinding(BaseModel):
    id: str
    framework: str # CIS, NIST, DISA_STIG, ISO_27001
    control_id: str # e.g. CIS 2.1.1
    title: str
    description: str
    severity: str # CRITICAL, HIGH, MEDIUM, LOW
    status: str # PASS, FAIL, WARNING
    evidence_line: Optional[int] = None
    evidence_text: Optional[str] = None
    why_it_matters: str
    remediation_cmd: str
    remediation_explanation: str

class FrameworkScore(BaseModel):
    framework: str
    score_percentage: float
    total_controls: int
    passed_controls: int
    failed_controls: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int

class AuditResult(BaseModel):
    device_info: Dict[str, str]
    overall_compliance_score: float
    framework_scores: List[FrameworkScore]
    findings: List[ComplianceFinding]
    csm: CommonSecurityModel
    unrecognized_gaps: List[Dict[str, Any]]

class AdaptiveRule(BaseModel):
    id: str
    vendor_pattern: str
    command_pattern: str
    target_parameter: str # e.g. inactivity_timeout_seconds, ssh_version, etc.
    extracted_value: Any
    created_at: str
    description: str
