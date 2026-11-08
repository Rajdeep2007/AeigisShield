"""
Data models and schemas for AegisTrust.
Strict typing with Pydantic v2.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    BENIGN = "benign"


class RiskClassification(str, Enum):
    LOW_RISK = "Low Risk"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"
    CONFIRMED_MALICIOUS = "Confirmed Malicious"
    INCONCLUSIVE = "Inconclusive"


class Finding(BaseModel):
    id: str = Field(..., description="Unique finding ID e.g. F-TYPO-01")
    module: str = Field(..., description="Module identifier (lexical, tls, intel, scam, headers)")
    title: str = Field(..., description="Short human-readable title")
    severity: Severity
    weight: int = Field(..., description="Score weight (positive for threat, negative for trust)")
    evidence: str = Field(..., description="Direct factual and technical evidence")
    source: str = Field(..., description="Verification source (e.g., Levenshtein, crt.sh, URLhaus, Cryptography)")
    remediation: Optional[str] = Field(None, description="Recommended user precaution or remediation")


class RedirectHop(BaseModel):
    hop: int
    url: str
    status_code: int
    resolved_ip: str
    is_cross_domain: bool
    is_downgrade: bool


class TLSSecurityReport(BaseModel):
    valid: bool
    issuer: str
    subject: str
    sans: List[str]
    days_to_expiry: int
    is_expired: bool
    key_size: int
    signature_algorithm: str
    is_distrusted_ca: bool
    distrusted_reason: Optional[str] = None
    ct_log_count: int
    fingerprint_sha256: str
    is_self_signed: bool


class ScamIndicator(BaseModel):
    indicator_type: str  # url, email, phone, upi_vpa, crypto_btc, crypto_eth, credential_request
    value: str
    context: str


class ScamTactic(BaseModel):
    tactic: str  # Urgency, Authority Impersonation, Financial Request, KYC Pretext
    confidence: float
    verbatim_quote: str
    explanation: str


class MessageAnalysis(BaseModel):
    extracted_indicators: List[ScamIndicator]
    identified_tactics: List[ScamTactic]
    extracted_urls: List[str]
    is_adversarial_injection_detected: bool = False
    adversarial_note: Optional[str] = None


class InvestigationRequest(BaseModel):
    url: Optional[str] = None
    message: Optional[str] = None


class InvestigationResponse(BaseModel):
    submission_id: str
    target: str
    target_type: str  # "url" or "message"
    timestamp: str
    risk_classification: RiskClassification
    risk_score: int
    evidence_coverage_percent: int
    explanation: str
    findings: List[Finding]
    redirect_chain: List[RedirectHop]
    tls_details: Optional[TLSSecurityReport] = None
    passive_headers: Dict[str, Any] = {}
    message_analysis: Optional[MessageAnalysis] = None
    correlation_cluster_id: Optional[str] = None
    limitations: List[str] = []
    checks_status: Dict[str, str] = {}
    report_hash_keccak256: str
    salted_indicator_hash: str
    onchain_registry_status: str = "Unregistered"


class Web3SubmitRequest(BaseModel):
    report_json: Dict[str, Any]
    supersedes_id: Optional[int] = None


class Web3VerifyRequest(BaseModel):
    report_json: Dict[str, Any]
    simulate_tamper: bool = False


class Web3DisputeRequest(BaseModel):
    report_hash: str
    reason: str = "Community dispute: indicator requires manual re-verification"


class Web3ValidateRequest(BaseModel):
    report_hash: str


class Web3VerificationResponse(BaseModel):
    verified: bool
    onchain_hash: str
    computed_hash: str
    hashes_match: bool
    submission_timestamp: Optional[str] = None
    status: str
    message: str
    block_number: Optional[int] = None
    tx_hash: Optional[str] = None
    report_id: Optional[int] = None
    validations_count: int = 0
    disputes_count: int = 0
    supersedes: int = 0
