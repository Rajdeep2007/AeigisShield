# 🏗️ AegisTrust System Architecture & API Specification

## 1. System Component Diagram

```
+-----------------------------------------------------------------------------------------+
|                                    NEXT.JS 14 FRONTEND                                  |
|   [URL / Message Input]  -->  [Interactive Graph]  -->  [Tamper-Proof Verify Modal]    |
+-----------------------------------------------------------------------------------------+
                                             │ HTTP / JSON
                                             ▼
+-----------------------------------------------------------------------------------------+
|                                      FASTAPI BACKEND                                    |
|                                                                                         |
|  +-----------------------------------------------------------------------------------+  |
|  |                          INGESTION & SSRF SHIELD LAYER                            |  |
|  |   - URL Normalizer (IDN to punycode, clean fragment/params)                       |  |
|  |   - SSRF Guard (DNS Pre-resolve, RFC1918 / Cloud Metadata CIDR filters)           |  |
|  +-----------------------------------------------------------------------------------+  |
|                                             │                                           |
|       ┌─────────────────────────────────────┼────────────────────────────────────┐      |
|       ▼                                     ▼                                    ▼      |
|  +─────────────────────────+  +─────────────────────────+  +─────────────────────────+  |
|  |  MODULE 1: URL & LEXICAL|  |  MODULE 2: TLS TRUST    |  |  MODULE 3: AI SCAM &    |  |
|  |  - Typosquatting (Lev)  |  |  - Chain & SAN match    |  |    MESSAGE ANALYZER     |  |
|  |  - Homoglyphs/Cyrillic  |  |  - Expiration & Ciphers |  |  - Regex Indicator Extr |  |
|  |  - Brand-in-subdomain   |  |  - eMudhra Distrusted CA|  |  - Social Eng. Tactics  |  |
|  |  - Safe Redirect Tracer |  |  - crt.sh CT Log query  |  |  - Verbatim Quotations  |  |
|  |  - Threat Intel Feeds   |  |  - Passive Headers (HSTS|  |  - Prompt Injection     |  |
|  |    (URLhaus/OpenPhish)  |  |    CSP, Cookies)        |  |    Sanitization         |  |
|  +─────────────────────────+  +─────────────────────────+  +─────────────────────────+  |
|       │                                     │                                    │      |
|       └─────────────────────────────────────┼────────────────────────────────────┘      |
|                                             ▼                                           |
|  +-----------------------------------------------------------------------------------+  |
|  |                     MODULE 4: DETERMINISTIC CORRELATION & SCORING                 |  |
|  |   - Mathematical Scoring Engine (Σ Positive Weights - Σ Negative Weights)         |  |
|  |   - Category caps & Evidence Coverage metric                                      |  |
|  |   - NetworkX Entity Correlation (Shared IP, Nameservers, SSL Fingerprints)        |  |
|  +-----------------------------------------------------------------------------------+  |
|                                             │                                           |
|                                             ▼                                           |
|  +-----------------------------------------------------------------------------------+  |
|  |                              EXPLAINABILITY LAYER                                 |  |
|  |   - LLM Evidence Summarizer (Input: list of Findings -> Output: plain english)    |  |
|  |   - Strict constraint: Model cannot alter classification or score                |  |
|  +-----------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------+
                                             │ keccak256(canonical_json)
                                             ▼
+-----------------------------------------------------------------------------------------+
|                               WEB3 VERIFICATION LAYER                                   |
|   - ReportRegistry.sol deployed on Hardhat / Sepolia                                     |
|   - Pure Cryptographic Commitment (Canonical RFC 8785 JSON Hash + Salted Indicator Hash)|
|   - Zero PII, Zero Raw URLs on chain                                                    |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Core Data Models (Pydantic / TypeScript Interfaces)

```python
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
    module: str = Field(..., description="Module that produced finding: lexical, tls, intel, scam")
    title: str = Field(..., description="Human-readable title e.g. Potential Brand Typosquatting")
    severity: Severity
    weight: int = Field(..., description="Points added or subtracted from risk score")
    evidence: str = Field(..., description="Direct factual evidence without fluff")
    source: str = Field(..., description="Origin of verification e.g. crt.sh, URLhaus, Levenshtein")
    remediation: Optional[str] = None

class RedirectHop(BaseModel):
    hop_number: int
    url: str
    status_code: int
    ip: str
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
    raw_fingerprint_sha256: str

class InvestigationResponse(BaseModel):
    submission_id: str
    target: str
    target_type: str  # "url" or "message"
    timestamp: str
    risk_classification: RiskClassification
    risk_score: int  # 0 to 100
    evidence_coverage_percent: int  # e.g. 87%
    verdict_explanation: str
    findings: List[Finding]
    redirect_chain: List[RedirectHop]
    tls_details: Optional[TLSSecurityReport] = None
    passive_headers: Dict[str, Any]
    correlation_cluster_id: Optional[str] = None
    report_hash_keccak256: str  # Ready for on-chain submission
```

---

## 3. REST API Contract Endpoints

### 1. `POST /api/v1/investigate/url`
* **Request**:
  ```json
  { "url": "https://paypa1-account-update.xyz/login" }
  ```
* **Response**: Returns complete `InvestigationResponse` schema.

### 2. `POST /api/v1/investigate/message`
* **Request**:
  ```json
  { "content": "URGENT: Your SBI netbanking account is suspended. Verify KYC immediately at http://sbi-kyc.top" }
  ```
* **Response**:
  - Extracted indicators (links, phone numbers, entities)
  - Extracted URLs auto-queued into URL investigation pipeline
  - Social engineering tactics identified with verbatim quotes

### 3. `GET /api/v1/correlations/{cluster_id}`
* **Response**:
  - Graph nodes: `[Domain, IP, Nameserver, CertHash]`
  - Graph edges: `[shares_ip, shares_ns, shares_cert]`

### 4. `POST /api/v1/web3/verify`
* **Request**:
  ```json
  {
    "report_id": 1,
    "report_json": { ... },
    "contract_address": "0x5FbDB2315678afecb367f032d93F642f64180aa3"
  }
  ```
* **Response**:
  ```json
  {
    "verified": true,
    "onchain_hash": "0x4a9b...",
    "computed_hash": "0x4a9b...",
    "match": true,
    "block_number": 42,
    "timestamp": 1794098234
  }
  ```
