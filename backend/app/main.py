"""
FastAPI Server for AegisTrust: AI + Cybersecurity + Web3 Evidence Platform.
Provides REST APIs for:
- URL and website threat investigation
- Message and scam social engineering analysis
- Threat correlation graph queries
- Web3 cryptographic registration and independent verification
"""

import time
import uuid
import copy
import os
from typing import Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.models.schemas import (
    InvestigationRequest,
    InvestigationResponse,
    Web3SubmitRequest,
    Web3VerifyRequest,
    Web3VerificationResponse,
    Finding
)
from app.modules.url_analyzer import URLAnalyzer
from app.modules.redirect_tracer import RedirectTracer
from app.modules.tls_analyzer import TLSAnalyzer
from app.modules.security_headers import SecurityHeadersAnalyzer
from app.modules.message_analyzer import MessageAnalyzer
from app.modules.correlation_engine import CorrelationEngine
from app.services.scoring_engine import ScoringEngine
from app.services.explainer_service import ExplainerService
from app.services.web3_service import Web3RegistryService
from app.core.canonical_hasher import compute_report_hash, compute_indicator_hash

app = FastAPI(
    title="AegisTrust Security Intelligence API",
    description="Evidence-grounded cybersecurity analysis, AI scam detection, and Web3 verifiable reporting.",
    version="1.0.0"
)

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static directory and root dashboard route
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
def serve_dashboard():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "AegisTrust API Active. Access /docs for OpenAPI documentation."}

@app.get("/sandbox")
def serve_sandbox():
    sandbox_file = os.path.join(static_dir, "sandbox.html")
    if os.path.exists(sandbox_file):
        return FileResponse(sandbox_file)
    return FileResponse(os.path.join(static_dir, "index.html"))

# Initialize engines
url_analyzer = URLAnalyzer()
tls_analyzer = TLSAnalyzer()
correlation_engine = CorrelationEngine()
web3_service = Web3RegistryService()

@app.get("/api/v1/health")
def health():
    return {"status": "healthy", "service": "AegisTrust", "version": "1.0.0"}

@app.get("/api/v1/distrusted-cas")
def get_distrusted_cas():
    return {"distrusted_cas": tls_analyzer.distrusted_cas}

@app.get("/api/v1/correlations/{domain}")
def get_correlations(domain: str):
    cluster = correlation_engine.find_cluster(domain)
    return cluster

@app.post("/api/v1/investigate/url", response_model=InvestigationResponse)
def investigate_url(req: InvestigationRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="URL parameter is required")

    submission_id = str(uuid.uuid4())[:8]
    all_findings: list[Finding] = []

    # 1. URL & Lexical Analysis
    lex_findings, meta = url_analyzer.analyze(req.url)
    all_findings.extend(lex_findings)

    # 2. Safe Redirect Chain Tracer
    redirect_hops, redirect_findings = RedirectTracer.trace(meta["normalized_url"])
    all_findings.extend(redirect_findings)

    # 3. TLS Certificate Analysis
    tls_report, tls_findings = tls_analyzer.analyze(meta["normalized_url"])
    all_findings.extend(tls_findings)

    # 4. Passive Security Headers Audit
    headers_dict, header_findings = SecurityHeadersAnalyzer.inspect(meta["normalized_url"])
    all_findings.extend(header_findings)

    # 5. Deterministic Risk Scoring
    score, classification, coverage = ScoringEngine.calculate_score(
        all_findings,
        checks_completed=7 if tls_report else 5,
        total_checks=8
    )

    # 6. AI Explainability Synthesis
    explanation = ExplainerService.generate_explanation(
        target=meta["registered_domain"],
        classification=classification,
        score=score,
        findings=all_findings,
        coverage_percent=coverage
    )

    # 7. Add to Correlation Graph
    resolved_ip = redirect_hops[0].resolved_ip if redirect_hops else None
    cert_fp = tls_report.fingerprint_sha256 if tls_report else None
    correlation_engine.add_incident(
        domain=meta["registered_domain"],
        ip=resolved_ip,
        cert_fp=cert_fp
    )

    # 8. Cryptographic Commitments
    clean_payload = {
        "submission_id": submission_id,
        "target": meta["registered_domain"],
        "target_type": "url",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "risk_classification": classification.value,
        "risk_score": score,
        "findings_count": len(all_findings),
        "primary_threat": all_findings[0].title if all_findings else "None"
    }
    report_hash = compute_report_hash(clean_payload)
    indicator_hash = compute_indicator_hash(meta["registered_domain"])

    return InvestigationResponse(
        submission_id=submission_id,
        target=meta["registered_domain"],
        target_type="url",
        timestamp=clean_payload["timestamp"],
        risk_classification=classification,
        risk_score=score,
        evidence_coverage_percent=coverage,
        explanation=explanation,
        findings=all_findings,
        redirect_chain=redirect_hops,
        tls_details=tls_report,
        passive_headers=headers_dict,
        correlation_cluster_id=meta["registered_domain"],
        report_hash_keccak256=report_hash,
        salted_indicator_hash=indicator_hash,
        onchain_registry_status="Unregistered"
    )

@app.post("/api/v1/investigate/message", response_model=InvestigationResponse)
def investigate_message(req: InvestigationRequest):
    if not req.message:
        raise HTTPException(status_code=400, detail="Message content is required")

    submission_id = str(uuid.uuid4())[:8]
    all_findings: list[Finding] = []

    # 1. Message & Social Engineering Analysis
    message_analysis, scam_findings = MessageAnalyzer.analyze(req.message)
    all_findings.extend(scam_findings)

    # 2. If URLs exist inside message, also run deep URL investigation
    redirect_hops = []
    tls_report = None
    headers_dict = {}

    if message_analysis.extracted_urls:
        first_url = message_analysis.extracted_urls[0]
        url_findings, meta = url_analyzer.analyze(first_url)
        all_findings.extend(url_findings)
        redirect_hops, r_findings = RedirectTracer.trace(meta["normalized_url"])
        all_findings.extend(r_findings)
        tls_report, t_findings = tls_analyzer.analyze(meta["normalized_url"])
        all_findings.extend(t_findings)

    # 3. Deterministic Risk Scoring
    score, classification, coverage = ScoringEngine.calculate_score(
        all_findings,
        checks_completed=7 if message_analysis.extracted_urls else 6,
        total_checks=8
    )

    # 4. Explainability
    target_name = message_analysis.extracted_urls[0] if message_analysis.extracted_urls else "Pasted Message Content"
    explanation = ExplainerService.generate_explanation(
        target=target_name,
        classification=classification,
        score=score,
        findings=all_findings,
        coverage_percent=coverage
    )

    # 5. Cryptographic Commitments
    clean_payload = {
        "submission_id": submission_id,
        "target": target_name,
        "target_type": "message",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "risk_classification": classification.value,
        "risk_score": score,
        "findings_count": len(all_findings),
        "primary_threat": all_findings[0].title if all_findings else "None"
    }
    report_hash = compute_report_hash(clean_payload)
    indicator_hash = compute_indicator_hash(target_name)

    return InvestigationResponse(
        submission_id=submission_id,
        target=target_name,
        target_type="message",
        timestamp=clean_payload["timestamp"],
        risk_classification=classification,
        risk_score=score,
        evidence_coverage_percent=coverage,
        explanation=explanation,
        findings=all_findings,
        redirect_chain=redirect_hops,
        tls_details=tls_report,
        passive_headers=headers_dict,
        message_analysis=message_analysis,
        report_hash_keccak256=report_hash,
        salted_indicator_hash=indicator_hash,
        onchain_registry_status="Unregistered"
    )

@app.post("/api/v1/web3/submit")
def submit_to_web3(req: Web3SubmitRequest):
    receipt = web3_service.submit_report(req.report_json)
    return receipt

@app.post("/api/v1/web3/verify", response_model=Web3VerificationResponse)
def verify_web3_report(req: Web3VerifyRequest):
    res = web3_service.verify_report(req.report_json, simulate_tamper=req.simulate_tamper)
    return res

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
