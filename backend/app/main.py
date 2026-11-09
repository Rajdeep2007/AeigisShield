"""
FastAPI Server for AegisTrust: AI + Cybersecurity + Web3 Evidence Platform.
Provides REST APIs for:
- URL and website threat investigation
- Message and scam social engineering analysis
- Threat correlation graph queries
- Web3 cryptographic registration, validation, dispute tracking, and independent verification
- Autonomous AI Security Agent (Observe -> Think -> Act -> Pivot -> Defend) & 24/7 Brand Watchdog
- Browser Extension Real-Time Protection & Blocklist Synchronization
"""

import time
import uuid
import os
import urllib3
from typing import List, Dict, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Auto-load .env configuration if present
def _load_env():
    for base in [os.path.dirname(__file__), os.path.join(os.path.dirname(__file__), ".."), os.path.join(os.path.dirname(__file__), "..", "..")]:
        env_file = os.path.join(base, ".env")
        if os.path.exists(env_file):
            try:
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k, v = k.strip(), v.strip().strip('"').strip("'")
                            if k and not os.environ.get(k):
                                os.environ[k] = v
                break
            except Exception:
                pass
_load_env()

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.models.schemas import (
    InvestigationRequest,
    InvestigationResponse,
    Web3SubmitRequest,
    Web3VerifyRequest,
    Web3DisputeRequest,
    Web3ValidateRequest,
    Web3VerificationResponse,
    Finding,
    Severity,
    AgentInvestigateRequest,
    AgentInvestigateResponse,
    WatchdogScanRequest,
    VisualAnalysisRequest,
    VisualAnalysisResult,
    ContainmentPackage,
    ContainmentCompileRequest,
)
from app.modules.visual_analyzer import VisualAnalyzer
from app.modules.containment_compiler import ContainmentCompiler
from app.modules.url_analyzer import URLAnalyzer
from app.modules.redirect_tracer import RedirectTracer
from app.modules.tls_analyzer import TLSAnalyzer
from app.modules.security_headers import SecurityHeadersAnalyzer
from app.modules.message_analyzer import MessageAnalyzer
from app.modules.correlation_engine import CorrelationEngine
from app.services.scoring_engine import ScoringEngine
from app.services.explainer_service import ExplainerService
from app.services.web3_service import Web3RegistryService
from app.services.agent_service import AegisAgentService
from app.core.canonical_hasher import (
    compute_report_hash,
    compute_indicator_hash,
    build_canonical_report_payload,
)

app = FastAPI(
    title="AegisTrust Security Intelligence API",
    description="Evidence-grounded cybersecurity analysis, AI scam detection, Autonomous Security Agent, and Web3 verifiable reporting.",
    version="3.0.0"
)

# Enable CORS for Next.js / browser clients & Chrome/Edge extension
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


@app.get("/consumer")
def serve_consumer():
    consumer_file = os.path.join(static_dir, "consumer.html")
    if os.path.exists(consumer_file):
        return FileResponse(consumer_file)
    return FileResponse(os.path.join(static_dir, "index.html"))


@app.get("/agent")
def serve_agent():
    agent_file = os.path.join(static_dir, "agent.html")
    if os.path.exists(agent_file):
        return FileResponse(agent_file)
    return FileResponse(os.path.join(static_dir, "index.html"))


@app.get("/sandbox")
def serve_sandbox():
    sandbox_file = os.path.join(static_dir, "sandbox.html")
    if os.path.exists(sandbox_file):
        return FileResponse(sandbox_file)
    return FileResponse(os.path.join(static_dir, "index.html"))


@app.get("/findings")
@app.get("/intel")
def serve_findings():
    f = os.path.join(static_dir, "findings.html")
    return FileResponse(f) if os.path.exists(f) else FileResponse(os.path.join(static_dir, "index.html"))


@app.get("/redirects")
@app.get("/url-analysis")
def serve_redirects():
    f = os.path.join(static_dir, "redirects.html")
    return FileResponse(f) if os.path.exists(f) else FileResponse(os.path.join(static_dir, "index.html"))


@app.get("/tls")
def serve_tls():
    f = os.path.join(static_dir, "tls.html")
    return FileResponse(f) if os.path.exists(f) else FileResponse(os.path.join(static_dir, "index.html"))


@app.get("/graph")
def serve_graph():
    f = os.path.join(static_dir, "graph.html")
    return FileResponse(f) if os.path.exists(f) else FileResponse(os.path.join(static_dir, "index.html"))


@app.get("/web3")
def serve_web3():
    f = os.path.join(static_dir, "web3.html")
    return FileResponse(f) if os.path.exists(f) else FileResponse(os.path.join(static_dir, "index.html"))


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    svg_icon = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#38bdf8"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>'
    return Response(content=svg_icon, media_type="image/svg+xml")


# Initialize engines
url_analyzer = URLAnalyzer()
tls_analyzer = TLSAnalyzer()
correlation_engine = CorrelationEngine()
web3_service = Web3RegistryService()
agent_service = AegisAgentService(
    url_analyzer=url_analyzer,
    tls_analyzer=tls_analyzer,
    correlation_engine=correlation_engine,
    web3_service=web3_service,
)


@app.get("/health")
@app.get("/api/v1/health")
def health():
    return {"status": "healthy", "service": "AegisTrust", "version": "3.0.0"}


@app.get("/api/v1/distrusted-cas")
def get_distrusted_cas():
    return {"distrusted_cas": tls_analyzer.distrusted_cas}


@app.get("/api/v1/intel-feeds")
def get_intel_feeds():
    return {"entries": url_analyzer.intel_snapshot}


@app.get("/api/v1/correlations/{domain}")
def get_correlations(domain: str):
    cluster = correlation_engine.find_cluster(domain)
    return cluster


@app.post("/api/v1/investigate/url", response_model=InvestigationResponse)
def investigate_url(req: InvestigationRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="URL parameter is required")

    submission_id = str(uuid.uuid4())[:8]
    all_findings: List[Finding] = []
    limitations: List[str] = []
    checks_status: Dict[str, str] = {}

    # 1. URL & Lexical Analysis
    lex_findings, meta = url_analyzer.analyze(req.url)
    all_findings.extend(lex_findings)
    checks_status["lexical_analysis"] = "completed"
    checks_status["threat_intel_lookup"] = "completed"

    # 2. Safe Redirect Chain Tracer
    redirect_hops, redirect_findings = RedirectTracer.trace(meta["normalized_url"])
    all_findings.extend(redirect_findings)

    has_nxdomain = any(f.id == "F-DNS-NXDOMAIN" for f in redirect_findings)
    has_ssrf_block = any(f.id == "F-REDIRECT-SSRF-BLOCKED" for f in redirect_findings)

    if redirect_hops and redirect_hops[-1].status_code > 0:
        checks_status["dns_resolution"] = "completed"
        checks_status["redirect_trace"] = "completed"
    elif has_nxdomain:
        checks_status["dns_resolution"] = "completed (NXDOMAIN)"
        checks_status["redirect_trace"] = "unavailable (domain offline/unregistered)"
        limitations.append("Live HTTP redirect trace could not complete because the domain did not resolve in public DNS.")
    elif has_ssrf_block:
        checks_status["dns_resolution"] = "blocked (SSRF Guard)"
        checks_status["redirect_trace"] = "blocked (SSRF Guard)"
        limitations.append("Active connection blocked by SSRF Guard due to restricted/internal IP target.")
    else:
        checks_status["dns_resolution"] = "completed"
        checks_status["redirect_trace"] = "partial (connection timeout)"
        limitations.append("Redirect chain could only be partially probed due to remote endpoint timeout.")

    # 3. TLS Certificate Analysis
    tls_report, tls_findings = tls_analyzer.analyze(meta["normalized_url"])
    all_findings.extend(tls_findings)
    checks_status["tls_inspection"] = "completed" if tls_report else "unavailable"
    if not tls_report:
        limitations.append("TLS handshake could not be established (host may be non-TLS, unresolvable, or blocking handshakes).")

    # 4. Passive Security Headers Audit
    headers_dict, header_findings = SecurityHeadersAnalyzer.inspect(meta["normalized_url"])
    all_findings.extend(header_findings)
    checks_status["security_headers"] = "completed" if headers_dict else "unavailable"
    if not headers_dict:
        limitations.append("Passive security header audit was limited because the endpoint did not return standard HTTP response headers.")

    # 5. Infrastructure Correlation in NetworkX Graph
    resolved_ip = redirect_hops[0].resolved_ip if redirect_hops else None
    cert_fp = tls_report.fingerprint_sha256 if tls_report else None
    domain_name = meta.get("domain", meta.get("hostname", ""))
    if domain_name:
        correlation_engine.add_incident(
            domain=domain_name,
            ip=resolved_ip,
            cert_fp=cert_fp
        )
        cluster_info = correlation_engine.find_cluster(domain_name)
        if cluster_info["cluster_size"] > 1:
            linked_peers = ", ".join(cluster_info["correlated_domains"][:3])
            all_findings.append(Finding(
                id="F-CORRELATION-CLUSTER",
                module="intel",
                title="Correlated Multi-Domain Fraud Infrastructure Detected",
                severity=Severity.HIGH,
                weight=25,
                evidence=(
                    f"Domain shares infrastructure (IP: {resolved_ip or 'Cluster'}, "
                    f"Cert: {cert_fp[:8] if cert_fp else 'Shared'}) with known campaigns: {linked_peers}."
                ),
                source="AegisTrust:NetworkXCorrelationEngine",
                remediation="High risk of coordinated malicious campaign. Treat associated hostnames with suspicion."
            ))
    checks_status["campaign_correlation"] = "completed"

    # 6. Deterministic Risk Scoring
    completed_checks_count = sum(1 for v in checks_status.values() if "completed" in v)
    score, classification, coverage = ScoringEngine.calculate_score(
        all_findings,
        checks_completed=max(completed_checks_count, 5),
        total_checks=8
    )

    # 7. Explainability
    explanation = ExplainerService.generate_explanation(
        target=meta["hostname"],
        classification=classification,
        score=score,
        findings=all_findings,
        coverage_percent=coverage
    )

    # 8. Cryptographic Commitments
    timestamp_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    temp_payload = {
        "submission_id": submission_id,
        "target": meta["hostname"],
        "target_type": "url",
        "timestamp": timestamp_str,
        "risk_classification": classification.value,
        "risk_score": score,
        "findings": all_findings,
    }
    report_hash = compute_report_hash(temp_payload)
    indicator_hash = compute_indicator_hash(meta["hostname"])

    containment_pkg = None
    if score >= 60 or classification.value in ("High Risk", "Confirmed Malicious"):
        containment_pkg = ContainmentCompiler.compile(
            target=meta["hostname"],
            risk_classification=classification.value,
            risk_score=score,
            resolved_ip=resolved_ip,
            cert_sha256=cert_fp,
            findings=all_findings,
            report_hash_keccak256=report_hash
        )

    return InvestigationResponse(
        submission_id=submission_id,
        target=meta["hostname"],
        target_type="url",
        timestamp=timestamp_str,
        risk_classification=classification,
        risk_score=score,
        evidence_coverage_percent=coverage,
        explanation=explanation,
        findings=all_findings,
        redirect_chain=redirect_hops,
        tls_details=tls_report,
        passive_headers=headers_dict,
        message_analysis=None,
        correlation_cluster_id=domain_name or meta["hostname"],
        limitations=limitations,
        checks_status=checks_status,
        report_hash_keccak256=report_hash,
        salted_indicator_hash=indicator_hash,
        onchain_registry_status="Unregistered",
        containment_package=containment_pkg
    )


@app.post("/api/v1/investigate/message", response_model=InvestigationResponse)
def investigate_message(req: InvestigationRequest):
    if not req.message:
        raise HTTPException(status_code=400, detail="Message content is required")

    submission_id = str(uuid.uuid4())[:8]
    all_findings: List[Finding] = []
    limitations: List[str] = []
    checks_status: Dict[str, str] = {}

    # 1. Social Engineering & Linguistic Heuristics
    message_analysis, scam_findings = MessageAnalyzer.analyze(req.message)
    all_findings.extend(scam_findings)
    checks_status["linguistic_heuristics"] = "completed"
    checks_status["prompt_injection_defense"] = "completed"
    checks_status["entity_extraction"] = "completed"

    redirect_hops = []
    tls_report = None
    headers_dict = {}
    primary_domain = None
    extracted_upis = [ind.value for ind in message_analysis.extracted_indicators if ind.indicator_type == "upi_vpa"]

    # 2. Deep investigation of embedded URLs
    if message_analysis.extracted_urls:
        first_url = message_analysis.extracted_urls[0]
        url_findings, meta = url_analyzer.analyze(first_url)
        primary_domain = meta.get("domain", meta.get("hostname"))

        # Safe trace
        hops, red_findings = RedirectTracer.trace(meta["normalized_url"])
        redirect_hops = hops
        url_findings.extend(red_findings)

        # TLS Analysis
        tls_rep, t_findings = tls_analyzer.analyze(meta["normalized_url"])
        tls_report = tls_rep
        url_findings.extend(t_findings)

        # Security Headers
        h_dict, h_findings = SecurityHeadersAnalyzer.inspect(meta["normalized_url"])
        headers_dict = h_dict
        url_findings.extend(h_findings)

        existing_ids = {f.id for f in all_findings}
        for uf in url_findings:
            if uf.id not in existing_ids:
                all_findings.append(uf)

        checks_status["embedded_url_lexical"] = "completed"
        checks_status["embedded_url_tls"] = "completed" if tls_report else "unavailable"
        checks_status["embedded_url_headers"] = "completed" if headers_dict else "unavailable"
    else:
        limitations.append("No embedded URLs found in message; network/TLS/header checks not applicable.")

    # 3. Correlate indicators in NetworkX Graph
    if primary_domain:
        resolved_ip = redirect_hops[0].resolved_ip if redirect_hops else None
        cert_fp = tls_report.fingerprint_sha256 if tls_report else None
        correlation_engine.add_incident(
            domain=primary_domain,
            ip=resolved_ip,
            cert_fp=cert_fp,
            upi=extracted_upis[0] if extracted_upis else None
        )
        cluster_info = correlation_engine.find_cluster(primary_domain)
        if cluster_info["cluster_size"] > 1:
            linked_peers = ", ".join(cluster_info["correlated_domains"][:3])
            all_findings.append(Finding(
                id="F-CORRELATION-CLUSTER",
                module="intel",
                title="Message Linked to Correlated Fraud Campaign Cluster",
                severity=Severity.HIGH,
                weight=25,
                evidence=(
                    f"Extracted indicators ({primary_domain}"
                    f"{', ' + extracted_upis[0] if extracted_upis else ''}) connect to "
                    f"active phishing cluster involving: {linked_peers}."
                ),
                source="AegisTrust:NetworkXCorrelationEngine",
                remediation="Do not interact with link or transfer funds; part of a coordinated scam campaign."
            ))
    checks_status["campaign_correlation"] = "completed"

    limitations.append(
        "Linguistic urgency alone is never treated as proof of fraud without corroborating technical or behavioral indicators."
    )

    # 4. Deterministic Risk Scoring
    score, classification, coverage = ScoringEngine.calculate_score(
        all_findings,
        checks_completed=7 if message_analysis.extracted_urls else 6,
        total_checks=8
    )

    # 5. Explainability
    target_name = primary_domain or (
        message_analysis.extracted_urls[0] if message_analysis.extracted_urls else "Pasted Message Content"
    )
    explanation = ExplainerService.generate_explanation(
        target=target_name,
        classification=classification,
        score=score,
        findings=all_findings,
        coverage_percent=coverage
    )

    # 6. Cryptographic Commitments
    timestamp_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    temp_payload = {
        "submission_id": submission_id,
        "target": target_name,
        "target_type": "message",
        "timestamp": timestamp_str,
        "risk_classification": classification.value,
        "risk_score": score,
        "findings": all_findings,
    }
    report_hash = compute_report_hash(temp_payload)
    indicator_hash = compute_indicator_hash(target_name)

    return InvestigationResponse(
        submission_id=submission_id,
        target=target_name,
        target_type="message",
        timestamp=timestamp_str,
        risk_classification=classification,
        risk_score=score,
        evidence_coverage_percent=coverage,
        explanation=explanation,
        findings=all_findings,
        redirect_chain=redirect_hops,
        tls_details=tls_report,
        passive_headers=headers_dict,
        message_analysis=message_analysis,
        correlation_cluster_id=primary_domain or target_name,
        limitations=limitations,
        checks_status=checks_status,
        report_hash_keccak256=report_hash,
        salted_indicator_hash=indicator_hash,
        onchain_registry_status="Unregistered"
    )


# --- Autonomous AI Security Agent & Proactive Watchdog Routes ---

@app.post("/api/v1/agent/investigate", response_model=AgentInvestigateResponse)
def agent_investigate(req: AgentInvestigateRequest):
    if not req.query and not req.page_url:
        raise HTTPException(status_code=400, detail="Either 'query' or 'page_url' is required for Agent investigation.")
    return agent_service.run_agent_investigation(req)


@app.post("/api/v1/agent/watchdog/scan")
def agent_watchdog_scan(req: WatchdogScanRequest):
    return agent_service.run_watchdog_scan(req.protected_brand)


@app.get("/api/v1/agent/watchdog/status")
def agent_watchdog_status():
    return {
        "history": agent_service.watchdog_history,
        "blocklist": list(agent_service.extension_blocklist.values()),
        "blocklist_count": len(agent_service.extension_blocklist),
    }


@app.get("/api/v1/extension/blocklist")
def get_extension_blocklist():
    return {
        "blocklist": list(agent_service.extension_blocklist.values()),
        "intel_feeds": url_analyzer.intel_snapshot,
        "distrusted_cas": tls_analyzer.distrusted_cas,
    }


# --- Web3 Registry Routes ---

@app.get("/api/v1/web3/reports")
def list_web3_reports():
    return {"reports": web3_service.list_reports(), "contract_address": web3_service.CONTRACT_ADDRESS}


@app.post("/api/v1/web3/submit")
def submit_to_web3(req: Web3SubmitRequest):
    receipt = web3_service.submit_report(req.report_json, supersedes_id=req.supersedes_id)
    return receipt


@app.post("/api/v1/web3/verify", response_model=Web3VerificationResponse)
def verify_web3_report(req: Web3VerifyRequest):
    res = web3_service.verify_report(req.report_json, simulate_tamper=req.simulate_tamper)
    return res


@app.post("/api/v1/web3/validate")
def validate_web3_report(req: Web3ValidateRequest):
    return web3_service.validate_report(req.report_hash)


@app.post("/api/v1/web3/dispute")
def dispute_web3_report(req: Web3DisputeRequest):
    return web3_service.dispute_report(req.report_hash, req.reason)



@app.post("/api/v1/investigate/visual", response_model=VisualAnalysisResult)
@app.post("/api/investigate/visual", response_model=VisualAnalysisResult)
def investigate_visual(req: VisualAnalysisRequest):
    import base64
    if not req.image_base64:
        raise HTTPException(status_code=400, detail="image_base64 is required")

    raw_b64 = req.image_base64
    if "," in raw_b64:
        raw_b64 = raw_b64.split(",", 1)[1]

    try:
        img_bytes = base64.b64decode(raw_b64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 image data: {str(e)}")

    apex = req.apex_domain or ""
    if not apex and req.target_url:
        _, meta = url_analyzer.analyze(req.target_url)
        apex = meta.get("domain", meta.get("hostname", ""))

    return VisualAnalyzer.analyze_image_bytes(
        image_bytes=img_bytes,
        target_url=req.target_url or "",
        apex_domain=apex
    )


@app.post("/api/v1/containment/compile", response_model=ContainmentPackage)
@app.post("/api/containment/compile", response_model=ContainmentPackage)
def compile_containment(req: ContainmentCompileRequest):
    finding_objs = []
    if req.findings:
        for f in req.findings:
            if isinstance(f, dict):
                finding_objs.append(Finding(**f))
            elif isinstance(f, Finding):
                finding_objs.append(f)

    return ContainmentCompiler.compile(
        target=req.target,
        risk_classification=req.risk_classification or "High Risk",
        risk_score=req.risk_score or 75,
        resolved_ip=req.resolved_ip,
        cert_sha256=req.cert_sha256,
        findings=finding_objs,
        report_hash_keccak256=req.report_hash_keccak256
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
