"""
Integration tests for FastAPI REST Endpoints.
Verifies:
- /api/v1/investigate/url (benign, typosquat, threat intel, limitations & coverage)
- /api/v1/investigate/message (scam detection, tactic quotes, correlation)
- /api/v1/correlations/{domain} (threat cluster graph)
- /api/v1/agent/investigate (Autonomous AI Security Agent multi-step tool loop & incident responder)
- /api/v1/agent/watchdog/scan & /api/v1/extension/blocklist (Proactive 24/7 Brand Watchdog & Extension Sync)
- /api/v1/web3/submit, /api/v1/web3/verify, /api/v1/web3/validate, /api/v1/web3/dispute
- /health, /favicon.ico, and dedicated static view routes
"""

import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app.main import (
    health,
    favicon,
    serve_dashboard,
    serve_consumer,
    serve_agent,
    serve_sandbox,
    serve_findings,
    serve_redirects,
    serve_tls,
    serve_graph,
    serve_web3,
    investigate_url,
    investigate_message,
    get_correlations,
    agent_investigate,
    agent_watchdog_scan,
    agent_watchdog_status,
    get_extension_blocklist,
    submit_to_web3,
    verify_web3_report,
    validate_web3_report,
    dispute_web3_report,
)
from app.models.schemas import (
    InvestigationRequest,
    AgentInvestigateRequest,
    WatchdogScanRequest,
    Web3SubmitRequest,
    Web3VerifyRequest,
    Web3ValidateRequest,
    Web3DisputeRequest,
)


def _to_dict(obj):
    if hasattr(obj, "model_dump"):
        return json.loads(obj.model_dump_json())
    return obj


def test_health_and_favicon_endpoints():
    data = _to_dict(health())
    assert data["status"] == "healthy"

    fav = favicon()
    assert fav.status_code == 200
    assert "svg" in fav.media_type


def test_static_page_routes():
    # Verify all dedicated subpages resolve properly
    for fn in (
        serve_dashboard,
        serve_consumer,
        serve_agent,
        serve_sandbox,
        serve_findings,
        serve_redirects,
        serve_tls,
        serve_graph,
        serve_web3,
    ):
        res = fn()
        assert res is not None


def test_investigate_url_typosquat():
    res = investigate_url(InvestigationRequest(url="https://paypa1-account-update.xyz/login"))
    data = _to_dict(res)
    assert data["risk_classification"] in ("High Risk", "Suspicious")
    assert data["risk_score"] >= 60
    assert len(data["findings"]) > 0
    assert len(data["limitations"]) > 0
    assert "report_hash_keccak256" in data


def test_investigate_url_benign():
    res = investigate_url(InvestigationRequest(url="https://github.com"))
    data = _to_dict(res)
    assert data["risk_classification"] == "Low Risk"
    assert data["risk_score"] < 25


def test_investigate_url_emudhra():
    res = investigate_url(InvestigationRequest(url="https://emudhra-compromised-ca.example"))
    data = _to_dict(res)
    assert data["risk_classification"] == "Confirmed Malicious"
    assert data["risk_score"] == 100
    assert data["tls_details"]["is_distrusted_ca"] is True


def test_investigate_message_scam():
    msg = "URGENT: Your SBI bank account is suspended due to pending KYC. Verify immediately at http://sbi-kyc-verify-portal.top or transfer fee to admin@okaxis"
    res = investigate_message(InvestigationRequest(message=msg))
    data = _to_dict(res)
    assert data["message_analysis"] is not None
    assert len(data["message_analysis"]["identified_tactics"]) > 0
    assert len(data["message_analysis"]["extracted_urls"]) > 0
    assert data["risk_classification"] in ("Confirmed Malicious", "High Risk")


def test_correlation_graph_endpoint():
    data = _to_dict(get_correlations("sbi-kyc-verify-portal.top"))
    assert "nodes" in data
    assert "edges" in data
    assert data["cluster_size"] >= 2  # Connected to sbi-rewards-redeem.cc


def test_autonomous_agent_emergency_incident_response():
    req = AgentInvestigateRequest(
        query="HELP! I already clicked http://onlinesbi-kyc-update.com/login and entered my password and OTP!",
        has_password_form=True,
        auto_anchor_web3=True,
    )
    data = _to_dict(agent_investigate(req))
    assert data["intent_detected"] == "EMERGENCY_INCIDENT_RESPONSE"
    assert data["risk_score"] >= 60
    assert data["risk_classification"] in ("High Risk", "Confirmed Malicious")
    assert len(data["steps"]) >= 7
    assert data["auto_anchored_web3"] is True
    assert data["web3_receipt"] is not None
    assert "tx_hash" in data["web3_receipt"]
    assert len(data["emergency_recovery_steps"]) >= 3


def test_watchdog_and_extension_blocklist():
    scan_res = _to_dict(agent_watchdog_scan(WatchdogScanRequest(protected_brand="paypal.com")))
    assert scan_res["protected_brand"] == "paypal.com"
    assert scan_res["candidates_scanned"] >= 3
    assert scan_res["threats_auto_blocked"] >= 1

    status_res = _to_dict(agent_watchdog_status())
    assert status_res["blocklist_count"] >= 1

    ext_res = _to_dict(get_extension_blocklist())
    assert len(ext_res["blocklist"]) >= 1
    assert len(ext_res["distrusted_cas"]) >= 1


def test_web3_submit_verify_validate_dispute_cycle():
    # 1. Investigate URL
    inv_res = investigate_url(InvestigationRequest(url="https://paypa1-account-update.xyz"))
    report_data = _to_dict(inv_res)

    # 2. Submit to Web3
    receipt = _to_dict(submit_to_web3(Web3SubmitRequest(report_json=report_data)))
    assert "tx_hash" in receipt
    assert "block_number" in receipt

    # 3. Verify Valid
    verify_res = _to_dict(verify_web3_report(Web3VerifyRequest(report_json=report_data, simulate_tamper=False)))
    assert verify_res["verified"] is True
    assert verify_res["hashes_match"] is True

    # 4. Community Validate
    val_res = _to_dict(validate_web3_report(Web3ValidateRequest(report_hash=report_data["report_hash_keccak256"])))
    assert val_res["ok"] is True
    assert val_res["entry"]["validations_count"] >= 2

    # 5. Verify Tampered (Simulated & Actual Payload Tampering)
    tamper_res = _to_dict(verify_web3_report(Web3VerifyRequest(report_json=report_data, simulate_tamper=True)))
    assert tamper_res["verified"] is False
    assert tamper_res["hashes_match"] is False
    assert "Tamper" in tamper_res["status"]

    real_tamper = dict(report_data)
    real_tamper["risk_score"] = 0
    real_tamper_res = _to_dict(verify_web3_report(Web3VerifyRequest(report_json=real_tamper, simulate_tamper=False)))
    assert real_tamper_res["verified"] is False
    assert real_tamper_res["hashes_match"] is False


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASSED: {t.__name__}", flush=True)
    print(f"\nAll {len(tests)} API integration tests passed!", flush=True)
    os._exit(0)
