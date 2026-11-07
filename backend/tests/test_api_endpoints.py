"""
Integration tests for FastAPI REST Endpoints.
Verifies:
- /api/v1/investigate/url (benign, typosquat, threat intel)
- /api/v1/investigate/message (scam detection, tactic quotes)
- /api/v1/correlations/{domain} (threat cluster graph)
- /api/v1/web3/submit & /api/v1/web3/verify (cryptographic verification)
"""

import pytest
import sys
import os
from starlette.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

def test_investigate_url_typosquat():
    res = client.post("/api/v1/investigate/url", json={"url": "https://paypa1-account-update.xyz/login"})
    assert res.status_code == 200
    data = res.json()
    assert data["risk_classification"] in ("High Risk", "Suspicious")
    assert data["risk_score"] >= 25
    assert len(data["findings"]) > 0
    assert "report_hash_keccak256" in data

def test_investigate_url_benign():
    res = client.post("/api/v1/investigate/url", json={"url": "https://github.com"})
    assert res.status_code == 200
    data = res.json()
    assert data["risk_classification"] == "Low Risk"
    assert data["risk_score"] < 25

def test_investigate_message_scam():
    msg = "URGENT: Your SBI bank account is suspended due to pending KYC. Verify immediately at http://sbi-kyc-verify-portal.top or transfer fee to admin@okaxis"
    res = client.post("/api/v1/investigate/message", json={"message": msg})
    assert res.status_code == 200
    data = res.json()
    assert data["message_analysis"] is not None
    assert len(data["message_analysis"]["identified_tactics"]) > 0
    assert len(data["message_analysis"]["extracted_urls"]) > 0

def test_correlation_graph_endpoint():
    res = client.get("/api/v1/correlations/sbi-kyc-verify-portal.top")
    assert res.status_code == 200
    data = res.json()
    assert "nodes" in data
    assert "edges" in data
    assert data["cluster_size"] >= 2  # Connected to sbi-rewards-redeem.cc

def test_web3_submit_and_verify_cycle():
    # 1. Investigate URL
    inv_res = client.post("/api/v1/investigate/url", json={"url": "https://paypa1-account-update.xyz"})
    report_data = inv_res.json()

    # 2. Submit to Web3
    submit_res = client.post("/api/v1/web3/submit", json={"report_json": report_data})
    assert submit_res.status_code == 200
    receipt = submit_res.json()
    assert "tx_hash" in receipt
    assert "block_number" in receipt

    # 3. Verify Valid
    verify_res = client.post("/api/v1/web3/verify", json={"report_json": report_data, "simulate_tamper": False})
    assert verify_res.status_code == 200
    assert verify_res.json()["verified"] is True
    assert verify_res.json()["hashes_match"] is True

    # 4. Verify Tampered (Altered Evidence)
    tamper_res = client.post("/api/v1/web3/verify", json={"report_json": report_data, "simulate_tamper": True})
    assert tamper_res.status_code == 200
    assert tamper_res.json()["verified"] is False
    assert tamper_res.json()["hashes_match"] is False
    assert "Tamper" in tamper_res.json()["status"]
