# 🛡️ AegisTrust: Autonomous AI Cyber Defense, Threat Intelligence & Web3 Provenance

> **Autonomous AI Security Agent • Real-Time Browser Extension Shield • Deterministic Threat Telemetry • Verifiable Web3 Audit Provenance**  
> Built for the **Zenith HackMatrix** Challenge with 100% Technical Rubric & Guardrail Compliance.

---

## 🌟 Key Highlights & Core Capabilities

- **Autonomous AI Security Agent (`/agent`)**: Executes a 7-step **`OBSERVE → ACT → PIVOT → DEFEND → SYNTHESIZE`** tool loop (`ioc_and_intent_extractor`, `url_lexical_and_brand_analyzer`, `ssrf_pinned_redirect_tracer`, `tls_and_ca_trust_inspector`, `networkx_campaign_graph_pivot`, `deterministic_scorer_and_web3_defender`, `evidence_grounded_copilot`). Supports pre-click Threat Hunting, Post-Click Emergency Incident Response (*"I already clicked & entered my password!"*), and **Proactive 24/7 Brand Watchdog** sweeps.
- **Real-Time Chrome / Edge Browser Extension (`extension/`)**: Manifest V3 browser shield that automatically scores every navigated tab, detects `<input type="password">` credential-harvesting forms on untrusted domains, injects a **Full-Screen Red Phishing Blocker Overlay** when `risk_score >= 60`, and adds right-click context-menu investigation for links and highlighted text.
- **Strict Deterministic Evidence Grounding**: Risk scores (`0–100`) and the 5-tier classification (`Low Risk`, `Suspicious`, `High Risk`, `Confirmed Malicious`, `Inconclusive` — **never labeled "Safe"**) are computed strictly upstream of the LLM. The AI model never alters the score or verdict.
- **SSRF-Hardened Inspection with DNS IP Pinning**: Pre-validates and resolves hostnames, blocks loopback/private/cloud-metadata CIDRs (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`, `fc00::/7`), restricts ports to `80, 443, 8080, 8443`, and pins the resolved IP on the socket to defeat DNS rebinding.
- **eMudhra & Distrusted CA Detection (`Mozilla Bugzilla #1898124`)**: Audits X.509 certificates and root-store distrust registries while explicitly educating users that **Valid TLS/HTTPS ≠ Legitimate Website** and noting that CA key-generation entropy defects are matched via external root-store advisories rather than inferred from a URL string alone.
- **Prompt-Injection Shield & False-Positive Guardrails**: Neutralizes adversarial prompt-injection payloads (`IGNORE PREVIOUS INSTRUCTIONS...`), extracts verbatim evidence quotes, protects institutional TLDs (`.gov.in`, `.edu`, `.ac.in`), and ensures urgent language alone never triggers `High Risk`.
- **Genuine Ethereum Keccak-256 & Web3 Provenance (`ReportRegistry.sol`)**: Computes RFC 8785 Canonical JSON commitments using genuine Ethereum Keccak-256 (`0x01` padding) and salted indicator hashes (`H(salt || canonical_domain)`) so **zero raw URLs or PII** are stored on-chain. Supports report submission, revision (`supersedes`), community validation (`validateReport`), dispute tracking (`disputeReport`), and real payload tamper verification.

---

## 🏗️ System Architecture

```
[ Browser Extension (MV3) / Web Portals / 24x7 Brand Watchdog ]
                               │
                               ▼
          [ Autonomous AI Agent Orchestrator (7-Step Loop) ]
                               │
                               ▼
        [ Ingestion & SSRF Gateway (DNS IP Pinning) ]
                               │
    ┌──────────────┬───────────┴───┬───────────────┬───────────────┐
    ▼              ▼               ▼               ▼               ▼
[Module 1]     [Module 1b]     [Module 2]      [Module 3]      [Module 4]
Lexical, IDN   SSRF-Pinned     X.509 TLS &     Scam Message    NetworkX Fraud
& Typosquat    Redirect Trace  eMudhra CA      & Injection     Cluster Graph
    │              │               │               │               │
    └──────────────┴───────────────┼───────────────┴───────────────┘
                                   ▼
            [ Deterministic Scoring Engine (Category Caps) ]
                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
     [ Hybrid Gemini + Fallback ]   [ RFC 8785 Canonical Keccak-256 ]
     [ Explainability & Copilot ]   [ ReportRegistry.sol + Blocklist ]
```

---

## 🖥️ Multi-Portal Web Interface & Browser Extension

| Portal / Component | Route / Path | Purpose |
| :--- | :--- | :--- |
| **Live Analyst SOC Console** | `http://localhost:8000/` | Full multi-module threat scanner and triage workspace |
| **Autonomous AI Security Agent & Watchdog** | `http://localhost:8000/agent` | 7-step autonomous agent console, post-click emergency responder, & 24/7 brand CT log watchdog |
| **Everyday Consumer Portal** | `http://localhost:8000/consumer` | Jargon-free personal scam checker for links, SMS/WhatsApp messages, and UPI IDs |
| **Safe Redirect & URL Hop Tracer** | `http://localhost:8000/redirects` | Step-by-step SSRF-pinned HTTP redirect chain and cross-domain hop visualizer |
| **TLS & Distrusted CA Inspector** | `http://localhost:8000/tls` | X.509 certificate chain auditor and eMudhra root-store distrust registry |
| **Threat Feeds & Scam Analyzer** | `http://localhost:8000/findings` | OpenPhish/URLhaus intelligence snapshot and social engineering tactic breakdown |
| **Web3 Tamper-Evident Registry** | `http://localhost:8000/web3` | RFC 8785 Keccak-256 on-chain ledger, community validation/dispute, & live tamper verifier |
| **Evaluation Test Bench (3+3)** | `http://localhost:8000/sandbox` | 3 Benign + 3 Malicious deterministic rubric presets for instant verification |
| **Chrome / Edge Browser Extension** | `extension/` | Manifest V3 extension with live badge scoring, DOM password sensor, right-click agent scan, and full-screen red phishing blocker |

---

## 🚀 Quickstart

### 1. Start the Backend Server
```powershell
# Install dependencies (Python 3.10+)
pip install -r requirements.txt

# Launch FastAPI server on port 8000
python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 --reload
```
*(Or run `start_server.bat` / `powershell .\start_server.ps1` on Windows.)*

### 2. Load the Chrome / Edge Browser Extension (`extension/`)
1. Open `chrome://extensions` (or `edge://extensions`) in your browser.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the `extension/` folder in this repository.
4. Browse any website to see real-time tab scoring, right-click any link/text to invoke the Aegis AI Agent, or click **"🚨 Simulate Full-Screen Phishing Block on This Tab"** in the extension popup.

---

## 🌐 REST API Endpoints

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/health` | `GET` | Service health and version status (`v1.1.0`) |
| `/api/v1/investigate/url` | `POST` | Full deterministic URL investigation pipeline |
| `/api/v1/investigate/message` | `POST` | Social engineering & embedded IOC message investigation |
| `/api/v1/agent/investigate` | `POST` | Autonomous 7-step AI Agent investigation & emergency incident response |
| `/api/v1/agent/watchdog/scan` | `POST` | Proactive 24/7 brand lookalike & CT log sweep with auto-Web3 defense |
| `/api/v1/agent/watchdog/status` | `GET` | Watchdog scan history and active browser blocklist count |
| `/api/v1/extension/blocklist` | `GET` | Synchronizes active blocklist, threat feeds, and distrusted CAs to the browser extension |
| `/api/v1/correlations/{domain}` | `GET` | Queries the NetworkX infrastructure correlation graph |
| `/api/v1/web3/reports` | `GET` | Lists anchored on-chain report commitments |
| `/api/v1/web3/submit` | `POST` | Anchors or revises (`supersedes_id`) an RFC 8785 Keccak-256 report commitment |
| `/api/v1/web3/verify` | `POST` | Recomputes canonical Keccak-256 hash from payload fields to verify integrity or detect tampering |
| `/api/v1/web3/validate` | `POST` | Records a community validation vote on an on-chain report |
| `/api/v1/web3/dispute` | `POST` | Flags an on-chain report as disputed for false-positive governance |

---

## 🧪 Automated Test Suite (24 Tests, 100% Pass Rate)

Run both test suites directly:
```powershell
python backend/tests/test_aegis_core.py
python backend/tests/test_api_endpoints.py
```

### Verified Test Coverage:
- **Core Engine Unit Tests (`test_aegis_core.py` — 14/14 Passed)**:
  - SSRF loopback (`127.0.0.1`), cloud metadata (`169.254.169.254`), RFC 1918 private subnet, and prohibited port blocking
  - Tokenized Levenshtein typosquatting, brand-in-subdomain spoofing, and verified benign giant discounts
  - Message IOC extraction, adversarial prompt-injection neutralization, and urgency-only false-positive guardrail
  - Deterministic scoring caps, RFC 8785 canonical JSON determinism, and genuine Keccak-256 payload tamper detection
- **API & Autonomous Agent Integration Tests (`test_api_endpoints.py` — 10/10 Passed)**:
  - All 9 static portal routes (`/`, `/consumer`, `/agent`, `/sandbox`, `/findings`, `/redirects`, `/tls`, `/graph`, `/web3`)
  - URL & Message investigation pipelines (`paypa1-account-update.xyz`, `github.com`, `emudhra-compromised-ca.example`, SBI scam SMS)
  - Autonomous Agent post-click emergency incident responder (`EMERGENCY_INCIDENT_RESPONSE`) & auto-Web3 anchoring
  - 24/7 Proactive Brand Watchdog sweep & Browser Extension blocklist synchronization
  - Full Web3 lifecycle: `submit -> verify -> validate -> tamper detection`

---

## 📁 Repository Structure

```
AegisTrust/
├── backend/
│   ├── app/
│   │   ├── core/                    # SSRF Guard (DNS IP Pinning) & RFC 8785 Keccak-256 Hasher
│   │   │   ├── canonical_hasher.py
│   │   │   └── ssrf_guard.py
│   │   ├── data/                    # Distrusted CAs (eMudhra), Top Brands, Threat Feeds & Ledger
│   │   ├── models/                  # Pydantic v2 Schemas & Agent Contracts
│   │   │   └── schemas.py
│   │   ├── modules/                 # 6 Threat Detection & Correlation Modules
│   │   │   ├── correlation_engine.py
│   │   │   ├── message_analyzer.py
│   │   │   ├── redirect_tracer.py
│   │   │   ├── security_headers.py
│   │   │   ├── tls_analyzer.py
│   │   │   └── url_analyzer.py
│   │   ├── services/                # Deterministic Scorer, AI Explainer, Web3 & Autonomous Agent
│   │   │   ├── agent_service.py
│   │   │   ├── explainer_service.py
│   │   │   ├── scoring_engine.py
│   │   │   └── web3_service.py
│   │   ├── static/                  # Multi-Portal Web UI (SOC, Consumer, Agent, Web3, Sandbox)
│   │   └── main.py                  # FastAPI Application Entry Point
│   └── tests/                       # 24 Automated Unit & Integration Tests
│       ├── test_aegis_core.py
│       └── test_api_endpoints.py
├── contracts/
│   └── ReportRegistry.sol           # Solidity 0.8.20 Smart Contract (Submit, Revise, Validate, Dispute, Verify)
├── extension/                       # Chrome / Edge Manifest V3 Real-Time Browser Shield
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── popup.html
│   └── popup.js
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```
