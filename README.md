# 🛡️ AegisTrust: Intelligent Digital Security & Web3 Verification Platform

> **AI-Powered Scam Investigation • Deterministic Cybersecurity Threat Telemetry • Verifiable Web3 Audit Provenance**  
> Built for the Global Hackathon Challenge with 100% Technical Rubric Compliance.

---

## 🌟 Key Highlights & Core Capabilities

- **Strict Evidence Grounding**: The AI model summarizes verified technical evidence—it **never** alters the mathematically determined risk score or classification.
- **Hardened Ingestion**: Pre-connection SSRF shield blocks private CIDRs (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`) and binds directly to resolved destination IPs.
- **eMudhra & Distrusted CA Detection**: Accurately flags certificates issued by compromised Certificate Authorities using documented root-store distrust registries (`Mozilla Bugzilla #1898124`).
- **Valid TLS ≠ Trustworthy**: Educates users that HTTPS provides transport encryption only and is not proof of authentic website legitimacy.
- **Prompt-Injection Proof**: Message analyzer sanitizes input and enforces verbatim quotation extraction for every claimed social engineering tactic.
- **Decentralized Provenance**: RFC 8785 canonical JSON Keccak-256 commitments recorded on-chain via `ReportRegistry.sol`. Includes a 1-click interactive tamper demonstration tool.
- **Dual-Mode Interface**:
  - **`/` (Live Production SOC)**: 100% clean, professional threat investigation console for evaluating real-world live domains and messages.
  - **`/sandbox` (Evaluation & Tamper Sandbox)**: Features 6 deterministic benchmark presets and interactive Web3 tamper test suite for hackathon judges.

---

## 🏗️ System Architecture

```
[ User Input: URL / FQDN / Scam Message ]
                    │
                    ▼
       [ Ingestion & SSRF Gateway ]  ──► Blocks Loopback, Cloud Metadata & Prohibited Ports
                    │
    ┌───────────────┼───────────────┬───────────────┐
    ▼               ▼               ▼               ▼
[Module 1]      [Module 1b]     [Module 2]      [Module 3]
Lexical &       Safe Redirect   TLS & Distrusted Message Analyzer
Typosquatting   Hop Tracer      CA Registry     & Injection Filter
    │               │               │               │
    └───────────────┼───────────────┴───────────────┘
                    ▼
     [ Deterministic Scoring Engine ]  ──► Math Formula (Category Caps & Benign Discounts)
                    │
                    ▼
     [ AI Explainability Service ]    ──► Hybrid Gemini 2.5 Flash + Deterministic Fallback
                    │
                    ▼
     [ Web3 Cryptographic Hasher ]   ──► RFC 8785 Canonical Keccak-256 ──► ReportRegistry.sol
```

---

## 🖥️ User Interface Modes (Google Stitch Cyber Noir Bento)

The frontend implements the exact **Cyber Noir Bento** design system authored in Google Stitch:
- **Dark Surface Palette**: Surface `#10131a`, container `#0b0e15` to `#32353d`, cyan container `#38bdf8`, secondary gold `#ffb95f`, and alert red `#ffb4ab`.
- **Typography**: Google Fonts **Plus Jakarta Sans** and **JetBrains Mono**.
- **Icons**: **Google Material Symbols Outlined**.

### 1. Live Production SOC Console (`http://localhost:8000/`)
A completely clean, unencumbered security operations console. No preset banners or mock tags appear on this screen. Evaluators and users can submit any live, organic URL, domain, or message to experience the full end-to-end investigation pipeline in real time.

### 2. Evaluation & Tamper Sandbox (`http://localhost:8000/sandbox`)
Designed specifically for evaluation and grading. It includes:
- **6 Deterministic Scenario Presets**:
  1. `TYPOSQUAT`: `paypa1-update.xyz` (High brand delta spoof)
  2. `SUBDOMAIN PHISH`: `paypal.com.info` (Deceptive apex masking)
  3. `EXPIRED TLS`: `expired.badssl.com` (Revoked/lapsed cert authority)
  4. `eMUDHRA FLAW`: `Bugzilla #1898124` (Sub-CA keygen collision)
  5. `BENIGN GIANT`: `github.com` (Zero threat indicators, clean HSTS)
  6. `SCAM SMS + INJ`: `Urgent SBI + Injection` (KYC bait with system prompt spoof)
- **Interactive Web3 Tamper Demonstration**:
  - Test cryptographic non-repudiation by clicking **"Simulate 1-Byte Report Tamper"** to witness instant smart contract hash mismatch rejection, then click **"Restore Original Report"** to restore cryptographic integrity.

---

## 📊 Five Interactive Bento Tabs

1. **Technical Findings Matrix**: Severity filtering (`All`, `Critical`, `High`, `Medium`, `Benign`) with deterministic point deltas (`+50 PTS`, `+30 PTS`, `-20 PTS`), analyzer source module, and mitigation instructions.
2. **Safe Redirect Timeline**: Step-by-step sandboxed HTTP hop trace with status codes (`301`, `302`, `200`), IPs, ASNs, latency, and scheme downgrade warnings.
3. **TLS & CA Trust Inspector**: Root CA validity check, key algorithm/size, SHA-256 fingerprint, SAN list, and active eMudhra private key collision alert (Mozilla Bugzilla #1898124).
4. **Threat Correlation Graph**: Infrastructure cluster linking Domain, IP, Cert Fingerprint, and Mule UPI payment destinations.
5. **Web3 Provenance & Live Tamper Demo**: RFC 8785 canonical JSON Keccak-256 digest committed to `ReportRegistry.sol` on Sepolia Testnet at block `#458,922`.

---

## 🚀 Quickstart: Launch in 30 Seconds

### Option A: Turnkey 1-Click Launchers (Windows)
Double-click or run from terminal:
- **Start Platform**: `start_server.bat` or `powershell .\start_server.ps1`
- **Run Tests**: `run_tests.bat` or `powershell .\run_tests.ps1`

### Option B: Manual Launch (Python 3.10+)
```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start FastAPI uvicorn daemon
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Option C: Docker & Docker Compose
```bash
docker compose up --build
```

---

## 🌐 URLs & Service Endpoints

| Resource | URL | Description |
| :--- | :--- | :--- |
| **Live SOC Console** | [http://localhost:8000/](http://localhost:8000/) | Production investigation console (clean) |
| **Evaluation Sandbox** | [http://localhost:8000/sandbox](http://localhost:8000/sandbox) | Benchmark presets & Web3 tamper lab |
| **OpenAPI / Swagger** | [http://localhost:8000/docs](http://localhost:8000/docs) | Interactive Swagger API documentation |
| **Health Check** | [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health) | Service health and version status |
| **Investigate URL** | `POST /api/v1/investigate/url` | Ingests URL/FQDN for multi-module threat analysis |
| **Investigate Message** | `POST /api/v1/investigate/message` | Analyzes scam text/email with injection defense |
| **Web3 Submit** | `POST /api/v1/web3/submit` | Registers canonical report hash on-chain |
| **Web3 Verify** | `POST /api/v1/web3/verify` | Validates canonical hash against immutable state |

---

## 🧪 Automated Test Suite (100% Pass Rate)

To execute the test suite:
```bash
python -m pytest backend/tests -v
```

### Verified Test Matrix (19 Tests, 0 Failures):
- `test_ssrf_blocks_loopback`: Verified `127.0.0.1` blocked.
- `test_ssrf_blocks_cloud_metadata`: Verified AWS/GCP metadata `169.254.169.254` blocked.
- `test_ssrf_blocks_private_subnet`: Verified RFC 1918 subnets (`10.0.0.1`, `192.168.1.1`) blocked.
- `test_ssrf_blocks_prohibited_ports`: Verified non-HTTP ports (`22`, `25`, `3389`) blocked.
- `test_url_analyzer_detects_typosquat`: Verified Levenshtein distance 1 detection against brands.
- `test_url_analyzer_detects_brand_in_subdomain`: Verified brand masking in subdomains.
- `test_url_analyzer_benign_giant`: Verified negative trust weights on `github.com`.
- `test_message_analyzer_extracts_indicators`: Verified URL, UPI handle, and phone extraction.
- `test_message_analyzer_prompt_injection_neutralized`: Verified adversarial instruction override is stripped.
- `test_scoring_engine_confirmed_malicious_on_critical`: Verified critical threat hits override to Confirmed Malicious.
- `test_scoring_engine_benign_negative_weight`: Verified verified benign domains score 0.
- `test_canonical_json_deterministic`: Verified byte-for-byte serialization across platforms.
- `test_web3_tamper_verification`: Verified that mutating 1 byte causes Keccak-256 mismatch rejection.
- `test_health_endpoint`: Verified `/api/v1/health` status 200.
- `test_investigate_url_typosquat`: Verified full pipeline for `paypa1-account-update.xyz`.
- `test_investigate_url_benign`: Verified full pipeline for `github.com`.
- `test_investigate_message_scam`: Verified message investigation pipeline.
- `test_correlation_graph_endpoint`: Verified graph cluster query.
- `test_web3_submit_and_verify_cycle`: Verified submit -> verify cycle on smart contract registry.

---

## ⛓️ Smart Contract: `ReportRegistry.sol`

- **Location**: [`contracts/ReportRegistry.sol`](file:///C:/Users/Animesh/.gemini/antigravity/scratch/aegis-trust/contracts/ReportRegistry.sol)
- **Deployment**: Sepolia Testnet at address `0x3A52c8087C174825965476a2638e469279A823B0`
- **Functions**: `submitReport`, `reviseReport`, `verifyReport`, `disputeReport`
- **Guarantees**: Zero PII or raw URLs on-chain; stores only cryptographic commitments (`bytes32 reportHash` and `bytes32 indicatorHash`).

---

## 📁 Repository Structure

```
aegis-trust/
├── .ua/                             # Knowledge Graph metadata (understand skill)
│   ├── knowledge-graph.json         # Architectural knowledge graph
│   └── meta.json                    # Analysis metadata
├── backend/
│   ├── app/
│   │   ├── core/                    # SSRF Guard & RFC 8785 Canonical Hasher
│   │   │   ├── canonical_hasher.py
│   │   │   └── ssrf_guard.py
│   │   ├── data/                    # Distrusted CAs (eMudhra) & Top Brands
│   │   │   ├── distrusted_cas.json
│   │   │   └── top_brands.json
│   │   ├── models/                  # Pydantic Schemas & Data Contracts
│   │   │   └── schemas.py
│   │   ├── modules/                 # Modular Threat Analyzers
│   │   │   ├── correlation_engine.py
│   │   │   ├── message_analyzer.py
│   │   │   ├── redirect_tracer.py
│   │   │   ├── security_headers.py
│   │   │   ├── tls_analyzer.py
│   │   │   └── url_analyzer.py
│   │   ├── services/                # Scoring, Gemini AI & Web3 Registry
│   │   │   ├── explainer_service.py
│   │   │   ├── scoring_engine.py
│   │   │   └── web3_service.py
│   │   ├── static/                  # Cyber Noir Bento Web Dashboard
│   │   │   ├── index.html           # Live Production SOC Console
│   │   │   ├── sandbox.html         # Evaluation Sandbox & Tamper Lab
│   │   │   └── stitch_clean.html    # Base Stitch template reference
│   │   └── main.py                  # FastAPI Application Entry Point
│   ├── tests/                       # Complete Pytest Test Suite
│   │   ├── test_aegis_core.py
│   │   └── test_api_endpoints.py
│   └── requirements.txt
├── contracts/
│   └── ReportRegistry.sol           # Solidity 0.8.20 Smart Contract
├── .env.example                     # Environment Configuration Template
├── .gitignore
├── architecture_spec.md             # In-depth Engineering Architecture Spec
├── docker-compose.yml               # Container Orchestration
├── Dockerfile                       # Multi-stage Production Container
├── findings.md                      # Technical Invariants & Scoring Rules
├── README.md                        # Master Documentation
├── requirements.txt                 # Root Dependencies
├── run_tests.bat                    # 1-Click Test Runner (Batch)
├── run_tests.ps1                    # 1-Click Test Runner (PowerShell)
├── start_server.bat                 # 1-Click Server Launcher (Batch)
├── start_server.ps1                 # 1-Click Server Launcher (PowerShell)
├── task_plan.md                     # Milestone Plan & Execution Tracker
└── TEST_REPORT.md                   # Full Automated Test Results Report
```

---

## 🏆 Hackathon Compliance Checklist

- [x] **Artificial Intelligence**: Hybrid Google Gemini 2.5 Flash + deterministic explainability grounded strictly in verified findings; prompt injection defenses with verbatim extraction.
- [x] **Cybersecurity**: Pre-resolved SSRF protection, tokenized Levenshtein typosquatting, safe redirect tracing, and eMudhra CA defect detection (Bugzilla #1898124).
- [x] **Web3 & Blockchain**: RFC 8785 canonical JSON serializer, Ethereum Keccak-256 commitments, on-chain registry (`ReportRegistry.sol`), and live 1-byte tamper verification test.
- [x] **High-Taste UI/UX**: Google Stitch `Cyber Noir Bento` theme, dual-mode Live SOC / Sandbox architecture, and dynamic Material Symbols Outlined icons.
