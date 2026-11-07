# 📋 Task Plan: AegisTrust (AI + Cyber + Web3 Evidence Platform)

> **Execution Protocol**: Manus-style crash-proof planning.
> **Total Timeline**: 48 Hours | **Target**: 100% Judge Rubric Coverage.

---

## 🎯 Phase Breakdown & Progress Tracker

- [x] **Phase 1: Project Skeleton, Security Foundations & SSRF Guard** *(Hours 0–4)*
  - [x] 1.1 Initialize monorepo: `backend/` (FastAPI), `frontend/` (Next.js/Tailwind), `contracts/` (Hardhat/Foundry)
  - [x] 1.2 Implement bulletproof SSRF validator (DNS pre-resolve, CIDR blacklist, port restriction 80/443, timeout 5s)
  - [x] 1.3 Build typed Pydantic models: `Finding`, `AnalysisRequest`, `InvestigationReport`, `ThreatCluster`
  - [x] 1.4 Write unit tests for SSRF guard (`127.0.0.1`, `169.254.169.254`, `[::1]`, DNS rebinding)

- [x] **Phase 2: Core Cybersecurity Pipeline (Modules 1, 1b, 2 & 5)** *(Hours 4–14)*
  - [x] 2.1 **URL Lexical & Typosquat Engine**: Levenshtein / Damerau against Top 100 targets, Cyrillic/homoglyph detection, brand-in-subdomain, suspicious keyword density
  - [x] 2.2 **Safe Redirect Tracer**: Hop-by-hop HEAD/GET with SSRF re-check on every hop, visual hop timeline
  - [x] 2.3 **TLS Trust Engine**: Python `cryptography` inspection (expiration, SAN matching, weak keys/ciphers, self-signed detection)
  - [x] 2.4 **Distrusted CA & CT Registry**: Static `distrusted_cas.json` (eMudhra incident & known compromised intermediates) + crt.sh CT issuance query
  - [x] 2.5 **Passive Security Header Audit**: HSTS, CSP, X-Frame-Options, cookie flags (`Secure`, `HttpOnly`, `SameSite`)
  - [x] 2.6 **Threat Intel Integration**: URLhaus / OpenPhish offline snapshot + live API fallback with cached results

- [x] **Phase 3: AI Scam Engine & Deterministic Scoring (Modules 3 & 4)** *(Hours 14–22)*
  - [x] 3.1 **Message Extraction Pipeline**: Regex extractors for URLs, emails, phone numbers, UPI/VPA handles, crypto addresses
  - [x] 3.2 **Prompt-Injection Proof LLM Classifier**: Delimited payload, strict JSON schema output, mandatory verbatim quote requirement
  - [x] 3.3 **Deterministic Risk Engine**: Weighted additive score with category caps, negative weights for legitimate domain age, and Evidence Coverage %
  - [x] 3.4 **LLM Evidence Explainer**: Strictly summarizes pre-computed findings; prompt strictly prohibits changing risk tier
  - [x] 3.5 **Threat Correlation Graph**: NetworkX graph linking entities by shared IP, Nameserver, WHOIS registrar, or cert fingerprint

- [x] **Phase 4: Web3 Verifiable Report Registry (Module 6)** *(Hours 22–30)*
  - [x] 4.1 Author `ReportRegistry.sol`: `submitReport`, `reviseReport` (supersedes chain), `disputeReport`, `validateReport`
  - [x] 4.2 Canonical JSON serializer: RFC 8785 deterministic ordering + `keccak256` hashing
  - [x] 4.3 Off-chain privacy preservation: salted/normalized domain hashes (`bytes32`), zero PII on-chain
  - [x] 4.4 Independent client-side verification script & UI tab (hashes matching, tamper demonstration)
  - [x] 4.5 Local testnet deployment (Hardhat/Anvil) with automated contract address and artifact export

- [x] **Phase 5: High-Taste SOC Frontend & Dashboard** *(Hours 30–40)*
  - [x] 5.1 Next.js 14 / Tailwind UI: High-contrast Dark SOC theme (cyber-slate, emerald, amber, rose)
  - [x] 5.2 Unified Input: Tabbed interface for "Investigate URL/Domain" vs "Analyze Scam Message"
  - [x] 5.3 Evidence Cards: Detailed finding chips (Issue, Evidence, Source, Severity, Mitigation)
  - [x] 5.4 Visual Redirect Timeline & Interactive Correlation Graph (Force-directed / Cytoscape)
  - [x] 5.5 Web3 Verification Panel: 1-click submit to blockchain, instant verified status badge, live tamper test button

- [x] **Phase 6: Testing, Documentation, Video Demo & Polish** *(Hours 40–48)*
  - [x] 6.1 Execute mandatory test suite: 3 Benign + 3 Suspicious + 1 Confirmed Malicious + `badssl.com` cases
  - [x] 6.2 Write `TEST_REPORT.md` documenting observed vs expected outputs and false-positive handling
  - [x] 6.3 Document architecture, threat models, and verifiable blockchain proofs in `README.md`
  - [x] 6.4 Rehearse 5-minute live demo script following the judging rubric flow

- [x] **Phase 7: Google Stitch Cyber Noir Bento Integration & Turnkey Production Packaging**
  - [x] 7.1 Implemented pixel-perfect Google Stitch design (`Cyber Noir Bento` theme, Tailwind tokens, Plus Jakarta Sans, JetBrains Mono, Material Symbols Outlined).
  - [x] 7.2 Architected **Dual-Mode Separation**:
    - **`/` (Live SOC Console)**: 100% clean, live threat investigation portal without demo presets or mock tags.
    - **`/sandbox` (Evaluation & Tamper Sandbox)**: Features 6 deterministic benchmark presets and live on-chain cryptographic tamper verification test.
  - [x] 7.3 Implemented all 5 Bento tabs: Findings Matrix (severity filters), Safe Redirect Timeline, TLS & eMudhra CA Inspector, Interactive Correlation Graph, and Web3 Provenance (RFC 8785 Keccak-256).
  - [x] 7.4 Created turnkey deployment packaging: `requirements.txt`, `.env.example`, `start_server.bat`, `start_server.ps1`, `run_tests.bat`, `run_tests.ps1`, `Dockerfile`, `docker-compose.yml`.
  - [x] 7.5 Executed `/understand` knowledge graph generation (`.ua/knowledge-graph.json` and `.ua/meta.json`).
  - [x] 7.6 Verified 100% pass rate across 19 unit & integration tests; synchronized with remote GitHub repository.
