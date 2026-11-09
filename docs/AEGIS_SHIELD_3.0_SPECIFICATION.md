# AegisShield 3.0: Autonomous Zero-Trust Cyber Defense Platform & Web3 Provenance Architecture
**Executive Technical Whitepaper & Architectural Specification**  
**Document Version:** 3.0.0-PROD | **Classification:** Technical Whitepaper / Architecture Reference  
**Release Target:** Enterprise SOC, CSIRT, Security Operations & Web3 Protection  

---

## 1. Executive Summary & Problem Domain

The modern cyber threat landscape has evolved beyond basic static phishing and domain spoofing. Attackers now weaponize multi-layered evasion chains:
1. **SSRF and IP-Hopping Obfuscation:** Threat actors cycle malicious traffic through intermediate meta-refreshes, client-side JavaScript redirects, and URL shorteners while probing internal metadata endpoints (`169.254.169.254`, `127.0.0.1`, RFC 1918 subnets).
2. **Subverted PKI & Compromised Certificate Authorities:** Attackers obtain valid HTTPS certificates from distrusted or audited Certificate Authorities (e.g., the *eMudhra* root compromise tracked under Mozilla Bugzilla #1898124), giving deceptive phishing portals the illusion of legitimacy.
3. **Visual Brand Spoofing:** Minor character modifications (typosquatting like `paypa1` or zero-width Unicode homoglyphs) are used to host exact visual replicas of login screens that evade standard regex and domain blocklists.
4. **Quishing (QR Code Phishing):** Attackers bypass corporate email and messaging gateways by embedding deceptive QR codes in images and PDFs, directing victims to out-of-band mobile phishing lures.
5. **Web3 Permit2 & EIP-2612 Drainers:** Instead of traditional on-chain approvals (`eth_sendTransaction`), modern crypto drainers solicit off-chain typed signatures (`eth_signTypedData_v4`) using Uniswap Permit2 contracts. These signatures bypass standard hardware wallet warnings, allowing attackers to sweep user tokens with zero upfront gas.

**AegisShield 3.0** is an autonomous, evidence-grounded cyber defense command center and browser shield engineered to neutralize these attack vectors in sub-second timeframes before compromise occurs.

---

## 2. High-Level Architecture

The AegisShield ecosystem operates across a four-tier architecture:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   CLIENT TIER                                          │
│  - Chromium / Edge MV3 Extension: `provider_hook.js` injected at `document_start`     │
│  - Intercepts `eth_signTypedData_v4` off-chain approvals (Uniswap Permit2, EIP-2612)  │
│  - Real-time tab scanning, credential harvesting `<input type="password">` detection  │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ REST / WebSocket
┌───────────────────────────────────────────▼────────────────────────────────────────────┐
│                              AUTONOMOUS SENSOR PIPELINE                                │
│  ├─ [Sensor 1] SSRF Guard: DNS pre-resolution & strict RFC 1918/Loopback IP pinning    │
│  ├─ [Sensor 2] Redirect Tracer: Step-by-step unrolling of HTTP 30x / JS / Meta hops   │
│  ├─ [Sensor 3] TLS & CA Auditor: X.509 RSA/ECC inspection & eMudhra distrust check     │
│  ├─ [Sensor 4] Lexical & Entropy Engine: Shannon entropy, TLD scoring, Punycode parser │
│  └─ [Sensor 5] Aegis Vision & Quishing Detonator: 64-bit dHash + 2D DCT pHash + QR     │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Normalized Indicators
┌───────────────────────────────────────────▼────────────────────────────────────────────┐
│                              DECISION & CORRELATION ENGINE                             │
│  - Bayesian Risk Scoring (0–100 Scale: Benign, Suspicious, High Risk, Malicious)      │
│  - NetworkX Force-Directed Fraud Mesh: Bipartite domain-IP-ASN correlation graph       │
│  - Autonomous Copilot: Emergency step-by-step incident response remediation generator │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                     ┌──────────────────────┴──────────────────────┐
                     ▼                                             ▼
┌─────────────────────────────────────────┐   ┌─────────────────────────────────────────┐
│         ACTIVE CONTAINMENT KIT          │   │         VERIFIABLE WEB3 LEDGER          │
│  - Cloudflare WAF JSON Rule             │   │  - Canonical JSON RFC 8785 Normalization│
│  - Snort / Suricata IDS Rule            │   │  - Keccak-256 State Hash Verification   │
│  - Pi-hole DNS RPZ Sinkhole Entry       │   │  - Ethereum / Base `ReportRegistry.sol` │
│  - STIX 2.1 CTI Threat Bundle           │   │  - Immutable Proof of Threat Existence  │
│  - CERT-In National Legal Dossier       │   │  - 100% Cryptographic Tamper Detection  │
└─────────────────────────────────────────┘   └─────────────────────────────────────────┘
```

---

## 3. Threat Detection Modules

### 3.1. SSRF Guard & IP-Pinned Resolution
Conventional web scanners are vulnerable to Server-Side Request Forgery (SSRF) and DNS rebinding attacks where an attacker alternates between a public IP and `127.0.0.1` or `169.254.169.254`.
AegisShield implements a custom pre-resolution socket monkey-patch:
1. Performs deterministic DNS resolution prior to initiating the TCP handshake.
2. Checks resolved IP addresses against IPv4/IPv6 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`).
3. Re-pins the verified public IP to the outgoing HTTP socket, neutralizing DNS rebinding race conditions.

### 3.2. Aegis Vision: Perceptual Hashing & Quishing Detonation
The visual analysis engine operates in two tiers:
1. **Sub-15ms Perceptual Hashing:**
   - **64-bit Difference Hash ($dHash$):** Downsamples the rendering to $9 \times 8$ grayscale, calculates horizontal gradient intensity differences ($P[x, y] > P[x+1, y]$), and generates a 64-bit fingerprint.
   - **2D Discrete Cosine Transform Hash ($pHash$):** Downsamples to $32 \times 32$, computes the frequency spectrum via 2D DCT, extracts the lowest $8 \times 8$ frequency matrix, and compares against the median frequency.
   - **Hamming Distance Threshold:** Compares the target against a golden registry of 12 protected financial & tech brand templates (PayPal, MetaMask, Microsoft, Google, Apple, Binance, Coinbase, etc.). A Hamming distance $\le 10$ ($>84.3\%$ visual similarity) on an unverified domain immediately triggers a visual spoofing verdict.
2. **Quishing Detonator:**
   - Detects embedded QR codes in landing pages and phishing lures.
   - Decodes payloads locally; if a URL payload points to an external redirector or spoofed login, it is recursively analyzed through the threat pipeline.
3. **Multimodal AI Fallback:**
   - If local visual metrics are ambiguous, the system dispatches the image to Google Gemini 2.5 Flash with structured schema extraction to evaluate brand spoofing intent.

### 3.3. Web3 Permit2 Drainer Shield
Modern crypto drainers exploit off-chain gasless approval standards:
- **Uniswap Permit2 (`0x000000000022D473030F116dDEE9F6B43aC78BA3`):** Allows spenders to transfer any approved ERC-20 token based on an off-chain `PermitSingle` or `PermitBatch` signature.
- **EIP-2612 & Dai-style Permits:** Solicits signature approvals for token allowances.

**Interception Mechanism:**
The AegisShield browser extension injects `provider_hook.js` into the `MAIN` execution context at `document_start` before web application scripts initialize:
1. Wraps `window.ethereum.request`.
2. Inspects calls to `eth_signTypedData_v4` and `eth_signTypedData`.
3. Parses the EIP-712 domain and message fields. If the signature targets `PermitSingle`, `PermitBatch`, or an unverified spender address on an untrusted origin, the hook intercepts the request and displays a full-screen, un-bypassable red warning dialog displaying the exact spender address, tokens at risk, and approval deadline before MetaMask or Rabby receives the prompt.

---

## 4. Active Containment Compiler

Rather than leaving incident response as an afterthought, AegisShield compiles immediate, actionable countermeasures across 5 standards:
1. **Cloudflare WAF Expression:** Generates JSON rules matching the host, URI path, and user-agent patterns with action `block`.
2. **Snort / Suricata IDS Rule:** Generates signature rules with unique SID, message classification, and flow inspection:
   ```
   drop tcp any any -> $EXTERNAL_NET $HTTP_PORTS (msg:"AEGIS-CONTAIN: Suspicious Typosquat Hostile Phishing"; content:"Host: paypa1-account-update.xyz"; sid:9000101; rev:1;)
   ```
3. **Pi-hole DNS RPZ:** Generates response-policy zone lines (`0.0.0.0 domain`) for enterprise DNS sinkholing.
4. **STIX 2.1 CTI Bundle:** Generates standard JSON objects containing `indicator`, `malware`, `observed-data`, and MITRE ATT&CK mapping (`T1566.002` Spearphishing Link).
5. **National Cybercrime Legal Evidence Dossier:** Generates a structured formal report citing IPC/IT Act sections, canonical timestamps, IP addresses, registrant info, and cryptographic hashes suitable for submission to CERT-In or local cybercrime cells.

---

## 5. Web3 Cryptographic Provenance & Tamper Demonstration

To ensure evidence cannot be altered after the fact by either attackers or rogue administrators:
1. **RFC 8785 Canonical JSON Normalization:** All report keys, integers, floats, and strings are canonicalized into an unambiguous deterministic byte stream.
2. **Keccak-256 State Hashing:** The canonical payload is hashed using Ethereum's cryptographic standard Keccak-256:
   $$\mathcal{H} = \text{Keccak-256}(\text{Canonicalize}(\text{Report}))$$
3. **Smart Contract Registry (`ReportRegistry.sol`):**
   - Stores `(reportHash, submitter, timestamp, riskScore, supersedesId)`.
   - Supports independent public dispute tracking and verifiable report supersession.
4. **Live Tamper Demonstration:** If even a single byte or timestamp inside a 100-page report is altered, re-hashing yields a completely different Keccak-256 digest, which fails on-chain verification instantly.

---

## 6. Dual-Mode User Experience

AegisShield recognizes that enterprise security tools often alienate everyday users with indecipherable raw telemetry:
- **SOC Analyst Mode:** Features deep raw telemetry, X.509 ASN.1 dumps, Shannon entropy values, EIP-712 message decoders, IP geolocation tags, and the interactive Constellation graph.
- **Everyday User Mode:** Transforms complex metrics into an accessible visual Threat Radar, high-contrast verdict badge, plain-English explanation, and an actionable 3-step safety checklist ("What should I do right now?").
- **Global Command Palette (`Cmd + K`):** Quick-action navigation, sandboxed benchmark executions, containment kit exports, and acoustic spatial synthesizer audio toggling.

---

## 7. Operational & Deployment Specification

### Production Dependencies
- Python 3.11+, FastAPI 0.110+, Uvicorn 0.29+, Cryptography 42.0+, PyCryptodome 3.20+, Pillow 10.0+, NetworkX 3.2+.
- Headless Chromium (Playwright / Chrome DevTools).
- Solidity ^0.8.20 / Hardhat / EVM Sepolia testnet.

### Containerization
The service is containerized via a production multi-stage `Dockerfile` with non-root security boundaries (`UID 1000`) and packaged with `docker-compose.yml`.
Healthcheck probe: `GET /api/v1/health` &rarr; `HTTP 200 OK`.

---
*© 2026 AegisTrust / AegisShield Security Architecture Group. All rights reserved.*
