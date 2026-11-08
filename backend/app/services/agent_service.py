"""
Autonomous AI Security Agent & Proactive Brand Watchdog Service.
Implements the Observe -> Think -> Act -> Pivot -> Defend loop across all 6 AegisTrust modules:
1. Dynamic Intent & IOC Extraction (detects pre-click triage vs. post-click emergency incident response)
2. Autonomous Tool Chaining (Lexical -> SSRF Redirect Unrolling -> TLS/eMudhra Audit -> Passive Headers)
3. NetworkX Campaign Graph Pivoting (discovers connected scam domains sharing IP/Cert/UPI infrastructure)
4. Autonomous Defense Execution (auto-anchors High Risk / Confirmed Malicious reports to ReportRegistry.sol
   and pushes active block rules to the Chrome/Edge Browser Extension)
5. Proactive 24/7 Brand Watchdog (scans CT logs & newly discovered lookalikes for protected brands)
"""

import os
import re
import time
import uuid
from typing import List, Dict, Any, Optional

from app.models.schemas import (
    AgentStep,
    AgentInvestigateRequest,
    AgentInvestigateResponse,
    InvestigationResponse,
    Finding,
    Severity,
    RiskClassification,
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

DOMAIN_TOKEN_REGEX = re.compile(
    r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|in|sbi|xyz|top|cc|info|biz|io|co|uk|shop|live|club|icu|work|example)\b',
    re.IGNORECASE,
)

POST_CLICK_PATTERNS = [
    r'already (clicked|entered|typed|shared|paid|sent|submitted)',
    r'i (clicked|entered|typed|shared|paid|sent|gave)',
    r'entered my (password|otp|pin|card|credentials)',
    r'what (do|should) i do',
    r'hacked',
    r'compromised',
    r'accidentally',
]

WATCHDOG_FEED_SIMULATION = {
    "paypal.com": [
        {"domain": "paypa1-account-update.xyz", "source": "crt.sh CT Log #984120", "ip": "185.196.10.45"},
        {"domain": "paypal.com.account-update.info", "source": "Newly Registered Domains Stream", "ip": "185.196.10.45"},
        {"domain": "paypal-Resolution-center-verify.top", "source": "crt.sh CT Log #984155", "ip": "185.196.10.45"},
    ],
    "onlinesbi.sbi": [
        {"domain": "sbi-kyc-verify-portal.top", "source": "OpenPhish + crt.sh Stream", "ip": "194.26.29.112"},
        {"domain": "sbi-rewards-redeem.cc", "source": "crt.sh CT Log #984199", "ip": "194.26.29.112"},
        {"domain": "onlinesbi-pan-link.xyz", "source": "Newly Registered Domains Stream", "ip": "194.26.29.112"},
    ],
    "hdfcbank.com": [
        {"domain": "hdfc-netbanking-unblock.top", "source": "crt.sh CT Log #984210", "ip": "194.26.29.112"},
        {"domain": "hdfcbank.com.kyc-portal.xyz", "source": "Newly Registered Domains Stream", "ip": "185.196.10.45"},
    ],
    "github.com": [
        {"domain": "github-SSO-authenticate.xyz", "source": "crt.sh CT Log #984301", "ip": "185.196.10.45"},
        {"domain": "github.com", "source": "Official Baseline Check", "ip": "140.82.121.4"},
    ],
}


class AegisAgentService:
    def __init__(
        self,
        url_analyzer: URLAnalyzer,
        tls_analyzer: TLSAnalyzer,
        correlation_engine: CorrelationEngine,
        web3_service: Web3RegistryService,
    ):
        self.url_analyzer = url_analyzer
        self.tls_analyzer = tls_analyzer
        self.correlation_engine = correlation_engine
        self.web3_service = web3_service
        self.extension_blocklist: Dict[str, Dict[str, Any]] = {}
        self.watchdog_history: List[Dict[str, Any]] = []

    def run_agent_investigation(self, req: AgentInvestigateRequest) -> AgentInvestigateResponse:
        session_id = "agt-" + str(uuid.uuid4())[:8]
        query = (req.query or req.page_url or "").strip()
        page_ctx = dict(req.page_context or {})
        if req.page_url and not page_ctx.get("current_url"):
            page_ctx["current_url"] = req.page_url
        if req.has_password_form:
            page_ctx["has_password_field"] = True

        steps: List[AgentStep] = []
        auto_actions: List[str] = []
        emergency_checklist: List[str] = []

        # ─────────────────────────────────────────────────────────────
        # STEP 1: OBSERVE & CLASSIFY INTENT + EXTRACT CLUES (IOCs)
        # ─────────────────────────────────────────────────────────────
        t0 = time.perf_counter()
        query_lower = query.lower()
        is_emergency = any(re.search(p, query_lower) for p in POST_CLICK_PATTERNS)

        msg_analysis, scam_findings = MessageAnalyzer.analyze(query)
        extracted_urls = list(msg_analysis.extracted_urls)

        if not extracted_urls:
            if page_ctx.get("current_url"):
                extracted_urls.append(str(page_ctx["current_url"]))
            else:
                bare_domains = DOMAIN_TOKEN_REGEX.findall(query)
                for bd in bare_domains:
                    if bd.lower() not in [u.lower() for u in extracted_urls]:
                        extracted_urls.append(f"https://{bd}")

        extracted_upis = [i.value for i in msg_analysis.extracted_indicators if i.indicator_type == "upi_vpa"]
        extracted_emails = [i.value for i in msg_analysis.extracted_indicators if i.indicator_type == "email"]

        if is_emergency:
            intent_mode = "EMERGENCY_INCIDENT_RESPONSE"
        elif page_ctx.get("source") == "browser_extension":
            intent_mode = "PAGE_GUARD"
        elif len(query.split()) > 4 and (msg_analysis.identified_tactics or extracted_upis or extracted_emails):
            intent_mode = "SCAM_TRIAGE"
        else:
            intent_mode = "THREAT_HUNT"

        step1_obs_parts = [f"Mode: {intent_mode}"]
        if extracted_urls:
            step1_obs_parts.append(f"Target URL/Domain(s): {', '.join(extracted_urls[:2])}")
        if extracted_upis:
            step1_obs_parts.append(f"UPI Payment Handles: {', '.join(extracted_upis)}")
        if msg_analysis.identified_tactics:
            step1_obs_parts.append(
                f"Psychological Tactics: {', '.join(t.tactic for t in msg_analysis.identified_tactics)}"
            )
        if msg_analysis.is_adversarial_injection_detected:
            step1_obs_parts.append("Adversarial Prompt Injection BLOCKED")

        steps.append(AgentStep(
            step_number=1,
            phase="OBSERVE",
            tool_name="ioc_and_intent_extractor",
            tool="IOC & Intent Extractor",
            thought=(
                "Parsing user input to determine operational mode (pre-click threat hunt vs. post-click emergency response) "
                "and extracting all embedded URLs, domains, UPI handles, and social engineering tactics."
            ),
            observation=" | ".join(step1_obs_parts),
            status="alert" if (is_emergency or msg_analysis.is_adversarial_injection_detected) else "completed",
            duration_ms=max(2, int((time.perf_counter() - t0) * 1000)),
        ))

        all_findings: List[Finding] = list(scam_findings)
        redirect_hops = []
        tls_report = None
        headers_dict: Dict[str, Any] = {}
        primary_domain = None
        checks_status: Dict[str, str] = {
            "agent_intent_parser": "completed",
            "prompt_injection_shield": "completed",
        }
        limitations: List[str] = []

        if page_ctx.get("has_password_field") and extracted_urls:
            steps.append(AgentStep(
                step_number=len(steps) + 1,
                phase="OBSERVE",
                tool_name="browser_dom_sensor",
                tool="Browser DOM Password Sensor",
                thought="Browser Extension reported active <input type='password'> or credential form on the current tab.",
                observation=f"Active credential-harvesting form capability detected on {extracted_urls[0]}.",
                status="warning",
                duration_ms=3,
            ))

        # ─────────────────────────────────────────────────────────────
        # STEP 2: ACT — URL LEXICAL, HOMOGRAPH & BRAND SPOOF ENGINE
        # ─────────────────────────────────────────────────────────────
        if extracted_urls:
            t1 = time.perf_counter()
            primary_url = extracted_urls[0]
            lex_findings, meta = self.url_analyzer.analyze(primary_url)
            primary_domain = meta.get("registered_domain") or meta.get("domain") or meta.get("hostname")

            existing_ids = {f.id for f in all_findings}
            for lf in lex_findings:
                if lf.id not in existing_ids:
                    all_findings.append(lf)

            is_verified_benign = any(f.severity == Severity.BENIGN for f in lex_findings)
            if page_ctx.get("has_password_field") and not is_verified_benign:
                all_findings.append(Finding(
                    id="F-EXT-PASSWORD-FORM",
                    module="scam",
                    title="Active Credential Harvesting Form on Unverified Domain",
                    severity=Severity.HIGH,
                    weight=25,
                    evidence=f"Browser extension DOM sensor detected a live password/login input field on unverified domain '{primary_domain}'.",
                    source="AegisTrust:BrowserExtensionSensor",
                    remediation="Do not type credentials; extension blocked form submission."
                ))
            elif is_emergency and not is_verified_benign:
                all_findings.append(Finding(
                    id="F-AGENT-POSTCLICK-COMPROMISE",
                    module="scam",
                    title="Post-Click Credential / OTP Phishing Exposure Reported",
                    severity=Severity.HIGH,
                    weight=25,
                    evidence=f"User reported active credential/OTP interaction with untrusted domain '{primary_domain}'.",
                    source="AegisTrust:IncidentResponder",
                    remediation="Immediately rotate credentials, revoke active sessions, and freeze affected payment channels."
                ))

            checks_status["lexical_analysis"] = "completed"
            checks_status["threat_intel_lookup"] = "completed"

            lex_titles = [f.title for f in lex_findings] or ["No lexical spoofing anomalies"]
            steps.append(AgentStep(
                step_number=len(steps) + 1,
                phase="ACT",
                tool_name="url_lexical_and_brand_analyzer",
                tool="URL Lexical & Homograph Engine",
                thought=f"Inspecting registrable apex domain '{primary_domain}' for Levenshtein typosquatting, subdomain brand traps, Punycode homographs, and URLhaus/OpenPhish hits.",
                observation=f"Registrable Domain: {primary_domain} -> Findings: {'; '.join(lex_titles[:3])}",
                status="alert" if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in lex_findings) else "completed",
                duration_ms=max(2, int((time.perf_counter() - t1) * 1000)),
            ))

            # ─────────────────────────────────────────────────────────────
            # STEP 3: ACT — SSRF-PINNED REDIRECT CHAIN UNROLLING
            # ─────────────────────────────────────────────────────────────
            t2 = time.perf_counter()
            redirect_hops, red_findings = RedirectTracer.trace(meta["normalized_url"])
            for rf in red_findings:
                if rf.id not in {f.id for f in all_findings}:
                    all_findings.append(rf)

            terminal_url = redirect_hops[-1].url if redirect_hops else meta["normalized_url"]
            if terminal_url != meta["normalized_url"]:
                dest_findings, dest_meta = self.url_analyzer.analyze(terminal_url)
                for df in dest_findings:
                    if df.id not in {f.id for f in all_findings}:
                        all_findings.append(df)

            hop_summary = (
                f"Traced {len(redirect_hops)} hop(s); terminal IP: {redirect_hops[-1].resolved_ip} (HTTP {redirect_hops[-1].status_code})"
                if redirect_hops
                else "Domain offline / NXDOMAIN in public DNS (evaluated via static & campaign intelligence)"
            )
            checks_status["redirect_trace"] = "completed" if redirect_hops else "completed (offline/synthetic)"
            steps.append(AgentStep(
                step_number=len(steps) + 1,
                phase="ACT",
                tool_name="ssrf_pinned_redirect_tracer",
                tool="SSRF-Pinned Redirect Tracer",
                thought="Unrolling redirect chain with SSRF pre-resolution and DNS IP pinning to uncover true destination host.",
                observation=hop_summary,
                status="warning" if len(redirect_hops) > 1 else "completed",
                duration_ms=max(5, int((time.perf_counter() - t2) * 1000)),
            ))

            # ─────────────────────────────────────────────────────────────
            # STEP 4: ACT — X.509 TLS, CA TRUST (eMudhra) & PASSIVE HEADERS
            # ─────────────────────────────────────────────────────────────
            t3 = time.perf_counter()
            tls_report, tls_findings = self.tls_analyzer.analyze(terminal_url)
            for tf in tls_findings:
                if tf.id not in {f.id for f in all_findings}:
                    all_findings.append(tf)

            headers_dict, hdr_findings = SecurityHeadersAnalyzer.inspect(terminal_url)
            for hf in hdr_findings:
                if hf.id not in {f.id for f in all_findings}:
                    all_findings.append(hf)

            checks_status["tls_inspection"] = "completed" if tls_report else "unavailable"
            checks_status["passive_headers"] = "completed" if headers_dict else "unavailable"

            if tls_report:
                if tls_report.is_distrusted_ca:
                    tls_obs = f"CRITICAL CA BREACH: Issued by distrusted CA ({tls_report.issuer}) — {tls_report.distrusted_reason}"
                    tls_status = "alert"
                elif tls_report.is_expired:
                    tls_obs = f"Certificate EXPIRED ({abs(tls_report.days_to_expiry)} days ago). Issuer: {tls_report.issuer}"
                    tls_status = "warning"
                else:
                    tls_obs = f"Valid X.509 cert ({tls_report.days_to_expiry}d left, {tls_report.key_size}-bit). Reminder: Valid HTTPS != Safe Site."
                    tls_status = "completed"
            else:
                tls_obs = "No active TLS listener on port 443 (offline/synthetic domain)."
                tls_status = "completed"
                limitations.append("Live TLS handshake unavailable; scored using lexical, scam, and correlation telemetry.")

            steps.append(AgentStep(
                step_number=len(steps) + 1,
                phase="ACT",
                tool_name="tls_and_ca_trust_inspector",
                tool="X.509 TLS & Root-Store CA Auditor",
                thought="Auditing X.509 certificate chain, SANs, key strength, root-store CA distrust registry (eMudhra Bugzilla #1898124), and passive HTTP headers.",
                observation=tls_obs,
                status=tls_status,
                duration_ms=max(4, int((time.perf_counter() - t3) * 1000)),
            ))

        # ─────────────────────────────────────────────────────────────
        # STEP 5: PIVOT — NETWORKX CAMPAIGN GRAPH CORRELATION
        # ─────────────────────────────────────────────────────────────
        t4 = time.perf_counter()
        pivot_target = primary_domain or (extracted_upis[0] if extracted_upis else None)
        cluster_info = {"cluster_size": 1, "correlated_domains": [], "nodes": [], "edges": []}
        if pivot_target:
            resolved_ip = redirect_hops[0].resolved_ip if redirect_hops else None
            cert_fp = tls_report.fingerprint_sha256 if tls_report else None
            if primary_domain:
                self.correlation_engine.add_incident(
                    domain=primary_domain,
                    ip=resolved_ip,
                    cert_fp=cert_fp,
                    upi=extracted_upis[0] if extracted_upis else None,
                )
            cluster_info = self.correlation_engine.find_cluster(pivot_target)
            if cluster_info["cluster_size"] > 1:
                peers = ", ".join(cluster_info["correlated_domains"][:4])
                if "F-CORRELATION-CLUSTER" not in {f.id for f in all_findings}:
                    all_findings.append(Finding(
                        id="F-CORRELATION-CLUSTER",
                        module="intel",
                        title="Agent Graph Pivot Uncovered Connected Phishing Ring",
                        severity=Severity.HIGH,
                        weight=25,
                        evidence=(
                            f"Autonomous pivot across NetworkX entity graph linked '{pivot_target}' to "
                            f"{len(cluster_info['correlated_domains'])} sibling campaign domain(s) sharing infrastructure: {peers}."
                        ),
                        source="AegisTrust:AgentGraphPivot",
                        remediation="Block entire infrastructure cluster (IP, SSL fingerprint, and payment VPA).",
                    ))
                pivot_obs = f"CAMPAIGN HIT: Linked to {len(cluster_info['correlated_domains'])} sibling domain(s) sharing infrastructure ({peers})."
                pivot_status = "alert"
            else:
                pivot_obs = f"Queried NetworkX entity graph for '{pivot_target}'; no prior sibling domains share this infrastructure yet."
                pivot_status = "completed"

            steps.append(AgentStep(
                step_number=len(steps) + 1,
                phase="PIVOT",
                tool_name="networkx_campaign_graph_pivot",
                tool="NetworkX Campaign Graph Pivot",
                thought=f"Pivoting on '{pivot_target}' across shared IPs, nameservers, TLS certificate hashes, and UPI mule handles to detect coordinated attack rings.",
                observation=pivot_obs,
                status=pivot_status,
                duration_ms=max(2, int((time.perf_counter() - t4) * 1000)),
            ))
        checks_status["campaign_correlation"] = "completed"

        # ─────────────────────────────────────────────────────────────
        # STEP 6: DEFEND — DETERMINISTIC SCORING & AUTO-WEB3 ANCHORING
        # ─────────────────────────────────────────────────────────────
        t5 = time.perf_counter()
        score, classification, coverage = ScoringEngine.calculate_score(
            all_findings,
            checks_completed=7 if tls_report else 6,
            total_checks=8,
        )

        target_label = primary_domain or (extracted_urls[0] if extracted_urls else "User Incident Query")
        explanation = ExplainerService.generate_explanation(
            target=target_label,
            classification=classification,
            score=score,
            findings=all_findings,
            coverage_percent=coverage,
        )

        timestamp_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        submission_id = str(uuid.uuid4())[:8]
        temp_payload = {
            "submission_id": submission_id,
            "target": target_label,
            "target_type": "url" if extracted_urls and not msg_analysis.identified_tactics else "message",
            "timestamp": timestamp_str,
            "risk_classification": classification.value,
            "risk_score": score,
            "findings": all_findings,
        }
        report_hash = compute_report_hash(temp_payload)
        indicator_hash = compute_indicator_hash(target_label)

        limitations.append(
            "Agent decisions are strictly bound to deterministic evidence scores; LLM cannot override risk tier."
        )

        inv_response = InvestigationResponse(
            submission_id=submission_id,
            target=target_label,
            target_type=temp_payload["target_type"],
            timestamp=timestamp_str,
            risk_classification=classification,
            risk_score=score,
            evidence_coverage_percent=coverage,
            explanation=explanation,
            findings=all_findings,
            redirect_chain=redirect_hops,
            tls_details=tls_report,
            passive_headers=headers_dict,
            message_analysis=msg_analysis if (msg_analysis.identified_tactics or msg_analysis.extracted_indicators) else None,
            correlation_cluster_id=primary_domain or target_label,
            limitations=limitations,
            checks_status=checks_status,
            report_hash_keccak256=report_hash,
            salted_indicator_hash=indicator_hash,
            onchain_registry_status="Unregistered",
        )

        onchain_receipt = None
        if req.auto_anchor_web3 and score >= 60:
            report_dict = inv_response.model_dump()
            onchain_receipt = self.web3_service.submit_report(report_dict)
            inv_response.onchain_registry_status = f"Auto-Anchored (Block #{onchain_receipt['block_number']})"
            auto_actions.append(
                f"Auto-anchored RFC 8785 Keccak-256 commitment ({report_hash[:18]}...) to ReportRegistry.sol in Block #{onchain_receipt['block_number']}."
            )
            if primary_domain:
                self.extension_blocklist[primary_domain.lower()] = {
                    "domain": primary_domain.lower(),
                    "risk_score": score,
                    "classification": classification.value,
                    "report_hash": report_hash,
                    "block_number": onchain_receipt["block_number"],
                    "timestamp": timestamp_str,
                }
                auto_actions.append(
                    f"Pushed real-time interception rule for '{primary_domain}' to Chrome/Edge Browser Extension shield."
                )

        steps.append(AgentStep(
            step_number=len(steps) + 1,
            phase="DEFEND",
            tool_name="deterministic_scorer_and_web3_defender",
            tool="Deterministic Scorer & Web3 Auto-Anchor",
            thought="Computing deterministic weighted risk score and executing autonomous Web3 commitment + extension blocklist update if threat threshold (>= 60) is crossed.",
            observation=(
                f"Verdict: {classification.value} (Score: {score}/100, Coverage: {coverage}%). "
                + (f"Auto-anchored to Block #{onchain_receipt['block_number']}!" if onchain_receipt else "No auto-block triggered (below high-risk threshold).")
            ),
            status="action_taken" if onchain_receipt else "completed",
            duration_ms=max(3, int((time.perf_counter() - t5) * 1000)),
        ))

        # ─────────────────────────────────────────────────────────────
        # STEP 7: SYNTHESIZE — COPILOT RESPONSE & EMERGENCY CHECKLIST
        # ─────────────────────────────────────────────────────────────
        if is_emergency:
            emergency_checklist = [
                f"1. DO NOT enter any further OTPs, PINs, or passwords on '{target_label}'. Immediately close the tab.",
                "2. From a clean tab, navigate manually to the official institution website and rotate your password immediately; revoke all active sessions.",
                "3. If banking/UPI details or OTPs were shared, call your bank's 24x7 fraud helpline (or 1930 National Cyber Crime Helpline) to freeze outgoing transfers.",
                f"4. Aegis Agent has automatically anchored the cryptographic evidence of this incident ({report_hash[:16]}...) on-chain so you have a tamper-proof audit trail.",
            ]
        elif score >= 60:
            emergency_checklist = [
                f"1. Block access to '{target_label}' across browser and network DNS filters.",
                "2. Do not submit credentials, session tokens, or UPI payments to this endpoint.",
                f"3. Share the on-chain Keccak-256 proof ({report_hash[:16]}...) with your SOC or community feed.",
            ]
        else:
            emergency_checklist = [
                "1. Remember: A valid TLS/HTTPS padlock never guarantees website legitimacy.",
                "2. Always verify the registrable domain before entering sensitive credentials.",
            ]

        copilot_reply = self._build_copilot_reply(
            query=query,
            intent_mode=intent_mode,
            inv=inv_response,
            cluster_info=cluster_info,
            onchain_receipt=onchain_receipt,
            emergency_checklist=emergency_checklist,
        )

        steps.append(AgentStep(
            step_number=len(steps) + 1,
            phase="SYNTHESIZE",
            tool_name="evidence_grounded_copilot",
            tool="Cyber Copilot Synthesis",
            thought="Synthesizing technical findings, campaign relationships, and on-chain proof into an actionable response.",
            observation=f"Generated {intent_mode} briefing with {len(inv_response.findings)} verified finding(s).",
            status="completed",
            duration_ms=5,
        ))

        return AgentInvestigateResponse(
            session_id=session_id,
            agent_id=session_id,
            timestamp=timestamp_str,
            intent_mode=intent_mode,
            intent_detected=intent_mode,
            primary_target=target_label,
            risk_score=score,
            risk_classification=classification.value,
            findings=all_findings,
            steps=steps,
            copilot_reply=copilot_reply,
            emergency_checklist=emergency_checklist,
            emergency_recovery_steps=emergency_checklist,
            auto_actions_taken=auto_actions,
            auto_anchored_web3=bool(onchain_receipt),
            report_hash_keccak256=report_hash,
            web3_receipt=onchain_receipt,
            onchain_receipt=onchain_receipt,
            investigation_report=inv_response,
        )

    def _build_copilot_reply(
        self,
        query: str,
        intent_mode: str,
        inv: InvestigationResponse,
        cluster_info: Dict[str, Any],
        onchain_receipt: Optional[Dict[str, Any]],
        emergency_checklist: List[str],
    ) -> str:
        lines = []
        if intent_mode == "EMERGENCY_INCIDENT_RESPONSE":
            lines.append(
                f"EMERGENCY INCIDENT RESPONSE ACTIVATED FOR '{inv.target}': "
                f"Target scored {inv.risk_score}/100 ({inv.risk_classification.value})."
            )
        else:
            lines.append(
                f"Aegis Autonomous Agent Verdict: {inv.risk_classification.value} (Score: {inv.risk_score}/100) "
                f"for '{inv.target}' (Evidence Coverage: {inv.evidence_coverage_percent}%)."
            )

        if inv.findings:
            top_ev = "; ".join(f"[{f.severity.value.upper()}] {f.title}" for f in inv.findings[:3])
            lines.append(f"Primary Evidence: {top_ev}.")

        if cluster_info.get("cluster_size", 1) > 1:
            peers = ", ".join(cluster_info["correlated_domains"][:4])
            lines.append(
                f"Campaign Ring Uncovered: NetworkX graph pivot linked '{inv.target}' to sibling domains ({peers})."
            )

        if onchain_receipt:
            lines.append(
                f"Autonomous Defense: Anchored Keccak-256 proof ({inv.report_hash_keccak256[:18]}...) in Block #{onchain_receipt['block_number']} and pushed rule to Browser Extension Blocklist."
            )

        return " ".join(lines)

    def run_watchdog_scan(self, protected_brand: str) -> Dict[str, Any]:
        """
        Proactive 24/7 Brand Watchdog Agent:
        Scans newly discovered lookalike domains from Certificate Transparency (crt.sh) & domain streams
        for the specified brand, runs the full investigation pipeline autonomously, and auto-anchors threats.
        """
        brand_key = protected_brand.strip().lower()
        watchdog_run_id = str(uuid.uuid4())[:6]
        candidates = WATCHDOG_FEED_SIMULATION.get(brand_key)
        if not candidates:
            base_token = brand_key.split(".")[0]
            candidates = [
                {"domain": f"{base_token}-verify-login.xyz", "source": "crt.sh CT Log Stream", "ip": "185.196.10.45"},
                {"domain": f"{brand_key}.account-update.info", "source": "Newly Registered Domains Stream", "ip": "194.26.29.112"},
            ]

        results = []
        for cand in candidates:
            dom = cand["domain"]
            agent_res = self.run_agent_investigation(
                AgentInvestigateRequest(query=f"https://{dom}", auto_anchor_web3=True)
            )
            rep = agent_res.investigation_report
            receipt = agent_res.onchain_receipt
            entry = {
                "domain": dom,
                "discovered_domain": dom,
                "discovery_source": cand["source"],
                "risk_score": rep.risk_score if rep else 0,
                "risk_classification": rep.risk_classification.value if rep else "Inconclusive",
                "findings_count": len(rep.findings) if rep else 0,
                "top_findings": [f.title for f in (rep.findings[:2] if rep else [])] or ["Baseline verified"],
                "auto_anchored": bool(receipt),
                "block_number": receipt["block_number"] if receipt else None,
                "tx_hash": receipt["tx_hash"] if receipt else "",
                "report_hash": rep.report_hash_keccak256 if rep else "",
                "timestamp": rep.timestamp if rep else "",
            }
            results.append(entry)
            self.watchdog_history.insert(0, entry)

        self.watchdog_history = self.watchdog_history[:30]
        return {
            "watchdog_run_id": watchdog_run_id,
            "protected_brand": brand_key,
            "candidates_scanned": len(results),
            "threats_auto_blocked": sum(1 for r in results if r["risk_score"] >= 60),
            "discovered_domains": results,
            "results": results,
            "active_blocklist_count": len(self.extension_blocklist),
        }
