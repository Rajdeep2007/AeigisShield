"""
Explainability Service with Hybrid Gemini LLM + Deterministic Fallback.
Synthesizes verified technical Findings into an understandable, evidence-grounded summary.

Strict Invariants:
1. The explainer summarizes facts; it NEVER alters the risk score or classification.
2. If GEMINI_API_KEY is present, it uses Google Gemini 2.5 Flash for deep contextual analysis.
3. If no API key is set, it falls back to the deterministic offline synthesis engine (zero latency, zero crash risk).
"""

import os
from typing import List, Optional
from app.models.schemas import Finding, RiskClassification, Severity

try:
    from google import genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

class ExplainerService:
    @staticmethod
    def generate_explanation(
        target: str,
        classification: RiskClassification,
        score: int,
        findings: List[Finding],
        coverage_percent: int,
        api_key: Optional[str] = None
    ) -> str:
        """
        Generates an executive-grade natural language explanation based strictly on verified findings.
        Attempts live Gemini API call first; falls back smoothly to deterministic engine.
        """
        gemini_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")

        if gemini_key and HAS_GENAI:
            try:
                return ExplainerService._generate_with_gemini(
                    target, classification, score, findings, coverage_percent, gemini_key
                )
            except Exception:
                # Fall through to deterministic engine on network or auth failure
                pass

        return ExplainerService._generate_deterministic(
            target, classification, score, findings, coverage_percent
        )

    @staticmethod
    def _generate_with_gemini(
        target: str,
        classification: RiskClassification,
        score: int,
        findings: List[Finding],
        coverage_percent: int,
        api_key: str
    ) -> str:
        client = genai.Client(api_key=api_key)

        findings_summary = []
        for f in findings:
            findings_summary.append(f"- [{f.severity.upper()}] {f.title}: {f.evidence} (Source: {f.source})")

        prompt = f"""
You are the senior cybersecurity intelligence analyst for AegisTrust.
Generate a concise, evidence-grounded technical summary of this security investigation.

MANDATORY RULES:
1. The mathematical risk score and classification have ALREADY been computed deterministically.
   - Classification: {classification.value}
   - Score: {score}/100
   - Evidence Coverage: {coverage_percent}%
   You must NOT change or dispute this classification.
2. If TLS is valid, reiterate that HTTPS encryption does NOT prove website authenticity or prevent fraud.
3. Base your analysis SOLELY on the verified findings below. Do not hallucinate external facts.

Target: {target}
Verified Technical Findings:
{chr(10).join(findings_summary) if findings_summary else "No malicious indicators detected."}

Format your response cleanly:
1. Executive Verdict & Assessment
2. Key Threat & Technical Drivers
3. Actionable Security Precautions for the User
"""
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        return response.text.strip()

    @staticmethod
    def _generate_deterministic(
        target: str,
        classification: RiskClassification,
        score: int,
        findings: List[Finding],
        coverage_percent: int
    ) -> str:
        lines = []

        if classification == RiskClassification.CONFIRMED_MALICIOUS:
            lines.append(f"⚠️ **CONFIRMED SECURITY THREAT**: Target '{target}' matches verified malicious records in authoritative cybersecurity feeds or utilizes a compromised Certificate Authority.")
        elif classification == RiskClassification.HIGH_RISK:
            lines.append(f"🚨 **HIGH RISK**: Multiple significant threat indicators (Risk Score: {score}/100) were identified for '{target}'. Interaction is strongly discouraged.")
        elif classification == RiskClassification.SUSPICIOUS:
            lines.append(f"⚠️ **SUSPICIOUS ACTIVITY**: One or more anomalous indicators were identified for '{target}' (Risk Score: {score}/100). Further verification is recommended.")
        elif classification == RiskClassification.LOW_RISK:
            lines.append(f"🛡️ **LOW RISK ASSESSMENT**: No significant malicious indicators were identified across {coverage_percent}% completed checks. (Notice: 'Low Risk' does not guarantee absolute safety; always exercise prudent security hygiene).")
        else:
            lines.append(f"❓ **INCONCLUSIVE**: Insufficient technical telemetry was obtainable for '{target}' to reach a definitive verdict.")

        # Highlight key findings
        critical_and_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        medium_and_low = [f for f in findings if f.severity in (Severity.MEDIUM, Severity.LOW)]
        benign_matches = [f for f in findings if f.severity == Severity.BENIGN]

        if critical_and_high:
            lines.append("\n**Primary Threats Detected:**")
            for f in critical_and_high[:4]:
                lines.append(f"- **{f.title}**: {f.evidence}")

        if medium_and_low and len(critical_and_high) < 3:
            lines.append("\n**Secondary Technical Observations:**")
            for f in medium_and_low[:3]:
                lines.append(f"- {f.title}: {f.evidence}")

        if benign_matches:
            lines.append("\n**Trust Indicators:**")
            for f in benign_matches:
                lines.append(f"- {f.title}: {f.evidence}")

        # Actionable recommendations
        lines.append("\n**Recommended Next Actions:**")
        if classification in (RiskClassification.CONFIRMED_MALICIOUS, RiskClassification.HIGH_RISK):
            lines.append("1. Do not enter credentials, financial information, or passwords.")
            lines.append("2. Avoid downloading files or approving browser notification prompts.")
            lines.append("3. Report this incident to your IT security department or national cyber portal.")
        elif classification == RiskClassification.SUSPICIOUS:
            lines.append("1. Verify the link origin via an independent, established communication channel.")
            lines.append("2. Double-check the exact spelling of the domain name.")
        else:
            lines.append("1. Standard browsing permitted.")
            lines.append("2. Ensure browser and OS security updates remain current.")

        return "\n".join(lines)
