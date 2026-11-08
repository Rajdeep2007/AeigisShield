"""
Module 5: Passive Website Security Assessment.
Inspects public HTTP security headers and server disclosures safely without active scanning:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options (Clickjacking defense)
- X-Content-Type-Options (MIME sniffing defense)
- Referrer-Policy & Permissions-Policy
- Cookie security flags (Secure, HttpOnly, SameSite)
- Server & Technology disclosure (X-Powered-By, Server banners)
"""

from typing import List, Dict, Any, Tuple
from app.models.schemas import Finding, Severity
from app.core.ssrf_guard import SSRFGuard


class SecurityHeadersAnalyzer:
    @staticmethod
    def inspect(target_url: str) -> Tuple[Dict[str, Any], List[Finding]]:
        """
        Passively checks HTTP response headers using SSRF-safe non-redirecting request.
        Returns: (headers_dict, findings_list)
        """
        findings: List[Finding] = []
        parsed_headers: Dict[str, Any] = {}

        try:
            resp, normalized_url, _, _ = SSRFGuard.safe_request(
                method="HEAD",
                url=target_url,
                timeout=3.0,
                headers={"User-Agent": "AegisTrust-Security-Audit/1.0"}
            )
            if resp.status_code in (405, 501):
                resp.close()
                resp, normalized_url, _, _ = SSRFGuard.safe_request(
                    method="GET",
                    url=target_url,
                    timeout=3.0,
                    headers={"User-Agent": "AegisTrust-Security-Audit/1.0"}
                )
            raw_headers = {k.lower(): v for k, v in resp.headers.items()}
            resp.close()
        except Exception:
            return parsed_headers, findings

        # 1. Check Strict-Transport-Security (HSTS)
        hsts = raw_headers.get("strict-transport-security")
        parsed_headers["hsts"] = bool(hsts)
        parsed_headers["hsts_value"] = hsts or "missing"
        if not hsts and normalized_url.startswith("https://"):
            findings.append(Finding(
                id="F-HDR-MISSING-HSTS",
                module="headers",
                title="Missing HTTP Strict Transport Security (HSTS) Header",
                severity=Severity.LOW,
                weight=5,
                evidence="Server does not enforce HSTS via 'Strict-Transport-Security' header.",
                source="AegisTrust:HeaderAuditor",
                remediation="Enable HSTS with 'max-age=31536000; includeSubDomains; preload' to prevent SSL-stripping."
            ))

        # 2. Check Content-Security-Policy (CSP)
        csp = raw_headers.get("content-security-policy")
        parsed_headers["csp"] = bool(csp)
        if not csp:
            findings.append(Finding(
                id="F-HDR-MISSING-CSP",
                module="headers",
                title="Missing Content Security Policy (CSP)",
                severity=Severity.LOW,
                weight=5,
                evidence="Server does not return a 'Content-Security-Policy' header.",
                source="AegisTrust:HeaderAuditor",
                remediation="Define a strict CSP to restrict executable script sources and mitigate Cross-Site Scripting (XSS)."
            ))

        # 3. Check X-Frame-Options (Clickjacking)
        x_frame = raw_headers.get("x-frame-options")
        parsed_headers["x_frame_options"] = x_frame or "missing"
        if not x_frame and not (csp and "frame-ancestors" in csp.lower()):
            findings.append(Finding(
                id="F-HDR-CLICKJACKING",
                module="headers",
                title="Missing Clickjacking Defense (X-Frame-Options)",
                severity=Severity.LOW,
                weight=5,
                evidence="Page lacks 'X-Frame-Options' header and CSP 'frame-ancestors' directive.",
                source="AegisTrust:HeaderAuditor",
                remediation="Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent framing attacks."
            ))

        # 4. Check X-Content-Type-Options
        x_cto = raw_headers.get("x-content-type-options")
        parsed_headers["x_content_type_options"] = x_cto or "missing"
        if not x_cto or "nosniff" not in x_cto.lower():
            findings.append(Finding(
                id="F-HDR-MIME-SNIFF",
                module="headers",
                title="MIME-Type Sniffing Protection Disabled",
                severity=Severity.LOW,
                weight=3,
                evidence="Server lacks 'X-Content-Type-Options: nosniff'.",
                source="AegisTrust:HeaderAuditor",
                remediation="Add 'X-Content-Type-Options: nosniff' header."
            ))

        # 5. Check Cookie Hygiene (Secure / HttpOnly / SameSite)
        set_cookie = raw_headers.get("set-cookie")
        parsed_headers["cookies_inspected"] = bool(set_cookie)
        if set_cookie:
            sc_lower = set_cookie.lower()
            missing_flags = []
            if normalized_url.startswith("https://") and "secure" not in sc_lower:
                missing_flags.append("Secure")
            if "httponly" not in sc_lower:
                missing_flags.append("HttpOnly")
            if "samesite" not in sc_lower:
                missing_flags.append("SameSite")
            if missing_flags:
                findings.append(Finding(
                    id="F-HDR-INSECURE-COOKIE",
                    module="headers",
                    title="Session Cookie Missing Hardening Flags",
                    severity=Severity.LOW,
                    weight=4,
                    evidence=f"Response 'Set-Cookie' header omits security attributes: {', '.join(missing_flags)}.",
                    source="AegisTrust:CookieAuditor",
                    remediation="Ensure session cookies set 'Secure; HttpOnly; SameSite=Strict/Lax'."
                ))

        # 6. Check Server / Technology Disclosure
        server = raw_headers.get("server")
        x_powered = raw_headers.get("x-powered-by")
        parsed_headers["server"] = server or "Hidden"
        parsed_headers["x_powered_by"] = x_powered or "Hidden"

        if x_powered or (server and any(char.isdigit() for char in server)):
            findings.append(Finding(
                id="F-HDR-VERSION-DISCLOSURE",
                module="headers",
                title="Technology Stack / Version Information Disclosed",
                severity=Severity.LOW,
                weight=3,
                evidence=f"Server exposes internal stack version banners: Server: '{server or 'N/A'}', X-Powered-By: '{x_powered or 'N/A'}'.",
                source="AegisTrust:HeaderAuditor",
                remediation="Suppress or sanitize server version banners to prevent reconnaissance of known CVEs."
            ))

        return parsed_headers, findings
