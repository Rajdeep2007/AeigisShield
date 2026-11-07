"""
Module 1b: Safe Redirect Chain Tracer.
Safely traces HTTP redirect chains step-by-step (max 5 hops) without executing scripts.
Re-checks SSRF rules on every single hop.
Detects cross-domain jumps, URL shortener expansions, and HTTPS-to-HTTP security downgrades.
"""

from urllib.parse import urlparse, urljoin
from typing import List, Tuple
import requests

from app.core.ssrf_guard import SSRFGuard, SSRFViolationError, DNSResolutionError
from app.models.schemas import RedirectHop, Finding, Severity

MAX_HOPS = 5
REQUEST_TIMEOUT = 3.5  # seconds

class RedirectTracer:
    @staticmethod
    def trace(initial_url: str) -> Tuple[List[RedirectHop], List[Finding]]:
        """
        Traces redirect hops safely.
        Returns: (hops_list, findings_list)
        """
        hops: List[RedirectHop] = []
        findings: List[Finding] = []
        current_url = initial_url

        session = requests.Session()
        session.headers.update({
            "User-Agent": "AegisTrust-Security-Scanner/1.0 (Passive Threat Assessment; +https://aegistrust.org/bot)"
        })

        for hop_idx in range(1, MAX_HOPS + 1):
            try:
                # 1. SSRF Validation before making connection
                normalized_url, hostname, port, resolved_ip = SSRFGuard.validate_url(current_url)
            except SSRFViolationError as e:
                findings.append(Finding(
                    id="F-REDIRECT-SSRF-BLOCKED",
                    module="lexical",
                    title="Prohibited SSRF Redirect Destination Blocked",
                    severity=Severity.CRITICAL,
                    weight=50,
                    evidence=f"Redirect chain attempted to pivot to restricted infrastructure on hop {hop_idx}: {str(e)}",
                    source="AegisTrust:SSRFGuard",
                    remediation="High malicious intent. Target attempted internal network scan or metadata access."
                ))
                break
            except DNSResolutionError as e:
                findings.append(Finding(
                    id="F-DNS-NXDOMAIN",
                    module="lexical",
                    title="Domain Not Resolvable via Public DNS (NXDOMAIN)",
                    severity=Severity.MEDIUM,
                    weight=10,
                    evidence=f"Domain failed DNS address lookup: {str(e)}. May be inactive, disposable, or synthetic.",
                    source="AegisTrust:DNSResolver",
                    remediation="Confirm if domain is currently registered and active."
                ))
                break
            except Exception as e:
                # DNS failure or network timeout on target
                break

            # 2. Perform non-redirecting HEAD or GET request
            try:
                # Connect with verify=False for passive observation so we can inspect bad SSL
                response = session.head(
                    normalized_url,
                    allow_redirects=False,
                    timeout=REQUEST_TIMEOUT,
                    verify=False
                )
                if response.status_code in (405, 501):  # Method Not Allowed for HEAD
                    response = session.get(
                        normalized_url,
                        allow_redirects=False,
                        timeout=REQUEST_TIMEOUT,
                        stream=True,
                        verify=False
                    )
            except Exception:
                # Network unreachable, timeout, or SSL handshake abort
                hops.append(RedirectHop(
                    hop=hop_idx,
                    url=current_url,
                    status_code=0,
                    resolved_ip=resolved_ip,
                    is_cross_domain=False,
                    is_downgrade=False
                ))
                break

            prev_parsed = urlparse(current_url)
            hops.append(RedirectHop(
                hop=hop_idx,
                url=current_url,
                status_code=response.status_code,
                resolved_ip=resolved_ip,
                is_cross_domain=False,
                is_downgrade=False
            ))

            # Check if this response indicates a redirect
            if response.status_code in (301, 302, 303, 307, 308) and "Location" in response.headers:
                next_url = response.headers["Location"]
                # Resolve relative redirects
                next_url = urljoin(current_url, next_url)
                next_parsed = urlparse(next_url)

                # Check cross-domain jump
                is_cross = prev_parsed.hostname != next_parsed.hostname
                # Check HTTPS -> HTTP downgrade
                is_downgrade = prev_parsed.scheme == "https" and next_parsed.scheme == "http"

                hops[-1].is_cross_domain = is_cross
                hops[-1].is_downgrade = is_downgrade

                if is_downgrade:
                    findings.append(Finding(
                        id="F-TLS-DOWNGRADE-REDIRECT",
                        module="tls",
                        title="Insecure Transport Downgrade in Redirect Chain",
                        severity=Severity.HIGH,
                        weight=30,
                        evidence=f"Hop {hop_idx} redirected from secure HTTPS ({prev_parsed.hostname}) to unencrypted HTTP ({next_parsed.hostname}).",
                        source="AegisTrust:RedirectTracer",
                        remediation="Severe security risk. Data transmitted over HTTP can be intercepted by network eavesdroppers."
                    ))

                if is_cross and hop_idx == 1 and any(short in prev_parsed.hostname for short in ["bit.ly", "tinyurl", "t.co", "is.gd"]):
                    findings.append(Finding(
                        id="F-SHORTENER-EXPANSION",
                        module="lexical",
                        title="URL Shortener Masking Final Destination",
                        severity=Severity.MEDIUM,
                        weight=10,
                        evidence=f"Link shortener '{prev_parsed.hostname}' expanded to target destination '{next_parsed.hostname}'.",
                        source="AegisTrust:RedirectTracer",
                        remediation="Examine the true destination host rather than trusting the short link."
                    ))

                current_url = next_url
            else:
                # Reached terminal destination
                break

        # Check for excessive redirects
        if len(hops) >= 4:
            findings.append(Finding(
                id="F-EXCESSIVE-REDIRECTS",
                module="lexical",
                title="Suspicious Multi-Hop Redirect Chain Detected",
                severity=Severity.MEDIUM,
                weight=15,
                evidence=f"Target traversed {len(hops)} consecutive redirect hops. Attackers frequently use long chains to evade automated sandbox crawlers.",
                source="AegisTrust:RedirectTracer",
                remediation="Exercise caution; complex redirect obfuscation detected."
            ))

        return hops, findings
