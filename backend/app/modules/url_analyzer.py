"""
Module 1: URL, Domain & Lexical Threat Analyzer.
Detects:
- Typosquatting (Levenshtein distance <= 2 and visual character substitutions like 1->l, 0->o, rn->m)
- Homoglyphs, Punycode IDN decoding, and mixed Cyrillic/Latin confusable substitutions
- Brand-in-subdomain spoofing (e.g., paypal.com.attacker.xyz)
- Suspicious URL structures, embedded credentials (@), and redirect parameters
- Dangerous keywords (login, kyc, otp, verify, refund) in untrusted domains
- Threat intelligence matches (URLhaus / OpenPhish)
"""

import json
import os
from urllib.parse import urlparse, parse_qs
from typing import List, Tuple, Dict, Any, Optional
from dataclasses import dataclass

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

from app.models.schemas import Finding, Severity

CONFUSABLES_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ӏ': 'l', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ο': 'o', 'α': 'a'
}

LEET_SUBSTITUTIONS = str.maketrans({'1': 'l', '0': 'o', '3': 'e', '5': 's', '4': 'a'})

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "kyc", "otp", "password",
    "account", "update", "secure", "banking", "authenticate", "wallet",
    "refund", "cashback", "tax-refund", "billing", "invoice", "claim",
    "support", "service", "suspended", "unblock", "security"
]

RISKY_TLDS = {
    "xyz", "top", "cc", "tk", "ml", "ga", "cf", "gq", "buzz", "work",
    "icu", "monster", "rest", "surf", "fit", "live", "club", "shop"
}

TRUSTED_INSTITUTIONAL_SUFFIXES = {
    "gov.in", "nic.in", "ac.in", "edu", "gov", "gov.uk", "ac.uk", "mil"
}

MULTI_PART_SLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "gov.in", "nic.in", "ac.in", "co.in",
    "org.in", "net.in", "com.au", "edu.au", "gov.au", "co.jp", "com.br", "com.sg"
}

REDIRECT_PARAMS = {"url", "redirect", "next", "dest", "target", "r", "to", "link", "goto", "continue"}


@dataclass
class _ExtractedDomain:
    subdomain: str
    domain: str
    suffix: str


def _fallback_extract(hostname: str) -> _ExtractedDomain:
    host = hostname.strip(".").lower()
    if not host:
        return _ExtractedDomain("", "", "")
    parts = host.split(".")
    if len(parts) == 1:
        return _ExtractedDomain("", parts[0], "")
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in MULTI_PART_SLDS:
        if len(parts) == 2:
            return _ExtractedDomain("", parts[0], parts[1])
        suffix = last_two
        domain = parts[-3]
        subdomain = ".".join(parts[:-3])
        return _ExtractedDomain(subdomain, domain, suffix)
    suffix = parts[-1]
    domain = parts[-2]
    subdomain = ".".join(parts[:-2])
    return _ExtractedDomain(subdomain, domain, suffix)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class URLAnalyzer:
    def __init__(self, data_dir: Optional[str] = None):
        if data_dir is None:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

        self.top_brands = self._load_json(os.path.join(data_dir, "top_brands.json")).get("brands", [])
        self.intel_snapshot = self._load_json(os.path.join(data_dir, "threat_intel_snapshot.json")).get("entries", [])
        self.extractor = tldextract.TLDExtract( suffix_list_urls=() ) if HAS_TLDEXTRACT else _fallback_extract

    def _load_json(self, path: str) -> Dict[str, Any]:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def analyze(self, raw_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        """
        Runs comprehensive lexical and domain security analysis.
        Returns: (findings_list, parsed_metadata)
        """
        findings: List[Finding] = []

        # 1. URL Normalization
        normalized_url = raw_url.strip()
        if not normalized_url.startswith(("http://", "https://")):
            normalized_url = "https://" + normalized_url

        parsed = urlparse(normalized_url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        query = parsed.query

        # Decode Punycode labels if present to inspect underlying Unicode characters
        decoded_hostname = hostname
        if "xn--" in hostname:
            try:
                decoded_hostname = hostname.encode("ascii").decode("idna")
            except Exception:
                decoded_hostname = hostname

        extracted = self.extractor(hostname)
        subdomain = extracted.subdomain.lower()
        domain_name = extracted.domain.lower()
        suffix = extracted.suffix.lower()
        registered_domain = f"{domain_name}.{suffix}" if suffix else domain_name

        meta = {
            "normalized_url": normalized_url,
            "hostname": hostname,
            "decoded_hostname": decoded_hostname,
            "subdomain": subdomain,
            "registered_domain": registered_domain,
            "tld": suffix,
            "path": path,
            "has_query": bool(query)
        }

        # 2. Check Threat Intelligence Feeds
        for entry in self.intel_snapshot:
            if (entry.get("domain") and entry["domain"] == registered_domain) or \
               (entry.get("url") and entry["url"] == normalized_url):
                findings.append(Finding(
                    id="F-INTEL-MATCH",
                    module="intel",
                    title="Known Threat Feed Intelligence Hit",
                    severity=Severity.CRITICAL,
                    weight=50,
                    evidence=f"Target URL/Domain matches verified active threat report from {entry.get('reporter', 'OpenPhish/URLhaus')}. Classification: {entry.get('threat')}.",
                    source=f"ThreatIntel:{entry.get('reporter')}",
                    remediation="Immediately block this domain and isolate any host that initiated connection."
                ))

        # 3. Check for Benign Giant Exact Matches & Institutional TLDs (False-Positive Protection)
        exact_brand_match = False
        for brand in self.top_brands:
            if registered_domain == brand["domain"].lower():
                exact_brand_match = True
                findings.append(Finding(
                    id="F-BENIGN-BRAND-MATCH",
                    module="lexical",
                    title="Verified Legitimate Registrable Domain",
                    severity=Severity.BENIGN,
                    weight=-35,
                    evidence=f"Target domain '{registered_domain}' exactly matches official verified domain for {brand['name']}.",
                    source="AegisTrust:VerifiedBrandRegistry",
                    remediation="None required; official domain infrastructure."
                ))
                break

        if not exact_brand_match and (
            registered_domain in TRUSTED_INSTITUTIONAL_SUFFIXES
            or suffix in TRUSTED_INSTITUTIONAL_SUFFIXES
            or any(registered_domain.endswith(f".{inst}") for inst in TRUSTED_INSTITUTIONAL_SUFFIXES)
        ):
            exact_brand_match = True
            findings.append(Finding(
                id="F-BENIGN-INSTITUTIONAL-TLD",
                module="lexical",
                title="Verified Government / Academic Institutional Domain",
                severity=Severity.BENIGN,
                weight=-30,
                evidence=f"Target '{registered_domain}' utilizes a restricted institutional registry TLD ('.{suffix}').",
                source="AegisTrust:InstitutionalRegistry",
                remediation="Standard institutional domain verification passed."
            ))

        # 4. Check for Brand-in-Subdomain Impersonation
        if not exact_brand_match and subdomain:
            for brand in self.top_brands:
                brand_domain = brand["domain"].lower()
                brand_keyword = brand["keywords"][0].lower()
                if brand_domain in subdomain or f"{brand_keyword}." in subdomain or f"-{brand_keyword}" in subdomain or subdomain == brand_keyword:
                    findings.append(Finding(
                        id="F-BRAND-SUBDOMAIN",
                        module="lexical",
                        title="Brand Impersonation in Subdomain",
                        severity=Severity.HIGH,
                        weight=35,
                        evidence=f"Subdomain '{subdomain}' references brand '{brand['name']}', while the actual registrable domain is '{registered_domain}'. This is a classic phishing deception technique.",
                        source="AegisTrust:SubdomainInspector",
                        remediation="Do not enter credentials. Attacker controls the host while mimicking the trusted brand."
                    ))
                    break

        # 5. Check for Typosquatting & Brand-Combo Spoofing on Registrable Domain
        if not exact_brand_match:
            tokens = list(set([domain_name] + domain_name.split("-")))
            for brand in self.top_brands:
                found_typo = False
                for kw in brand.get("keywords", []):
                    target_word = kw.lower()
                    for token in tokens:
                        if token == target_word and domain_name != target_word:
                            # Brand name combined with hyphenated pretext in untrusted registrable domain (e.g. paypal-security-alert.info, onlinesbi-kyc-update.com)
                            findings.append(Finding(
                                id="F-BRAND-COMBO-SPOOF",
                                module="lexical",
                                title="Protected Brand Name Embedded in Untrusted Domain",
                                severity=Severity.HIGH,
                                weight=35,
                                evidence=f"Registrable domain '{registered_domain}' embeds protected brand token '{target_word}' ({brand['name']}) alongside pretext words outside official '{brand['domain']}'.",
                                source="AegisTrust:BrandComboAnalyzer",
                                remediation=f"Do not trust compound domains mimicking '{brand['domain']}'."
                            ))
                            found_typo = True
                            break

                        dist = levenshtein_distance(token, target_word)
                        de_leeted = token.translate(LEET_SUBSTITUTIONS).replace("rn", "m")
                        is_leet_match = (de_leeted == target_word and token != target_word)
                        if is_leet_match or (dist in (1, 2) and abs(len(token) - len(target_word)) <= 2 and len(target_word) >= 4):
                            effective_dist = 1 if is_leet_match else dist
                            findings.append(Finding(
                                id="F-TYPOSQUAT",
                                module="lexical",
                                title="Potential Brand Typosquatting Detected",
                                severity=Severity.HIGH if effective_dist == 1 else Severity.MEDIUM,
                                weight=35 if effective_dist == 1 else 20,
                                evidence=f"Domain token '{token}' in '{domain_name}' has an edit distance of {effective_dist} from targeted brand '{brand['name']}' ({target_word}).",
                                source="AegisTrust:LevenshteinAnalyzer",
                                remediation=f"Verify if you intended to visit official '{brand['domain']}' instead of this lookalike."
                            ))
                            found_typo = True
                            break
                    if found_typo:
                        break
                if found_typo:
                    break

        # 6. Check for Homoglyph / Confusable Script Attacks
        has_homoglyphs = False
        confusable_replacements = []
        for char in decoded_hostname:
            if char in CONFUSABLES_MAP:
                has_homoglyphs = True
                confusable_replacements.append(f"'{char}' (looks like '{CONFUSABLES_MAP[char]}')")

        if has_homoglyphs:
            findings.append(Finding(
                id="F-HOMOGLYPH",
                module="lexical",
                title="Deceptive Homoglyph / Confusable Characters Detected",
                severity=Severity.HIGH,
                weight=35,
                evidence=f"Hostname contains non-Latin confusable characters designed to visually mimic legitimate letters: {', '.join(confusable_replacements[:4])}.",
                source="AegisTrust:UnicodeConfusableMatrix",
                remediation="High risk of visual spoofing. Avoid trusting URL display strings."
            ))

        # Check for Punycode IDN
        if "xn--" in hostname:
            findings.append(Finding(
                id="F-PUNYCODE-IDN",
                module="lexical",
                title="Internationalized Domain Name (Punycode) in Use",
                severity=Severity.MEDIUM,
                weight=20,
                evidence=f"Hostname utilizes Punycode ('xn--') encoding: {hostname} (decoded: {decoded_hostname}). Often used in IDN homograph spoofing.",
                source="AegisTrust:IDNParser",
                remediation="Ensure browser resolves and displays the true underlying script before trusting."
            ))

        # 7. Check for Embedded Credentials (@ symbol)
        if "@" in raw_url:
            findings.append(Finding(
                id="F-EMBEDDED-CRED",
                module="lexical",
                title="Embedded Userinfo Credentials in URL (@)",
                severity=Severity.HIGH,
                weight=25,
                evidence="URL contains '@' symbol preceding host. This syntax can mislead users into thinking the text prior to '@' is the destination host.",
                source="AegisTrust:RFC3986Parser",
                remediation="Never navigate to URLs with userinfo tricks."
            ))

        # 8. Check for Embedded Open Redirect Parameters
        if query:
            qs = parse_qs(query)
            for param in REDIRECT_PARAMS:
                if param in qs:
                    target_val = qs[param][0]
                    if target_val.startswith(("http://", "https://", "//")):
                        findings.append(Finding(
                            id="F-EMBEDDED-REDIRECT",
                            module="lexical",
                            title="Embedded Destination Redirect Parameter Detected",
                            severity=Severity.MEDIUM,
                            weight=15,
                            evidence=f"URL contains open redirect parameter '{param}={target_val}'. Often abused to bounce users to unvetted landing pages.",
                            source="AegisTrust:QueryInspector",
                            remediation="Inspect final landing URL carefully before interacting."
                        ))
                        break

        # 9. Suspicious Keyword Density in Non-Brand Domains
        if not exact_brand_match:
            matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in hostname or kw in path]
            if len(matched_keywords) >= 2:
                findings.append(Finding(
                    id="F-KEYWORD-CLUSTER",
                    module="lexical",
                    title="High-Risk Authentication Keyword Cluster",
                    severity=Severity.MEDIUM,
                    weight=20,
                    evidence=f"Domain/path contains multiple sensitive transaction keywords: {', '.join(matched_keywords[:4])} outside an authoritative domain.",
                    source="AegisTrust:LexicalPatternMatcher",
                    remediation="Confirm organizational identity directly before providing personal or financial details."
                ))
            elif len(matched_keywords) == 1:
                findings.append(Finding(
                    id="F-KEYWORD-SINGLE",
                    module="lexical",
                    title="Sensitive Pretext Keyword Present in URL",
                    severity=Severity.LOW,
                    weight=10,
                    evidence=f"URL contains authentication/security keyword: '{matched_keywords[0]}'.",
                    source="AegisTrust:LexicalPatternMatcher",
                    remediation="Verify context of request."
                ))

        # 10. Check Risky TLDs
        if suffix in RISKY_TLDS and not exact_brand_match:
            findings.append(Finding(
                id="F-RISKY-TLD",
                module="lexical",
                title="Domain Registered on High-Abuse Top-Level Domain",
                severity=Severity.LOW,
                weight=10,
                evidence=f"The domain uses the '.{suffix}' TLD, which exhibits high prevalence in automated spam and disposable phishing campaigns.",
                source="AegisTrust:TLDReputationTable",
                remediation="Evaluate other technical indicators in combination."
            ))

        # 11. Structural Anomaly: Excessive Hyphens
        if hostname.count("-") >= 3 and not exact_brand_match:
            findings.append(Finding(
                id="F-EXCESSIVE-HYPHENS",
                module="lexical",
                title="Suspicious Domain Structure: Excessive Hyphenation",
                severity=Severity.LOW,
                weight=5,
                evidence=f"Hostname contains {hostname.count('-')} hyphens, a pattern common in automated typosquat generation.",
                source="AegisTrust:DomainEntropyInspector",
                remediation="Check organization legitimacy."
            ))

        return findings, meta
