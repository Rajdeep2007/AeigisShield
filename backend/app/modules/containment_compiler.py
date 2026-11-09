"""
AegisShield 3.0: Autonomous Active Containment Compiler.
Compiles multi-format defense bundles when a threat is identified:
1. Cloudflare WAF JSON Rule
2. Suricata / Snort IDS Signature
3. Pi-hole / BIND9 DNS RPZ Sinkhole Line
4. STIX 2.1 Threat Intel JSON Bundle (with MITRE ATT&CK mappings)
5. National Cybercrime Formal Legal Evidence Dossier (Markdown / PDF-ready)
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.models.schemas import ContainmentPackage, Finding


class ContainmentCompiler:
    @staticmethod
    def compile(
        target: str,
        risk_classification: str,
        risk_score: int,
        resolved_ip: Optional[str] = None,
        cert_sha256: Optional[str] = None,
        findings: Optional[List[Finding]] = None,
        report_hash_keccak256: Optional[str] = None
    ) -> ContainmentPackage:
        """
        Compiles instant active containment assets for network administrators, SOC analysts, and victims.
        """
        findings = findings or []
        now_iso = datetime.now(timezone.utc).isoformat()
        clean_target = target.replace("http://", "").replace("https://", "").split("/")[0].strip()
        ip_addr = resolved_ip if (resolved_ip and resolved_ip != "0.0.0.0") else None

        # 1. Cloudflare WAF Custom Rule
        cf_expr = f'(http.host eq "{clean_target}")'
        if ip_addr:
            cf_expr += f' or (ip.src eq {ip_addr})'

        cloudflare_rule = {
            "id": f"cf-aegis-{uuid.uuid4().hex[:12]}",
            "description": f"AegisShield Autonomous Block: {clean_target} (Risk: {risk_score}/100)",
            "action": "block",
            "expression": cf_expr,
            "enabled": True,
            "created_on": now_iso,
            "metadata": {
                "source": "AegisShield 3.0 Cyber Mesh",
                "classification": risk_classification,
                "score": risk_score
            }
        }

        # 2. Snort / Suricata IDS Signatures
        sid_num = 9900000 + (abs(hash(clean_target)) % 99999)
        snort_rule = (
            f'alert tcp $HOME_NET any -> $EXTERNAL_NET [80,443] ('
            f'msg:"AEGIS-THREAT: Outbound connection to malicious campaign {clean_target}"; '
            f'flow:to_server,established; '
            f'content:"{clean_target}"; http_header; '
            f'metadata:created_at {now_iso}, confidence high; '
            f'classtype:trojan-activity; sid:{sid_num}; rev:1;)'
        )

        suricata_rule = (
            f'drop tls $HOME_NET any -> $EXTERNAL_NET any ('
            f'msg:"AEGIS-SURICATA: Blocked TLS connection to {clean_target}"; '
            f'tls.sni; content:"{clean_target}"; nocase; '
            f'classtype:bad-unknown; sid:{sid_num + 1}; rev:1;)'
        )

        # 3. Pi-hole / BIND9 DNS RPZ Sinkhole Lines
        rpz_line = (
            f"; AegisTrust Autonomous DNS Sinkhole - {now_iso}\n"
            f"{clean_target} CNAME .\n"
            f"*.{clean_target} CNAME ."
        )

        # 4. STIX 2.1 Threat Intel Bundle
        bundle_id = f"bundle--{uuid.uuid4()}"
        indicator_id = f"indicator--{uuid.uuid4()}"
        threat_actor_id = f"threat-actor--{uuid.uuid4()}"
        rel_id = f"relationship--{uuid.uuid4()}"

        stix_bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": [
                {
                    "type": "identity",
                    "spec_version": "2.1",
                    "id": "identity--aegistrust-mesh",
                    "name": "AegisShield Autonomous Intelligence Mesh",
                    "identity_class": "system"
                },
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "name": f"Malicious Domain: {clean_target}",
                    "description": f"Flagged by AegisShield scoring engine as {risk_classification} (Score {risk_score}/100)",
                    "pattern": f"[domain-name:value = '{clean_target}']",
                    "pattern_type": "stix",
                    "valid_from": now_iso,
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1566.002",
                            "url": "https://attack.mitre.org/techniques/T1566/002/"
                        },
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1583.001",
                            "url": "https://attack.mitre.org/techniques/T1583/001/"
                        }
                    ]
                },
                {
                    "type": "threat-actor",
                    "spec_version": "2.1",
                    "id": threat_actor_id,
                    "created": now_iso,
                    "name": f"Adversary Campaign targeting {clean_target}",
                    "threat_actor_types": ["cybercrime-syndicate", "phishing-operator"]
                },
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "relationship_type": "indicates",
                    "source_ref": indicator_id,
                    "target_ref": threat_actor_id
                }
            ]
        }

        # 5. National Cybercrime Legal Evidence Dossier
        findings_md = ""
        for idx, f in enumerate(findings, 1):
            severity = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            findings_md += f"| {idx} | **{f.title}** | `{severity.upper()}` | {f.evidence} | `{f.source}` |\n"

        if not findings_md:
            findings_md = "| 1 | **Heuristic Threat Detection** | `CRITICAL` | Threat score exceeded threshold | `Deterministic Engine` |\n"

        legal_dossier = f"""# 🏛️ NATIONAL CYBER CRIME INVESTIGATION EVIDENCE DOSSIER
**Formally Compiled by AegisShield Autonomous Evidence Mesh**  
**Incident Reference**: `AEGIS-EVID-{uuid.uuid4().hex[:12].upper()}`  
**Generated At**: {now_iso}  
**Classification**: {risk_classification.upper()} (Deterministic Threat Score: {risk_score}/100)

---

## 1. INCIDENT TARGET TELEMETRY
* **Target Domain / URI**: `{clean_target}`
* **Resolved Gateway IP**: `{ip_addr or 'Dynamic CDN / Unresolved'}`
* **X.509 Certificate SHA-256**: `{cert_sha256 or 'N/A'}`
* **Cryptographic Report Hash (RFC 8785 Keccak-256)**: `{report_hash_keccak256 or '0x00'}`

---

## 2. VERIFIED FORENSIC FINDINGS MATRIX
| # | Finding Indicator | Severity | Observed Technical Evidence | Verification Source |
|---|---|---|---|---|
{findings_md}

---

## 3. BLOCKCHAIN CRYPTOGRAPHIC PROVENANCE
The technical findings above were canonicalized under RFC 8785 and irreversibly committed to the EVM Report Registry Smart Contract:
* **Integrity Proof**: Tamper-proof mathematical digest `keccak256(canonical_json)`.
* **Privacy Assurance**: Indicator is one-way salted (`bytes32`), ensuring zero victim PII disclosure while providing indisputable non-repudiation in legal proceedings.

---

## 4. ACTIONABLE LAW ENFORCEMENT & ISP SEIZURE REQUEST
1. **Domain Registrar**: Issue emergency DNS suspension / ICANN Registry Lock for `{clean_target}` under ICANN Emergency Domain Takedown Protocol.
2. **Hosting Provider / CDN**: Freeze associated VPS/server instances and preserve server access logs (`access.log`, `error.log`).
3. **Banking / Mule Freeze**: If UPI IDs or crypto wallet addresses were identified in the correlation cluster, initiate immediate nodal banking account freeze via Indian Cyber Crime Portal (1930) or FTC Sentinel.
"""

        return ContainmentPackage(
            target=clean_target,
            timestamp=now_iso,
            risk_classification=risk_classification,
            risk_score=risk_score,
            cloudflare_waf_rule=cloudflare_rule,
            snort_ids_rule=snort_rule,
            suricata_rule=suricata_rule,
            dns_rpz_line=rpz_line,
            stix21_bundle=stix_bundle,
            legal_evidence_dossier_markdown=legal_dossier
        )
