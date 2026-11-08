"""
Module 4: Intelligent Threat Correlation Engine.
Constructs a deterministic entity relationship graph linking domains, IPs,
nameservers, SSL certificate fingerprints, and payment identifiers.
Detects shared infrastructure across seemingly separate phishing campaigns.
"""

import ipaddress
from typing import Dict, Any, List, Optional
import networkx as nx

SHARED_CDN_NETWORKS = [
    # Cloudflare IPv4
    ipaddress.ip_network("104.16.0.0/12"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("131.0.72.0/22"),
    # Fastly
    ipaddress.ip_network("151.101.0.0/16"),
    ipaddress.ip_network("199.232.0.0/16"),
    # GitHub Pages
    ipaddress.ip_network("185.199.108.0/22"),
    # CloudFront
    ipaddress.ip_network("13.32.0.0/15"),
    ipaddress.ip_network("13.224.0.0/14"),
    ipaddress.ip_network("18.64.0.0/14"),
    ipaddress.ip_network("99.84.0.0/15"),
    # IPv6 Cloudflare / Fastly
    ipaddress.ip_network("2606:4700::/32"),
    ipaddress.ip_network("2a04:4e42::/32"),
]


def is_shared_cdn_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in SHARED_CDN_NETWORKS)
    except Exception:
        return False


class CorrelationEngine:
    def __init__(self):
        self.graph = nx.Graph()
        self._seed_known_campaigns()

    def _seed_known_campaigns(self):
        """Pre-populates known infrastructure to demonstrate correlation immediately."""
        # Campaign Alpha: SBI Phishing Cluster
        self.add_incident(
            domain="sbi-kyc-verify-portal.top",
            ip="194.26.29.112",
            nameserver="ns1.offshore-dns.biz",
            cert_fp="3f8a9e01bc442a8b991d",
            upi="sbihelpdesk99@okaxis"
        )
        self.add_incident(
            domain="sbi-rewards-redeem.cc",
            ip="194.26.29.112",
            nameserver="ns1.offshore-dns.biz",
            cert_fp="3f8a9e01bc442a8b991d",
            upi="sbihelpdesk99@okaxis"
        )
        # Campaign Beta: PayPal Lookalike Ring
        self.add_incident(
            domain="paypa1-account-update.xyz",
            ip="185.196.10.45",
            nameserver="ns1.bulletproof-hosting.is",
            cert_fp="8811ca99bb34ef1012ab"
        )
        self.add_incident(
            domain="paypal-security-alert.info",
            ip="185.196.10.45",
            nameserver="ns1.bulletproof-hosting.is",
            cert_fp="8811ca99bb34ef1012ab"
        )
        self.add_incident(
            domain="account-update.info",
            ip="185.196.10.45",
            nameserver="ns1.bulletproof-hosting.is",
            cert_fp="8811ca99bb34ef1012ab"
        )
        # Campaign Gamma: eMudhra Compromised Sub-CA Cluster
        self.add_incident(
            domain="emudhra-compromised-ca.example",
            ip="103.42.19.88",
            nameserver="ns1.rogue-trust-Test.org",
            cert_fp="4a7b51e045a165b452817dc9437cf21a"
        )
        self.add_incident(
            domain="tax-portal-verify-in.org",
            ip="103.42.19.88",
            nameserver="ns1.rogue-trust-test.org",
            cert_fp="4a7b51e045a165b452817dc9437cf21a"
        )

    def add_incident(
        self,
        domain: str,
        ip: Optional[str] = None,
        nameserver: Optional[str] = None,
        cert_fp: Optional[str] = None,
        upi: Optional[str] = None
    ):
        """Adds nodes and connects them in the relationship graph."""
        if not domain:
            return
        domain_clean = domain.strip().lower()
        domain_node = f"domain:{domain_clean}"
        self.graph.add_node(domain_node, label=domain_clean, type="domain")

        if ip and ip != "0.0.0.0":
            is_cdn = is_shared_cdn_ip(ip)
            ip_node = f"ip:{ip}"
            self.graph.add_node(
                ip_node,
                label=f"IP: {ip}" + (" (CDN Multi-Tenant)" if is_cdn else ""),
                type="shared_cdn_ip" if is_cdn else "ip",
                is_cdn=is_cdn
            )
            self.graph.add_edge(domain_node, ip_node, relationship="RESOLVES_TO")

        if nameserver:
            ns_node = f"ns:{nameserver.lower()}"
            self.graph.add_node(ns_node, label=f"NS: {nameserver.lower()}", type="nameserver")
            self.graph.add_edge(domain_node, ns_node, relationship="HOSTED_BY_NS")

        if cert_fp:
            cert_node = f"cert:{cert_fp[:10].lower()}"
            self.graph.add_node(cert_node, label=f"Cert: {cert_fp[:8]}", type="certificate")
            self.graph.add_edge(domain_node, cert_node, relationship="SHARES_CERT")

        if upi:
            upi_node = f"upi:{upi.lower()}"
            self.graph.add_node(upi_node, label=f"UPI: {upi.lower()}", type="payment_handle")
            self.graph.add_edge(domain_node, upi_node, relationship="PAYMENT_DESTINATION")

    def find_cluster(self, domain: str) -> Dict[str, Any]:
        """
        Finds the connected component containing this domain (or UPI/indicator) and returns graph data.
        """
        clean = domain.strip().lower()
        target_node = f"domain:{clean}"
        if target_node not in self.graph:
            # Check if it's a UPI or other node
            for n in self.graph.nodes():
                if clean in n.lower():
                    target_node = n
                    break

        if target_node not in self.graph:
            return {
                "cluster_size": 1,
                "correlated_domains": [],
                "nodes": [{"id": target_node, "label": domain, "type": "domain"}],
                "edges": []
            }

        # Prevent Anycast / Multi-Tenant CDN IPs from bridging unrelated domains
        bridged_graph = self.graph.copy()
        cdn_nodes = [n for n, d in bridged_graph.nodes(data=True) if d.get("is_cdn", False)]
        bridged_graph.remove_nodes_from(cdn_nodes)

        if target_node in bridged_graph:
            component = nx.node_connected_component(bridged_graph, target_node)
            subgraph_nodes = set(component)
            # Re-attach direct neighbors (e.g. the domain's own CDN IP) for visualization
            for neighbor in self.graph.neighbors(target_node):
                subgraph_nodes.add(neighbor)
            subgraph = self.graph.subgraph(subgraph_nodes)
        else:
            direct_nodes = {target_node}
            for neighbor in self.graph.neighbors(target_node):
                direct_nodes.add(neighbor)
            subgraph = self.graph.subgraph(direct_nodes)

        nodes = []
        for n in subgraph.nodes():
            attrs = subgraph.nodes[n]
            nodes.append({
                "id": n,
                "label": attrs.get("label", n),
                "type": attrs.get("type", "unknown")
            })

        edges = []
        for u, v in subgraph.edges():
            rel = subgraph.edges[u, v].get("relationship", "CONNECTED")
            edges.append({
                "source": u,
                "target": v,
                "relationship": rel
            })

        correlated_domains = [
            subgraph.nodes[n]["label"]
            for n in subgraph.nodes()
            if subgraph.nodes[n].get("type") == "domain" and subgraph.nodes[n]["label"].lower() != clean
        ]

        return {
            "cluster_size": len(correlated_domains) + 1,
            "correlated_domains": correlated_domains,
            "nodes": nodes,
            "edges": edges
        }
