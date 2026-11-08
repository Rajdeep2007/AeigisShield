"""
Module 4: Intelligent Threat Correlation Engine.
Constructs a deterministic entity relationship graph linking domains, IPs,
nameservers, SSL certificate fingerprints, and payment identifiers.
Detects shared infrastructure across seemingly separate phishing campaigns.
"""

from typing import Dict, Any, List, Optional
import networkx as nx


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
            ip_node = f"ip:{ip}"
            self.graph.add_node(ip_node, label=f"IP: {ip}", type="ip")
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

        component = nx.node_connected_component(self.graph, target_node)
        subgraph = self.graph.subgraph(component)

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
