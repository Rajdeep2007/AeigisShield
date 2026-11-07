"""
SSRF Guard Module.
Protects the platform against Server-Side Request Forgery, internal port scanning,
cloud metadata exfiltration (AWS/GCP/Azure 169.254.169.254), and DNS rebinding attacks.
"""

import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, List

BLOCKED_CIDRS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),       # AWS/GCP/Azure instance metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),          # Multicast
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),              # Loopback
    ipaddress.ip_network("fc00::/7"),             # Unique local
    ipaddress.ip_network("fe80::/10"),            # Link-local
    ipaddress.ip_network("ff00::/8"),             # Multicast
]

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 8080, 8443}

class SSRFViolationError(Exception):
    """Raised when an inspected URL targets internal or restricted infrastructure."""
    pass

class DNSResolutionError(Exception):
    """Raised when a domain name cannot be resolved in public DNS."""
    pass

class SSRFGuard:
    @staticmethod
    def validate_url(url: str) -> Tuple[str, str, int, str]:
        """
        Validates URL scheme, port, and pre-resolves DNS to ensure the destination IP
        does not belong to private, loopback, or cloud metadata ranges.

        Returns: (normalized_url, hostname, port, resolved_ip)
        Raises: SSRFViolationError
        """
        if not url:
            raise SSRFViolationError("Empty URL provided")

        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            raise SSRFViolationError(f"Prohibited URL scheme: '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

        hostname = parsed.hostname
        if not hostname:
            raise SSRFViolationError("Invalid URL: missing hostname")

        # Determine target port
        port = parsed.port
        if port is None:
            port = 443 if scheme == "https" else 80

        if port not in ALLOWED_PORTS:
            raise SSRFViolationError(f"Prohibited destination port: {port}. Only standard web ports (80, 443, 8080, 8443) allowed.")

        # Check for literal IP address in hostname
        try:
            ip_obj = ipaddress.ip_address(hostname)
            SSRFGuard._check_ip_safety(ip_obj)
            return url, hostname, port, str(ip_obj)
        except ValueError:
            # Hostname is a domain name, proceed to DNS resolution
            pass

        # Resolve DNS addresses
        resolved_ips = SSRFGuard._resolve_hostname(hostname)
        if not resolved_ips:
            raise SSRFViolationError(f"Failed to resolve DNS for hostname '{hostname}'")

        # Ensure all resolved IPs are safe
        for ip_str in resolved_ips:
            ip_obj = ipaddress.ip_address(ip_str)
            SSRFGuard._check_ip_safety(ip_obj)

        return url, hostname, port, resolved_ips[0]

    @staticmethod
    def _check_ip_safety(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        """Verifies an IP address does not match any blocked private or link-local CIDR."""
        for network in BLOCKED_CIDRS:
            if ip_obj in network:
                raise SSRFViolationError(
                    f"Access Denied: Target IP {ip_obj} falls within prohibited internal/metadata subnet {network}."
                )

    @staticmethod
    def _resolve_hostname(hostname: str) -> List[str]:
        """Resolves hostname to IPv4 and IPv6 addresses."""
        resolved = []
        try:
            # socket.getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
            infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for info in infos:
                sockaddr = info[4]
                ip_addr = sockaddr[0]
                if ip_addr not in resolved:
                    resolved.append(ip_addr)
        except socket.gaierror as e:
            raise DNSResolutionError(f"DNS Resolution Error for {hostname}: {str(e)}")
        return resolved
