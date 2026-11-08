"""
SSRF Guard Module.
Protects the platform against Server-Side Request Forgery, internal port scanning,
cloud metadata exfiltration (AWS/GCP/Azure 169.254.169.254), and DNS rebinding attacks.
"""

import ipaddress
import socket
import urllib3
from urllib.parse import urlparse
from typing import Tuple, List, Optional
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BLOCKED_CIDRS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),        # RFC 6598 Carrier-Grade NAT
    ipaddress.ip_network("127.0.0.0/8"),          # Loopback
    ipaddress.ip_network("169.254.0.0/16"),       # AWS/GCP/Azure instance metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
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
    _dns_cache: dict = {}

    @staticmethod
    def validate_url(url: str) -> Tuple[str, str, int, str]:
        """
        Validates URL scheme, port, and pre-resolves DNS to ensure the destination IP
        does not belong to private, loopback, or cloud metadata ranges.

        Returns: (normalized_url, hostname, port, resolved_ip)
        Raises: SSRFViolationError, DNSResolutionError
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
            raise SSRFViolationError(
                f"Prohibited destination port: {port}. Only standard web ports (80, 443, 8080, 8443) allowed."
            )

        # Check for literal IP address in hostname
        try:
            ip_obj = ipaddress.ip_address(hostname)
            SSRFGuard._check_ip_safety(ip_obj)
            return url, hostname, port, str(ip_obj)
        except ValueError:
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
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
            for network in BLOCKED_CIDRS:
                if ip_obj in network:
                    raise SSRFViolationError(
                        f"Access Denied: Target IP {ip_obj} falls within prohibited internal/metadata subnet {network}."
                    )
            raise SSRFViolationError(
                f"Access Denied: Target IP {ip_obj} is a restricted non-public address."
            )
        for network in BLOCKED_CIDRS:
            if ip_obj in network:
                raise SSRFViolationError(
                    f"Access Denied: Target IP {ip_obj} falls within prohibited internal/metadata subnet {network}."
                )

    @staticmethod
    def _resolve_hostname(hostname: str) -> List[str]:
        """Resolves hostname to IPv4 and IPv6 addresses with short in-memory cache and 1.5s hard timeout."""
        host_key = hostname.lower()
        if host_key in SSRFGuard._dns_cache:
            cached = SSRFGuard._dns_cache[host_key]
            if isinstance(cached, Exception):
                raise cached
            return cached

        import threading
        res_box = [None]
        err_box = [None]

        def _lookup():
            try:
                res_box[0] = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except Exception as ex:
                err_box[0] = ex

        t = threading.Thread(target=_lookup, daemon=True)
        t.start()
        t.join(timeout=1.2)

        resolved = []
        try:
            if t.is_alive():
                raise TimeoutError("DNS lookup timed out (1.2s)")
            if err_box[0] is not None:
                raise err_box[0]
            for info in (res_box[0] or []):
                sockaddr = info[4]
                ip_addr = sockaddr[0]
                if ip_addr not in resolved:
                    resolved.append(ip_addr)
            SSRFGuard._dns_cache[host_key] = resolved
        except Exception as e:
            err = DNSResolutionError(f"DNS Resolution Error for {hostname}: {str(e)}")
            SSRFGuard._dns_cache[host_key] = err
            raise err
        return resolved

    @staticmethod
    def safe_request(
        method: str,
        url: str,
        timeout: float = 3.5,
        session: Optional[requests.Session] = None,
        headers: Optional[dict] = None
    ) -> Tuple[requests.Response, str, str, int]:
        """
        Executes an SSRF-validated, non-redirecting HTTP request with DNS-rebinding protection.
        Never executes scripts or downloads large binaries (streams headers only).
        Returns: (response, normalized_url, hostname, resolved_ip)
        """
        normalized_url, hostname, port, resolved_ip = SSRFGuard.validate_url(url)
        sess = session or requests.Session()
        req_headers = {
            "User-Agent": "AegisTrust-Security-Scanner/1.0 (Passive Threat Assessment)",
            "Host": hostname if port in (80, 443) else f"{hostname}:{port}",
        }
        if headers:
            req_headers.update(headers)

        # Pin DNS resolution for this hostname during the socket connection to prevent TOCTOU rebinding
        orig_getaddrinfo = socket.getaddrinfo

        def _pinned_getaddrinfo(host, p, family=0, type=0, proto=0, flags=0):
            if host and host.lower() == hostname.lower():
                ip_obj = ipaddress.ip_address(resolved_ip)
                fam = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
                return [(fam, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (resolved_ip, p or port))]
            return orig_getaddrinfo(host, p, family, type, proto, flags)

        try:
            socket.getaddrinfo = _pinned_getaddrinfo
            resp = sess.request(
                method=method.upper(),
                url=normalized_url,
                headers=req_headers,
                allow_redirects=False,
                timeout=timeout,
                verify=False,
                stream=True,
            )
            return resp, normalized_url, hostname, resolved_ip
        finally:
            socket.getaddrinfo = orig_getaddrinfo
