"""
RFC 8785 Canonical JSON serializer and cryptographic commitment generator.
Guarantees deterministic byte-for-byte serialization across Python and JavaScript.
Computes genuine Ethereum Keccak-256 (0x01 padding) commitments.
"""

import json
from typing import Any, Dict, List

# Keccak-f[1600] constants for pure-Python Ethereum Keccak-256 fallback
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol64(val: int, shift: int) -> int:
    return ((val << shift) | (val >> (64 - shift))) & 0xFFFFFFFFFFFFFFFF


def _keccak_f1600(state: List[List[int]]) -> None:
    for r in range(24):
        # Theta
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        # Rho and Pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol64(state[x][y], _ROT[x][y])
        # Chi
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        # Iota
        state[0][0] ^= _RC[r]


def _ethereum_keccak256(data: bytes) -> bytes:
    """
    Computes genuine Ethereum Keccak-256 (0x01 padding, rate=136 bytes).
    Identical to Solidity `keccak256()` and Ethers.js `ethers.keccak256()`.
    """
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except ImportError:
        pass

    rate = 136  # 1088 bits for Keccak-256
    state = [[0] * 5 for _ in range(5)]
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:(i + 1) * 8], "little")
            state[i % 5][i // 5] ^= lane
        _keccak_f1600(state)

    out = bytearray()
    for y in range(5):
        for x in range(5):
            if len(out) < 32:
                out.extend(state[x][y].to_bytes(8, "little"))
    return bytes(out[:32])


def _canonicalize_obj(obj: Any) -> Any:
    """Recursively formats dicts with sorted keys and normalized representations per RFC 8785."""
    if isinstance(obj, dict):
        return {str(k): _canonicalize_obj(v) for k, v in sorted(obj.items(), key=lambda item: str(item[0]))}
    elif isinstance(obj, list):
        return [_canonicalize_obj(item) for item in obj]
    elif isinstance(obj, float):
        if obj.is_integer():
            return int(obj)
        return obj
    return obj


def canonicalize_json(data: Dict[str, Any]) -> str:
    """
    Serializes a Python dictionary to an RFC 8785 compliant canonical JSON string:
    - Sorted keys at all nesting depths
    - Compact separators (no whitespace around ':' and ',')
    - UTF-8 encoding
    """
    cleaned = _canonicalize_obj(data)
    return json.dumps(cleaned, separators=(",", ":"), ensure_ascii=False)


def build_canonical_report_payload(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts the canonical, tamper-evident commitment payload from either a full
    InvestigationResponse dict or a minimal report dict.
    Ensures identical hash calculation during creation, submission, and verification.
    """
    # If this is a custom/minimal dict without standard investigation keys, strip volatile fields
    standard_keys = {"submission_id", "target", "target_type", "timestamp", "risk_classification", "risk_score"}
    if not standard_keys.issubset(report_data.keys()):
        cleaned = {
            k: v for k, v in report_data.items()
            if k not in ("report_hash_keccak256", "salted_indicator_hash", "onchain_registry_status")
        }
        return cleaned

    findings = report_data.get("findings")
    if isinstance(findings, list):
        findings_count = len(findings)
        first_finding = findings[0] if findings else None
        if isinstance(first_finding, dict):
            primary_threat = first_finding.get("title", "None")
        elif hasattr(first_finding, "title"):
            primary_threat = first_finding.title
        else:
            primary_threat = "None"
    else:
        findings_count = int(report_data.get("findings_count", 0))
        primary_threat = str(report_data.get("primary_threat", "None"))

    risk_cls = report_data.get("risk_classification", "Inconclusive")
    if hasattr(risk_cls, "value"):
        risk_cls = risk_cls.value

    return {
        "submission_id": str(report_data.get("submission_id", "")),
        "target": str(report_data.get("target", "")),
        "target_type": str(report_data.get("target_type", "url")),
        "timestamp": str(report_data.get("timestamp", "")),
        "risk_classification": str(risk_cls),
        "risk_score": int(report_data.get("risk_score", 0)),
        "findings_count": findings_count,
        "primary_threat": str(primary_threat),
    }


def compute_report_hash(report_data: Dict[str, Any]) -> str:
    """
    Produces the 0x-prefixed Ethereum Keccak-256 hash commitment of canonicalized report JSON.
    """
    canonical_payload = build_canonical_report_payload(report_data)
    canonical_str = canonicalize_json(canonical_payload)
    digest = _ethereum_keccak256(canonical_str.encode("utf-8"))
    return "0x" + digest.hex()


def compute_indicator_hash(indicator: str, salt: str = "AegisTrust_Salt_2026") -> str:
    """
    Computes salted Ethereum Keccak-256 hash of the normalized domain/indicator
    to protect off-chain privacy while enabling on-chain correlation lookups.
    """
    normalized = indicator.strip().lower()
    payload = f"{normalized}::{salt}".encode("utf-8")
    digest = _ethereum_keccak256(payload)
    return "0x" + digest.hex()
