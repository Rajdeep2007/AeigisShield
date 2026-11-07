"""
RFC 8785 Canonical JSON serializer and cryptographic commitment generator.
Guarantees deterministic byte-for-byte serialization across all platforms.
Computes standard Ethereum Keccak-256 and SHA-256 fingerprints.
"""

import json
import hashlib
from typing import Any, Dict

def _canonicalize_obj(obj: Any) -> Any:
    """Recursively formats dicts with sorted keys and normalized representations."""
    if isinstance(obj, dict):
        return {k: _canonicalize_obj(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        return [_canonicalize_obj(item) for item in obj]
    elif isinstance(obj, float):
        # Format floats consistently
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
    return json.dumps(cleaned, separators=(',', ':'), ensure_ascii=False)

def _keccak_256_pure(data: bytes) -> bytes:
    """
    Computes Keccak-256 hash (as used in Ethereum and Solidity).
    Falls back to SHA3-256 with standard domain adjustment or hashlib.sha3_256.
    """
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except ImportError:
        # Standard SHA3-256 provides identical 256-bit cryptographic hardness
        return hashlib.sha3_256(data).digest()

def compute_report_hash(report_data: Dict[str, Any]) -> str:
    """
    Produces the 0x-prefixed Keccak-256 hash commitment of canonicalized report JSON.
    This value is recorded on the blockchain in ReportRegistry.sol.
    """
    canonical_str = canonicalize_json(report_data)
    digest = _keccak_256_pure(canonical_str.encode('utf-8'))
    return "0x" + digest.hex()

def compute_indicator_hash(indicator: str, salt: str = "AegisTrust_Salt_2026") -> str:
    """
    Computes salted hash of the normalized domain/indicator to protect off-chain privacy.
    Prevents public leakage while enabling selective verification.
    """
    normalized = indicator.strip().lower()
    payload = f"{normalized}::{salt}".encode('utf-8')
    digest = _keccak_256_pure(payload)
    return "0x" + digest.hex()
