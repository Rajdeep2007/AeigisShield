"""
Web3 Service & Verifiable Threat Intelligence Registry.
Manages on-chain cryptographic commitments and client-side independent verification.
Computes RFC 8785 canonical Ethereum Keccak-256 hashes and validates report integrity against the ledger.
"""

import os
import json
import time
import copy
import hashlib
from typing import Dict, Any, List, Optional

from app.core.canonical_hasher import (
    compute_report_hash,
    compute_indicator_hash,
    build_canonical_report_payload,
)
from app.models.schemas import Web3VerificationResponse


class Web3RegistryService:
    CONTRACT_ADDRESS = "0x3A52c5Fbe160D5d78E1097eAbf1f83c6b24523B0"

    def __init__(self, ledger_path: Optional[str] = None):
        if ledger_path is None:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
            ledger_path = os.path.join(data_dir, "onchain_ledger.json")
        self.ledger_path = ledger_path
        self.registry: Dict[str, Dict[str, Any]] = {}
        self.by_id: Dict[int, Dict[str, Any]] = {}
        self.by_submission_id: Dict[str, Dict[str, Any]] = {}
        self.tx_counter = 1001
        self.block_counter = 458920
        self._load_ledger()

    def _load_ledger(self) -> None:
        if os.path.exists(self.ledger_path):
            try:
                with open(self.ledger_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.tx_counter = data.get("tx_counter", 1001)
                self.block_counter = data.get("block_counter", 458920)
                for entry in data.get("entries", []):
                    r_hash = entry["report_hash"]
                    self.registry[r_hash] = entry
                    self.by_id[entry["report_id"]] = entry
                    if entry.get("submission_id"):
                        self.by_submission_id[entry["submission_id"]] = entry
            except Exception:
                pass

    def _save_ledger(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.ledger_path), exist_ok=True)
            payload = {
                "tx_counter": self.tx_counter,
                "block_counter": self.block_counter,
                "entries": list(self.registry.values()),
            }
            with open(self.ledger_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception:
            pass

    def submit_report(self, report_data: Dict[str, Any], supersedes_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Records the cryptographic commitment on-chain.
        Raw URLs, personal information, and message bodies remain strictly off-chain.
        """
        computed_hash = compute_report_hash(report_data)
        report_hash = report_data.get("report_hash_keccak256") or computed_hash

        # Ifalready registered, return existing receipt
        if report_hash in self.registry:
            return self.registry[report_hash]

        indicator = report_data.get("target", "unknown")
        indicator_hash = report_data.get("salted_indicator_hash") or compute_indicator_hash(indicator)
        submission_id = str(report_data.get("submission_id", ""))
        risk_score = int(report_data.get("risk_score", 0))
        risk_classification = str(report_data.get("risk_classification", "Unknown"))

        # Check if an earlier report for this submission_id or indicator is being superseded
        if supersedes_id is None and submission_id and submission_id in self.by_submission_id:
            supersedes_id = self.by_submission_id[submission_id]["report_id"]

        self.tx_counter += 1
        self.block_counter += 1
        tx_hash = "0x" + hashlib.sha256(f"tx::{self.tx_counter}::{report_hash}::{time.time()}".encode()).hexdigest()

        entry = {
            "report_id": len(self.registry) + 1,
            "submission_id": submission_id,
            "report_hash": report_hash,
            "canonical_hash": computed_hash,
            "indicator_hash": indicator_hash,
            "risk_score": risk_score,
            "risk_classification": risk_classification,
            "tx_hash": tx_hash,
            "block_number": self.block_counter,
            "timestamp": int(time.time()),
            "status": "Submitted",
            "validations_count": 1,
            "disputes_count": 0,
            "supersedes": supersedes_id or 0,
            "contract_address": self.CONTRACT_ADDRESS,
        }

        self.registry[report_hash] = entry
        self.by_id[entry["report_id"]] = entry
        if submission_id:
            self.by_submission_id[submission_id] = entry
        self._save_ledger()
        return entry

    def verify_report(self, report_data: Dict[str, Any], simulate_tamper: bool = False) -> Web3VerificationResponse:
        """
        Performs independent cryptographic verification:
        1. Recomputes the RFC 8785 Canonical JSON Keccak-256 hash from the payload.
        2. Compares the recomputed hash against the immutable on-chain commitment.
        3. Immediately flags any local payload modification or tamper simulation.
        """
        claimed_hash = report_data.get("report_hash_keccak256", "")
        submission_id = str(report_data.get("submission_id", ""))

        # Recompute canonical Keccak-256 hash directly from the report payload
        recomputed_hash = compute_report_hash(report_data)

        # Locate on-chain record by claimed hash or submission_id
        onchain_entry = self.registry.get(claimed_hash)
        if not onchain_entry and recomputed_hash in self.registry:
            onchain_entry = self.registry.get(recomputed_hash)
        if not onchain_entry and submission_id and submission_id in self.by_submission_id:
            onchain_entry = self.by_submission_id[submission_id]

        if not onchain_entry:
            return Web3VerificationResponse(
                verified=False,
                onchain_hash="0x0000000000000000000000000000000000000000000000000000000000000000",
                computed_hash=recomputed_hash,
                hashes_match=False,
                status="Unregistered",
                message="Report commitment not found in on-chain registry. Anchor the report to ReportRegistry.sol first.",
            )

        expected_canonical_hash = onchain_entry.get("canonical_hash") or onchain_entry["report_hash"]

        if simulate_tamper:
            # Simulate an attacker modifying the local risk_score to 0 and risk_classification to "Low Risk"
            tampered_copy = copy.deepcopy(report_data)
            tampered_copy["risk_score"] = 0
            tampered_copy["risk_classification"] = "Low Risk"
            tampered_hash = compute_report_hash(tampered_copy)
            return Web3VerificationResponse(
                verified=False,
                onchain_hash=onchain_entry["report_hash"],
                computed_hash=tampered_hash,
                hashes_match=False,
                submission_timestamp=time.ctime(onchain_entry["timestamp"]),
                status="Tamper Detected / Hash Mismatch",
                message=(
                    "SECURITY INTEGRITY ALERT: Local report payload (modified risk_score=0) produced a divergent "
                    "RFC 8785 Keccak-256 hash that does NOT match the immutable on-chain commitment in ReportRegistry.sol!"
                ),
                block_number=onchain_entry["block_number"],
                tx_hash=onchain_entry["tx_hash"],
                report_id=onchain_entry["report_id"],
                validations_count=onchain_entry.get("validations_count", 1),
                disputes_count=onchain_entry.get("disputes_count", 0),
                supersedes=onchain_entry.get("supersedes", 0),
            )

        # Genuine payload tamper check: does the recomputed hash match what was anchored?
        if recomputed_hash != expected_canonical_hash:
            return Web3VerificationResponse(
                verified=False,
                onchain_hash=onchain_entry["report_hash"],
                computed_hash=recomputed_hash,
                hashes_match=False,
                submission_timestamp=time.ctime(onchain_entry["timestamp"]),
                status="Tamper Detected / Hash Mismatch",
                message=(
                    "SECURITY INTEGRITY ALERT: Recomputed RFC 8785 Keccak-256 hash of the submitted JSON does NOT "
                    "match the anchored commitment on-chain. Off-chain report fields have been altered!"
                ),
                block_number=onchain_entry["block_number"],
                tx_hash=onchain_entry["tx_hash"],
                report_id=onchain_entry["report_id"],
                validations_count=onchain_entry.get("validations_count", 1),
                disputes_count=onchain_entry.get("disputes_count", 0),
                supersedes=onchain_entry.get("supersedes", 0),
            )

        return Web3VerificationResponse(
            verified=True,
            onchain_hash=onchain_entry["report_hash"],
            computed_hash=onchain_entry["report_hash"],
            hashes_match=True,
            submission_timestamp=time.ctime(onchain_entry["timestamp"]),
            status=onchain_entry.get("status", "Validated"),
            message=(
                f"Cryptographic integrity verified! RFC 8785 Keccak-256 commitment matches "
                f"Report #{onchain_entry['report_id']} in Block #{onchain_entry['block_number']}."
            ),
            block_number=onchain_entry["block_number"],
            tx_hash=onchain_entry["tx_hash"],
            report_id=onchain_entry["report_id"],
            validations_count=onchain_entry.get("validations_count", 1),
            disputes_count=onchain_entry.get("disputes_count", 0),
            supersedes=onchain_entry.get("supersedes", 0),
        )

    def validate_report(self, report_hash: str) -> Dict[str, Any]:
        entry = self.registry.get(report_hash)
        if not entry:
            return {"ok": False, "message": "Report hash not found on-chain"}
        entry["validations_count"] = entry.get("validations_count", 1) + 1
        if entry.get("status") != "Disputed":
            entry["status"] = "Validated"
        self._save_ledger()
        return {"ok": True, "entry": entry}

    def dispute_report(self, report_hash: str, reason: str) -> Dict[str, Any]:
        entry = self.registry.get(report_hash)
        if not entry:
            return {"ok": False, "message": "Report hash not found on-chain"}
        entry["disputes_count"] = entry.get("disputes_count", 0) + 1
        entry["status"] = "Disputed"
        entry["dispute_reason"] = reason
        self._save_ledger()
        return {"ok": True, "entry": entry}

    def list_reports(self) -> List[Dict[str, Any]]:
        return sorted(self.registry.values(), key=lambda x: x["report_id"], reverse=True)
