"""
Deterministic Mathematical Risk Scoring Engine.
Calculates risk purely on objective technical evidence.
Enforces category caps, negative weights for verified benign indicators,
and calculates Evidence Coverage percentage.
Zero LLM interference in verdict classification.
"""

from typing import List, Tuple
from app.models.schemas import Finding, Severity, RiskClassification

# Maximum points allowed from any single category to prevent weak signal stacking
CATEGORY_CAPS = {
    "lexical": 50,
    "tls": 50,
    "intel": 50,
    "scam": 50,
    "headers": 15
}

class ScoringEngine:
    @staticmethod
    def calculate_score(findings: List[Finding], checks_completed: int = 8, total_checks: int = 8) -> Tuple[int, RiskClassification, int]:
        """
        Computes final risk score (0 to 100), risk classification, and evidence coverage percentage.
        Returns: (score, classification, evidence_coverage_percent)
        """
        # Calculate Evidence Coverage
        coverage_percent = int((checks_completed / max(1, total_checks)) * 100)

        # Check for immediate Authoritative Feed Hit or Distrusted CA
        has_critical_hit = any(f.severity == Severity.CRITICAL for f in findings)
        if has_critical_hit:
            return 100, RiskClassification.CONFIRMED_MALICIOUS, coverage_percent

        # Group positive weights by module to apply category caps
        module_positive_weights = {}
        total_negative_weights = 0

        for f in findings:
            if f.weight > 0:
                module_positive_weights[f.module] = module_positive_weights.get(f.module, 0) + f.weight
            elif f.weight < 0:
                total_negative_weights += abs(f.weight)

        # Apply category caps
        total_positive_score = 0
        for mod, score in module_positive_weights.items():
            cap = CATEGORY_CAPS.get(mod, 40)
            total_positive_score += min(score, cap)

        # Compute net score
        net_score = max(0, min(100, total_positive_score - total_negative_weights))

        # Check if coverage is inadequate (< 50%) and no major threat found
        if coverage_percent < 50 and net_score < 40:
            return net_score, RiskClassification.INCONCLUSIVE, coverage_percent

        # Determine Classification
        if net_score >= 60:
            classification = RiskClassification.HIGH_RISK
        elif net_score >= 25:
            classification = RiskClassification.SUSPICIOUS
        else:
            classification = RiskClassification.LOW_RISK

        return net_score, classification, coverage_percent
