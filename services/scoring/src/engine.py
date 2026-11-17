"""
Pure dynamic risk scoring engine.
Aggregates active rule weights against Reputation and Velocity signals
and evaluates ALLOW / DENY decisions.
"""

from __future__ import annotations

from typing import Sequence

from .schemas import (
    ActiveRule,
    ReputationLookupResult,
    VelocityLookupResult,
    Verdict,
)


def evaluate_risk(
    rules: Sequence[ActiveRule],
    reputation: ReputationLookupResult,
    velocity: VelocityLookupResult,
    deny_threshold: float = 60.0,
) -> tuple[float, Verdict, list[str]]:
    """
    Computes dynamic risk score in range [0.0, 100.0] from active rules and signals.
    Decision rule: risk_score >= deny_threshold (default 60.0) -> DENY, else -> ALLOW.
    """
    raw_score = 0.0
    reasons: list[str] = []

    for rule in rules:
        if not rule.is_active:
            continue

        metric = rule.metric_type.upper()

        if metric == "VELOCITY":
            name_lower = rule.name.lower()
            if any(token in name_lower for token in ("phone", "destination", "dest")):
                if velocity.phone_count_5m > rule.threshold_val:
                    raw_score += rule.weight
                    reasons.append(
                        f"VELOCITY_PHONE_EXCEEDED: {rule.name} "
                        f"(count={velocity.phone_count_5m} > {rule.threshold_val:g})"
                    )
            elif "ip" in name_lower:
                if velocity.ip_count_1m > rule.threshold_val:
                    raw_score += rule.weight
                    reasons.append(
                        f"VELOCITY_IP_EXCEEDED: {rule.name} "
                        f"(count={velocity.ip_count_1m} > {rule.threshold_val:g})"
                    )
            else:
                peak_count = max(velocity.ip_count_1m, velocity.phone_count_5m)
                if peak_count > rule.threshold_val:
                    raw_score += rule.weight
                    reasons.append(
                        f"VELOCITY_LIMIT_EXCEEDED: {rule.name} "
                        f"(count={peak_count} > {rule.threshold_val:g})"
                    )

        elif metric == "REPUTATION":
            if reputation.is_blacklisted:
                raw_score += rule.weight
                if reputation.matched_entities:
                    for match in reputation.matched_entities:
                        reasons.append(
                            f"REPUTATION_BLACKLIST_MATCH: {match.type} {match.value} ({match.reason})"
                        )
                else:
                    reasons.append(f"REPUTATION_BLACKLIST_MATCH: {rule.name}")

        elif metric == "GEO":
            geo_matches = [
                match
                for match in reputation.matched_entities
                if match.type.upper() == "MCC_MNC"
            ]
            if geo_matches:
                raw_score += rule.weight
                for match in geo_matches:
                    reasons.append(
                        f"GEO_HIGH_RISK_MCC: {rule.name} ({match.value}: {match.reason})"
                    )

    # Deduplicate reasons while preserving original ordering
    unique_reasons = list(dict.fromkeys(reasons))

    # Clamp aggregate risk score to [0.0, 100.0]
    risk_score = round(min(100.0, max(0.0, raw_score)), 2)
    verdict = Verdict.DENY if risk_score >= deny_threshold else Verdict.ALLOW

    return risk_score, verdict, unique_reasons
