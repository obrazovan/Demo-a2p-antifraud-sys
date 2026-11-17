"""
Unit tests for Scoring Service dynamic risk calculation logic (`evaluate_risk`).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _load_pkg(pkg_name: str, pkg_dir: Path) -> None:
    if pkg_name in sys.modules:
        return
    spec = importlib.util.spec_from_file_location(
        pkg_name,
        pkg_dir / "__init__.py",
        submodule_search_locations=[str(pkg_dir)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[pkg_name] = module
    spec.loader.exec_module(module)


_load_pkg("scoring_src", PROJECT_ROOT / "services" / "scoring" / "src")

from scoring_src.engine import evaluate_risk  # noqa: E402
from scoring_src.schemas import (  # noqa: E402
    ActiveRule,
    MatchedEntity,
    ReputationLookupResult,
    VelocityLookupResult,
    Verdict,
)


def _default_rules() -> list[ActiveRule]:
    return [
        ActiveRule(
            id=1,
            name="High velocity IP (>10 req/min)",
            metric_type="VELOCITY",
            threshold_val=10.0,
            weight=40.0,
            is_active=True,
        ),
        ActiveRule(
            id=2,
            name="High velocity Destination (>30 req/min)",
            metric_type="VELOCITY",
            threshold_val=30.0,
            weight=50.0,
            is_active=True,
        ),
        ActiveRule(
            id=3,
            name="Blacklisted prefix/IP",
            metric_type="REPUTATION",
            threshold_val=0.0,
            weight=100.0,
            is_active=True,
        ),
    ]


def test_clean_traffic_scores_zero_and_allows():
    score, verdict, reasons = evaluate_risk(
        rules=_default_rules(),
        reputation=ReputationLookupResult(is_blacklisted=False, matched_entities=[]),
        velocity=VelocityLookupResult(ip_count_1m=1, phone_count_5m=1),
    )
    assert score == 0.0
    assert verdict == Verdict.ALLOW
    assert reasons == []


@pytest.mark.parametrize(
    ("weight", "expected_verdict"),
    [
        (59.99, Verdict.ALLOW),
        (60.0, Verdict.DENY),
        (60.01, Verdict.DENY),
    ],
)
def test_exact_deny_threshold_boundary(weight: float, expected_verdict: Verdict):
    rules = [
        ActiveRule(
            id=10,
            name="Boundary IP rule",
            metric_type="VELOCITY",
            threshold_val=5.0,
            weight=weight,
            is_active=True,
        )
    ]
    score, verdict, reasons = evaluate_risk(
        rules=rules,
        reputation=ReputationLookupResult(),
        velocity=VelocityLookupResult(ip_count_1m=6, phone_count_5m=1),
    )
    assert score == weight
    assert verdict == expected_verdict
    assert len(reasons) == 1


def test_velocity_threshold_strictly_greater_than():
    # Exactly at threshold (10 and 30) must NOT trigger
    score_at, verdict_at, reasons_at = evaluate_risk(
        rules=_default_rules(),
        reputation=ReputationLookupResult(),
        velocity=VelocityLookupResult(ip_count_1m=10, phone_count_5m=30),
    )
    assert score_at == 0.0
    assert verdict_at == Verdict.ALLOW
    assert reasons_at == []

    # Just above IP threshold -> 40.0 (ALLOW)
    score_ip, verdict_ip, reasons_ip = evaluate_risk(
        rules=_default_rules(),
        reputation=ReputationLookupResult(),
        velocity=VelocityLookupResult(ip_count_1m=11, phone_count_5m=30),
    )
    assert score_ip == 40.0
    assert verdict_ip == Verdict.ALLOW
    assert len(reasons_ip) == 1
    assert "VELOCITY_IP_EXCEEDED" in reasons_ip[0]

    # Above both IP (40.0) and Destination (50.0) -> 90.0 (DENY)
    score_both, verdict_both, reasons_both = evaluate_risk(
        rules=_default_rules(),
        reputation=ReputationLookupResult(),
        velocity=VelocityLookupResult(ip_count_1m=11, phone_count_5m=31),
    )
    assert score_both == 90.0
    assert verdict_both == Verdict.DENY
    assert len(reasons_both) == 2


def test_reputation_and_geo_rules_clamp_to_100():
    rules = _default_rules() + [
        ActiveRule(
            id=4,
            name="High-risk GEO range",
            metric_type="GEO",
            threshold_val=0.0,
            weight=40.0,
            is_active=True,
        )
    ]
    reputation = ReputationLookupResult(
        is_blacklisted=True,
        matched_entities=[
            MatchedEntity(type="IP", value="198.51.100.24", reason="Tor exit node"),
            MatchedEntity(type="MCC_MNC", value="62801", reason="Gabon test range"),
        ],
    )
    score, verdict, reasons = evaluate_risk(
        rules=rules,
        reputation=reputation,
        velocity=VelocityLookupResult(ip_count_1m=20, phone_count_5m=40),
    )
    assert score == 100.0
    assert verdict == Verdict.DENY
    assert any("REPUTATION_BLACKLIST_MATCH: IP 198.51.100.24" in r for r in reasons)
    assert any("GEO_HIGH_RISK_MCC" in r for r in reasons)
    assert any("VELOCITY_IP_EXCEEDED" in r for r in reasons)
    assert any("VELOCITY_PHONE_EXCEEDED" in r for r in reasons)


def test_inactive_rules_are_ignored():
    rules = [
        ActiveRule(
            id=1,
            name="Disabled blacklist rule",
            metric_type="REPUTATION",
            threshold_val=0.0,
            weight=100.0,
            is_active=False,
        )
    ]
    score, verdict, reasons = evaluate_risk(
        rules=rules,
        reputation=ReputationLookupResult(
            is_blacklisted=True,
            matched_entities=[MatchedEntity(type="IP", value="198.51.100.24", reason="Test")],
        ),
        velocity=VelocityLookupResult(ip_count_1m=1, phone_count_5m=1),
    )
    assert score == 0.0
    assert verdict == Verdict.ALLOW
    assert reasons == []
