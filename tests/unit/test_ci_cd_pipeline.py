"""
Automated validation tests for the GitHub Actions Production CI/CD pipeline.
Verifies YAML syntax, workflow triggers, permissions, all 5 pipeline stages,
and full 7-microservice Docker build matrix coverage.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
WORKFLOW_PATH = PROJECT_ROOT / ".github" / "workflows" / "ci-cd.yml"

EXPECTED_SERVICES = {
    "antifraud-gateway": "gateway/Dockerfile",
    "service-rule-engine": "services/rule-engine/Dockerfile",
    "service-reputation": "services/reputation/Dockerfile",
    "service-velocity": "services/velocity/Dockerfile",
    "service-scoring": "services/scoring/Dockerfile",
    "service-analytics": "services/analytics/Dockerfile",
    "service-alerting": "services/alerting/Dockerfile",
}


def _load_workflow() -> dict[str, Any]:
    assert WORKFLOW_PATH.exists(), f"Missing CI/CD workflow file: {WORKFLOW_PATH}"
    data = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_ci_cd_workflow_triggers_and_permissions() -> None:
    wf = _load_workflow()
    # PyYAML parses top-level `on:` as boolean True in YAML 1.1
    triggers = wf.get("on") or wf.get(True)
    assert isinstance(triggers, dict), "Workflow must define trigger events"
    assert "push" in triggers, "Workflow must trigger on push"
    assert "pull_request" in triggers, "Workflow must trigger on pull_request"
    assert "workflow_dispatch" in triggers, "Workflow must support manual dispatch"

    perms = wf.get("permissions", {})
    assert perms.get("contents") == "read"
    assert perms.get("packages") == "write"


def test_ci_cd_workflow_has_all_five_production_stages() -> None:
    wf = _load_workflow()
    jobs = wf.get("jobs", {})
    expected_jobs = {
        "lint-and-security",
        "unit-and-integration-tests",
        "validate-kubernetes",
        "build-and-scan-images",
        "deploy-production",
    }
    assert expected_jobs.issubset(set(jobs.keys())), f"Missing jobs: {expected_jobs - set(jobs.keys())}"

    # Verify dependency DAG: build waits for quality gates; deploy waits for build
    build_needs = set(jobs["build-and-scan-images"].get("needs", []))
    assert build_needs == {
        "lint-and-security",
        "unit-and-integration-tests",
        "validate-kubernetes",
    }
    deploy_needs = set(jobs["deploy-production"].get("needs", []))
    assert deploy_needs == {"build-and-scan-images"}


def test_ci_cd_docker_matrix_covers_all_seven_microservices() -> None:
    wf = _load_workflow()
    matrix_entries = wf["jobs"]["build-and-scan-images"]["strategy"]["matrix"]["include"]
    actual_map = {item["service"]: item["dockerfile"] for item in matrix_entries}
    assert actual_map == EXPECTED_SERVICES

    for dockerfile_rel in actual_map.values():
        assert (PROJECT_ROOT / dockerfile_rel).exists(), f"Referenced Dockerfile not found: {dockerfile_rel}"
