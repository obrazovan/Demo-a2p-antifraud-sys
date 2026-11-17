"""
Automated validation tests for Lab 3 Docker optimization and Kubernetes manifests.
Verifies:
  - .dockerignore presence and multi-stage non-root Dockerfiles across all 7 services
  - Namespace, ConfigMap (zero localhost URLs), and base64-encoded Secret
  - Deployments for all 6 business microservices + API Gateway with replicas,
    containerPort, resource requests/limits, livenessProbe (/health),
    readinessProbe (/ready), and non-root securityContext
  - Matching Kubernetes Services (ClusterIP / NodePort) with aligned label selectors
  - Kustomization resource integrity
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
K8S_DIR = PROJECT_ROOT / "k8s"

APP_SERVICES: dict[str, int] = {
    "service-rule-engine": 8001,
    "service-reputation": 8002,
    "service-velocity": 8003,
    "service-scoring": 8004,
    "service-analytics": 8005,
    "service-alerting": 8006,
    "antifraud-gateway": 8080,
}

SERVICE_DIRS: list[Path] = [
    PROJECT_ROOT / "gateway",
    PROJECT_ROOT / "services" / "rule-engine",
    PROJECT_ROOT / "services" / "reputation",
    PROJECT_ROOT / "services" / "velocity",
    PROJECT_ROOT / "services" / "scoring",
    PROJECT_ROOT / "services" / "analytics",
    PROJECT_ROOT / "services" / "alerting",
]


def _load_all_k8s_documents() -> list[dict[str, Any]]:
    kustomization = yaml.safe_load((K8S_DIR / "kustomization.yaml").read_text(encoding="utf-8"))
    docs: list[dict[str, Any]] = []
    for rel_path in kustomization["resources"]:
        manifest_path = K8S_DIR / rel_path
        assert manifest_path.exists(), f"Missing manifest referenced in kustomization.yaml: {rel_path}"
        for doc in yaml.safe_load_all(manifest_path.read_text(encoding="utf-8")):
            if doc is not None:
                docs.append(doc)
    return docs


def test_dockerfiles_and_dockerignore_best_practices():
    """All 7 services and root must have .dockerignore, multi-stage builds, and non-root USER."""
    assert (PROJECT_ROOT / ".dockerignore").exists()

    for svc_dir in SERVICE_DIRS:
        dockerfile = svc_dir / "Dockerfile"
        dockerignore = svc_dir / ".dockerignore"
        assert dockerfile.exists(), f"Missing Dockerfile in {svc_dir}"
        assert dockerignore.exists(), f"Missing .dockerignore in {svc_dir}"

        content = dockerfile.read_text(encoding="utf-8")
        assert "AS builder" in content, f"{dockerfile} must use multi-stage builder"
        assert "AS runner" in content, f"{dockerfile} must use multi-stage runner"
        assert "USER appuser" in content, f"{dockerfile} must run as non-root appuser"


def test_k8s_namespace_configmap_and_secret():
    """Verifies Namespace, ConfigMap (no localhost URLs), and base64-encoded Secret."""
    docs = _load_all_k8s_documents()

    namespaces = [d for d in docs if d.get("kind") == "Namespace"]
    assert any(ns["metadata"]["name"] == "antifraud" for ns in namespaces)

    configmaps = {
        d["metadata"]["name"]: d
        for d in docs
        if d.get("kind") == "ConfigMap"
    }
    assert "antifraud-config" in configmaps
    cfg_data = configmaps["antifraud-config"]["data"]

    for key, val in cfg_data.items():
        if key.endswith("_URL"):
            assert "localhost" not in val, f"ConfigMap {key} must use K8s DNS, not localhost"
            assert "127.0.0.1" not in val, f"ConfigMap {key} must use K8s DNS, not 127.0.0.1"

    secrets = {
        d["metadata"]["name"]: d
        for d in docs
        if d.get("kind") == "Secret"
    }
    assert "antifraud-secrets" in secrets
    secret_data = secrets["antifraud-secrets"]["data"]
    for key, b64_val in secret_data.items():
        decoded = base64.b64decode(b64_val).decode("utf-8")
        assert len(decoded) > 0, f"Secret key {key} decoded to empty string"


def test_k8s_microservices_deployments_probes_and_resources():
    """Every microservice Deployment must define replicas, probes (/health, /ready), and resource limits."""
    docs = _load_all_k8s_documents()
    deployments = {
        d["metadata"]["name"]: d
        for d in docs
        if d.get("kind") == "Deployment"
    }

    for svc_name, expected_port in APP_SERVICES.items():
        assert svc_name in deployments, f"Missing Deployment for {svc_name}"
        dep = deployments[svc_name]
        assert dep["metadata"]["namespace"] == "antifraud"
        assert dep["spec"]["replicas"] >= 1

        pod_spec = dep["spec"]["template"]["spec"]
        assert pod_spec["securityContext"]["runAsNonRoot"] is True
        assert pod_spec["securityContext"]["runAsUser"] == 1001

        container = pod_spec["containers"][0]
        ports = [p["containerPort"] for p in container["ports"]]
        assert expected_port in ports

        # Resource requests and limits
        resources = container["resources"]
        assert "cpu" in resources["requests"] and "memory" in resources["requests"]
        assert "cpu" in resources["limits"] and "memory" in resources["limits"]

        # Liveness (/health) and Readiness (/ready) probes
        liveness = container["livenessProbe"]["httpGet"]
        readiness = container["readinessProbe"]["httpGet"]
        assert liveness["path"] == "/health" and liveness["port"] == expected_port
        assert readiness["path"] == "/ready" and readiness["port"] == expected_port


def test_k8s_services_align_with_deployments():
    """Every microservice must have a K8s Service with matching selector and port."""
    docs = _load_all_k8s_documents()
    deployments = {
        d["metadata"]["name"]: d
        for d in docs
        if d.get("kind") == "Deployment"
    }
    services = {
        d["metadata"]["name"]: d
        for d in docs
        if d.get("kind") == "Service"
    }

    for svc_name, expected_port in APP_SERVICES.items():
        assert svc_name in services, f"Missing Service for {svc_name}"
        svc = services[svc_name]
        dep = deployments[svc_name]

        selector = svc["spec"]["selector"]
        template_labels = dep["spec"]["template"]["metadata"]["labels"]
        for k, v in selector.items():
            assert template_labels.get(k) == v

        svc_port = svc["spec"]["ports"][0]
        assert svc_port["port"] == expected_port
        assert svc_port["targetPort"] == expected_port

    # Gateway must be exposed via NodePort
    assert services["antifraud-gateway"]["spec"]["type"] == "NodePort"
