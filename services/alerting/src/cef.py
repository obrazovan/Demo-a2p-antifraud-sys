"""
Common Event Format (CEF:0) alert builder and severity evaluation logic.
"""

from __future__ import annotations

from .config import settings
from .schemas import AlertSeverity, IncomingInspectionEvent

CEF_VENDOR = "AntifraudPlatform"
CEF_PRODUCT = "A2PSecurityGuard"
CEF_VERSION = "1.0"


def _escape_cef_header(value: str) -> str:
    """Escapes backslashes and pipes in CEF header fields."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _escape_cef_extension(value: str) -> str:
    """Escapes backslashes, equals signs, and newlines in CEF extension values."""
    return (
        value.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def should_trigger_alert(
    event: IncomingInspectionEvent,
    critical_threshold: float = settings.CRITICAL_RISK_THRESHOLD,
) -> bool:
    """Returns True if verdict is DENY or risk_score >= 80.0."""
    return event.verdict.upper() == "DENY" or event.risk_score >= critical_threshold


def classify_severity(
    event: IncomingInspectionEvent,
    critical_threshold: float = settings.CRITICAL_RISK_THRESHOLD,
) -> tuple[AlertSeverity, int]:
    """
    Maps an inspection event to (AlertSeverity, CEF numeric severity 0..10).
    - risk_score >= 80.0 -> CRITICAL (CEF severity 9, ERROR log)
    - verdict == DENY (< 80.0) -> HIGH (CEF severity 7, WARNING log)
    """
    if event.risk_score >= critical_threshold:
        return AlertSeverity.CRITICAL, 9
    return AlertSeverity.HIGH, 7


def format_cef_alert(
    event: IncomingInspectionEvent,
    critical_threshold: float = settings.CRITICAL_RISK_THRESHOLD,
) -> tuple[AlertSeverity, str]:
    """
    Builds a standards-compliant CEF:0 security alert line.
    Format:
      CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
    """
    severity_enum, cef_sev_num = classify_severity(event, critical_threshold=critical_threshold)

    if severity_enum == AlertSeverity.CRITICAL:
        signature_id = "AF-CRIT-001"
        event_name = "Critical SMS Fraud Risk Detected"
    else:
        signature_id = "AF-DENY-001"
        event_name = "SMS Authentication Traffic Blocked"

    reasons_text = "; ".join(event.reasons) if event.reasons else "Policy threshold exceeded"

    extensions = [
        f"src={_escape_cef_extension(event.client_ip)}",
        f"duser={_escape_cef_extension(event.phone_number)}",
        f"cs1={_escape_cef_extension(event.mcc_mnc)}",
        "cs1Label=MCC_MNC",
        f"cn1={event.risk_score:.2f}",
        "cn1Label=RiskScore",
        f"act={_escape_cef_extension(event.verdict.upper())}",
        f"externalId={_escape_cef_extension(str(event.request_id))}",
        f"msg={_escape_cef_extension(reasons_text)}",
    ]

    header = "|".join(
        [
            "CEF:0",
            _escape_cef_header(CEF_VENDOR),
            _escape_cef_header(CEF_PRODUCT),
            _escape_cef_header(CEF_VERSION),
            _escape_cef_header(signature_id),
            _escape_cef_header(event_name),
            str(cef_sev_num),
        ]
    )
    cef_line = f"{header}|{' '.join(extensions)}"
    return severity_enum, cef_line
