"""
Shared schemas, DTOs, and logging facilities.
"""

from shared.schemas import (
    CommonJSONFormatter,
    EntityType,
    ErrorEnvelope,
    HealthStatus,
    InspectionCompletedEvent,
    InspectionResponse,
    InspectionResult,
    LogEntry,
    MatchedEntity,
    ReputationCheckRequest,
    ReputationCheckResponse,
    RuleDefinition,
    SMSCheckRequest,
    VelocityHitRequest,
    VelocityHitResponse,
    Verdict,
    request_id_ctx,
    setup_structured_logging,
)
from shared.logger import (
    get_logger,
    get_request_id,
    request_context,
    set_request_id,
)

__all__ = [
    "CommonJSONFormatter",
    "EntityType",
    "ErrorEnvelope",
    "HealthStatus",
    "InspectionCompletedEvent",
    "InspectionResponse",
    "InspectionResult",
    "LogEntry",
    "MatchedEntity",
    "ReputationCheckRequest",
    "ReputationCheckResponse",
    "RuleDefinition",
    "SMSCheckRequest",
    "VelocityHitRequest",
    "VelocityHitResponse",
    "Verdict",
    "get_logger",
    "get_request_id",
    "request_context",
    "request_id_ctx",
    "set_request_id",
    "setup_structured_logging",
]

