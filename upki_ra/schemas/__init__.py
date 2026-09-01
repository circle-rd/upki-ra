"""
uPKI RA Server - API Schema Package.

Pydantic request/response models for the RA's REST API. These are the
single source of truth for the OpenAPI contract consumed by `uPKI-app`'s
TypeScript codegen (see uPKI-app/docs/ROADMAP.md).
"""

from .activity import (
    ActivityAction,
    ActivityLogEntry,
    ActivityLogList,
    ActivitySource,
    ActivityStatus,
    ActivityTarget,
)
from .alerts import Alert, AlertSeverity, AlertType
from .cas import CAGraph, CAGraphEdge, CAStatus, CAType, CertificateAuthority
from .certificates import (
    Certificate,
    CertificateList,
    CertificateStatus,
    RevokeCertificateRequest,
)
from .common import CamelModel, ErrorResponse, PaginatedData, SuccessResponse
from .csrs import CSRCreateRequest, CSRItem, CSRList, CSRStatus
from .graph import Graph, GraphEdge, GraphNode, GraphNodeType
from .profiles import (
    CertificateProfile,
    CSRApprovalMode,
    CSRApprovalPolicy,
    CSRAutoRule,
    CSRAutoRuleType,
    CustomOID,
    ProfileField,
    ProfileFieldType,
    ProfileFieldValidation,
    ProfileWriteRequest,
)
from .stats import (
    CertificateByProfile,
    CertificateStats,
    ExpirationForecastPoint,
    IssuanceTrendPoint,
)

__all__ = [
    "ActivityAction",
    "ActivityLogEntry",
    "ActivityLogList",
    "ActivitySource",
    "ActivityStatus",
    "ActivityTarget",
    "Alert",
    "AlertSeverity",
    "AlertType",
    "CAGraph",
    "CAGraphEdge",
    "CAStatus",
    "CAType",
    "CSRApprovalMode",
    "CSRApprovalPolicy",
    "CSRAutoRule",
    "CSRAutoRuleType",
    "CSRCreateRequest",
    "CSRItem",
    "CSRList",
    "CSRStatus",
    "CamelModel",
    "Certificate",
    "CertificateAuthority",
    "CertificateByProfile",
    "CertificateList",
    "CertificateProfile",
    "CertificateStats",
    "CertificateStatus",
    "CustomOID",
    "ErrorResponse",
    "ExpirationForecastPoint",
    "Graph",
    "GraphEdge",
    "GraphNode",
    "GraphNodeType",
    "IssuanceTrendPoint",
    "PaginatedData",
    "ProfileField",
    "ProfileFieldType",
    "ProfileFieldValidation",
    "ProfileWriteRequest",
    "RevokeCertificateRequest",
    "SuccessResponse",
]
