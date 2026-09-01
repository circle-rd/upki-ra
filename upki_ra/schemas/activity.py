"""
uPKI RA Server - Activity Log API Schemas.

Mirrors `Upkiweb`'s `ActivityLog` type (see
uPKI-app/docs/FRONTEND_DATA_REQUIREMENTS.md §2.5).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from .common import CamelModel, PaginatedData

ActivityAction = Literal[
    "created", "renewed", "revoked", "approved", "rejected", "downloaded", "restored"
]
ActivityTarget = Literal["certificate", "profile", "ca", "csr", "user"]
ActivityStatus = Literal["success", "failed"]
ActivitySource = Literal["Web App", "MCP Server", "API", "SCEP", "ACME"]


class ActivityLogEntry(CamelModel):
    """A single audit trail entry."""

    id: str
    timestamp: datetime
    action: ActivityAction
    actor: str
    target: ActivityTarget
    target_id: str
    target_name: str
    status: ActivityStatus
    details: str | None = None
    source: ActivitySource | None = None
    source_ip: str | None = None

    @classmethod
    def from_storage_row(cls, row: dict[str, Any]) -> ActivityLogEntry:
        """Build an `ActivityLogEntry` from an `InventoryStorage` log row."""
        return cls(
            id=row["id"],
            timestamp=row["timestamp"],
            action=row["action"],
            actor=row["actor"],
            target=row["target"],
            target_id=row["target_id"],
            target_name=row["target_name"],
            status=row["status"],
            details=row.get("details"),
            source=row.get("source"),
            source_ip=row.get("source_ip"),
        )


class ActivityLogList(PaginatedData[ActivityLogEntry]):
    """Paginated list of activity log entries."""
