"""
uPKI RA Server - Alert API Schemas.

Mirrors `Upkiweb`'s `Alert` type (see
uPKI-app/docs/FRONTEND_DATA_REQUIREMENTS.md §2.6).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from .common import CamelModel

AlertType = Literal["expiring", "caExpiring", "revoked", "csrPending", "error"]
AlertSeverity = Literal["low", "medium", "high", "critical"]


class Alert(CamelModel):
    """A single dashboard/notification alert."""

    id: str
    type: AlertType
    severity: AlertSeverity
    title: str
    message: str
    timestamp: datetime
    acknowledged: bool
    target_id: str | None = None

    @classmethod
    def from_storage_row(cls, row: dict[str, Any]) -> Alert:
        """Build an `Alert` from an `InventoryStorage` alert row."""
        return cls(
            id=row["id"],
            type=row["type"],
            severity=row["severity"],
            title=row["title"],
            message=row["message"],
            timestamp=row["timestamp"],
            acknowledged=row["acknowledged"],
            target_id=row.get("target_id"),
        )
