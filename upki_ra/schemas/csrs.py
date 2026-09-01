"""
uPKI RA Server - CSR Approval Queue API Schemas.

A manual approve/reject queue, distinct from ACME orders (RFC 8555,
auto-validated) - see uPKI-app/docs/FRONTEND_DATA_REQUIREMENTS.md §2.4.
Mirrors `Upkiweb`'s `CSR` type.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from .common import CamelModel, PaginatedData

CSRStatus = Literal["pending", "approved", "rejected"]


class CSRItem(CamelModel):
    """A single pending/approved/rejected manual CSR request."""

    id: str
    subject: str
    organization: str | None = None
    requested_by: str | None = None
    requested_at: datetime
    status: CSRStatus
    profile_id: str | None = None
    key_type: str | None = None

    @classmethod
    def from_storage_row(cls, row: dict[str, Any]) -> CSRItem:
        """Build a `CSRItem` from an `InventoryStorage` CSR request row."""
        return cls(
            id=row["id"],
            subject=row["subject"],
            organization=row.get("organization"),
            requested_by=row.get("requested_by"),
            requested_at=row["requested_at"],
            status=row["status"],
            profile_id=row.get("profile_id"),
            key_type=row.get("key_type"),
        )


class CSRList(PaginatedData[CSRItem]):
    """Paginated list of CSR requests."""


class CSRCreateRequest(CamelModel):
    """Request body for submitting a new CSR to the approval queue."""

    subject: str
    organization: str | None = None
    requested_by: str | None = None
    profile_id: str | None = None
    key_type: str | None = None
    csr_pem: str
