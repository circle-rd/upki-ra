"""
uPKI RA Server - Certificate API Schemas.

Mirrors `Upkiweb`'s `Certificate` type (see
uPKI-app/docs/FRONTEND_DATA_REQUIREMENTS.md §2.1) plus a handful of
backend-only fields (`ca_id`, `sans`, `source`, revocation info) that the
current demo UI doesn't render yet but are available for future use.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from .common import CamelModel, PaginatedData

CertificateStatus = Literal["valid", "expired", "revoked"]


class Certificate(CamelModel):
    """A single certificate, as listed/returned by the inventory API."""

    id: str = Field(..., description="Certificate serial number, used as the canonical id")
    subject: str
    organization: str | None = None
    issuer: str | None = None
    serial_number: str
    valid_from: datetime
    valid_to: datetime
    status: CertificateStatus
    key_type: str
    key_usage: list[str] = Field(default_factory=list)
    profile_id: str | None = None
    # Backend-only extensions, not present in the original Upkiweb mock type.
    ca_id: str | None = None
    sans: list[str] = Field(default_factory=list)
    source: str = "API"
    revoked_at: datetime | None = None
    revocation_reason: str | None = None

    @classmethod
    def from_storage_row(cls, row: dict[str, Any]) -> Certificate:
        """Build a `Certificate` from an `InventoryStorage` certificate row."""
        return cls(
            id=row["serial"],
            subject=row["common_name"],
            organization=row.get("organization"),
            issuer=row.get("issuer_dn"),
            serial_number=row["serial"],
            valid_from=row["valid_from"],
            valid_to=row["valid_to"],
            status=row["status"],
            key_type=row["key_type"],
            key_usage=row.get("key_usage") or [],
            profile_id=row.get("profile_id"),
            ca_id=row.get("ca_id"),
            sans=row.get("san") or [],
            source=row.get("source") or "API",
            revoked_at=row.get("revoked_at"),
            revocation_reason=row.get("revocation_reason"),
        )


class CertificateList(PaginatedData[Certificate]):
    """Paginated list of certificates."""


class RevokeCertificateRequest(CamelModel):
    """Request body for ``POST /certificates/{serial}/revoke``."""

    reason: str = "unspecified"
