"""
uPKI RA Server - Certificate Authority API Schemas.

Mirrors `Upkiweb`'s `CertificateAuthority` type (see
uPKI-app/docs/FRONTEND_DATA_REQUIREMENTS.md §2.2) plus the CA hierarchy
graph endpoint (§5).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from .common import CamelModel

CAType = Literal["root", "intermediate", "registration"]
CAStatus = Literal["active", "expired", "revoked"]


class CertificateAuthority(CamelModel):
    """A single certificate authority node."""

    id: str
    name: str
    type: CAType
    status: CAStatus
    subject: str
    valid_from: datetime
    valid_to: datetime
    parent_id: str | None = None

    @classmethod
    def from_storage_row(cls, row: dict[str, Any]) -> CertificateAuthority:
        """Build a `CertificateAuthority` from an `InventoryStorage` CA row."""
        return cls(
            id=row["id"],
            name=row["name"],
            type=row["type"],
            status=row["status"],
            subject=row["subject"],
            valid_from=row["valid_from"],
            valid_to=row["valid_to"],
            parent_id=row.get("parent_id"),
        )


class CAGraphEdge(CamelModel):
    """A parent -> child edge in the CA hierarchy graph."""

    source: str
    target: str


class CAGraph(CamelModel):
    """Nodes + edges for ``GET /cas/graph``."""

    nodes: list[CertificateAuthority]
    edges: list[CAGraphEdge]
