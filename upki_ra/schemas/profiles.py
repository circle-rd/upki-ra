"""
uPKI RA Server - Certificate Profile API Schemas.

Mirrors `Upkiweb`'s `CertificateProfile`/`ProfileField`/`CSRApprovalPolicy`
types (see uPKI-app/docs/FRONTEND_DATA_REQUIREMENTS.md §2.3).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from .common import CamelModel

ProfileFieldType = Literal["text", "email", "select", "number", "multiselect", "oid-list"]
CSRApprovalMode = Literal["manual", "auto"]
CSRAutoRuleType = Literal["domain", "ip", "dns"]


class ProfileFieldValidation(CamelModel):
    """Validation constraints for a single profile field."""

    pattern: str | None = None
    min_length: int | None = None
    max_length: int | None = None


class ProfileField(CamelModel):
    """A single field definition within a certificate profile's form."""

    id: str
    name: str
    label: str
    type: ProfileFieldType
    required: bool
    validation: ProfileFieldValidation | None = None
    default_value: str | None = None
    options: list[str] | None = None
    selected_values: list[str] | None = None


class CSRAutoRule(CamelModel):
    """A single auto-approval rule (matched against domain/ip/dns SANs)."""

    id: str
    type: CSRAutoRuleType
    pattern: str
    description: str | None = None


class CSRApprovalPolicy(CamelModel):
    """Approval policy attached to a profile: manual review or auto-rules."""

    mode: CSRApprovalMode
    auto_rules: list[CSRAutoRule] | None = None


class CustomOID(CamelModel):
    """A custom X.509 extension OID/value pair attached to a profile."""

    oid: str
    value: str
    critical: bool


class CertificateProfile(CamelModel):
    """A certificate issuance profile."""

    id: str
    name: str
    description: str = ""
    fields: list[ProfileField] = Field(default_factory=list)
    key_type: str
    validity_days: int
    key_usage: list[str] = Field(default_factory=list)
    extended_key_usage: list[str] | None = None
    digest_type: str | None = None
    domain: str | None = None
    cert_types: list[str] | None = None
    custom_oids: list[CustomOID] | None = Field(default=None, alias="customOIDs")
    csr_approval: CSRApprovalPolicy | None = None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_storage_row(cls, row: dict[str, Any]) -> CertificateProfile:
        """Build a `CertificateProfile` from an `InventoryStorage` profile row.

        The row's `data` blob already holds every field below except
        id/name/description/created_at/updated_at, which are indexed columns.
        """
        payload = dict(row["data"])
        payload["id"] = row["id"]
        payload["name"] = row["name"]
        payload["description"] = row.get("description") or ""
        payload["createdAt"] = row["created_at"]
        payload["updatedAt"] = row["updated_at"]
        return cls.model_validate(payload)


class ProfileWriteRequest(CamelModel):
    """Request body for creating/updating a profile."""

    name: str
    description: str = ""
    fields: list[ProfileField] = Field(default_factory=list)
    key_type: str
    validity_days: int
    key_usage: list[str] = Field(default_factory=list)
    extended_key_usage: list[str] | None = None
    digest_type: str | None = None
    domain: str | None = None
    cert_types: list[str] | None = None
    custom_oids: list[CustomOID] | None = Field(default=None, alias="customOIDs")
    csr_approval: CSRApprovalPolicy | None = None
