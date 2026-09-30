"""
uPKI RA Server - Dashboard Statistics API Schemas.

Mirrors `Upkiweb`'s `CertificateStats`/`IssuanceTrend`/`CertificateByType`/
`ExpirationForecast` types (see
uPKI-app/docs/FRONTEND_DATA_REQUIREMENTS.md §2.7).
"""

from __future__ import annotations

from pydantic import Field

from .common import CamelModel


class CertificateStats(CamelModel):
    """The 6 KPI counters shown on the Dashboard overview."""

    total: int
    active: int
    expiring_soon: int
    expired: int
    revoked: int
    pending_csrs: int = Field(alias="pendingCSRs")


class IssuanceTrendPoint(CamelModel):
    """A single point of the issuance trend line chart."""

    date: str
    count: int


class CertificateByProfile(CamelModel):
    """Certificate counts grouped by profile, for the Dashboard donut chart."""

    profile_id: str | None = None
    profile_name: str | None = None
    count: int


class ExpirationForecastPoint(CamelModel):
    """A single point of the expiration forecast bar chart."""

    month: str
    count: int
