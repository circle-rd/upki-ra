"""
uPKI RA Server - Inventory API Routes.

This module provides the REST API surface consumed by the `uPKI-app`
frontend: paginated/filtered/searchable listings, detail views, statistics
and CA-hierarchy correlation for certificates, certificate authorities,
profiles and the CSR approval queue, plus the activity log and alerts.

See uPKI-app/docs/FRONTEND_DATA_REQUIREMENTS.md §3 for the design this
implements, and uPKI-app/docs/ROADMAP.md for the "shared types" strategy
these Pydantic models feed into.

Auth note: these endpoints are intentionally unauthenticated for now, same
as `public_api.py` - the initial deployment is demo-mode with hardcoded
frontend credentials (see ROADMAP.md); production LDAP/role-based auth is
an explicitly separate future task. Mutating endpoints record a generic
"Web App" actor in the activity log until real auth lands.
"""

from __future__ import annotations

from typing import Literal

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_pem_x509_certificate
from fastapi import APIRouter, HTTPException, Query, Response

from ..core.upki_error import CAConnectionError, UPKIError, ValidationError
from ..registration_authority import RegistrationAuthority
from ..schemas import (
    ActivityLogEntry,
    ActivityLogList,
    Alert,
    CAGraph,
    CAGraphEdge,
    Certificate,
    CertificateAuthority,
    CertificateByProfile,
    CertificateList,
    CertificateProfile,
    CertificateStats,
    CSRCreateRequest,
    CSRItem,
    CSRList,
    ExpirationForecastPoint,
    Graph,
    IssuanceTrendPoint,
    ProfileWriteRequest,
    RevokeCertificateRequest,
    SuccessResponse,
)
from ..services.graph import GraphRootNotFoundError, UnknownGraphRootError, build_graph
from ..storage.inventory_storage import new_id
from ..utils.common import format_error

# Demo-mode placeholder actor until real auth lands (see module docstring).
_DEMO_ACTOR = "admin@example.com"
_DEMO_SOURCE = "Web App"

SortDir = Literal["asc", "desc"]


def create_inventory_routes(ra: RegistrationAuthority) -> APIRouter:
    """Create the inventory API routes with RA instance.

    Args:
        ra: RegistrationAuthority instance.

    Returns:
        Configured FastAPI APIRouter.
    """
    router = APIRouter(prefix="", tags=["inventory"])

    # ========================================================================
    # Certificates
    # ========================================================================

    @router.get("/certificates", response_model=SuccessResponse[CertificateList])
    async def list_certificates(
        q: str | None = None,
        status: str | None = None,
        profile: str | None = None,
        key_type: str | None = None,
        ca: str | None = None,
        sort: str = "validTo",
        sort_dir: SortDir = "asc",
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=25, ge=1, le=100),
    ) -> SuccessResponse[CertificateList]:
        """List certificates with search/filter/sort/pagination."""
        rows, total = ra.inventory.list_certificates(
            search=q,
            status=status,
            profile_id=profile,
            key_type=key_type,
            ca_id=ca,
            sort=sort,
            sort_dir=sort_dir,
            page=page,
            page_size=page_size,
        )
        certs = [Certificate.from_storage_row(row) for row in rows]
        return SuccessResponse(data=CertificateList.build(certs, total, page, page_size))

    @router.get("/certificates/{serial}", response_model=SuccessResponse[Certificate])
    async def get_certificate(serial: str) -> SuccessResponse[Certificate]:
        """Get a single certificate's full detail by serial number."""
        row = ra.inventory.get_certificate(serial)
        if not row:
            raise HTTPException(
                status_code=404,
                detail=format_error("Certificate not found", "NOT_FOUND", 404),
            )
        return SuccessResponse(data=Certificate.from_storage_row(row))

    @router.post(
        "/certificates/{serial}/revoke", response_model=SuccessResponse[Certificate]
    )
    async def revoke_certificate(
        serial: str, body: RevokeCertificateRequest
    ) -> SuccessResponse[Certificate]:
        """Revoke a certificate by serial number."""
        row = ra.inventory.get_certificate(serial)
        if not row:
            raise HTTPException(
                status_code=404,
                detail=format_error("Certificate not found", "NOT_FOUND", 404),
            )

        try:
            ok = ra.revoke(
                dn=row["dn"], reason=body.reason, actor=_DEMO_ACTOR, source=_DEMO_SOURCE
            )
        except ValidationError as e:
            raise HTTPException(
                status_code=400, detail=format_error(str(e), "VALIDATION_ERROR", 400)
            ) from e
        except CAConnectionError as e:
            raise HTTPException(
                status_code=503, detail=format_error(str(e), "CA_ERROR", 503)
            ) from e
        except UPKIError as e:
            raise HTTPException(
                status_code=500, detail=format_error(str(e), e.code, 500)
            ) from e

        if not ok:
            raise HTTPException(
                status_code=400,
                detail=format_error("Failed to revoke certificate", "OPERATION_FAILED", 400),
            )

        updated = ra.inventory.get_certificate(serial)
        return SuccessResponse(data=Certificate.from_storage_row(updated or row))

    @router.post(
        "/certificates/{serial}/renew", response_model=SuccessResponse[Certificate]
    )
    async def renew_certificate(serial: str) -> SuccessResponse[Certificate]:
        """Renew a certificate by serial number.

        Renewal issues a brand-new certificate (new serial/validity) for the
        same Common Name; the response reflects the new certificate, not the
        one identified by `serial` in the path.
        """
        row = ra.inventory.get_certificate(serial)
        if not row:
            raise HTTPException(
                status_code=404,
                detail=format_error("Certificate not found", "NOT_FOUND", 404),
            )

        try:
            ra.renew(dn=row["dn"], actor=_DEMO_ACTOR, source=_DEMO_SOURCE)
        except ValidationError as e:
            raise HTTPException(
                status_code=400, detail=format_error(str(e), "VALIDATION_ERROR", 400)
            ) from e
        except CAConnectionError as e:
            raise HTTPException(
                status_code=503, detail=format_error(str(e), "CA_ERROR", 503)
            ) from e
        except UPKIError as e:
            raise HTTPException(
                status_code=500, detail=format_error(str(e), e.code, 500)
            ) from e

        renewed = ra.inventory.get_certificate_by_common_name(row["common_name"])
        return SuccessResponse(data=Certificate.from_storage_row(renewed or row))

    @router.get("/certificates/{serial}/download")
    async def download_certificate(
        serial: str, format: Literal["pem", "der"] = "pem"
    ) -> Response:
        """Download a certificate in PEM or DER format.

        PKCS12 is not offered here: the RA does not hold private keys (only
        the CA/enrolling client does), and a PKCS12 bundle requires one.
        """
        row = ra.inventory.get_certificate(serial)
        if not row or not row.get("pem"):
            raise HTTPException(
                status_code=404,
                detail=format_error("Certificate not found", "NOT_FOUND", 404),
            )

        if format == "pem":
            return Response(
                content=row["pem"],
                media_type="application/x-pem-file",
                headers={
                    "Content-Disposition": f'attachment; filename="{row["common_name"]}.pem"'
                },
            )

        der_bytes = load_pem_x509_certificate(row["pem"].encode("utf-8")).public_bytes(
            Encoding.DER
        )
        return Response(
            content=der_bytes,
            media_type="application/pkix-cert",
            headers={
                "Content-Disposition": f'attachment; filename="{row["common_name"]}.der"'
            },
        )

    # ========================================================================
    # Certificate Authorities
    # ========================================================================

    @router.get("/cas", response_model=SuccessResponse[list[CertificateAuthority]])
    async def list_cas() -> SuccessResponse[list[CertificateAuthority]]:
        """List all known certificate authorities."""
        rows = ra.inventory.list_cas()
        return SuccessResponse(data=[CertificateAuthority.from_storage_row(r) for r in rows])

    @router.get("/cas/graph", response_model=SuccessResponse[CAGraph])
    async def get_ca_graph() -> SuccessResponse[CAGraph]:
        """Get the CA hierarchy as nodes + parent->child edges."""
        graph = ra.inventory.get_ca_graph()
        return SuccessResponse(
            data=CAGraph(
                nodes=[CertificateAuthority.from_storage_row(n) for n in graph["nodes"]],
                edges=[CAGraphEdge(**e) for e in graph["edges"]],
            )
        )

    @router.get("/cas/{ca_id}", response_model=SuccessResponse[CertificateAuthority])
    async def get_ca(ca_id: str) -> SuccessResponse[CertificateAuthority]:
        """Get a single certificate authority's detail."""
        row = ra.inventory.get_ca(ca_id)
        if not row:
            raise HTTPException(
                status_code=404, detail=format_error("CA not found", "NOT_FOUND", 404)
            )
        return SuccessResponse(data=CertificateAuthority.from_storage_row(row))

    # ========================================================================
    # Correlation graph
    # ========================================================================

    @router.get("/graph", response_model=SuccessResponse[Graph])
    async def get_graph(root: str) -> SuccessResponse[Graph]:
        """Get a small neighborhood subgraph around a single entity.

        `root` is a ``type:id`` reference, e.g. ``certificate:AA:BB:CC``,
        ``ca:ca-1``, ``profile:prof-1`` or ``csr:csr-1``.
        """
        try:
            graph = build_graph(ra.inventory, root)
        except UnknownGraphRootError as e:
            raise HTTPException(
                status_code=400, detail=format_error(str(e), "VALIDATION_ERROR", 400)
            ) from e
        except GraphRootNotFoundError as e:
            raise HTTPException(
                status_code=404, detail=format_error(str(e), "NOT_FOUND", 404)
            ) from e
        return SuccessResponse(data=graph)

    # ========================================================================
    # Profiles
    # ========================================================================

    @router.get("/profiles", response_model=SuccessResponse[list[CertificateProfile]])
    async def list_profiles() -> SuccessResponse[list[CertificateProfile]]:
        """List all certificate profiles."""
        rows = ra.inventory.list_profiles()
        return SuccessResponse(data=[CertificateProfile.from_storage_row(r) for r in rows])

    @router.get("/profiles/{profile_id}", response_model=SuccessResponse[CertificateProfile])
    async def get_profile(profile_id: str) -> SuccessResponse[CertificateProfile]:
        """Get a single certificate profile's detail."""
        row = ra.inventory.get_profile(profile_id)
        if not row:
            raise HTTPException(
                status_code=404, detail=format_error("Profile not found", "NOT_FOUND", 404)
            )
        return SuccessResponse(data=CertificateProfile.from_storage_row(row))

    @router.post("/profiles", response_model=SuccessResponse[CertificateProfile])
    async def create_profile(body: ProfileWriteRequest) -> SuccessResponse[CertificateProfile]:
        """Create a new certificate profile."""
        profile_id = new_id("prof")
        payload = body.model_dump(exclude={"name", "description"}, by_alias=True)
        ra.inventory.upsert_profile(profile_id, body.name, body.description, payload)
        ra.inventory.add_log(
            {
                "action": "created",
                "actor": _DEMO_ACTOR,
                "target": "profile",
                "target_id": profile_id,
                "target_name": body.name,
                "status": "success",
                "source": _DEMO_SOURCE,
            }
        )
        row = ra.inventory.get_profile(profile_id)
        assert row is not None  # just upserted above
        return SuccessResponse(data=CertificateProfile.from_storage_row(row))

    @router.put("/profiles/{profile_id}", response_model=SuccessResponse[CertificateProfile])
    async def update_profile(
        profile_id: str, body: ProfileWriteRequest
    ) -> SuccessResponse[CertificateProfile]:
        """Update an existing certificate profile."""
        existing = ra.inventory.get_profile(profile_id)
        if not existing:
            raise HTTPException(
                status_code=404, detail=format_error("Profile not found", "NOT_FOUND", 404)
            )

        payload = body.model_dump(exclude={"name", "description"}, by_alias=True)
        ra.inventory.upsert_profile(profile_id, body.name, body.description, payload)
        row = ra.inventory.get_profile(profile_id)
        assert row is not None  # just upserted above
        return SuccessResponse(data=CertificateProfile.from_storage_row(row))

    @router.delete("/profiles/{profile_id}")
    async def delete_profile(profile_id: str) -> SuccessResponse[dict]:
        """Delete a certificate profile."""
        existing = ra.inventory.get_profile(profile_id)
        if not existing:
            raise HTTPException(
                status_code=404, detail=format_error("Profile not found", "NOT_FOUND", 404)
            )

        ra.inventory.delete_profile(profile_id)
        ra.inventory.add_log(
            {
                "action": "revoked",  # closest ActivityAction to "removed" for a profile
                "actor": _DEMO_ACTOR,
                "target": "profile",
                "target_id": profile_id,
                "target_name": existing["name"],
                "status": "success",
                "details": "Profile deleted",
                "source": _DEMO_SOURCE,
            }
        )
        return SuccessResponse(data={"deleted": True})

    # ========================================================================
    # CSR approval queue
    # ========================================================================

    @router.get("/csrs", response_model=SuccessResponse[CSRList])
    async def list_csrs(
        status: str | None = None,
        sort: str = "requestedAt",
        sort_dir: SortDir = "desc",
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=25, ge=1, le=100),
    ) -> SuccessResponse[CSRList]:
        """List CSR approval-queue requests with filter/sort/pagination."""
        rows, total = ra.inventory.list_csrs(
            status=status, sort=sort, sort_dir=sort_dir, page=page, page_size=page_size
        )
        items = [CSRItem.from_storage_row(r) for r in rows]
        return SuccessResponse(data=CSRList.build(items, total, page, page_size))

    @router.post("/csrs", response_model=SuccessResponse[CSRItem])
    async def create_csr(body: CSRCreateRequest) -> SuccessResponse[CSRItem]:
        """Submit a new CSR to the manual-approval queue."""
        csr_id = ra.inventory.create_csr(body.model_dump(by_alias=False))
        ra.inventory.add_log(
            {
                "action": "created",
                "actor": body.requested_by or _DEMO_ACTOR,
                "target": "csr",
                "target_id": csr_id,
                "target_name": body.subject,
                "status": "success",
                "source": _DEMO_SOURCE,
            }
        )
        row = ra.inventory.get_csr(csr_id)
        assert row is not None  # just created above
        item = CSRItem.from_storage_row(row)
        await ra.ws_manager.broadcast("csr.created", item.model_dump(by_alias=True, mode="json"))
        return SuccessResponse(data=item)

    @router.post("/csrs/{csr_id}/approve", response_model=SuccessResponse[CSRItem])
    async def approve_csr(csr_id: str) -> SuccessResponse[CSRItem]:
        """Approve a pending CSR: issues the certificate via the CA."""
        csr_row = ra.inventory.get_csr(csr_id)
        if not csr_row:
            raise HTTPException(
                status_code=404, detail=format_error("CSR not found", "NOT_FOUND", 404)
            )
        if csr_row["status"] != "pending":
            raise HTTPException(
                status_code=400,
                detail=format_error("CSR is not pending", "INVALID_STATE", 400),
            )

        try:
            ra.certify(
                csr=csr_row["csr_pem"],
                profile=csr_row.get("profile_id") or "server",
                actor=_DEMO_ACTOR,
                source=_DEMO_SOURCE,
            )
        except ValidationError as e:
            raise HTTPException(
                status_code=400, detail=format_error(str(e), "VALIDATION_ERROR", 400)
            ) from e
        except CAConnectionError as e:
            raise HTTPException(
                status_code=503, detail=format_error(str(e), "CA_ERROR", 503)
            ) from e
        except UPKIError as e:
            raise HTTPException(
                status_code=500, detail=format_error(str(e), e.code, 500)
            ) from e

        issued = ra.inventory.get_certificate_by_common_name(csr_row["subject"])
        ra.inventory.resolve_csr(
            csr_id,
            "approved",
            resolved_by=_DEMO_ACTOR,
            certificate_serial=issued["serial"] if issued else None,
        )
        ra.inventory.add_log(
            {
                "action": "approved",
                "actor": _DEMO_ACTOR,
                "target": "csr",
                "target_id": csr_id,
                "target_name": csr_row["subject"],
                "status": "success",
                "source": _DEMO_SOURCE,
            }
        )
        row = ra.inventory.get_csr(csr_id)
        assert row is not None
        item = CSRItem.from_storage_row(row)
        await ra.ws_manager.broadcast("csr.approved", item.model_dump(by_alias=True, mode="json"))
        return SuccessResponse(data=item)

    @router.post("/csrs/{csr_id}/reject", response_model=SuccessResponse[CSRItem])
    async def reject_csr(csr_id: str) -> SuccessResponse[CSRItem]:
        """Reject a pending CSR."""
        csr_row = ra.inventory.get_csr(csr_id)
        if not csr_row:
            raise HTTPException(
                status_code=404, detail=format_error("CSR not found", "NOT_FOUND", 404)
            )
        if csr_row["status"] != "pending":
            raise HTTPException(
                status_code=400,
                detail=format_error("CSR is not pending", "INVALID_STATE", 400),
            )

        ra.inventory.resolve_csr(csr_id, "rejected", resolved_by=_DEMO_ACTOR)
        ra.inventory.add_log(
            {
                "action": "rejected",
                "actor": _DEMO_ACTOR,
                "target": "csr",
                "target_id": csr_id,
                "target_name": csr_row["subject"],
                "status": "success",
                "source": _DEMO_SOURCE,
            }
        )
        row = ra.inventory.get_csr(csr_id)
        assert row is not None
        item = CSRItem.from_storage_row(row)
        await ra.ws_manager.broadcast("csr.rejected", item.model_dump(by_alias=True, mode="json"))
        return SuccessResponse(data=item)

    # ========================================================================

    @router.get("/stats/overview", response_model=SuccessResponse[CertificateStats])
    async def stats_overview() -> SuccessResponse[CertificateStats]:
        """Get the Dashboard's 5 KPI counters."""
        counts = ra.inventory.get_certificate_counts()
        return SuccessResponse(data=CertificateStats.model_validate(counts))

    @router.get(
        "/stats/issuance-trend", response_model=SuccessResponse[list[IssuanceTrendPoint]]
    )
    async def stats_issuance_trend(
        days: int = Query(default=30, ge=1, le=366),
    ) -> SuccessResponse[list[IssuanceTrendPoint]]:
        """Get certificate issuance counts per day over the trailing window."""
        rows, _ = ra.inventory.list_certificates(page=1, page_size=1_000_000)
        counts_by_day: dict[str, int] = {}
        for row in rows:
            day = str(row["created_at"])[:10]
            counts_by_day[day] = counts_by_day.get(day, 0) + 1
        points = [
            IssuanceTrendPoint(date=day, count=count) for day, count in sorted(counts_by_day.items())
        ]
        return SuccessResponse(data=points[-days:])

    @router.get("/stats/by-profile", response_model=SuccessResponse[list[CertificateByProfile]])
    async def stats_by_profile() -> SuccessResponse[list[CertificateByProfile]]:
        """Get certificate counts grouped by profile, for the Dashboard donut chart."""
        raw = ra.inventory.get_certificates_by_profile()
        profiles_by_id = {p["id"]: p["name"] for p in ra.inventory.list_profiles()}
        return SuccessResponse(
            data=[
                CertificateByProfile(
                    profile_id=row["profile_id"],
                    profile_name=profiles_by_id.get(row["profile_id"]),
                    count=row["count"],
                )
                for row in raw
            ]
        )

    @router.get(
        "/stats/expiration-forecast",
        response_model=SuccessResponse[list[ExpirationForecastPoint]],
    )
    async def stats_expiration_forecast(
        months: int = Query(default=6, ge=1, le=24),
    ) -> SuccessResponse[list[ExpirationForecastPoint]]:
        """Get counts of valid certificates expiring per upcoming month."""
        forecast = ra.inventory.get_expiration_forecast(months=months)
        return SuccessResponse(data=[ExpirationForecastPoint(**f) for f in forecast])

    # ========================================================================
    # Activity log
    # ========================================================================

    @router.get("/activity", response_model=SuccessResponse[ActivityLogList])
    async def list_activity(
        q: str | None = None,
        action: str | None = None,
        target: str | None = None,
        source: str | None = None,
        status: str | None = None,
        sort_dir: SortDir = "desc",
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=25, ge=1, le=100),
    ) -> SuccessResponse[ActivityLogList]:
        """List activity log entries with search/filter/sort/pagination."""
        rows, total = ra.inventory.list_logs(
            search=q,
            action=action,
            target=target,
            source=source,
            status=status,
            sort_dir=sort_dir,
            page=page,
            page_size=page_size,
        )
        entries = [ActivityLogEntry.from_storage_row(r) for r in rows]
        return SuccessResponse(data=ActivityLogList.build(entries, total, page, page_size))

    # ========================================================================
    # Alerts
    # ========================================================================

    @router.get("/alerts", response_model=SuccessResponse[list[Alert]])
    async def list_alerts(
        acknowledged: bool | None = None,
    ) -> SuccessResponse[list[Alert]]:
        """List alerts, optionally filtered by acknowledged state."""
        rows = ra.inventory.list_alerts(acknowledged=acknowledged)
        return SuccessResponse(data=[Alert.from_storage_row(r) for r in rows])

    @router.post("/alerts/{alert_id}/ack", response_model=SuccessResponse[dict])
    async def acknowledge_alert(alert_id: str) -> SuccessResponse[dict]:
        """Acknowledge a single alert."""
        ok = ra.inventory.acknowledge_alert(alert_id)
        if not ok:
            raise HTTPException(
                status_code=404, detail=format_error("Alert not found", "NOT_FOUND", 404)
            )
        await ra.ws_manager.broadcast("alert.acknowledged", {"id": alert_id})
        return SuccessResponse(data={"acknowledged": True})

    @router.post("/alerts/ack-all", response_model=SuccessResponse[dict])
    async def acknowledge_all_alerts() -> SuccessResponse[dict]:
        """Acknowledge every currently-unacknowledged alert."""
        count = ra.inventory.acknowledge_all_alerts()
        if count:
            await ra.ws_manager.broadcast("alert.acknowledged", {"count": count})
        return SuccessResponse(data={"acknowledged": count})

    return router
