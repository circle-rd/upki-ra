"""
uPKI RA Server - Inventory Sync Service.

Bridges certificate issuance/revocation/renewal events into the RA's local
`InventoryStorage` index and activity log, so every code path that changes
certificate state keeps the read/query API (listing, filtering, stats,
graph) in sync - regardless of whether that code path goes through
`RegistrationAuthority.certify/renew/revoke/unrevoke` or calls the CA
`ZMQClient` directly (e.g. node registration, ACME finalize/revoke).

Indexing is best-effort and never the source of truth (the CA vault is):
callers should treat failures here as non-fatal to the underlying PKI
operation - see each method's docstring.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ..schemas import Certificate
from ..storage import InventoryStorage
from ..utils.cert_metadata import compute_status, parse_certificate_metadata

if TYPE_CHECKING:
    from ..utils.tools import ZMQClient


class InventorySyncService:
    """Keeps `InventoryStorage` (and the activity log) up to date."""

    def __init__(self, storage: InventoryStorage) -> None:
        """Initialize the sync service.

        Args:
            storage: The RA's inventory storage instance.
        """
        self.storage = storage

    def record_issuance(
        self,
        cert_pem: str,
        *,
        actor: str,
        source: str,
        profile_id: str | None = None,
        ca_id: str | None = None,
        action: str = "created",
    ) -> Certificate:
        """Index a newly issued (or renewed) certificate and log the activity.

        When `profile_id`/`ca_id` aren't provided (e.g. on renewal, where the
        CA's response carries neither), they are inherited from the most
        recent previously-indexed certificate sharing the same Common Name,
        if any.

        Args:
            cert_pem: The freshly issued certificate, PEM-encoded.
            actor: Who/what triggered the issuance (email, DN, or "system"/"anonymous").
            source: Origin of the request ("Web App"/"API"/"ACME"/"SCEP"/"MCP Server").
            profile_id: Profile used to issue the certificate, if known.
            ca_id: Issuing CA id, if known.
            action: "created" or "renewed" (only affects the activity log entry).

        Returns:
            The indexed certificate as an API schema instance.

        Raises:
            ValueError: If `cert_pem` cannot be parsed as an X.509 certificate.
        """
        metadata = parse_certificate_metadata(cert_pem)

        if profile_id is None or ca_id is None:
            previous = self.storage.get_certificate_by_common_name(metadata["common_name"])
            if previous:
                profile_id = profile_id or previous.get("profile_id")
                ca_id = ca_id or previous.get("ca_id")

        metadata["profile_id"] = profile_id
        metadata["ca_id"] = ca_id
        metadata["source"] = source
        self.storage.upsert_certificate(metadata)

        self.storage.add_log(
            {
                "action": action,
                "actor": actor,
                "target": "certificate",
                "target_id": metadata["serial"],
                "target_name": metadata["common_name"],
                "status": "success",
                "source": source,
            }
        )

        row = self.storage.get_certificate(metadata["serial"])
        assert row is not None  # just upserted above
        return Certificate.from_storage_row(row)

    def record_revocation(self, common_name: str, reason: str, *, actor: str, source: str) -> bool:
        """Mark the current active certificate for `common_name` as revoked.

        Args:
            common_name: Common Name of the certificate being revoked.
            reason: Revocation reason.
            actor: Who/what triggered the revocation.
            source: Origin of the request.

        Returns:
            True if a matching indexed certificate was found and updated,
            False otherwise (e.g. the certificate was never indexed - this
            does not necessarily mean the underlying CA revocation failed).
        """
        row = self.storage.get_certificate_by_common_name(common_name, status="valid")
        if row is None:
            row = self.storage.get_certificate_by_common_name(common_name)
        if row is None or row["status"] == "revoked":
            return False

        revoked_at = datetime.now(UTC).isoformat()
        updated = self.storage.set_certificate_status(
            row["serial"], "revoked", revoked_at=revoked_at, revocation_reason=reason
        )
        if updated:
            self.storage.add_log(
                {
                    "action": "revoked",
                    "actor": actor,
                    "target": "certificate",
                    "target_id": row["serial"],
                    "target_name": common_name,
                    "status": "success",
                    "details": f"Added to CRL ({reason})",
                    "source": source,
                }
            )
        return updated

    def record_unrevocation(self, common_name: str, *, actor: str, source: str) -> bool:
        """Restore the most recently revoked certificate for `common_name`.

        Args:
            common_name: Common Name of the certificate being restored.
            actor: Who/what triggered the restoration.
            source: Origin of the request.

        Returns:
            True if a matching revoked certificate was found and updated,
            False otherwise.
        """
        row = self.storage.get_certificate_by_common_name(common_name, status="revoked")
        if row is None:
            return False

        status = compute_status(datetime.fromisoformat(row["valid_to"]))
        updated = self.storage.set_certificate_status(row["serial"], status)
        if updated:
            self.storage.add_log(
                {
                    "action": "restored",
                    "actor": actor,
                    "target": "certificate",
                    "target_id": row["serial"],
                    "target_name": common_name,
                    "status": "success",
                    "details": "Removed from CRL",
                    "source": source,
                }
            )
        return updated

    def reindex_from_ca(self, zmq_client: ZMQClient) -> dict[str, Any]:
        """Best-effort startup backfill: rebuild the index from what the CA reports.

        Relies on the CA's ``list_nodes`` ZMQ task (`Authority.list_nodes()`)
        returning each certificate's raw PEM and best-effort revoked flag
        directly; falls back to a per-node ``view`` call for older CA builds
        that don't include the PEM inline. Degrades gracefully (returns
        ``supported: False``) instead of raising if the CA doesn't support
        ``list_nodes`` at all - see uPKI-app/docs/ROADMAP.md decisions log.

        Args:
            zmq_client: The RA's CA ZMQ client.

        Returns:
            Dict with keys ``supported`` (whether ``list_nodes`` worked at
            all), ``reindexed`` (count of certificates (re)indexed) and
            ``skipped`` (count of nodes the CA reported but couldn't be
            backfilled, e.g. because no PEM was available).
        """
        try:
            nodes = zmq_client.list_nodes()
        except Exception:
            return {"supported": False, "reindexed": 0, "skipped": 0}

        reindexed = 0
        skipped = 0
        for node in nodes:
            if not isinstance(node, dict):
                skipped += 1
                continue

            cert_pem = node.get("certificate")
            dn = node.get("dn", "")
            if not cert_pem and dn:
                try:
                    details = zmq_client.view_certificate(dn=dn)
                    cert_pem = details.get("certificate") or details.get("pem")
                except Exception:
                    cert_pem = None

            if not cert_pem:
                skipped += 1
                continue

            try:
                result = self.record_issuance(
                    cert_pem, actor="system", source="API", action="created"
                )
            except ValueError:
                skipped += 1
                continue

            reindexed += 1
            if node.get("revoked"):
                self.record_revocation(
                    result.subject, "unspecified", actor="system", source="API"
                )

        return {"supported": True, "reindexed": reindexed, "skipped": skipped}
