"""
uPKI RA Server - Inventory Storage Module.

This module provides SQLite-based storage for the certificate/CA/profile
inventory that backs the RA's read/query REST API: listing, filtering,
searching, pagination, statistics, the CA hierarchy graph, the CSR approval
queue, the activity log and alerts.

It is intentionally separate from `SQLiteStorage` (ACME protocol state:
nonces/accounts/orders/authorizations/challenges) since the two schemas are
unrelated and evolve independently. `uPKI-ca` itself is not modified: this
storage is a local, RA-maintained index populated at issuance/revocation
time (and rebuildable via a reindex routine), not a replacement for the CA's
own certificate/key vault.

All queries use parameterized statements; sortable/filterable column names
are resolved through fixed allow-lists (never interpolated from caller
input) to prevent SQL injection via crafted `sort`/filter query parameters.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import UTC, datetime
from typing import Any

from ..utils.cert_metadata import compute_status

# Public API field name -> actual SQL column name. Never build SQL from
# caller-supplied strings directly; always resolve through this mapping.
CERTIFICATE_SORT_COLUMNS: dict[str, str] = {
    "subject": "common_name",
    "organization": "organization",
    "validFrom": "valid_from",
    "validTo": "valid_to",
    "status": "status",
    "keyType": "key_type",
    "issuer": "issuer_dn",
    "serialNumber": "serial",
}

# A certificate's real, current status can't be trusted from the stored
# `status` column alone (see `_decode_certificate_row`): it's only ever
# written once at issuance/revocation time, so a certificate simply passing
# its `valid_to` date would otherwise be reported "valid" forever. Every
# query filtering/counting by status must use this expression instead of
# the raw column - fixed/hardcoded, never built from caller input.
CERTIFICATE_STATUS_EXPR = (
    "(CASE WHEN status = 'revoked' THEN 'revoked' "
    "WHEN valid_to <= CURRENT_TIMESTAMP THEN 'expired' "
    "ELSE 'valid' END)"
)

ACTIVITY_SORT_COLUMNS: dict[str, str] = {
    "timestamp": "timestamp",
    "action": "action",
    "actor": "actor",
    "target": "target",
}

CSR_SORT_COLUMNS: dict[str, str] = {
    "subject": "subject",
    "requestedAt": "requested_at",
    "status": "status",
}


def new_id(prefix: str) -> str:
    """Generate a short, prefixed unique identifier (e.g. ``log-<uuid>``)."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class InventoryStorage:
    """SQLite-based storage for the certificate/CA/profile inventory.

    Attributes:
        data_dir: Directory where the SQLite database file is kept.
        db_path: Full path to the SQLite database file.
    """

    def __init__(self, data_dir: str) -> None:
        """Initialize the inventory storage backend.

        Args:
            data_dir: Directory where the database file should be kept.
        """
        self.data_dir = data_dir
        self.db_path = os.path.join(data_dir, "inventory.db")
        self._connection: sqlite3.Connection | None = None

    def _get_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            os.makedirs(self.data_dir, exist_ok=True)
            self._connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
        return self._connection

    def __enter__(self) -> InventoryStorage:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Context manager exit - ensures connection is closed."""
        self.close()

    def close(self) -> None:
        """Close the database connection."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def initialize(self) -> None:
        """Create all necessary database tables and indices if missing."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS certificate_authorities (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                status TEXT NOT NULL,
                subject TEXT NOT NULL,
                valid_from TIMESTAMP NOT NULL,
                valid_to TIMESTAMP NOT NULL,
                parent_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (parent_id) REFERENCES certificate_authorities(id)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS certificates (
                serial TEXT PRIMARY KEY,
                dn TEXT NOT NULL,
                common_name TEXT NOT NULL,
                organization TEXT,
                issuer_dn TEXT,
                ca_id TEXT,
                profile_id TEXT,
                key_type TEXT NOT NULL,
                key_usage TEXT NOT NULL DEFAULT '[]',
                san TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL,
                valid_from TIMESTAMP NOT NULL,
                valid_to TIMESTAMP NOT NULL,
                source TEXT NOT NULL DEFAULT 'API',
                revoked_at TIMESTAMP,
                revocation_reason TEXT,
                pem TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # ca_id/profile_id are intentionally plain indexed columns, not FKs:
        # a CA or profile may be deleted later while certificate history is kept.
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_certificates_profile ON certificates(profile_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_certificates_ca ON certificates(ca_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_certificates_valid_to ON certificates(valid_to)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_certificates_key_type ON certificates(key_type)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_certificates_common_name ON certificates(common_name)"
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS csr_requests (
                id TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                organization TEXT,
                requested_by TEXT,
                profile_id TEXT,
                key_type TEXT,
                csr_pem TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP,
                resolved_by TEXT,
                certificate_serial TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_csr_status ON csr_requests(status)"
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS activity_log (
                id TEXT PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                target TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_name TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                source TEXT,
                source_ip TEXT
            )
            """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_log(timestamp)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_activity_action ON activity_log(action)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_activity_target ON activity_log(target)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_activity_source ON activity_log(source)"
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                acknowledged INTEGER NOT NULL DEFAULT 0,
                target_id TEXT
            )
            """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged)"
        )

        conn.commit()

    # ========================================================================
    # Certificate Authorities
    # ========================================================================

    def upsert_ca(self, ca: dict[str, Any]) -> bool:
        """Insert or update a certificate authority record.

        Args:
            ca: Dict with keys id, name, type, status, subject, valid_from,
                valid_to and optionally parent_id.

        Returns:
            True if successful, False otherwise.
        """
        try:
            conn = self._get_connection()
            conn.execute(
                """
                INSERT INTO certificate_authorities
                    (id, name, type, status, subject, valid_from, valid_to, parent_id, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name, type=excluded.type, status=excluded.status,
                    subject=excluded.subject, valid_from=excluded.valid_from,
                    valid_to=excluded.valid_to, parent_id=excluded.parent_id,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    ca["id"],
                    ca["name"],
                    ca["type"],
                    ca["status"],
                    ca["subject"],
                    ca["valid_from"],
                    ca["valid_to"],
                    ca.get("parent_id"),
                ),
            )
            conn.commit()
            return True
        except sqlite3.Error:
            return False

    def get_ca(self, ca_id: str) -> dict[str, Any] | None:
        """Retrieve a certificate authority by id."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM certificate_authorities WHERE id = ?", (ca_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_cas(self) -> list[dict[str, Any]]:
        """List all certificate authorities, ordered by name."""
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT * FROM certificate_authorities ORDER BY name"
        ).fetchall()
        return [dict(row) for row in rows]

    def get_ca_graph(self) -> dict[str, list[dict[str, Any]]]:
        """Return the CA hierarchy as nodes + parent->child edges.

        Returns:
            Dict with a ``nodes`` list (full CA records) and an ``edges``
            list of ``{"source": parent_id, "target": id}`` pairs.
        """
        cas = self.list_cas()
        edges = [
            {"source": ca["parent_id"], "target": ca["id"]}
            for ca in cas
            if ca.get("parent_id")
        ]
        return {"nodes": cas, "edges": edges}

    # ========================================================================
    # Profiles
    # ========================================================================

    def upsert_profile(self, profile_id: str, name: str, description: str, data: dict[str, Any]) -> bool:
        """Insert or update a certificate profile.

        Args:
            profile_id: Unique profile identifier.
            name: Human-readable profile name.
            description: Profile description.
            data: Full profile payload (fields, keyUsage, validityDays, ...),
                stored as an opaque JSON blob since its shape is UI-defined.

        Returns:
            True if successful, False otherwise.
        """
        try:
            conn = self._get_connection()
            payload = json.dumps(data)
            conn.execute(
                """
                INSERT INTO profiles (id, name, description, data, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name, description=excluded.description,
                    data=excluded.data, updated_at=CURRENT_TIMESTAMP
                """,
                (profile_id, name, description, payload),
            )
            conn.commit()
            return True
        except sqlite3.Error:
            return False

    def get_profile(self, profile_id: str) -> dict[str, Any] | None:
        """Retrieve a profile by id, with its JSON payload decoded."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM profiles WHERE id = ?", (profile_id,)
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["data"] = json.loads(result["data"])
        return result

    def list_profiles(self) -> list[dict[str, Any]]:
        """List all profiles, with their JSON payload decoded."""
        conn = self._get_connection()
        rows = conn.execute("SELECT * FROM profiles ORDER BY name").fetchall()
        results = []
        for row in rows:
            result = dict(row)
            result["data"] = json.loads(result["data"])
            results.append(result)
        return results

    def delete_profile(self, profile_id: str) -> bool:
        """Delete a profile by id."""
        conn = self._get_connection()
        cursor = conn.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))
        conn.commit()
        return cursor.rowcount > 0

    # ========================================================================
    # Certificates
    # ========================================================================

    def upsert_certificate(self, cert: dict[str, Any]) -> bool:
        """Insert or update a certificate inventory record.

        Args:
            cert: Dict with keys serial, dn, common_name, organization,
                issuer_dn, ca_id, profile_id, key_type, key_usage (list),
                san (list), status, valid_from, valid_to, source, and
                optionally revoked_at/revocation_reason.

        Returns:
            True if successful, False otherwise.
        """
        try:
            conn = self._get_connection()
            conn.execute(
                """
                INSERT INTO certificates
                    (serial, dn, common_name, organization, issuer_dn, ca_id, profile_id,
                     key_type, key_usage, san, status, valid_from, valid_to, source,
                     revoked_at, revocation_reason, pem, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(serial) DO UPDATE SET
                    dn=excluded.dn, common_name=excluded.common_name,
                    organization=excluded.organization, issuer_dn=excluded.issuer_dn,
                    ca_id=excluded.ca_id, profile_id=excluded.profile_id,
                    key_type=excluded.key_type, key_usage=excluded.key_usage,
                    san=excluded.san, status=excluded.status,
                    valid_from=excluded.valid_from, valid_to=excluded.valid_to,
                    source=excluded.source, revoked_at=excluded.revoked_at,
                    revocation_reason=excluded.revocation_reason, pem=excluded.pem,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    cert["serial"],
                    cert["dn"],
                    cert["common_name"],
                    cert.get("organization"),
                    cert.get("issuer_dn"),
                    cert.get("ca_id"),
                    cert.get("profile_id"),
                    cert["key_type"],
                    json.dumps(cert.get("key_usage", [])),
                    json.dumps(cert.get("san", [])),
                    cert["status"],
                    cert["valid_from"],
                    cert["valid_to"],
                    cert.get("source", "API"),
                    cert.get("revoked_at"),
                    cert.get("revocation_reason"),
                    cert.get("pem", ""),
                ),
            )
            conn.commit()
            return True
        except sqlite3.Error:
            return False

    def set_certificate_status(
        self,
        serial: str,
        status: str,
        revoked_at: str | None = None,
        revocation_reason: str | None = None,
    ) -> bool:
        """Update a certificate's status (e.g. after revoke/unrevoke/renew)."""
        conn = self._get_connection()
        cursor = conn.execute(
            """
            UPDATE certificates
            SET status = ?, revoked_at = ?, revocation_reason = ?, updated_at = CURRENT_TIMESTAMP
            WHERE serial = ?
            """,
            (status, revoked_at, revocation_reason, serial),
        )
        conn.commit()
        return cursor.rowcount > 0

    def get_certificate(self, serial: str) -> dict[str, Any] | None:
        """Retrieve a single certificate by serial number."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM certificates WHERE serial = ?", (serial,)
        ).fetchone()
        if not row:
            return None
        return self._decode_certificate_row(row)

    def list_certificates(
        self,
        *,
        search: str | None = None,
        status: str | None = None,
        profile_id: str | None = None,
        key_type: str | None = None,
        ca_id: str | None = None,
        sort: str = "validTo",
        sort_dir: str = "asc",
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[dict[str, Any]], int]:
        """List certificates with search/filter/sort/pagination.

        Args:
            search: Free-text match against subject/organization/serial.
            status: Exact filter on status (valid/expired/revoked).
            profile_id: Exact filter on profile id.
            key_type: Exact filter on key type.
            ca_id: Exact filter on issuing CA id.
            sort: Public field name to sort by, resolved through
                CERTIFICATE_SORT_COLUMNS (unknown values fall back to validTo).
            sort_dir: "asc" or "desc" (any other value is treated as "asc").
            page: 1-indexed page number.
            page_size: Number of items per page (caller is responsible for
                capping this to a sane maximum).

        Returns:
            Tuple of (page of decoded certificate dicts, total matching count).
        """
        column = CERTIFICATE_SORT_COLUMNS.get(sort, "valid_to")
        direction = "DESC" if sort_dir == "desc" else "ASC"

        where_clauses: list[str] = []
        params: list[Any] = []

        if search:
            where_clauses.append(
                "(common_name LIKE ? OR organization LIKE ? OR serial LIKE ?)"
            )
            like_term = f"%{search}%"
            params.extend([like_term, like_term, like_term])
        if status:
            where_clauses.append(f"{CERTIFICATE_STATUS_EXPR} = ?")
            params.append(status)
        if profile_id:
            where_clauses.append("profile_id = ?")
            params.append(profile_id)
        if key_type:
            where_clauses.append("key_type = ?")
            params.append(key_type)
        if ca_id:
            where_clauses.append("ca_id = ?")
            params.append(ca_id)

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        conn = self._get_connection()
        total = conn.execute(
            f"SELECT COUNT(*) FROM certificates {where_sql}", params
        ).fetchone()[0]

        offset = max(page - 1, 0) * page_size
        rows = conn.execute(
            f"SELECT * FROM certificates {where_sql} "
            f"ORDER BY {column} {direction} LIMIT ? OFFSET ?",
            [*params, page_size, offset],
        ).fetchall()

        return [self._decode_certificate_row(row) for row in rows], total

    @staticmethod
    def _decode_certificate_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["key_usage"] = json.loads(result["key_usage"] or "[]")
        result["san"] = json.loads(result["san"] or "[]")
        # `status` is only ever written once, at issuance/revocation time,
        # and never revisited afterwards - a certificate that simply passes
        # its `valid_to` date would otherwise be reported "valid" forever.
        # Recompute it live from the current time on every read instead of
        # trusting the stored snapshot; `revoked` is the one real, tracked
        # state transition so it stays authoritative.
        result["status"] = compute_status(
            datetime.fromisoformat(result["valid_to"]),
            revoked=result["status"] == "revoked",
        )
        return result

    def get_certificate_by_common_name(
        self, common_name: str, *, status: str | None = None
    ) -> dict[str, Any] | None:
        """Return the most recently indexed certificate row for a CN.

        The CA itself keeps a single active certificate per name; this
        mirrors that by picking the most recently issued match when
        multiple historical rows share the same common name. Used by the
        revoke/unrevoke sync hooks, which only receive a DN/CN (not a
        serial) from their callers.

        Ordered by SQLite's own ``rowid`` (strictly increasing per INSERT,
        stable across an `ON CONFLICT DO UPDATE`), not `valid_from`: two
        certificates for the same CN issued in quick succession (the exact
        renewal scenario this method exists for) can carry a `valid_from`
        identical down to the microsecond, making that ordering ambiguous.

        Args:
            common_name: Certificate Common Name to look up.
            status: Optional exact status filter (e.g. only the currently
                "valid" one, or only a "revoked" one to restore).

        Returns:
            The matching certificate row, or None if not found.
        """
        conn = self._get_connection()
        if status:
            row = conn.execute(
                f"SELECT * FROM certificates WHERE common_name = ? AND {CERTIFICATE_STATUS_EXPR} = ? "
                "ORDER BY rowid DESC LIMIT 1",
                (common_name, status),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM certificates WHERE common_name = ? "
                "ORDER BY rowid DESC LIMIT 1",
                (common_name,),
            ).fetchone()
        return self._decode_certificate_row(row) if row else None

    def list_certificates_by_common_name(self, common_name: str) -> list[dict[str, Any]]:
        """Return every certificate ever indexed for a CN, oldest first.

        Used to walk a renewal chain (predecessor/successor lookups for the
        `/graph` correlation endpoint) - ordered by `rowid`, see
        `get_certificate_by_common_name` for why insertion order is used
        instead of `valid_from`.
        """
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT * FROM certificates WHERE common_name = ? ORDER BY rowid ASC",
            (common_name,),
        ).fetchall()
        return [self._decode_certificate_row(row) for row in rows]

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_certificate_counts(self) -> dict[str, int]:
        """Return aggregate certificate counts for the dashboard overview."""
        conn = self._get_connection()
        total = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
        active = conn.execute(
            f"SELECT COUNT(*) FROM certificates WHERE {CERTIFICATE_STATUS_EXPR} = 'valid'"
        ).fetchone()[0]
        revoked = conn.execute(
            "SELECT COUNT(*) FROM certificates WHERE status = 'revoked'"
        ).fetchone()[0]
        expiring_soon = conn.execute(
            f"SELECT COUNT(*) FROM certificates WHERE {CERTIFICATE_STATUS_EXPR} = 'valid' "
            "AND valid_to <= DATETIME('now', '+90 days')"
        ).fetchone()[0]
        expired = conn.execute(
            f"SELECT COUNT(*) FROM certificates WHERE {CERTIFICATE_STATUS_EXPR} = 'expired'"
        ).fetchone()[0]
        pending_csrs = conn.execute(
            "SELECT COUNT(*) FROM csr_requests WHERE status = 'pending'"
        ).fetchone()[0]
        return {
            "total": total,
            "active": active,
            "expiringSoon": expiring_soon,
            "expired": expired,
            "revoked": revoked,
            "pendingCSRs": pending_csrs,
        }

    def get_certificates_by_profile(self) -> list[dict[str, Any]]:
        """Return certificate counts grouped by profile id (for the donut chart)."""
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT profile_id, COUNT(*) as count FROM certificates GROUP BY profile_id"
        ).fetchall()
        return [dict(row) for row in rows]

    def get_expiration_forecast(self, months: int = 6) -> list[dict[str, Any]]:
        """Return counts of valid certificates expiring per upcoming month.

        Args:
            months: Number of upcoming months to include.

        Returns:
            List of ``{"month": "YYYY-MM", "count": int}`` dicts, one entry
            per month, in chronological order (zero-filled).
        """
        conn = self._get_connection()
        rows = conn.execute(
            f"""
            SELECT strftime('%Y-%m', valid_to) as month, COUNT(*) as count
            FROM certificates
            WHERE {CERTIFICATE_STATUS_EXPR} = 'valid'
              AND valid_to BETWEEN CURRENT_TIMESTAMP AND DATETIME('now', ? || ' months')
            GROUP BY month
            """,
            (str(months),),
        ).fetchall()
        counts_by_month = {row["month"]: row["count"] for row in rows}

        forecast = []
        cursor_date = datetime.now(UTC)
        for _ in range(months):
            month_key = cursor_date.strftime("%Y-%m")
            forecast.append({"month": month_key, "count": counts_by_month.get(month_key, 0)})
            # advance to the first day of the next month
            if cursor_date.month == 12:
                cursor_date = cursor_date.replace(year=cursor_date.year + 1, month=1, day=1)
            else:
                cursor_date = cursor_date.replace(month=cursor_date.month + 1, day=1)
        return forecast

    # ========================================================================
    # CSR queue
    # ========================================================================

    def create_csr(self, csr: dict[str, Any]) -> str:
        """Create a new pending CSR request.

        Args:
            csr: Dict with keys subject, organization, requested_by,
                profile_id, key_type, csr_pem.

        Returns:
            The generated CSR request id.
        """
        csr_id = new_id("csr")
        conn = self._get_connection()
        conn.execute(
            """
            INSERT INTO csr_requests
                (id, subject, organization, requested_by, profile_id, key_type, csr_pem, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
            """,
            (
                csr_id,
                csr["subject"],
                csr.get("organization"),
                csr.get("requested_by"),
                csr.get("profile_id"),
                csr.get("key_type"),
                csr["csr_pem"],
            ),
        )
        conn.commit()
        return csr_id

    def get_csr(self, csr_id: str) -> dict[str, Any] | None:
        """Retrieve a CSR request by id."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM csr_requests WHERE id = ?", (csr_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_csr_by_certificate_serial(self, serial: str) -> dict[str, Any] | None:
        """Retrieve the CSR request that resulted in a given certificate, if any."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM csr_requests WHERE certificate_serial = ?", (serial,)
        ).fetchone()
        return dict(row) if row else None

    def list_csrs(
        self,
        *,
        status: str | None = None,
        sort: str = "requestedAt",
        sort_dir: str = "desc",
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[dict[str, Any]], int]:
        """List CSR requests with filter/sort/pagination.

        Args:
            status: Exact filter on status (pending/approved/rejected).
            sort: Public field name to sort by, resolved through
                CSR_SORT_COLUMNS (unknown values fall back to requested_at).
            sort_dir: "asc" or "desc".
            page: 1-indexed page number.
            page_size: Number of items per page.

        Returns:
            Tuple of (page of CSR dicts, total matching count).
        """
        column = CSR_SORT_COLUMNS.get(sort, "requested_at")
        direction = "DESC" if sort_dir == "desc" else "ASC"

        where_sql = ""
        params: list[Any] = []
        if status:
            where_sql = "WHERE status = ?"
            params.append(status)

        conn = self._get_connection()
        total = conn.execute(
            f"SELECT COUNT(*) FROM csr_requests {where_sql}", params
        ).fetchone()[0]

        offset = max(page - 1, 0) * page_size
        rows = conn.execute(
            f"SELECT * FROM csr_requests {where_sql} "
            f"ORDER BY {column} {direction} LIMIT ? OFFSET ?",
            [*params, page_size, offset],
        ).fetchall()

        return [dict(row) for row in rows], total

    def resolve_csr(
        self, csr_id: str, status: str, resolved_by: str, certificate_serial: str | None = None
    ) -> bool:
        """Mark a CSR request as approved or rejected.

        Args:
            csr_id: The CSR request id.
            status: "approved" or "rejected".
            resolved_by: Actor who resolved the request.
            certificate_serial: Serial of the certificate issued as a result,
                when status is "approved".

        Returns:
            True if a matching pending row was updated, False otherwise.
        """
        conn = self._get_connection()
        cursor = conn.execute(
            """
            UPDATE csr_requests
            SET status = ?, resolved_by = ?, resolved_at = CURRENT_TIMESTAMP,
                certificate_serial = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'pending'
            """,
            (status, resolved_by, certificate_serial, csr_id),
        )
        conn.commit()
        return cursor.rowcount > 0

    # ========================================================================
    # Activity log
    # ========================================================================

    def add_log(self, entry: dict[str, Any]) -> str:
        """Append an activity log entry.

        Args:
            entry: Dict with keys action, actor, target, target_id,
                target_name, status, and optionally details/source/source_ip.

        Returns:
            The generated log entry id.
        """
        log_id = new_id("log")
        conn = self._get_connection()
        conn.execute(
            """
            INSERT INTO activity_log
                (id, action, actor, target, target_id, target_name, status, details, source, source_ip)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                log_id,
                entry["action"],
                entry["actor"],
                entry["target"],
                entry["target_id"],
                entry["target_name"],
                entry["status"],
                entry.get("details"),
                entry.get("source"),
                entry.get("source_ip"),
            ),
        )
        conn.commit()
        return log_id

    def list_logs(
        self,
        *,
        search: str | None = None,
        action: str | None = None,
        target: str | None = None,
        source: str | None = None,
        status: str | None = None,
        sort_dir: str = "desc",
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[dict[str, Any]], int]:
        """List activity log entries with search/filter/pagination.

        Args:
            search: Free-text match against target_name/actor/source_ip.
            action: Exact filter on action.
            target: Exact filter on target type.
            source: Exact filter on source.
            status: Exact filter on status (success/failed).
            sort_dir: "asc" or "desc" sort by timestamp.
            page: 1-indexed page number.
            page_size: Number of items per page.

        Returns:
            Tuple of (page of log dicts, total matching count).
        """
        direction = "DESC" if sort_dir != "asc" else "ASC"

        where_clauses: list[str] = []
        params: list[Any] = []
        if search:
            where_clauses.append("(target_name LIKE ? OR actor LIKE ? OR source_ip LIKE ?)")
            like_term = f"%{search}%"
            params.extend([like_term, like_term, like_term])
        if action:
            where_clauses.append("action = ?")
            params.append(action)
        if target:
            where_clauses.append("target = ?")
            params.append(target)
        if source:
            where_clauses.append("source = ?")
            params.append(source)
        if status:
            where_clauses.append("status = ?")
            params.append(status)

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        conn = self._get_connection()
        total = conn.execute(
            f"SELECT COUNT(*) FROM activity_log {where_sql}", params
        ).fetchone()[0]

        offset = max(page - 1, 0) * page_size
        rows = conn.execute(
            f"SELECT * FROM activity_log {where_sql} "
            f"ORDER BY timestamp {direction} LIMIT ? OFFSET ?",
            [*params, page_size, offset],
        ).fetchall()

        return [dict(row) for row in rows], total

    # ========================================================================
    # Alerts
    # ========================================================================

    def add_alert(self, alert: dict[str, Any]) -> str:
        """Create a new (unacknowledged) alert.

        Args:
            alert: Dict with keys type, severity, title, message, and
                optionally target_id.

        Returns:
            The generated alert id.
        """
        alert_id = new_id("alert")
        conn = self._get_connection()
        conn.execute(
            """
            INSERT INTO alerts (id, type, severity, title, message, target_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                alert["type"],
                alert["severity"],
                alert["title"],
                alert["message"],
                alert.get("target_id"),
            ),
        )
        conn.commit()
        return alert_id

    def list_alerts(self, *, acknowledged: bool | None = None) -> list[dict[str, Any]]:
        """List alerts, optionally filtered by acknowledged state."""
        conn = self._get_connection()
        if acknowledged is None:
            rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE acknowledged = ? ORDER BY timestamp DESC",
                (1 if acknowledged else 0,),
            ).fetchall()
        results = []
        for row in rows:
            result = dict(row)
            result["acknowledged"] = bool(result["acknowledged"])
            results.append(result)
        return results

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark a single alert as acknowledged."""
        conn = self._get_connection()
        cursor = conn.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
        )
        conn.commit()
        return cursor.rowcount > 0

    def acknowledge_all_alerts(self) -> int:
        """Mark all alerts as acknowledged.

        Returns:
            The number of alerts that were newly acknowledged.
        """
        conn = self._get_connection()
        cursor = conn.execute("UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0")
        conn.commit()
        return cursor.rowcount
