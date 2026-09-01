"""
uPKI RA Server - API Schema Unit Tests.

Verifies the camelCase wire contract (including the explicit alias
overrides for acronym fields like `pendingCSRs`/`customOIDs`), the
`from_storage_row` builders against real `InventoryStorage` rows, and the
generic pagination/response envelopes.
"""

import shutil
import tempfile
import unittest

from upki_ra.schemas import (
    ActivityLogEntry,
    Alert,
    CAGraph,
    Certificate,
    CertificateAuthority,
    CertificateList,
    CertificateProfile,
    CertificateStats,
    CSRItem,
    PaginatedData,
    SuccessResponse,
)
from upki_ra.storage import InventoryStorage


class TestCertificateSchema(unittest.TestCase):
    """Test cases for the `Certificate` schema."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_from_storage_row_and_camel_case_serialization(self):
        self.storage.upsert_certificate(
            {
                "serial": "AA:BB:01",
                "dn": "CN=example.com,O=Example Corp",
                "common_name": "example.com",
                "organization": "Example Corp",
                "issuer_dn": "CN=Intermediate CA",
                "ca_id": "ca-2",
                "profile_id": "prof-1",
                "key_type": "RSA-2048",
                "key_usage": ["digitalSignature", "keyEncipherment"],
                "san": ["example.com", "www.example.com"],
                "status": "valid",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_to": "2030-01-01T00:00:00Z",
                "source": "Web App",
            }
        )
        row = self.storage.get_certificate("AA:BB:01")
        cert = Certificate.from_storage_row(row)

        self.assertEqual(cert.id, "AA:BB:01")
        self.assertEqual(cert.subject, "example.com")
        self.assertEqual(cert.status, "valid")

        payload = cert.model_dump(by_alias=True, mode="json")
        self.assertEqual(payload["id"], "AA:BB:01")
        self.assertEqual(payload["subject"], "example.com")
        self.assertEqual(payload["serialNumber"], "AA:BB:01")
        self.assertEqual(payload["keyType"], "RSA-2048")
        self.assertEqual(payload["keyUsage"], ["digitalSignature", "keyEncipherment"])
        self.assertEqual(payload["profileId"], "prof-1")
        self.assertEqual(payload["caId"], "ca-2")
        self.assertEqual(payload["sans"], ["example.com", "www.example.com"])
        self.assertEqual(payload["validFrom"], "2024-01-01T00:00:00Z")
        self.assertEqual(payload["validTo"], "2030-01-01T00:00:00Z")

    def test_optional_fields_default_safely(self):
        self.storage.upsert_certificate(
            {
                "serial": "s1",
                "dn": "CN=a",
                "common_name": "a",
                "key_type": "RSA-2048",
                "status": "valid",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_to": "2030-01-01T00:00:00Z",
            }
        )
        row = self.storage.get_certificate("s1")
        cert = Certificate.from_storage_row(row)
        self.assertIsNone(cert.organization)
        self.assertIsNone(cert.profile_id)
        self.assertEqual(cert.key_usage, [])
        self.assertEqual(cert.sans, [])
        self.assertEqual(cert.source, "API")


class TestCertificateAuthoritySchema(unittest.TestCase):
    """Test cases for the `CertificateAuthority`/`CAGraph` schemas."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_from_storage_row(self):
        self.storage.upsert_ca(
            {
                "id": "ca-1",
                "name": "Root CA",
                "type": "root",
                "status": "active",
                "subject": "CN=Root CA",
                "valid_from": "2020-01-01T00:00:00Z",
                "valid_to": "2030-01-01T00:00:00Z",
            }
        )
        row = self.storage.get_ca("ca-1")
        ca = CertificateAuthority.from_storage_row(row)
        payload = ca.model_dump(by_alias=True, mode="json")
        self.assertEqual(payload["parentId"], None)
        self.assertEqual(payload["validFrom"], "2020-01-01T00:00:00Z")

    def test_ca_graph_shape(self):
        self.storage.upsert_ca(
            {
                "id": "ca-root",
                "name": "Root CA",
                "type": "root",
                "status": "active",
                "subject": "CN=Root CA",
                "valid_from": "2020-01-01T00:00:00Z",
                "valid_to": "2030-01-01T00:00:00Z",
            }
        )
        self.storage.upsert_ca(
            {
                "id": "ca-intermediate",
                "name": "Intermediate CA",
                "type": "intermediate",
                "status": "active",
                "subject": "CN=Intermediate CA",
                "valid_from": "2022-01-01T00:00:00Z",
                "valid_to": "2027-01-01T00:00:00Z",
                "parent_id": "ca-root",
            }
        )
        raw_graph = self.storage.get_ca_graph()
        graph = CAGraph(
            nodes=[CertificateAuthority.from_storage_row(row) for row in raw_graph["nodes"]],
            edges=raw_graph["edges"],
        )
        payload = graph.model_dump(by_alias=True, mode="json")
        self.assertEqual(len(payload["nodes"]), 2)
        self.assertEqual(payload["edges"], [{"source": "ca-root", "target": "ca-intermediate"}])


class TestCertificateProfileSchema(unittest.TestCase):
    """Test cases for the `CertificateProfile` schema, including the
    `customOIDs` acronym alias override."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_from_storage_row_with_camel_case_blob(self):
        self.storage.upsert_profile(
            "prof-1",
            "Web Server",
            "TLS server certs",
            {
                "fields": [],
                "keyType": "RSA-2048",
                "validityDays": 365,
                "keyUsage": ["digitalSignature"],
                "customOIDs": [{"oid": "1.2.3.4", "value": "x", "critical": False}],
            },
        )
        row = self.storage.get_profile("prof-1")
        profile = CertificateProfile.from_storage_row(row)
        self.assertEqual(profile.key_type, "RSA-2048")
        self.assertEqual(profile.validity_days, 365)
        self.assertEqual(profile.custom_oids[0].oid, "1.2.3.4")

        payload = profile.model_dump(by_alias=True, mode="json")
        self.assertIn("customOIDs", payload)
        self.assertEqual(payload["validityDays"], 365)

    def test_from_storage_row_with_snake_case_blob(self):
        # populate_by_name=True must also accept snake_case keys directly.
        self.storage.upsert_profile(
            "prof-1",
            "Web Server",
            "",
            {
                "fields": [],
                "key_type": "RSA-2048",
                "validity_days": 365,
                "key_usage": [],
            },
        )
        row = self.storage.get_profile("prof-1")
        profile = CertificateProfile.from_storage_row(row)
        self.assertEqual(profile.key_type, "RSA-2048")
        self.assertEqual(profile.validity_days, 365)


class TestCSRItemSchema(unittest.TestCase):
    """Test cases for the `CSRItem` schema."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_from_storage_row(self):
        csr_id = self.storage.create_csr(
            {"subject": "new.example.com", "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----"}
        )
        row = self.storage.get_csr(csr_id)
        item = CSRItem.from_storage_row(row)
        payload = item.model_dump(by_alias=True, mode="json")
        self.assertEqual(payload["status"], "pending")
        self.assertEqual(payload["subject"], "new.example.com")


class TestActivityLogSchema(unittest.TestCase):
    """Test cases for the `ActivityLogEntry` schema."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_from_storage_row(self):
        self.storage.add_log(
            {
                "action": "created",
                "actor": "admin@example.com",
                "target": "certificate",
                "target_id": "s1",
                "target_name": "example.com",
                "status": "success",
                "source": "Web App",
                "source_ip": "10.0.0.1",
            }
        )
        rows, _ = self.storage.list_logs()
        entry = ActivityLogEntry.from_storage_row(rows[0])
        payload = entry.model_dump(by_alias=True, mode="json")
        self.assertEqual(payload["targetId"], "s1")
        self.assertEqual(payload["targetName"], "example.com")
        self.assertEqual(payload["sourceIp"], "10.0.0.1")


class TestAlertSchema(unittest.TestCase):
    """Test cases for the `Alert` schema."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_from_storage_row(self):
        self.storage.add_alert(
            {
                "type": "expiring",
                "severity": "medium",
                "title": "Certificate Expiring",
                "message": "Certificate for example.com expires soon.",
            }
        )
        alerts = self.storage.list_alerts()
        alert = Alert.from_storage_row(alerts[0])
        payload = alert.model_dump(by_alias=True, mode="json")
        self.assertEqual(payload["acknowledged"], False)
        self.assertIsNone(payload["targetId"])


class TestStatsSchema(unittest.TestCase):
    """Test cases for the `CertificateStats` acronym alias override."""

    def test_pending_csrs_alias(self):
        stats = CertificateStats(total=10, active=8, expiring_soon=1, revoked=1, pending_csrs=2)
        payload = stats.model_dump(by_alias=True)
        self.assertEqual(payload["pendingCSRs"], 2)
        self.assertNotIn("pendingCsrs", payload)

    def test_populate_by_name_still_works_from_camel_json(self):
        stats = CertificateStats.model_validate(
            {"total": 1, "active": 1, "expiringSoon": 0, "revoked": 0, "pendingCSRs": 0}
        )
        self.assertEqual(stats.pending_csrs, 0)


class TestCommonEnvelopes(unittest.TestCase):
    """Test cases for `PaginatedData`/`SuccessResponse` generics."""

    def test_paginated_data_build(self):
        page = PaginatedData[int].build(items=[1, 2], total=5, page=1, page_size=2)
        self.assertEqual(page.total_pages, 3)
        payload = page.model_dump(by_alias=True)
        self.assertEqual(payload["pageSize"], 2)
        self.assertEqual(payload["totalPages"], 3)

    def test_paginated_data_build_empty(self):
        page = PaginatedData[int].build(items=[], total=0, page=1, page_size=25)
        self.assertEqual(page.total_pages, 1)

    def test_success_response_envelope(self):
        response = SuccessResponse[int](data=42)
        payload = response.model_dump(by_alias=True)
        self.assertEqual(payload, {"status": "success", "data": 42})

    def test_certificate_list_is_a_paginated_data_of_certificate(self):
        cert = Certificate(
            id="s1",
            subject="example.com",
            serial_number="s1",
            valid_from="2024-01-01T00:00:00Z",
            valid_to="2030-01-01T00:00:00Z",
            status="valid",
            key_type="RSA-2048",
        )
        cert_list = CertificateList.build(items=[cert], total=1, page=1, page_size=25)
        payload = cert_list.model_dump(by_alias=True, mode="json")
        self.assertEqual(payload["items"][0]["id"], "s1")
        self.assertEqual(payload["totalPages"], 1)


if __name__ == "__main__":
    unittest.main()
