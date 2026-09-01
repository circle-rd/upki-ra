"""
uPKI RA Server - Inventory Sync Service Unit Tests.
"""

import datetime
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from upki_ra.services.inventory_sync import InventorySyncService
from upki_ra.storage import InventoryStorage


def _build_certificate(*, common_name: str = "example.com", days_valid: int = 365) -> str:
    """Build a minimal self-signed certificate PEM for test purposes."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=3650))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")


class TestRecordIssuance(unittest.TestCase):
    """Test cases for `InventorySyncService.record_issuance`."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()
        self.service = InventorySyncService(self.storage)

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_indexes_certificate_and_logs_activity(self):
        pem = _build_certificate(common_name="api.example.com")
        result = self.service.record_issuance(
            pem, actor="admin@example.com", source="Web App", profile_id="prof-1"
        )

        self.assertEqual(result.subject, "api.example.com")
        self.assertEqual(result.profile_id, "prof-1")

        logs, total = self.storage.list_logs()
        self.assertEqual(total, 1)
        self.assertEqual(logs[0]["action"], "created")
        self.assertEqual(logs[0]["actor"], "admin@example.com")
        self.assertEqual(logs[0]["target_name"], "api.example.com")

    def test_renewal_inherits_profile_from_previous_certificate(self):
        first_pem = _build_certificate(common_name="renew.example.com")
        self.service.record_issuance(
            first_pem, actor="system", source="API", profile_id="prof-2", ca_id="ca-1"
        )

        second_pem = _build_certificate(common_name="renew.example.com")
        renewed = self.service.record_issuance(
            second_pem, actor="system", source="API", action="renewed"
        )

        self.assertEqual(renewed.profile_id, "prof-2")
        self.assertEqual(renewed.ca_id, "ca-1")

        logs, total = self.storage.list_logs(action="renewed")
        self.assertEqual(total, 1)

    def test_invalid_certificate_raises(self):
        with self.assertRaises(ValueError):
            self.service.record_issuance("not a cert", actor="system", source="API")


class TestRecordRevocation(unittest.TestCase):
    """Test cases for `InventorySyncService.record_revocation`/`record_unrevocation`."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()
        self.service = InventorySyncService(self.storage)

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_revocation_updates_status_and_logs(self):
        pem = _build_certificate(common_name="revoke.example.com")
        self.service.record_issuance(pem, actor="system", source="API")

        updated = self.service.record_revocation(
            "revoke.example.com", "keyCompromise", actor="admin@example.com", source="Web App"
        )
        self.assertTrue(updated)

        row = self.storage.get_certificate_by_common_name("revoke.example.com")
        self.assertEqual(row["status"], "revoked")
        self.assertEqual(row["revocation_reason"], "keyCompromise")

        logs, total = self.storage.list_logs(action="revoked")
        self.assertEqual(total, 1)

    def test_revocation_of_unknown_common_name_returns_false(self):
        self.assertFalse(
            self.service.record_revocation("nope.example.com", "unspecified", actor="a", source="API")
        )

    def test_revocation_twice_is_a_no_op(self):
        pem = _build_certificate(common_name="revoke.example.com")
        self.service.record_issuance(pem, actor="system", source="API")
        self.service.record_revocation("revoke.example.com", "unspecified", actor="a", source="API")

        self.assertFalse(
            self.service.record_revocation("revoke.example.com", "unspecified", actor="a", source="API")
        )

    def test_unrevocation_restores_valid_status(self):
        pem = _build_certificate(common_name="restore.example.com", days_valid=365)
        self.service.record_issuance(pem, actor="system", source="API")
        self.service.record_revocation("restore.example.com", "unspecified", actor="a", source="API")

        updated = self.service.record_unrevocation(
            "restore.example.com", actor="admin@example.com", source="Web App"
        )
        self.assertTrue(updated)

        row = self.storage.get_certificate_by_common_name("restore.example.com")
        self.assertEqual(row["status"], "valid")
        self.assertIsNone(row["revocation_reason"])

        logs, total = self.storage.list_logs(action="restored")
        self.assertEqual(total, 1)

    def test_unrevocation_restores_expired_status(self):
        pem = _build_certificate(common_name="restore-expired.example.com", days_valid=-30)
        self.service.record_issuance(pem, actor="system", source="API")
        self.service.record_revocation(
            "restore-expired.example.com", "unspecified", actor="a", source="API"
        )

        self.service.record_unrevocation("restore-expired.example.com", actor="a", source="API")
        row = self.storage.get_certificate_by_common_name("restore-expired.example.com")
        self.assertEqual(row["status"], "expired")

    def test_unrevocation_of_non_revoked_returns_false(self):
        pem = _build_certificate(common_name="valid.example.com")
        self.service.record_issuance(pem, actor="system", source="API")
        self.assertFalse(
            self.service.record_unrevocation("valid.example.com", actor="a", source="API")
        )


class TestReindexFromCA(unittest.TestCase):
    """Test cases for `InventorySyncService.reindex_from_ca`."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()
        self.service = InventorySyncService(self.storage)

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_degrades_gracefully_when_list_nodes_unsupported(self):
        zmq_client = MagicMock()
        zmq_client.list_nodes.side_effect = RuntimeError("Unknown task: list_nodes")

        result = self.service.reindex_from_ca(zmq_client)
        self.assertEqual(result, {"supported": False, "reindexed": 0, "skipped": 0})

    def test_reindexes_nodes_with_pem_included_inline(self):
        """Primary path: the CA's list_nodes response already carries the PEM."""
        pem = _build_certificate(common_name="node1.example.com")
        zmq_client = MagicMock()
        zmq_client.list_nodes.return_value = [{"dn": "/CN=node1.example.com", "certificate": pem}]

        result = self.service.reindex_from_ca(zmq_client)
        self.assertEqual(result, {"supported": True, "reindexed": 1, "skipped": 0})
        self.assertIsNotNone(self.storage.get_certificate_by_common_name("node1.example.com"))
        zmq_client.view_certificate.assert_not_called()

    def test_reindex_marks_revoked_nodes(self):
        pem = _build_certificate(common_name="revoked.example.com")
        zmq_client = MagicMock()
        zmq_client.list_nodes.return_value = [
            {"dn": "/CN=revoked.example.com", "certificate": pem, "revoked": True}
        ]

        self.service.reindex_from_ca(zmq_client)
        row = self.storage.get_certificate_by_common_name("revoked.example.com")
        self.assertEqual(row["status"], "revoked")

    def test_falls_back_to_view_certificate_when_pem_missing_inline(self):
        pem = _build_certificate(common_name="node1.example.com")
        zmq_client = MagicMock()
        zmq_client.list_nodes.return_value = [{"dn": "/CN=node1.example.com"}]
        zmq_client.view_certificate.return_value = {"certificate": pem}

        result = self.service.reindex_from_ca(zmq_client)
        self.assertEqual(result, {"supported": True, "reindexed": 1, "skipped": 0})
        zmq_client.view_certificate.assert_called_once_with(dn="/CN=node1.example.com")

    def test_skips_nodes_without_pem(self):
        zmq_client = MagicMock()
        zmq_client.list_nodes.return_value = [{"dn": "/CN=node1.example.com"}]
        zmq_client.view_certificate.return_value = {}

        result = self.service.reindex_from_ca(zmq_client)
        self.assertEqual(result, {"supported": True, "reindexed": 0, "skipped": 1})

    def test_skips_non_dict_nodes(self):
        zmq_client = MagicMock()
        zmq_client.list_nodes.return_value = ["not-a-dict"]

        result = self.service.reindex_from_ca(zmq_client)
        self.assertEqual(result, {"supported": True, "reindexed": 0, "skipped": 1})

    def test_skips_when_view_certificate_fallback_raises(self):
        zmq_client = MagicMock()
        zmq_client.list_nodes.return_value = [{"dn": "/CN=node1.example.com"}]
        zmq_client.view_certificate.side_effect = RuntimeError("CA unreachable")

        result = self.service.reindex_from_ca(zmq_client)
        self.assertEqual(result, {"supported": True, "reindexed": 0, "skipped": 1})

    def test_skips_nodes_with_unparsable_inline_pem(self):
        zmq_client = MagicMock()
        zmq_client.list_nodes.return_value = [
            {"dn": "/CN=node1.example.com", "certificate": "not a real certificate"}
        ]

        result = self.service.reindex_from_ca(zmq_client)
        self.assertEqual(result, {"supported": True, "reindexed": 0, "skipped": 1})


if __name__ == "__main__":
    unittest.main()
