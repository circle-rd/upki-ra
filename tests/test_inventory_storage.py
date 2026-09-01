"""
uPKI RA Server - Inventory Storage Unit Tests.

Unit tests for the SQLite-based certificate/CA/profile inventory storage.
"""

import shutil
import tempfile
import unittest

from upki_ra.storage import InventoryStorage


class TestInventoryStorageCAs(unittest.TestCase):
    """Test cases for certificate authority storage."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _root_ca(self, **overrides):
        ca = {
            "id": "ca-1",
            "name": "Root CA",
            "type": "root",
            "status": "active",
            "subject": "CN=Root CA",
            "valid_from": "2020-01-01T00:00:00Z",
            "valid_to": "2030-01-01T00:00:00Z",
        }
        ca.update(overrides)
        return ca

    def test_upsert_and_get_ca(self):
        self.assertTrue(self.storage.upsert_ca(self._root_ca()))
        ca = self.storage.get_ca("ca-1")
        self.assertIsNotNone(ca)
        self.assertEqual(ca["name"], "Root CA")
        self.assertIsNone(ca["parent_id"])

    def test_get_ca_missing(self):
        self.assertIsNone(self.storage.get_ca("does-not-exist"))

    def test_upsert_ca_returns_false_on_storage_error(self):
        self.storage._get_connection().close()  # force the next execute() to fail
        self.assertFalse(self.storage.upsert_ca(self._root_ca()))

    def test_upsert_ca_updates_existing(self):
        self.storage.upsert_ca(self._root_ca())
        self.storage.upsert_ca(self._root_ca(name="Root CA Renamed", status="expired"))
        ca = self.storage.get_ca("ca-1")
        self.assertEqual(ca["name"], "Root CA Renamed")
        self.assertEqual(ca["status"], "expired")

    def test_list_cas_ordered_by_name(self):
        self.storage.upsert_ca(self._root_ca(id="ca-2", name="Zeta CA"))
        self.storage.upsert_ca(self._root_ca(id="ca-1", name="Alpha CA"))
        cas = self.storage.list_cas()
        self.assertEqual([c["name"] for c in cas], ["Alpha CA", "Zeta CA"])

    def test_ca_graph_edges(self):
        self.storage.upsert_ca(self._root_ca(id="ca-root"))
        self.storage.upsert_ca(
            self._root_ca(id="ca-intermediate", type="intermediate", parent_id="ca-root")
        )
        graph = self.storage.get_ca_graph()
        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual(graph["edges"], [{"source": "ca-root", "target": "ca-intermediate"}])


class TestInventoryStorageProfiles(unittest.TestCase):
    """Test cases for profile storage."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_upsert_and_get_profile(self):
        self.storage.upsert_profile(
            "prof-1", "Web Server", "TLS server certs", {"keyType": "RSA-2048"}
        )
        profile = self.storage.get_profile("prof-1")
        self.assertEqual(profile["name"], "Web Server")
        self.assertEqual(profile["data"]["keyType"], "RSA-2048")

    def test_get_profile_missing(self):
        self.assertIsNone(self.storage.get_profile("nope"))

    def test_upsert_profile_returns_false_on_storage_error(self):
        self.storage._get_connection().close()
        self.assertFalse(self.storage.upsert_profile("prof-1", "Web Server", "", {}))

    def test_list_profiles(self):
        self.storage.upsert_profile("prof-2", "Zeta", "", {})
        self.storage.upsert_profile("prof-1", "Alpha", "", {})
        profiles = self.storage.list_profiles()
        self.assertEqual([p["name"] for p in profiles], ["Alpha", "Zeta"])

    def test_delete_profile(self):
        self.storage.upsert_profile("prof-1", "Web Server", "", {})
        self.assertTrue(self.storage.delete_profile("prof-1"))
        self.assertIsNone(self.storage.get_profile("prof-1"))

    def test_delete_profile_missing(self):
        self.assertFalse(self.storage.delete_profile("nope"))


class TestInventoryStorageCertificates(unittest.TestCase):
    """Test cases for certificate inventory storage."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _cert(self, **overrides):
        cert = {
            "serial": "AA:BB:01",
            "dn": "CN=example.com,O=Example Corp",
            "common_name": "example.com",
            "organization": "Example Corp",
            "issuer_dn": "CN=Intermediate CA",
            "ca_id": "ca-2",
            "profile_id": "prof-1",
            "key_type": "RSA-2048",
            "key_usage": ["digitalSignature", "keyEncipherment"],
            "san": ["example.com"],
            "status": "valid",
            "valid_from": "2024-01-01T00:00:00Z",
            "valid_to": "2030-01-01T00:00:00Z",
            "source": "Web App",
        }
        cert.update(overrides)
        return cert

    def test_upsert_and_get_certificate(self):
        self.assertTrue(self.storage.upsert_certificate(self._cert()))
        cert = self.storage.get_certificate("AA:BB:01")
        self.assertEqual(cert["common_name"], "example.com")
        self.assertEqual(cert["key_usage"], ["digitalSignature", "keyEncipherment"])
        self.assertEqual(cert["san"], ["example.com"])

    def test_get_certificate_missing(self):
        self.assertIsNone(self.storage.get_certificate("nope"))

    def test_upsert_certificate_returns_false_on_storage_error(self):
        self.storage._get_connection().close()
        self.assertFalse(self.storage.upsert_certificate(self._cert()))

    def test_upsert_certificate_updates_existing(self):
        self.storage.upsert_certificate(self._cert())
        self.storage.upsert_certificate(self._cert(status="revoked", revocation_reason="keyCompromise"))
        cert = self.storage.get_certificate("AA:BB:01")
        self.assertEqual(cert["status"], "revoked")
        self.assertEqual(cert["revocation_reason"], "keyCompromise")

    def test_set_certificate_status(self):
        self.storage.upsert_certificate(self._cert())
        self.assertTrue(
            self.storage.set_certificate_status("AA:BB:01", "revoked", revoked_at="2026-01-01T00:00:00Z")
        )
        cert = self.storage.get_certificate("AA:BB:01")
        self.assertEqual(cert["status"], "revoked")
        self.assertEqual(cert["revoked_at"], "2026-01-01T00:00:00Z")

    def test_set_certificate_status_missing(self):
        self.assertFalse(self.storage.set_certificate_status("nope", "revoked"))

    def test_list_certificates_pagination(self):
        for i in range(5):
            self.storage.upsert_certificate(self._cert(serial=f"serial-{i}", common_name=f"host{i}.example.com"))
        items, total = self.storage.list_certificates(page=1, page_size=2, sort="subject", sort_dir="asc")
        self.assertEqual(total, 5)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["common_name"], "host0.example.com")

        items_page2, total2 = self.storage.list_certificates(page=2, page_size=2, sort="subject", sort_dir="asc")
        self.assertEqual(total2, 5)
        self.assertEqual(items_page2[0]["common_name"], "host2.example.com")

    def test_list_certificates_filter_by_status(self):
        self.storage.upsert_certificate(self._cert(serial="s1", status="valid"))
        self.storage.upsert_certificate(self._cert(serial="s2", status="revoked"))
        items, total = self.storage.list_certificates(status="revoked")
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["serial"], "s2")

    def test_list_certificates_filter_by_profile_and_key_type(self):
        self.storage.upsert_certificate(self._cert(serial="s1", profile_id="prof-1", key_type="RSA-2048"))
        self.storage.upsert_certificate(self._cert(serial="s2", profile_id="prof-2", key_type="ECDSA-P256"))
        items, total = self.storage.list_certificates(profile_id="prof-2")
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["serial"], "s2")

        items, total = self.storage.list_certificates(key_type="RSA-2048")
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["serial"], "s1")

    def test_list_certificates_search(self):
        self.storage.upsert_certificate(self._cert(serial="s1", common_name="api.example.com", organization="ACME"))
        self.storage.upsert_certificate(self._cert(serial="s2", common_name="mail.example.com", organization="Other Corp"))
        items, total = self.storage.list_certificates(search="api")
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["serial"], "s1")

        items, total = self.storage.list_certificates(search="Other Corp")
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["serial"], "s2")

    def test_list_certificates_sort_direction(self):
        self.storage.upsert_certificate(self._cert(serial="s1", common_name="a.example.com"))
        self.storage.upsert_certificate(self._cert(serial="s2", common_name="z.example.com"))
        items, _ = self.storage.list_certificates(sort="subject", sort_dir="desc")
        self.assertEqual(items[0]["common_name"], "z.example.com")

    def test_list_certificates_unknown_sort_falls_back(self):
        self.storage.upsert_certificate(self._cert(serial="s1"))
        # Should not raise even though "not-a-real-field" isn't in the allow-list.
        items, total = self.storage.list_certificates(sort="not-a-real-field")
        self.assertEqual(total, 1)

    def test_get_certificate_by_common_name_missing(self):
        self.assertIsNone(self.storage.get_certificate_by_common_name("nope.example.com"))

    def test_get_certificate_by_common_name_picks_most_recently_inserted(self):
        """Regression test: two certs for the same CN with an IDENTICAL
        valid_from (the exact renewal scenario) must still resolve to the
        most recently inserted one, not an arbitrary tied row."""
        self.storage.upsert_certificate(
            self._cert(serial="old", common_name="renew.example.com", valid_from="2024-01-01T00:00:00Z")
        )
        self.storage.upsert_certificate(
            self._cert(serial="new", common_name="renew.example.com", valid_from="2024-01-01T00:00:00Z")
        )
        row = self.storage.get_certificate_by_common_name("renew.example.com")
        self.assertEqual(row["serial"], "new")

    def test_get_certificate_by_common_name_filters_by_status(self):
        self.storage.upsert_certificate(
            self._cert(serial="s1", common_name="x.example.com", status="valid")
        )
        self.storage.upsert_certificate(
            self._cert(serial="s2", common_name="x.example.com", status="revoked")
        )
        row = self.storage.get_certificate_by_common_name("x.example.com", status="revoked")
        self.assertEqual(row["serial"], "s2")


class TestInventoryStorageStatistics(unittest.TestCase):
    """Test cases for aggregate statistics."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_certificate_counts(self):
        self.storage.upsert_certificate(
            {
                "serial": "s1",
                "dn": "CN=a",
                "common_name": "a",
                "key_type": "RSA-2048",
                "status": "valid",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_to": "2099-01-01T00:00:00Z",
            }
        )
        self.storage.upsert_certificate(
            {
                "serial": "s2",
                "dn": "CN=b",
                "common_name": "b",
                "key_type": "RSA-2048",
                "status": "revoked",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_to": "2030-01-01T00:00:00Z",
            }
        )
        self.storage.create_csr(
            {"subject": "pending.example.com", "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----"}
        )

        counts = self.storage.get_certificate_counts()
        self.assertEqual(counts["total"], 2)
        self.assertEqual(counts["active"], 1)
        self.assertEqual(counts["revoked"], 1)
        self.assertEqual(counts["pendingCSRs"], 1)

    def test_get_certificates_by_profile(self):
        self.storage.upsert_certificate(
            {
                "serial": "s1",
                "dn": "CN=a",
                "common_name": "a",
                "profile_id": "prof-1",
                "key_type": "RSA-2048",
                "status": "valid",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_to": "2099-01-01T00:00:00Z",
            }
        )
        by_profile = self.storage.get_certificates_by_profile()
        self.assertEqual(by_profile, [{"profile_id": "prof-1", "count": 1}])

    def test_get_expiration_forecast_length_and_zero_fill(self):
        forecast = self.storage.get_expiration_forecast(months=6)
        self.assertEqual(len(forecast), 6)
        self.assertTrue(all(entry["count"] == 0 for entry in forecast))
        self.assertTrue(all(len(entry["month"]) == 7 for entry in forecast))  # "YYYY-MM"


class TestInventoryStorageCSRQueue(unittest.TestCase):
    """Test cases for the CSR approval queue."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_create_and_get_csr(self):
        csr_id = self.storage.create_csr(
            {"subject": "new.example.com", "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----"}
        )
        csr = self.storage.get_csr(csr_id)
        self.assertEqual(csr["subject"], "new.example.com")
        self.assertEqual(csr["status"], "pending")

    def test_get_csr_missing(self):
        self.assertIsNone(self.storage.get_csr("nope"))

    def test_list_csrs_filter_by_status(self):
        pending_id = self.storage.create_csr(
            {"subject": "a.example.com", "csr_pem": "csr-a"}
        )
        approved_id = self.storage.create_csr(
            {"subject": "b.example.com", "csr_pem": "csr-b"}
        )
        self.storage.resolve_csr(approved_id, "approved", "admin@example.com", certificate_serial="s1")

        pending, total_pending = self.storage.list_csrs(status="pending")
        self.assertEqual(total_pending, 1)
        self.assertEqual(pending[0]["id"], pending_id)

        approved, total_approved = self.storage.list_csrs(status="approved")
        self.assertEqual(total_approved, 1)
        self.assertEqual(approved[0]["id"], approved_id)
        self.assertEqual(approved[0]["certificate_serial"], "s1")

    def test_resolve_csr_twice_fails(self):
        csr_id = self.storage.create_csr({"subject": "a.example.com", "csr_pem": "csr-a"})
        self.assertTrue(self.storage.resolve_csr(csr_id, "rejected", "admin@example.com"))
        # Already resolved -> no longer pending -> second resolution is a no-op.
        self.assertFalse(self.storage.resolve_csr(csr_id, "approved", "admin@example.com"))

    def test_resolve_csr_missing(self):
        self.assertFalse(self.storage.resolve_csr("nope", "approved", "admin@example.com"))


class TestInventoryStorageActivityLog(unittest.TestCase):
    """Test cases for the activity log."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _entry(self, **overrides):
        entry = {
            "action": "created",
            "actor": "admin@example.com",
            "target": "certificate",
            "target_id": "s1",
            "target_name": "example.com",
            "status": "success",
            "source": "Web App",
        }
        entry.update(overrides)
        return entry

    def test_add_and_list_logs(self):
        self.storage.add_log(self._entry())
        logs, total = self.storage.list_logs()
        self.assertEqual(total, 1)
        self.assertEqual(logs[0]["action"], "created")

    def test_list_logs_filter_by_action_and_status(self):
        self.storage.add_log(self._entry(action="created", status="success"))
        self.storage.add_log(self._entry(action="revoked", status="failed"))
        logs, total = self.storage.list_logs(action="revoked")
        self.assertEqual(total, 1)
        self.assertEqual(logs[0]["status"], "failed")

        logs, total = self.storage.list_logs(status="failed")
        self.assertEqual(total, 1)
        self.assertEqual(logs[0]["action"], "revoked")

    def test_list_logs_filter_by_target_and_source(self):
        self.storage.add_log(self._entry(target="certificate", source="Web App"))
        self.storage.add_log(self._entry(target="profile", source="ACME"))

        logs, total = self.storage.list_logs(target="profile")
        self.assertEqual(total, 1)
        self.assertEqual(logs[0]["source"], "ACME")

        logs, total = self.storage.list_logs(source="Web App")
        self.assertEqual(total, 1)
        self.assertEqual(logs[0]["target"], "certificate")

    def test_list_logs_search(self):
        self.storage.add_log(self._entry(target_name="api.example.com", actor="alice@example.com"))
        self.storage.add_log(self._entry(target_name="mail.example.com", actor="bob@example.com"))
        logs, total = self.storage.list_logs(search="alice")
        self.assertEqual(total, 1)
        self.assertEqual(logs[0]["target_name"], "api.example.com")

    def test_list_logs_pagination(self):
        for i in range(3):
            self.storage.add_log(self._entry(target_name=f"host{i}.example.com"))
        logs, total = self.storage.list_logs(page=1, page_size=2)
        self.assertEqual(total, 3)
        self.assertEqual(len(logs), 2)


class TestInventoryStorageAlerts(unittest.TestCase):
    """Test cases for alerts."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage = InventoryStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _alert(self, **overrides):
        alert = {
            "type": "expiring",
            "severity": "medium",
            "title": "Certificate Expiring",
            "message": "Certificate for example.com expires soon.",
        }
        alert.update(overrides)
        return alert

    def test_add_and_list_alerts(self):
        self.storage.add_alert(self._alert())
        alerts = self.storage.list_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertFalse(alerts[0]["acknowledged"])

    def test_list_alerts_filter_by_acknowledged(self):
        alert_id = self.storage.add_alert(self._alert())
        self.storage.add_alert(self._alert(title="Another alert"))
        self.storage.acknowledge_alert(alert_id)

        unacked = self.storage.list_alerts(acknowledged=False)
        self.assertEqual(len(unacked), 1)
        self.assertEqual(unacked[0]["title"], "Another alert")

        acked = self.storage.list_alerts(acknowledged=True)
        self.assertEqual(len(acked), 1)
        self.assertEqual(acked[0]["id"], alert_id)

    def test_acknowledge_alert_missing(self):
        self.assertFalse(self.storage.acknowledge_alert("nope"))

    def test_acknowledge_all_alerts(self):
        self.storage.add_alert(self._alert())
        self.storage.add_alert(self._alert(title="Another alert"))
        count = self.storage.acknowledge_all_alerts()
        self.assertEqual(count, 2)
        self.assertEqual(self.storage.list_alerts(acknowledged=False), [])

    def test_acknowledge_all_alerts_idempotent(self):
        self.storage.add_alert(self._alert())
        self.storage.acknowledge_all_alerts()
        self.assertEqual(self.storage.acknowledge_all_alerts(), 0)


class TestInventoryStorageContextManager(unittest.TestCase):
    """Test cases for context-manager usage and connection lifecycle."""

    def test_context_manager_closes_connection(self):
        temp_dir = tempfile.mkdtemp()
        try:
            with InventoryStorage(temp_dir) as storage:
                storage.initialize()
                storage.upsert_ca(
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
            self.assertIsNone(storage._connection)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
