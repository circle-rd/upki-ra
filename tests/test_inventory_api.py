"""
uPKI RA Server - Inventory API Unit Tests.

Integration tests for the `uPKI-app`-facing REST API
(`upki_ra/routes/inventory_api.py`), backed by a real `RegistrationAuthority`
instance whose `InventoryStorage` is a real temp-dir SQLite database and
whose `zmq_client` is mocked (no live CA needed for revoke/renew/certify).
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
from fastapi import FastAPI
from fastapi.testclient import TestClient

from upki_ra.core.upki_error import CAConnectionError
from upki_ra.core.upki_logger import UPKILogger
from upki_ra.registration_authority import RegistrationAuthority
from upki_ra.routes.inventory_api import create_inventory_routes
from upki_ra.routes.ws_api import create_ws_routes


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


class InventoryAPITestCase(unittest.TestCase):
    """Base test case wiring a FastAPI TestClient to a real RA + mocked ZMQ client."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.ra = RegistrationAuthority(
            data_dir=self.temp_dir, logger=UPKILogger(name="test-inventory-api")
        )
        self.zmq_client = MagicMock()
        self.ra._zmq_client = self.zmq_client  # bypass the real ZMQ connection

        app = FastAPI()
        app.include_router(create_inventory_routes(self.ra), prefix="/api/v1/inventory")
        app.include_router(create_ws_routes(self.ra), prefix="/api/v1/inventory")
        self.client = TestClient(app, raise_server_exceptions=True)

    def tearDown(self):
        self.ra.inventory.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _seed_certificate(self, **overrides):
        pem = _build_certificate(
            common_name=overrides.pop("common_name", "example.com"),
            days_valid=overrides.pop("days_valid", 365),
        )
        return self.ra.inventory_sync.record_issuance(
            pem, actor="system", source="API", **overrides
        )


class TestCertificatesEndpoints(InventoryAPITestCase):
    """Test cases for the /certificates endpoints."""

    def test_list_empty(self):
        resp = self.client.get("/api/v1/inventory/certificates")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["data"]["items"], [])
        self.assertEqual(body["data"]["total"], 0)

    def test_list_and_pagination(self):
        for i in range(3):
            self._seed_certificate(common_name=f"host{i}.example.com")

        resp = self.client.get(
            "/api/v1/inventory/certificates", params={"page": 1, "page_size": 2, "sort": "subject"}
        )
        body = resp.json()
        self.assertEqual(body["data"]["total"], 3)
        self.assertEqual(len(body["data"]["items"]), 2)
        self.assertEqual(body["data"]["items"][0]["subject"], "host0.example.com")

    def test_list_filter_by_status(self):
        self._seed_certificate(common_name="valid.example.com")
        revoked = self._seed_certificate(common_name="revoked.example.com")
        self.ra.inventory.set_certificate_status(revoked.id, "revoked")

        resp = self.client.get("/api/v1/inventory/certificates", params={"status": "revoked"})
        body = resp.json()
        self.assertEqual(body["data"]["total"], 1)
        self.assertEqual(body["data"]["items"][0]["subject"], "revoked.example.com")

    def test_list_filter_by_ca(self):
        self._seed_certificate(common_name="other-ca.example.com", ca_id="ca-2")
        self._seed_certificate(common_name="target-ca.example.com", ca_id="ca-1")

        resp = self.client.get("/api/v1/inventory/certificates", params={"ca": "ca-1"})
        body = resp.json()
        self.assertEqual(body["data"]["total"], 1)
        self.assertEqual(body["data"]["items"][0]["subject"], "target-ca.example.com")

    def test_list_search(self):
        self._seed_certificate(common_name="findme.example.com")
        self._seed_certificate(common_name="other.example.com")

        resp = self.client.get("/api/v1/inventory/certificates", params={"q": "findme"})
        body = resp.json()
        self.assertEqual(body["data"]["total"], 1)
        self.assertEqual(body["data"]["items"][0]["subject"], "findme.example.com")

    def test_list_pagination_beyond_range_returns_empty_page(self):
        self._seed_certificate(common_name="only-one.example.com")

        resp = self.client.get("/api/v1/inventory/certificates", params={"page": 99, "page_size": 10})
        body = resp.json()
        self.assertEqual(body["data"]["total"], 1)
        self.assertEqual(body["data"]["items"], [])

    def test_list_rejects_page_below_one(self):
        resp = self.client.get("/api/v1/inventory/certificates", params={"page": 0})
        self.assertEqual(resp.status_code, 422)

    def test_list_rejects_page_size_above_max(self):
        resp = self.client.get("/api/v1/inventory/certificates", params={"page_size": 101})
        self.assertEqual(resp.status_code, 422)

    def test_list_rejects_page_size_below_min(self):
        resp = self.client.get("/api/v1/inventory/certificates", params={"page_size": 0})
        self.assertEqual(resp.status_code, 422)

    def test_get_detail_success(self):
        cert = self._seed_certificate(common_name="detail.example.com")
        resp = self.client.get(f"/api/v1/inventory/certificates/{cert.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["data"]["subject"], "detail.example.com")

    def test_get_detail_not_found(self):
        resp = self.client.get("/api/v1/inventory/certificates/nope")
        self.assertEqual(resp.status_code, 404)

    def test_revoke_success(self):
        cert = self._seed_certificate(common_name="revoke.example.com")
        self.zmq_client.revoke_certificate.return_value = True

        resp = self.client.post(
            f"/api/v1/inventory/certificates/{cert.id}/revoke", json={"reason": "keyCompromise"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["data"]["status"], "revoked")
        self.zmq_client.revoke_certificate.assert_called_once()

    def test_revoke_not_found(self):
        resp = self.client.post("/api/v1/inventory/certificates/nope/revoke", json={})
        self.assertEqual(resp.status_code, 404)

    def test_revoke_invalid_reason_returns_400(self):
        cert = self._seed_certificate(common_name="revoke-bad-reason.example.com")
        resp = self.client.post(
            f"/api/v1/inventory/certificates/{cert.id}/revoke",
            json={"reason": "not-a-real-reason"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_revoke_ca_failure_returns_400(self):
        cert = self._seed_certificate(common_name="revoke-fail.example.com")
        self.zmq_client.revoke_certificate.return_value = False

        resp = self.client.post(f"/api/v1/inventory/certificates/{cert.id}/revoke", json={})
        self.assertEqual(resp.status_code, 400)

    def test_revoke_ca_connection_error_returns_503(self):
        cert = self._seed_certificate(common_name="revoke-503.example.com")
        self.zmq_client.revoke_certificate.side_effect = CAConnectionError("CA unreachable")

        resp = self.client.post(f"/api/v1/inventory/certificates/{cert.id}/revoke", json={})
        self.assertEqual(resp.status_code, 503)

    def test_revoke_unexpected_ca_error_returns_500(self):
        cert = self._seed_certificate(common_name="revoke-500.example.com")
        self.zmq_client.revoke_certificate.side_effect = RuntimeError("boom")

        resp = self.client.post(f"/api/v1/inventory/certificates/{cert.id}/revoke", json={})
        self.assertEqual(resp.status_code, 500)

    def test_renew_success(self):
        cert = self._seed_certificate(common_name="renew.example.com")
        new_pem = _build_certificate(common_name="renew.example.com", days_valid=730)
        self.zmq_client.renew_certificate.return_value = {"certificate": new_pem, "serial": 999}

        resp = self.client.post(f"/api/v1/inventory/certificates/{cert.id}/renew")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["data"]["subject"], "renew.example.com")
        # A renewal issues a brand-new serial, distinct from the original.
        self.assertNotEqual(resp.json()["data"]["id"], cert.id)

    def test_renew_not_found(self):
        resp = self.client.post("/api/v1/inventory/certificates/nope/renew")
        self.assertEqual(resp.status_code, 404)

    def test_renew_ca_connection_error_returns_503(self):
        cert = self._seed_certificate(common_name="renew-503.example.com")
        self.zmq_client.renew_certificate.side_effect = CAConnectionError("CA unreachable")

        resp = self.client.post(f"/api/v1/inventory/certificates/{cert.id}/renew")
        self.assertEqual(resp.status_code, 503)

    def test_renew_unexpected_ca_error_returns_500(self):
        cert = self._seed_certificate(common_name="renew-500.example.com")
        self.zmq_client.renew_certificate.side_effect = RuntimeError("boom")

        resp = self.client.post(f"/api/v1/inventory/certificates/{cert.id}/renew")
        self.assertEqual(resp.status_code, 500)

    def test_download_pem(self):
        cert = self._seed_certificate(common_name="download.example.com")
        resp = self.client.get(f"/api/v1/inventory/certificates/{cert.id}/download")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("BEGIN CERTIFICATE", resp.text)

    def test_download_der(self):
        cert = self._seed_certificate(common_name="download-der.example.com")
        resp = self.client.get(
            f"/api/v1/inventory/certificates/{cert.id}/download", params={"format": "der"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["content-type"], "application/pkix-cert")

    def test_download_not_found(self):
        resp = self.client.get("/api/v1/inventory/certificates/nope/download")
        self.assertEqual(resp.status_code, 404)

    def test_download_rejects_unsupported_format(self):
        cert = self._seed_certificate(common_name="download-pkcs12.example.com")
        resp = self.client.get(
            f"/api/v1/inventory/certificates/{cert.id}/download", params={"format": "pkcs12"}
        )
        self.assertEqual(resp.status_code, 422)


class TestCAsEndpoints(InventoryAPITestCase):
    """Test cases for the /cas endpoints."""

    def test_list_cas_empty(self):
        resp = self.client.get("/api/v1/inventory/cas")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["data"], [])

    def _seed_ca(self, **overrides):
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
        self.ra.inventory.upsert_ca(ca)
        return ca

    def test_list_cas(self):
        self._seed_ca()
        resp = self.client.get("/api/v1/inventory/cas")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()["data"]), 1)

    def test_get_ca_detail(self):
        self._seed_ca()
        resp = self.client.get("/api/v1/inventory/cas/ca-1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["data"]["name"], "Root CA")

    def test_get_ca_not_found(self):
        resp = self.client.get("/api/v1/inventory/cas/nope")
        self.assertEqual(resp.status_code, 404)

    def test_ca_graph(self):
        self._seed_ca(id="ca-root")
        self._seed_ca(id="ca-intermediate", type="intermediate", parent_id="ca-root")
        resp = self.client.get("/api/v1/inventory/cas/graph")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()["data"]
        self.assertEqual(len(body["nodes"]), 2)
        self.assertEqual(body["edges"], [{"source": "ca-root", "target": "ca-intermediate"}])


class TestProfilesEndpoints(InventoryAPITestCase):
    """Test cases for the /profiles endpoints."""

    def test_list_profiles_empty(self):
        resp = self.client.get("/api/v1/inventory/profiles")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["data"], [])

    def test_create_profile_missing_required_field_rejected(self):
        resp = self.client.post(
            "/api/v1/inventory/profiles",
            json={"name": "Incomplete"},  # missing keyType/validityDays
        )
        self.assertEqual(resp.status_code, 422)

    def _profile_payload(self, **overrides):
        payload = {
            "name": "Web Server",
            "description": "TLS server certs",
            "fields": [],
            "keyType": "RSA-2048",
            "validityDays": 365,
            "keyUsage": ["digitalSignature"],
        }
        payload.update(overrides)
        return payload

    def test_create_and_get_profile(self):
        resp = self.client.post("/api/v1/inventory/profiles", json=self._profile_payload())
        self.assertEqual(resp.status_code, 200)
        profile_id = resp.json()["data"]["id"]

        get_resp = self.client.get(f"/api/v1/inventory/profiles/{profile_id}")
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.json()["data"]["keyType"], "RSA-2048")

    def test_get_profile_not_found(self):
        resp = self.client.get("/api/v1/inventory/profiles/nope")
        self.assertEqual(resp.status_code, 404)

    def test_list_profiles(self):
        self.client.post("/api/v1/inventory/profiles", json=self._profile_payload())
        resp = self.client.get("/api/v1/inventory/profiles")
        self.assertEqual(len(resp.json()["data"]), 1)

    def test_update_profile(self):
        create_resp = self.client.post("/api/v1/inventory/profiles", json=self._profile_payload())
        profile_id = create_resp.json()["data"]["id"]

        update_resp = self.client.put(
            f"/api/v1/inventory/profiles/{profile_id}",
            json=self._profile_payload(name="Web Server v2", validityDays=730),
        )
        self.assertEqual(update_resp.status_code, 200)
        self.assertEqual(update_resp.json()["data"]["name"], "Web Server v2")
        self.assertEqual(update_resp.json()["data"]["validityDays"], 730)

    def test_update_profile_not_found(self):
        resp = self.client.put(
            "/api/v1/inventory/profiles/nope", json=self._profile_payload()
        )
        self.assertEqual(resp.status_code, 404)

    def test_delete_profile(self):
        create_resp = self.client.post("/api/v1/inventory/profiles", json=self._profile_payload())
        profile_id = create_resp.json()["data"]["id"]

        delete_resp = self.client.delete(f"/api/v1/inventory/profiles/{profile_id}")
        self.assertEqual(delete_resp.status_code, 200)
        self.assertIsNone(self.ra.inventory.get_profile(profile_id))

    def test_delete_profile_not_found(self):
        resp = self.client.delete("/api/v1/inventory/profiles/nope")
        self.assertEqual(resp.status_code, 404)


class TestCSRsEndpoints(InventoryAPITestCase):
    """Test cases for the /csrs endpoints."""

    def _make_csr_pem(self, common_name: str = "csr-node.example.com") -> str:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .sign(key, hashes.SHA256())
        )
        return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def test_create_and_list_csrs(self):
        resp = self.client.post(
            "/api/v1/inventory/csrs",
            json={"subject": "new.example.com", "csrPem": self._make_csr_pem("new.example.com")},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["data"]["status"], "pending")

        list_resp = self.client.get("/api/v1/inventory/csrs")
        self.assertEqual(list_resp.json()["data"]["total"], 1)

    def test_approve_csr_issues_certificate(self):
        csr_pem = self._make_csr_pem("approved.example.com")
        create_resp = self.client.post(
            "/api/v1/inventory/csrs", json={"subject": "approved.example.com", "csrPem": csr_pem}
        )
        csr_id = create_resp.json()["data"]["id"]

        issued_pem = _build_certificate(common_name="approved.example.com")
        self.zmq_client.sign_csr.return_value = {"certificate": issued_pem, "serial": 123}

        approve_resp = self.client.post(f"/api/v1/inventory/csrs/{csr_id}/approve")
        self.assertEqual(approve_resp.status_code, 200)
        self.assertEqual(approve_resp.json()["data"]["status"], "approved")

        certs = self.client.get("/api/v1/inventory/certificates").json()["data"]["items"]
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0]["subject"], "approved.example.com")

    def test_approve_csr_not_found(self):
        resp = self.client.post("/api/v1/inventory/csrs/nope/approve")
        self.assertEqual(resp.status_code, 404)

    def test_reject_csr(self):
        create_resp = self.client.post(
            "/api/v1/inventory/csrs",
            json={"subject": "rejected.example.com", "csrPem": self._make_csr_pem()},
        )
        csr_id = create_resp.json()["data"]["id"]

        reject_resp = self.client.post(f"/api/v1/inventory/csrs/{csr_id}/reject")
        self.assertEqual(reject_resp.status_code, 200)
        self.assertEqual(reject_resp.json()["data"]["status"], "rejected")

    def test_approve_already_resolved_csr_fails(self):
        create_resp = self.client.post(
            "/api/v1/inventory/csrs",
            json={"subject": "twice.example.com", "csrPem": self._make_csr_pem()},
        )
        csr_id = create_resp.json()["data"]["id"]
        self.client.post(f"/api/v1/inventory/csrs/{csr_id}/reject")

        resp = self.client.post(f"/api/v1/inventory/csrs/{csr_id}/approve")
        self.assertEqual(resp.status_code, 400)

    def test_reject_csr_not_found(self):
        resp = self.client.post("/api/v1/inventory/csrs/nope/reject")
        self.assertEqual(resp.status_code, 404)

    def test_reject_already_resolved_csr_fails(self):
        create_resp = self.client.post(
            "/api/v1/inventory/csrs",
            json={"subject": "reject-twice.example.com", "csrPem": self._make_csr_pem()},
        )
        csr_id = create_resp.json()["data"]["id"]
        self.client.post(f"/api/v1/inventory/csrs/{csr_id}/reject")

        resp = self.client.post(f"/api/v1/inventory/csrs/{csr_id}/reject")
        self.assertEqual(resp.status_code, 400)

    def test_approve_csr_with_invalid_csr_pem_returns_400(self):
        create_resp = self.client.post(
            "/api/v1/inventory/csrs",
            json={"subject": "bad-pem.example.com", "csrPem": "not a real csr"},
        )
        csr_id = create_resp.json()["data"]["id"]

        resp = self.client.post(f"/api/v1/inventory/csrs/{csr_id}/approve")
        self.assertEqual(resp.status_code, 400)

    def test_approve_csr_unexpected_ca_error_returns_500(self):
        create_resp = self.client.post(
            "/api/v1/inventory/csrs",
            json={"subject": "approve-500.example.com", "csrPem": self._make_csr_pem()},
        )
        csr_id = create_resp.json()["data"]["id"]
        self.zmq_client.sign_csr.side_effect = RuntimeError("boom")

        resp = self.client.post(f"/api/v1/inventory/csrs/{csr_id}/approve")
        self.assertEqual(resp.status_code, 500)

    def test_approve_csr_ca_connection_error_returns_503(self):
        create_resp = self.client.post(
            "/api/v1/inventory/csrs",
            json={"subject": "ca-down.example.com", "csrPem": self._make_csr_pem()},
        )
        csr_id = create_resp.json()["data"]["id"]
        self.zmq_client.sign_csr.side_effect = CAConnectionError("CA unreachable")

        resp = self.client.post(f"/api/v1/inventory/csrs/{csr_id}/approve")
        self.assertEqual(resp.status_code, 503)

    def test_list_csrs_filter_by_status(self):
        pending_resp = self.client.post(
            "/api/v1/inventory/csrs",
            json={"subject": "pending.example.com", "csrPem": self._make_csr_pem()},
        )
        rejected_resp = self.client.post(
            "/api/v1/inventory/csrs",
            json={"subject": "to-reject.example.com", "csrPem": self._make_csr_pem()},
        )
        self.client.post(f"/api/v1/inventory/csrs/{rejected_resp.json()['data']['id']}/reject")

        resp = self.client.get("/api/v1/inventory/csrs", params={"status": "pending"})
        body = resp.json()["data"]
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["id"], pending_resp.json()["data"]["id"])

    def test_list_csrs_pagination(self):
        for i in range(3):
            self.client.post(
                "/api/v1/inventory/csrs",
                json={"subject": f"host{i}.example.com", "csrPem": self._make_csr_pem()},
            )

        resp = self.client.get("/api/v1/inventory/csrs", params={"page": 1, "page_size": 2})
        body = resp.json()["data"]
        self.assertEqual(body["total"], 3)
        self.assertEqual(len(body["items"]), 2)


class TestStatsEndpoints(InventoryAPITestCase):
    """Test cases for the /stats endpoints."""

    def test_overview(self):
        self._seed_certificate(common_name="a.example.com")
        revoked = self._seed_certificate(common_name="b.example.com")
        self.ra.inventory.set_certificate_status(revoked.id, "revoked")

        resp = self.client.get("/api/v1/inventory/stats/overview")
        body = resp.json()["data"]
        self.assertEqual(body["total"], 2)
        self.assertEqual(body["revoked"], 1)
        self.assertEqual(body["pendingCSRs"], 0)

    def test_issuance_trend(self):
        self._seed_certificate(common_name="a.example.com")
        resp = self.client.get("/api/v1/inventory/stats/issuance-trend")
        self.assertEqual(resp.status_code, 200)
        self.assertGreaterEqual(len(resp.json()["data"]), 1)

    def test_by_profile(self):
        self._seed_certificate(common_name="a.example.com", profile_id="prof-1")
        resp = self.client.get("/api/v1/inventory/stats/by-profile")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["data"][0]["profileId"], "prof-1")

    def test_expiration_forecast(self):
        resp = self.client.get("/api/v1/inventory/stats/expiration-forecast", params={"months": 3})
        body = resp.json()["data"]
        self.assertEqual(len(body), 3)


class TestActivityEndpoint(InventoryAPITestCase):
    """Test cases for the /activity endpoint."""

    def test_list_activity_after_issuance(self):
        self._seed_certificate(common_name="a.example.com")
        resp = self.client.get("/api/v1/inventory/activity")
        body = resp.json()["data"]
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["action"], "created")

    def test_list_activity_filter_by_action(self):
        self._seed_certificate(common_name="a.example.com")
        resp = self.client.get("/api/v1/inventory/activity", params={"action": "revoked"})
        self.assertEqual(resp.json()["data"]["total"], 0)

    def test_list_activity_pagination(self):
        for i in range(3):
            self._seed_certificate(common_name=f"host{i}.example.com")

        resp = self.client.get("/api/v1/inventory/activity", params={"page": 1, "page_size": 2})
        body = resp.json()["data"]
        self.assertEqual(body["total"], 3)
        self.assertEqual(len(body["items"]), 2)

    def test_list_activity_rejects_invalid_sort_dir(self):
        resp = self.client.get("/api/v1/inventory/activity", params={"sort_dir": "sideways"})
        self.assertEqual(resp.status_code, 422)


class TestAlertsEndpoints(InventoryAPITestCase):
    """Test cases for the /alerts endpoints."""

    def test_list_and_ack_alert(self):
        alert_id = self.ra.inventory.add_alert(
            {"type": "expiring", "severity": "medium", "title": "t", "message": "m"}
        )
        resp = self.client.get("/api/v1/inventory/alerts")
        self.assertEqual(len(resp.json()["data"]), 1)

        ack_resp = self.client.post(f"/api/v1/inventory/alerts/{alert_id}/ack")
        self.assertEqual(ack_resp.status_code, 200)

        unacked = self.client.get(
            "/api/v1/inventory/alerts", params={"acknowledged": "false"}
        ).json()["data"]
        self.assertEqual(unacked, [])

    def test_ack_unknown_alert(self):
        resp = self.client.post("/api/v1/inventory/alerts/nope/ack")
        self.assertEqual(resp.status_code, 404)

    def test_list_alerts_acknowledged_true_filter(self):
        alert_id = self.ra.inventory.add_alert(
            {"type": "expiring", "severity": "medium", "title": "t", "message": "m"}
        )
        self.ra.inventory.add_alert(
            {"type": "error", "severity": "high", "title": "t2", "message": "m2"}
        )
        self.client.post(f"/api/v1/inventory/alerts/{alert_id}/ack")

        acked = self.client.get(
            "/api/v1/inventory/alerts", params={"acknowledged": "true"}
        ).json()["data"]
        self.assertEqual(len(acked), 1)
        self.assertEqual(acked[0]["id"], alert_id)

    def test_ack_all(self):
        self.ra.inventory.add_alert(
            {"type": "expiring", "severity": "low", "title": "t1", "message": "m1"}
        )
        self.ra.inventory.add_alert(
            {"type": "error", "severity": "high", "title": "t2", "message": "m2"}
        )
        resp = self.client.post("/api/v1/inventory/alerts/ack-all")
        self.assertEqual(resp.json()["data"]["acknowledged"], 2)


class TestGraphEndpoint(InventoryAPITestCase):
    """Test cases for the /graph correlation endpoint."""

    def test_certificate_root(self):
        cert = self._seed_certificate(common_name="graph.example.com")
        resp = self.client.get("/api/v1/inventory/graph", params={"root": f"certificate:{cert.id}"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()["data"]
        self.assertEqual([n["id"] for n in body["nodes"]], [f"certificate:{cert.id}"])

    def test_invalid_root_format(self):
        resp = self.client.get("/api/v1/inventory/graph", params={"root": "no-colon"})
        self.assertEqual(resp.status_code, 400)

    def test_unknown_root_type(self):
        resp = self.client.get("/api/v1/inventory/graph", params={"root": "widget:1"})
        self.assertEqual(resp.status_code, 400)

    def test_root_not_found(self):
        resp = self.client.get("/api/v1/inventory/graph", params={"root": "certificate:nope"})
        self.assertEqual(resp.status_code, 404)


class TestWebSocketGateway(InventoryAPITestCase):
    """End-to-end tests for the /ws broadcast gateway."""

    def test_revoke_broadcasts_certificate_revoked(self):
        cert = self._seed_certificate(common_name="ws-revoke.example.com")
        self.zmq_client.revoke_certificate.return_value = True

        with self.client.websocket_connect("/api/v1/inventory/ws") as ws:
            resp = self.client.post(
                f"/api/v1/inventory/certificates/{cert.id}/revoke", json={"reason": "unspecified"}
            )
            self.assertEqual(resp.status_code, 200)

            message = ws.receive_json()
            self.assertEqual(message["type"], "certificate.revoked")
            self.assertEqual(message["data"]["id"], cert.id)
            self.assertEqual(message["data"]["status"], "revoked")
            self.assertIn("ts", message)

    def test_csr_lifecycle_broadcasts_events(self):
        with self.client.websocket_connect("/api/v1/inventory/ws") as ws:
            create_resp = self.client.post(
                "/api/v1/inventory/csrs",
                json={"subject": "ws-csr.example.com", "csrPem": "-----BEGIN CERTIFICATE REQUEST-----"},
            )
            csr_id = create_resp.json()["data"]["id"]
            created_msg = ws.receive_json()
            self.assertEqual(created_msg["type"], "csr.created")

            reject_resp = self.client.post(f"/api/v1/inventory/csrs/{csr_id}/reject")
            self.assertEqual(reject_resp.status_code, 200)
            rejected_msg = ws.receive_json()
            self.assertEqual(rejected_msg["type"], "csr.rejected")

    def test_alert_ack_broadcasts_event(self):
        alert_id = self.ra.inventory.add_alert(
            {"type": "expiring", "severity": "medium", "title": "t", "message": "m"}
        )
        with self.client.websocket_connect("/api/v1/inventory/ws") as ws:
            resp = self.client.post(f"/api/v1/inventory/alerts/{alert_id}/ack")
            self.assertEqual(resp.status_code, 200)
            message = ws.receive_json()
            self.assertEqual(message["type"], "alert.acknowledged")

    def test_disconnected_client_does_not_break_broadcast(self):
        cert = self._seed_certificate(common_name="ws-disconnect.example.com")
        self.zmq_client.revoke_certificate.return_value = True

        with self.client.websocket_connect("/api/v1/inventory/ws"):
            pass  # connect then immediately disconnect

        # No listener left; the revoke call itself must still succeed.
        resp = self.client.post(
            f"/api/v1/inventory/certificates/{cert.id}/revoke", json={"reason": "unspecified"}
        )
        self.assertEqual(resp.status_code, 200)

    def test_disconnect_is_cleaned_up_from_manager(self):
        with self.client.websocket_connect("/api/v1/inventory/ws"):
            self.assertEqual(self.ra.ws_manager.connection_count, 1)

        # Starlette's TestClient synchronously tears down the connection on
        # context-manager exit, so the route's WebSocketDisconnect handler
        # (which calls ws_manager.disconnect) has already run by this point.
        self.assertEqual(self.ra.ws_manager.connection_count, 0)


if __name__ == "__main__":
    unittest.main()
