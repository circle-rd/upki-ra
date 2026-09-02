"""
uPKI RA Server - Routes Unit Tests.

Unit tests for FastAPI routes.
"""

import unittest


class TestRoutes(unittest.TestCase):
    """Test cases for API routes."""

    def test_route_structure(self):
        """Test route module imports."""
        from upki_ra.routes import (
            create_client_routes,
            create_private_routes,
            create_public_routes,
        )

        # Should be callable
        self.assertTrue(callable(create_public_routes))
        self.assertTrue(callable(create_private_routes))
        self.assertTrue(callable(create_client_routes))


class TestAPIResponses(unittest.TestCase):
    """Test cases for API response formats."""

    def test_format_response_structure(self):
        """Test response format structure."""
        from upki_ra.utils.common import format_response

        response = format_response(status="success", data={"key": "value"})

        self.assertEqual(response["status"], "success")
        self.assertIn("data", response)

    def test_format_error_structure(self):
        """Test error format structure."""
        from upki_ra.utils.common import format_error

        response = format_error(message="Test error", code="TEST_ERROR", status_code=400)

        self.assertEqual(response["status"], "error")
        self.assertEqual(response["code"], "TEST_ERROR")
        self.assertEqual(response["message"], "Test error")


class TestRegistrationAuthority(unittest.TestCase):
    """Test cases for RegistrationAuthority class."""

    def test_ra_initialization(self):
        """Test RA can be initialized."""
        import shutil
        import tempfile

        from upki_ra.core import UPKILogger
        from upki_ra.registration_authority import RegistrationAuthority

        temp_dir = tempfile.mkdtemp()

        try:
            logger = UPKILogger(name="test-ra")
            ra = RegistrationAuthority(
                data_dir=temp_dir, ca_host="127.0.0.1", ca_port=5000, logger=logger
            )

            self.assertEqual(ra.data_dir, temp_dir)
            self.assertEqual(ra.ca_host, "127.0.0.1")
            self.assertEqual(ra.ca_port, 5000)

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_ra_default_values(self):
        """Test RA default values."""
        import shutil
        import tempfile

        from upki_ra.core import UPKILogger
        from upki_ra.registration_authority import RegistrationAuthority

        temp_dir = tempfile.mkdtemp()

        try:
            logger = UPKILogger(name="test-ra")
            ra = RegistrationAuthority(logger=logger)

            self.assertEqual(ra.ca_host, RegistrationAuthority.DEFAULT_CA_HOST)
            self.assertEqual(ra.ca_port, RegistrationAuthority.DEFAULT_CA_PORT)

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_is_registered_default(self):
        """Test is_registered returns False when not registered."""
        import shutil
        import tempfile

        from upki_ra.core import UPKILogger
        from upki_ra.registration_authority import RegistrationAuthority

        temp_dir = tempfile.mkdtemp()

        try:
            logger = UPKILogger(name="test-ra")
            ra = RegistrationAuthority(data_dir=temp_dir, logger=logger)

            # Should not be registered initially
            self.assertFalse(ra.is_registered())

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestZMQClient(unittest.TestCase):
    """Test cases for ZMQ client."""

    def test_zmq_client_initialization(self):
        """Test ZMQ client can be initialized."""
        from upki_ra.core import UPKILogger
        from upki_ra.utils.tools import ZMQClient

        logger = UPKILogger(name="test-zmq")
        client = ZMQClient(host="127.0.0.1", port=5000, logger=logger)

        self.assertEqual(client.host, "127.0.0.1")
        self.assertEqual(client.port, 5000)
        self.assertEqual(client.connection_url, "tcp://127.0.0.1:5000")

    def test_zmq_client_defaults(self):
        """Test ZMQ client default values."""
        from upki_ra.utils.tools import ZMQClient

        client = ZMQClient()

        self.assertEqual(client.host, ZMQClient.DEFAULT_HOST)
        self.assertEqual(client.port, ZMQClient.DEFAULT_PORT)
        self.assertEqual(client.timeout, ZMQClient.DEFAULT_TIMEOUT)

    def test_registration_client_defaults(self):
        """Test RegistrationClient default port."""
        from upki_ra.utils.tools import RegistrationClient

        client = RegistrationClient()

        # Registration uses port 5001
        self.assertEqual(client.port, 5001)


class TestTLSAuth(unittest.TestCase):
    """Test cases for TLS authentication."""

    def test_tls_auth_initialization(self):
        """Test TLS auth can be initialized."""
        from upki_ra.core import UPKILogger
        from upki_ra.utils.tlsauth import TLSAuth

        logger = UPKILogger(name="test-tls")
        auth = TLSAuth(ca_cert="/path/to/ca.crt", logger=logger)

        self.assertEqual(auth.ca_cert, "/path/to/ca.crt")

    def test_tls_auth_admin_dns(self):
        """Test admin DN management."""
        from upki_ra.utils.tlsauth import TLSAuth

        auth = TLSAuth()

        # Initially empty
        self.assertEqual(len(auth.admin_dns), 0)

        # Set admin DNS
        dns_list = ["/C=US/O=Test/CN=admin1", "/C=US/O=Test/CN=admin2"]
        auth.admin_dns = dns_list

        self.assertEqual(len(auth.admin_dns), 2)

    def test_is_admin(self):
        """Test admin authorization check."""
        from upki_ra.utils.tlsauth import TLSAuth

        auth = TLSAuth()
        auth.admin_dns = ["/C=US/O=Test/CN=admin1"]

        # Should be admin
        self.assertTrue(auth.is_admin("/C=US/O=Test/CN=admin1"))

        # Should not be admin
        self.assertFalse(auth.is_admin("/C=US/O=Test/CN=other"))

    def test_extract_cn_from_dn(self):
        """Test CN extraction from DN."""
        from upki_ra.utils.tlsauth import TLSAuth

        auth = TLSAuth()

        cn = auth.extract_cn_from_dn("/C=US/O=Test/CN=test.example.com")
        self.assertEqual(cn, "test.example.com")

        cn = auth.extract_cn_from_dn("CN=test,O=Org,C=US")
        self.assertEqual(cn, "test")


class TestErrorResponseShape(unittest.TestCase):
    """Regression tests for the RA app's global error handlers (`ra_server.py`).

    `format_error()` used to return a `(dict, status_code)` tuple while every
    call site used it as `detail=format_error(...)` - the whole tuple ended
    up as `HTTPException.detail`, and depending on which global exception
    handler picked it up, a client ended up with either a Python-repr string
    with no top-level `code` field, or (for 404s specifically) a hardcoded
    generic message that silently discarded the real code/message entirely.
    These tests hit the REAL app built by `ra_server.create_app()` (not a
    bare `FastAPI()` with just routes attached, which bypasses the buggy
    handlers entirely and would never have caught this).
    """

    @classmethod
    def setUpClass(cls):
        import importlib.util
        import os
        import tempfile

        from fastapi.testclient import TestClient

        from upki_ra.core.upki_logger import UPKILogger
        from upki_ra.registration_authority import RegistrationAuthority

        ra_server_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ra_server.py")
        spec = importlib.util.spec_from_file_location("ra_server", ra_server_path)
        ra_server = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ra_server)

        cls.temp_dir = tempfile.mkdtemp()
        cls.ra = RegistrationAuthority(
            data_dir=cls.temp_dir, logger=UPKILogger(name="test-error-shape")
        )
        cls.app = ra_server.create_app(cls.ra)
        cls.client = TestClient(cls.app)

    def test_structured_404_preserves_code_and_message(self):
        """A route-level `HTTPException(404, detail=format_error(...))` must
        keep its specific code/message, not be replaced by the generic 404
        handler's hardcoded "Not found"."""
        resp = self.client.get("/api/v1/inventory/certificates/DOES-NOT-EXIST")
        self.assertEqual(resp.status_code, 404)
        body = resp.json()
        self.assertEqual(body["status"], "error")
        self.assertEqual(body["code"], "NOT_FOUND")
        self.assertEqual(body["message"], "Certificate not found")

    def test_unmatched_route_404_still_has_a_code(self):
        """A genuinely unmatched route (no `HTTPException` raised by any
        route handler) must still get a `code` field, not just a bare
        message."""
        resp = self.client.get("/api/v1/totally/bogus/path")
        self.assertEqual(resp.status_code, 404)
        body = resp.json()
        self.assertEqual(body["status"], "error")
        self.assertEqual(body["code"], "NOT_FOUND")

    def test_non_404_error_has_clean_code_not_a_tuple_repr(self):
        """A non-404 `HTTPException(..., detail=format_error(...))` must
        return the exact code/message, never a Python-repr string of the
        old `(dict, status_code)` tuple `format_error()` used to return."""
        self.ra.inventory.upsert_certificate(
            {
                "serial": "ERR-SHAPE-TEST",
                "dn": "CN=err-shape-test.example.com",
                "common_name": "err-shape-test.example.com",
                "key_type": "RSA-2048",
                "status": "valid",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_to": "2099-01-01T00:00:00Z",
            }
        )
        resp = self.client.post(
            "/api/v1/inventory/certificates/ERR-SHAPE-TEST/revoke",
            json={"reason": "not-a-real-reason"},
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.json()
        self.assertEqual(body["status"], "error")
        self.assertEqual(body["code"], "VALIDATION_ERROR")
        self.assertNotIn("status_code", body)
        # The old bug embedded the whole tuple's Python repr in the message,
        # e.g. "({'status': 'error', ...}, 400)" - that shape must be gone.
        self.assertNotIn("{'status'", body["message"])


if __name__ == "__main__":
    unittest.main()
