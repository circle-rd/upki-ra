"""
uPKI RA Server - Utils Module Unit Tests.

Unit tests for utility functions.
"""

import os
import shutil
import tempfile
import unittest

from pytest import fail
from upki_ra.utils.common import (
    build_dn,
    compute_sha256,
    decode_base64,
    encode_base64,
    ensure_directory,
    format_error,
    format_response,
    get_file_extension,
    is_pem_format,
    normalize_dn,
    parse_dn,
    parse_pem,
    read_file,
    read_json_file,
    sanitize_filename,
    validate_required_fields,
    write_file,
    write_json_file,
)
from upki_ra.utils.tlsauth import CertificateValidator


class TestCommonUtils(unittest.TestCase):
    """Test cases for common utility functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_ensure_directory(self):
        """Test directory creation."""
        test_dir = os.path.join(self.temp_dir, "subdir", "nested")
        ensure_directory(test_dir)
        self.assertTrue(os.path.exists(test_dir))

    def test_write_and_read_file(self):
        """Test file write and read."""
        test_file = os.path.join(self.temp_dir, "test.txt")
        content = "Test content"

        self.assertTrue(write_file(test_file, content))

        result = read_file(test_file)
        self.assertEqual(result, content)

    def test_read_nonexistent_file(self):
        """Test reading nonexistent file."""
        result = read_file("/nonexistent/path/file.txt")
        self.assertIsNone(result)

    def test_write_and_read_json(self):
        """Test JSON file operations."""
        test_file = os.path.join(self.temp_dir, "test.json")
        data = {"key": "value", "number": 42}

        self.assertTrue(write_json_file(test_file, data))

        result = read_json_file(test_file)
        self.assertEqual(result, data)

    def test_read_invalid_json(self):
        """Test reading invalid JSON."""
        test_file = os.path.join(self.temp_dir, "invalid.json")
        write_file(test_file, "{invalid json")

        result = read_json_file(test_file)
        self.assertIsNone(result)

    def test_encode_decode_base64(self):
        """Test base64 encoding and decoding."""
        original = b"Hello, World!"

        encoded = encode_base64(original)
        self.assertIsInstance(encoded, str)

        decoded = decode_base64(encoded)
        self.assertEqual(decoded, original)

    def test_decode_invalid_base64(self):
        """Test decoding invalid base64."""
        result = decode_base64("not-valid-base64!!!")
        self.assertIsNone(result)

    def test_parse_pem(self):
        """Test PEM parsing."""
        pem = """-----BEGIN CERTIFICATE-----
MIIBgDCCASegAwIBAgIBATANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1U
UEtJIFRlc3QgQ0EwHhcNMjEwMTAxMDAwMDAwWhcNMjIwMTAxMDAwMDAwWjAY
MRYwFAYDVQQDDA1QUEsgVGVzdCBDQTQwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAAR/A2Kfn+8m3+5JnK3mNl8l5pXK3mNl8l5pXK3mNl8l5pXK3mNl8l5pX
K3mNl8l5pXK3mNl8l5pXK3mNl8o4IGwTCCBr0wDgYDVR0PAQH/BAQDAgeAMBMG
A1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwSwYJYIZIAYb4QgEN
BEIARABBAEEAcwBhAGwAZQAgAFAAcgBvAHYAaQBkAGUAcgAgAHYAMQAuADgw
HQYDVR0OBBYEFH9YJ9YJ9YJ9YJ9YJ9YJ9YJ9YMB8GA1UdIwQYMBaAFH9YJ9YJ
9YJ9YJ9YJ9YJ9YJ9YMB0GA1UdEQQWMBSCCWxvY2FsaG9zdIcEfwAAATcw
-----END CERTIFICATE-----"""

        result = parse_pem(pem, "CERTIFICATE")
        self.assertIsNotNone(result)
        if result is None:
            return fail("Failed to parse PEM")
        self.assertEqual(len(result), 1)
        self.assertIn("-----BEGIN CERTIFICATE-----", result[0])

    def test_parse_pem_no_match(self):
        """Test parsing PEM with no matches."""
        result = parse_pem("not a pem", "CERTIFICATE")
        self.assertIsNone(result)

    def test_build_dn(self):
        """Test DN building."""
        components = {"C": "US", "O": "Company", "CN": "example.com"}

        dn = build_dn(components)
        self.assertIn("C=US", dn)
        self.assertIn("O=Company", dn)
        self.assertIn("CN=example.com", dn)

    def test_parse_dn(self):
        """Test DN parsing."""
        dn = "/C=US/O=Company/CN=test.example.com"

        components = parse_dn(dn)

        self.assertEqual(components.get("C"), "US")
        self.assertEqual(components.get("O"), "Company")
        self.assertEqual(components.get("CN"), "test.example.com")

    def test_compute_sha256(self):
        """Test SHA256 hashing."""
        result = compute_sha256("test string")

        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 64)  # SHA256 hex is 64 chars

    def test_normalize_dn(self):
        """Test DN normalization."""
        dn = "/C=US/O=Company/CN=Test.Example.COM"

        normalized = normalize_dn(dn)

        self.assertEqual(normalized, "/c=us/o=company/cn=test.example.com")

    def test_format_response(self):
        """Test response formatting."""
        response = format_response(
            status="success", data={"key": "value"}, message="Operation completed"
        )

        self.assertEqual(response["status"], "success")
        self.assertEqual(response["data"]["key"], "value")
        self.assertEqual(response["message"], "Operation completed")

    def test_format_error(self):
        """Test error formatting."""
        response, status_code = format_error(
            message="Error occurred", code="ERROR_CODE", status_code=400
        )

        self.assertEqual(response["status"], "error")
        self.assertEqual(response["code"], "ERROR_CODE")
        self.assertEqual(response["message"], "Error occurred")
        self.assertEqual(status_code, 400)

    def test_validate_required_fields(self):
        """Test required fields validation."""
        data = {"field1": "value1", "field2": "value2"}

        error = validate_required_fields(data, ["field1", "field2"])
        self.assertIsNone(error)

        error = validate_required_fields(data, ["field1", "field3"])
        self.assertIsNotNone(error)
        if error is None:
            return fail("Failed to validate required fields")

        self.assertIn("field3", error)

    def test_sanitize_filename(self):
        """Test filename sanitization."""
        result = sanitize_filename("test<>file?.txt")
        self.assertNotIn("<", result)
        self.assertNotIn(">", result)
        self.assertNotIn("?", result)

    def test_get_file_extension(self):
        """Test file extension extraction."""
        self.assertEqual(get_file_extension("test.txt"), "txt")
        self.assertEqual(get_file_extension("test.tar.gz"), "gz")
        self.assertEqual(get_file_extension("test"), "")

    def test_is_pem_format(self):
        """Test PEM format detection."""
        self.assertTrue(
            is_pem_format(
                "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
            )
        )
        self.assertFalse(is_pem_format("not a pem"))


class TestCertificateValidator(unittest.TestCase):
    """Test cases for certificate validation."""

    def test_validate_csr_valid(self):
        """Test CSR validation with valid CSR."""
        csr = """-----BEGIN CERTIFICATE REQUEST-----
MIIBkTCB+wIJAJHGOV9dP4NIMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnVu
dXNl
-----END CERTIFICATE REQUEST-----"""

        is_valid, error = CertificateValidator.validate_csr(csr)

        self.assertTrue(is_valid)
        self.assertEqual(error, "")

    def test_validate_csr_empty(self):
        """Test CSR validation with empty CSR."""
        is_valid, error = CertificateValidator.validate_csr("")

        self.assertFalse(is_valid)
        self.assertIn("empty", error.lower())

    def test_validate_csr_no_header(self):
        """Test CSR validation without PEM header."""
        is_valid, error = CertificateValidator.validate_csr("not a csr")

        self.assertFalse(is_valid)

    def test_validate_profile_valid(self):
        """Test profile validation with valid profile."""
        for profile in CertificateValidator.VALID_PROFILES:
            is_valid, error = CertificateValidator.validate_profile(profile)
            self.assertTrue(is_valid)

    def test_validate_profile_invalid(self):
        """Test profile validation with invalid profile."""
        is_valid, error = CertificateValidator.validate_profile("invalid_profile")

        self.assertFalse(is_valid)

    def test_validate_revocation_reason_empty(self):
        """Test revocation reason validation with empty reason."""
        is_valid, error = CertificateValidator.validate_revocation_reason("")

        self.assertTrue(is_valid)  # Empty is acceptable (defaults to unspecified)

    def test_validate_revocation_reason_invalid(self):
        """Test revocation reason validation with invalid reason."""
        is_valid, error = CertificateValidator.validate_revocation_reason(
            "invalid_reason"
        )

        self.assertFalse(is_valid)


if __name__ == "__main__":
    unittest.main()
