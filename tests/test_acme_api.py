"""
uPKI RA Server - ACME API Unit Tests.

Unit tests for ACME protocol functions (JWS, base64url, JWK handling).
"""

import datetime
import hashlib
import json
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from upki_ra.routes.acme_api import (
    _base64url_decode,
    _base64url_encode,
    _jwk_to_public_key,
    _validate_tls_alpn01_async,
    _verify_jws_signature,
)


class TestBase64URLEncoding(unittest.TestCase):
    """Test cases for base64url encoding/decoding functions."""

    def test_base64url_encode_standard(self):
        """Test base64url encoding with standard data."""
        data = b"Hello, World!"
        encoded = _base64url_encode(data)

        # Should not contain padding
        self.assertNotIn("=", encoded)
        # Should use URL-safe characters
        self.assertNotIn("+", encoded)
        self.assertNotIn("/", encoded)

    def test_base64url_encode_empty(self):
        """Test base64url encoding with empty data."""
        encoded = _base64url_encode(b"")
        self.assertEqual(encoded, "")

    def test_base64url_decode_standard(self):
        """Test base64url decoding with standard data."""
        # "SGVsbG8sIFdvcmxkIQ==" is "Hello, World!" in base64
        encoded = "SGVsbG8sIFdvcmxkIQ"
        decoded = _base64url_decode(encoded)
        self.assertEqual(decoded, b"Hello, World!")

    def test_base64url_decode_with_padding(self):
        """Test base64url decoding with padding already present."""
        encoded = "YQ"  # "a" in base64
        decoded = _base64url_decode(encoded)
        self.assertEqual(decoded, b"a")

    def test_base64url_decode_url_safe(self):
        """Test base64url decoding with URL-safe characters."""
        # "-" and "_" should be converted to "+" and "/"
        # "AB+" -> "AB-" in base64url
        encoded = "AB-"
        decoded = _base64url_decode(encoded)
        # AB- = 0x00 0x1f in base64
        self.assertEqual(decoded, b"\x00\x1f")


class TestJWKToPublicKey(unittest.TestCase):
    """Test cases for JWK to public key conversion."""

    def test_jwk_to_rsa_key(self):
        """Test converting RSA JWK to public key."""
        # Generate a test RSA key
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        # Extract numbers from the key
        n = public_key.public_numbers().n
        e = public_key.public_numbers().e

        jwk = {
            "kty": "RSA",
            "n": _base64url_encode(n.to_bytes(256, byteorder="big")),
            "e": _base64url_encode(e.to_bytes(4, byteorder="big")),
        }

        result = _jwk_to_public_key(jwk)
        self.assertIsNotNone(result)

    def test_jwk_to_ec_p256_key(self):
        """Test converting EC P-256 JWK to public key."""
        private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        public_key = private_key.public_key()

        # Extract public numbers
        public_numbers = public_key.public_numbers()

        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": _base64url_encode(public_numbers.x.to_bytes(32, byteorder="big")),
            "y": _base64url_encode(public_numbers.y.to_bytes(32, byteorder="big")),
        }

        result = _jwk_to_public_key(jwk)
        self.assertIsNotNone(result)

    def test_jwk_to_ec_p384_key(self):
        """Test converting EC P-384 JWK to public key."""
        private_key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
        public_key = private_key.public_key()

        public_numbers = public_key.public_numbers()

        jwk = {
            "kty": "EC",
            "crv": "P-384",
            "x": _base64url_encode(public_numbers.x.to_bytes(48, byteorder="big")),
            "y": _base64url_encode(public_numbers.y.to_bytes(48, byteorder="big")),
        }

        result = _jwk_to_public_key(jwk)
        self.assertIsNotNone(result)

    def test_jwk_unsupported_key_type(self):
        """Test JWK with unsupported key type."""
        jwk = {"kty": "UNKNOWN", "n": "dGVzdA"}

        with self.assertRaises(ValueError) as context:
            _jwk_to_public_key(jwk)

        self.assertIn("Unsupported key type", str(context.exception))

    def test_jwk_unsupported_curve(self):
        """Test EC JWK with unsupported curve."""
        jwk = {"kty": "EC", "crv": "P-999", "x": "dGVzdA", "y": "dGVzdA"}

        with self.assertRaises(ValueError) as context:
            _jwk_to_public_key(jwk)

        self.assertIn("Unsupported", str(context.exception))


class TestJWSSignature(unittest.TestCase):
    """Test cases for JWS signature verification."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        # Generate a test RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        # Also generate EC key for ES256 tests
        self.ec_private_key = ec.generate_private_key(
            ec.SECP256R1(), backend=default_backend()
        )
        self.ec_public_key = self.ec_private_key.public_key()

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_jws_parts(self, payload: str, algorithm: str) -> tuple[str, str, str]:
        """Helper to create JWS flattened-JSON parts (protected_b64, payload_b64, sig_b64).

        EC signatures are returned in IEEE P1363 format (r || s) as required by JWS.
        """
        from cryptography.hazmat.primitives import hashes

        protected = {"alg": algorithm}
        protected_b64 = _base64url_encode(json.dumps(protected).encode())
        sign_input = f"{protected_b64}.{payload}".encode()

        if algorithm == "RS256":
            sig_der = self.private_key.sign(
                sign_input, padding.PKCS1v15(), hashes.SHA256()
            )
            sig_b64 = _base64url_encode(sig_der)
        elif algorithm == "ES256":
            # DER signature from cryptography — convert to IEEE P1363 (r || s)
            sig_der = self.ec_private_key.sign(sign_input, ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(sig_der)
            sig_p1363 = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            sig_b64 = _base64url_encode(sig_p1363)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        return protected_b64, payload, sig_b64

    def test_verify_jws_rs256(self):
        """Test JWS signature verification with RS256."""
        payload = _base64url_encode(b'{"test": "data"}')
        protected_b64, payload_b64, sig_b64 = self._create_jws_parts(payload, "RS256")

        # Should not raise
        _verify_jws_signature(
            protected_b64, payload_b64, sig_b64, self.public_key, "RS256"
        )

    def test_verify_jws_es256(self):
        """Test JWS signature verification with ES256."""
        ec_private_key = ec.generate_private_key(
            ec.SECP256R1(), backend=default_backend()
        )
        ec_public_key = ec_private_key.public_key()

        payload = _base64url_encode(b'{"test": "data"}')
        protected = {"alg": "ES256"}
        protected_b64 = _base64url_encode(json.dumps(protected).encode())
        sign_input = f"{protected_b64}.{payload}".encode()

        # DER → P1363
        sig_der = ec_private_key.sign(sign_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(sig_der)
        sig_p1363 = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        sig_b64 = _base64url_encode(sig_p1363)

        # Should not raise
        _verify_jws_signature(protected_b64, payload, sig_b64, ec_public_key, "ES256")

    def test_verify_jws_invalid_signature(self):
        """Test JWS signature verification with invalid signature."""
        payload = _base64url_encode(b'{"test": "data"}')
        protected_b64, payload_b64, _ = self._create_jws_parts(payload, "RS256")
        bad_sig_b64 = _base64url_encode(b"invalid_signature" * 10)

        with self.assertRaises(InvalidSignature):
            _verify_jws_signature(
                protected_b64, payload_b64, bad_sig_b64, self.public_key, "RS256"
            )

    def test_verify_jws_invalid_format(self):
        """Test _verify_jws_signature raises on unsupported algorithm (replaces old format test)."""
        payload = _base64url_encode(b'{"test": "data"}')
        protected_b64, payload_b64, sig_b64 = self._create_jws_parts(payload, "RS256")

        with self.assertRaises(ValueError):
            _verify_jws_signature(
                protected_b64, payload_b64, sig_b64, self.public_key, "UNSUPPORTED"
            )

    def test_verify_jws_unsupported_algorithm(self):
        """Test JWS with unsupported algorithm."""
        payload = _base64url_encode(b'{"test": "data"}')
        protected_b64, payload_b64, sig_b64 = self._create_jws_parts(payload, "RS256")

        with self.assertRaises(ValueError) as context:
            _verify_jws_signature(
                protected_b64, payload_b64, sig_b64, self.public_key, "UNSUPPORTED"
            )

        self.assertIn("Unsupported algorithm", str(context.exception))


class TestACMERequestParsing(unittest.TestCase):
    """Test cases for ACME request parsing utilities."""

    def test_parse_jws_header(self):
        """Test parsing JWS protected header."""
        # Create a simple JWS
        protected = {"alg": "RS256", "kid": "https://example.com/acme/account/test"}
        protected_encoded = _base64url_encode(json.dumps(protected).encode())
        payload = _base64url_encode(b"{}")
        signature = _base64url_encode(b"test_signature")

        jws = f"{protected_encoded}.{payload}.{signature}"

        # Decode and parse
        parts = jws.split(".")
        self.assertEqual(len(parts), 3)

        decoded_protected = json.loads(_base64url_decode(parts[0]).decode())
        self.assertEqual(decoded_protected["alg"], "RS256")
        self.assertEqual(
            decoded_protected["kid"], "https://example.com/acme/account/test"
        )

    def test_extract_account_id_from_kid(self):
        """Test extracting account ID from kid URL."""
        kid = "https://example.com/acme/account/abc123"
        account_id = kid.split("/acme/account/")[-1]
        self.assertEqual(account_id, "abc123")

    def test_extract_account_id_from_simple_kid(self):
        """Test extracting account ID from simple kid."""
        kid = "abc123"
        account_id = kid.split("/acme/account/")[-1]
        self.assertEqual(account_id, "abc123")


class TestTLSALPN01Validation(unittest.IsolatedAsyncioTestCase):
    """Tests for TLS-ALPN-01 validation (RFC 8737)."""

    def _build_acme_cert(
        self, domain: str, key_auth: str, correct_digest: bool = True
    ) -> bytes:
        """Build a minimal self-signed certificate with an acmeIdentifier extension.

        Args:
            domain: The DNS name to include in the SAN.
            key_auth: The key authorization string whose SHA-256 is embedded.
            correct_digest: When False, embed a zeroed digest to simulate failure.

        Returns:
            DER-encoded certificate bytes.
        """
        import cryptography.x509 as x509

        key = rsa.generate_private_key(65537, 2048, default_backend())
        digest = hashlib.sha256(key_auth.encode()).digest()
        if not correct_digest:
            digest = b"\x00" * 32
        # RFC 8737: extension value is a DER OCTET STRING wrapping the digest
        ext_value = bytes([0x04, 0x20]) + digest

        acme_oid = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.31")
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(
                datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(domain)]),
                critical=False,
            )
            .add_extension(
                x509.UnrecognizedExtension(acme_oid, ext_value),
                critical=True,
            )
            .sign(key, hashes.SHA256(), default_backend())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def _make_mock_connection(self, cert_der: bytes):
        """Return (mock_reader, mock_writer) for asyncio.open_connection."""
        mock_ssl_obj = MagicMock()
        mock_ssl_obj.getpeercert.return_value = cert_der
        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = mock_ssl_obj
        mock_writer.wait_closed = AsyncMock()
        mock_reader = MagicMock()
        return mock_reader, mock_writer

    async def test_tls_alpn01_valid_cert(self):
        """Happy path: cert with correct acmeIdentifier → challenge status valid."""
        domain = "example.com"
        token = "testtoken"
        thumbprint = "testthumbprint"
        key_auth = f"{token}.{thumbprint}"

        cert_der = self._build_acme_cert(domain, key_auth, correct_digest=True)
        mock_reader, mock_writer = self._make_mock_connection(cert_der)

        challenge = {
            "type": "tls-alpn-01",
            "token": token,
            "key_authorization": key_auth,
            "status": "processing",
        }
        auth = {"value": domain, "status": "processing", "order_id": None}
        mock_storage = MagicMock()
        mock_ra = MagicMock()
        mock_ra.logger = MagicMock()

        with patch(
            "asyncio.open_connection",
            AsyncMock(return_value=(mock_reader, mock_writer)),
        ):
            await _validate_tls_alpn01_async(
                "auth1", challenge, auth, mock_storage, mock_ra
            )

        self.assertEqual(challenge["status"], "valid")
        self.assertEqual(auth["status"], "valid")
        mock_storage.update_authorization.assert_called_once()

    async def test_tls_alpn01_wrong_digest(self):
        """Wrong digest in acmeIdentifier → challenge status invalid."""
        domain = "example.com"
        token = "testtoken"
        thumbprint = "testthumbprint"
        key_auth = f"{token}.{thumbprint}"

        # Build cert with zeroed digest (simulates attacker presenting wrong cert)
        cert_der = self._build_acme_cert(domain, key_auth, correct_digest=False)
        mock_reader, mock_writer = self._make_mock_connection(cert_der)

        challenge = {
            "type": "tls-alpn-01",
            "token": token,
            "key_authorization": key_auth,
            "status": "processing",
        }
        auth = {"value": domain, "status": "processing", "order_id": None}
        mock_storage = MagicMock()
        mock_ra = MagicMock()
        mock_ra.logger = MagicMock()

        with patch(
            "asyncio.open_connection",
            AsyncMock(return_value=(mock_reader, mock_writer)),
        ):
            await _validate_tls_alpn01_async(
                "auth1", challenge, auth, mock_storage, mock_ra
            )

        self.assertEqual(challenge["status"], "invalid")
        self.assertEqual(auth["status"], "invalid")
        mock_ra.logger.error.assert_called_once()

    async def test_tls_alpn01_connection_error(self):
        """Network failure → challenge status invalid, error logged."""
        challenge = {
            "type": "tls-alpn-01",
            "token": "tok",
            "key_authorization": "tok.thumb",
            "status": "processing",
        }
        auth = {
            "value": "unreachable.example.com",
            "status": "processing",
            "order_id": None,
        }
        mock_storage = MagicMock()
        mock_ra = MagicMock()
        mock_ra.logger = MagicMock()

        with patch(
            "asyncio.open_connection",
            AsyncMock(side_effect=OSError("Connection refused")),
        ):
            await _validate_tls_alpn01_async(
                "auth1", challenge, auth, mock_storage, mock_ra
            )

        self.assertEqual(challenge["status"], "invalid")
        self.assertEqual(auth["status"], "invalid")
        mock_ra.logger.error.assert_called_once()


if __name__ == "__main__":
    unittest.main()
