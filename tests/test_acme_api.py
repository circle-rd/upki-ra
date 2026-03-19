"""
uPKI RA Server - ACME API Unit Tests.

Unit tests for ACME protocol functions (JWS, base64url, JWK handling).
"""

import json
import shutil
import tempfile
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from upki_ra.routes.acme_api import (
    _base64url_decode,
    _base64url_encode,
    _jwk_to_public_key,
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

        self.assertIn("Unsupported curve", str(context.exception))


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

    def _create_jws(self, payload: str, algorithm: str) -> str:
        """Helper to create a test JWS."""
        from cryptography.hazmat.primitives import hashes

        # Create protected header
        protected = {"alg": algorithm}
        protected_b64 = _base64url_encode(json.dumps(protected).encode())

        # Sign the payload
        sign_input = f"{protected_b64}.{payload}".encode()

        if algorithm == "RS256":
            signature = self.private_key.sign(
                sign_input, padding.PKCS1v15(), hashes.SHA256()
            )
        elif algorithm == "ES256":
            signature = self.ec_private_key.sign(sign_input, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        signature_b64 = _base64url_encode(signature)

        return f"{protected_b64}.{payload}.{signature_b64}"

    def test_verify_jws_rs256(self):
        """Test JWS signature verification with RS256."""
        payload = _base64url_encode(b'{"test": "data"}')
        jws = self._create_jws(payload, "RS256")

        result = _verify_jws_signature(jws, self.public_key, "RS256")
        self.assertTrue(result)

    def test_verify_jws_es256(self):
        """Test JWS signature verification with ES256."""

        # Generate EC key for this test
        ec_private_key = ec.generate_private_key(
            ec.SECP256R1(), backend=default_backend()
        )
        ec_public_key = ec_private_key.public_key()

        payload = _base64url_encode(b'{"test": "data"}')

        # Create JWS with EC key
        protected = {"alg": "ES256"}
        protected_b64 = _base64url_encode(json.dumps(protected).encode())
        sign_input = f"{protected_b64}.{payload}".encode()
        signature = ec_private_key.sign(sign_input, ec.ECDSA(hashes.SHA256()))
        signature_b64 = _base64url_encode(signature)
        jws = f"{protected_b64}.{payload}.{signature_b64}"

        result = _verify_jws_signature(jws, ec_public_key, "ES256")
        self.assertTrue(result)

    def test_verify_jws_invalid_signature(self):
        """Test JWS signature verification with invalid signature."""
        payload = _base64url_encode(b'{"test": "data"}')
        jws = self._create_jws(payload, "RS256")

        # Modify the signature to make it invalid
        parts = jws.split(".")
        parts[2] = _base64url_encode(b"invalid_signature" * 10)
        invalid_jws = ".".join(parts)

        with self.assertRaises((ValueError, Exception)):
            _verify_jws_signature(invalid_jws, self.public_key, "RS256")

    def test_verify_jws_invalid_format(self):
        """Test JWS with invalid format."""
        invalid_jws = "not.a.valid.jws"

        with self.assertRaises(ValueError) as context:
            _verify_jws_signature(invalid_jws, self.public_key, "RS256")

        self.assertIn("Invalid JWS format", str(context.exception))

    def test_verify_jws_unsupported_algorithm(self):
        """Test JWS with unsupported algorithm."""
        payload = _base64url_encode(b'{"test": "data"}')
        jws = self._create_jws(payload, "RS256")

        with self.assertRaises(ValueError) as context:
            _verify_jws_signature(jws, self.public_key, "UNSUPPORTED")

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


if __name__ == "__main__":
    unittest.main()
