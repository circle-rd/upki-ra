"""
uPKI RA Server - Certificate Metadata Parsing Unit Tests.
"""

import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from upki_ra.utils.cert_metadata import (
    compute_status,
    extract_cn_from_dn,
    format_serial,
    parse_certificate_metadata,
)


def _build_certificate(
    *,
    common_name: str = "example.com",
    organization: str | None = "Example Corp",
    key=None,
    days_valid: int = 365,
    key_usage: x509.KeyUsage | None = None,
    sans: list[str] | None = None,
    serial_number: int | None = None,
) -> str:
    """Build a minimal self-signed certificate PEM for test purposes."""
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    subject = issuer = x509.Name(name_attrs)

    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial_number or x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=3650))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
    )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )

    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")


class TestExtractCnFromDn(unittest.TestCase):
    """Test cases for `extract_cn_from_dn`."""

    def test_rfc4514_format(self):
        self.assertEqual(extract_cn_from_dn("CN=example.com,O=Example Corp"), "example.com")

    def test_openssl_slash_format(self):
        self.assertEqual(extract_cn_from_dn("/CN=example.com/O=Example Corp"), "example.com")

    def test_no_cn(self):
        self.assertIsNone(extract_cn_from_dn("O=Example Corp"))

    def test_case_insensitive(self):
        self.assertEqual(extract_cn_from_dn("cn=example.com"), "example.com")


class TestFormatSerial(unittest.TestCase):
    """Test cases for `format_serial`."""

    def test_basic(self):
        self.assertEqual(format_serial(0xABCDEF), "AB:CD:EF")

    def test_odd_length_hex_padded(self):
        self.assertEqual(format_serial(0xA), "0A")

    def test_zero(self):
        self.assertEqual(format_serial(0), "00")


class TestComputeStatus(unittest.TestCase):
    """Test cases for `compute_status`."""

    def test_revoked_always_wins(self):
        future = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        self.assertEqual(compute_status(future, revoked=True), "revoked")

    def test_valid_when_not_yet_expired(self):
        future = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        self.assertEqual(compute_status(future), "valid")

    def test_expired_when_past(self):
        past = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
        self.assertEqual(compute_status(past), "expired")

    def test_naive_datetime_is_treated_as_utc(self):
        future_naive = datetime.datetime.now(datetime.UTC).replace(tzinfo=None) + datetime.timedelta(
            days=1
        )
        self.assertEqual(compute_status(future_naive), "valid")


class TestParseCertificateMetadata(unittest.TestCase):
    """Test cases for `parse_certificate_metadata`."""

    def test_basic_fields(self):
        pem = _build_certificate(
            common_name="api.example.com", organization="Example Corp", serial_number=0xAABBCC
        )
        metadata = parse_certificate_metadata(pem)

        self.assertEqual(metadata["serial"], "AA:BB:CC")
        self.assertEqual(metadata["common_name"], "api.example.com")
        self.assertEqual(metadata["organization"], "Example Corp")
        self.assertIn("api.example.com", metadata["dn"])
        self.assertEqual(metadata["issuer_dn"], "api.example.com")  # self-signed: issuer CN == subject CN
        self.assertEqual(metadata["status"], "valid")

    def test_rsa_key_type(self):
        pem = _build_certificate(key=rsa.generate_private_key(public_exponent=65537, key_size=4096))
        metadata = parse_certificate_metadata(pem)
        self.assertEqual(metadata["key_type"], "RSA-4096")

    def test_ecdsa_p256_key_type(self):
        pem = _build_certificate(key=ec.generate_private_key(ec.SECP256R1()))
        metadata = parse_certificate_metadata(pem)
        self.assertEqual(metadata["key_type"], "ECDSA-P256")

    def test_ecdsa_p384_key_type(self):
        pem = _build_certificate(key=ec.generate_private_key(ec.SECP384R1()))
        metadata = parse_certificate_metadata(pem)
        self.assertEqual(metadata["key_type"], "ECDSA-P384")

    def test_unsupported_key_type_falls_back_to_unknown(self):
        # Ed25519 needs algorithm=None when signing, which `_build_certificate`
        # doesn't special-case - test the private `_key_type` helper directly
        # against a minimal stand-in certificate instead of a full X.509 cert.
        from unittest.mock import MagicMock

        from cryptography.hazmat.primitives.asymmetric import ed25519

        from upki_ra.utils.cert_metadata import _key_type

        fake_cert = MagicMock()
        fake_cert.public_key.return_value = ed25519.Ed25519PrivateKey.generate().public_key()
        self.assertEqual(_key_type(fake_cert), "UNKNOWN")

    def test_key_usage_extension(self):
        usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        pem = _build_certificate(key_usage=usage)
        metadata = parse_certificate_metadata(pem)
        self.assertEqual(set(metadata["key_usage"]), {"digitalSignature", "keyEncipherment"})

    def test_no_key_usage_extension_defaults_empty(self):
        pem = _build_certificate()
        metadata = parse_certificate_metadata(pem)
        self.assertEqual(metadata["key_usage"], [])

    def test_key_usage_encipher_and_decipher_only_require_key_agreement(self):
        usage = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=True,
            decipher_only=False,
        )
        pem = _build_certificate(key_usage=usage)
        metadata = parse_certificate_metadata(pem)
        self.assertIn("keyAgreement", metadata["key_usage"])
        self.assertIn("encipherOnly", metadata["key_usage"])
        self.assertNotIn("decipherOnly", metadata["key_usage"])

    def test_key_usage_decipher_only(self):
        usage = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=True,
        )
        pem = _build_certificate(key_usage=usage)
        metadata = parse_certificate_metadata(pem)
        self.assertIn("decipherOnly", metadata["key_usage"])
        self.assertNotIn("encipherOnly", metadata["key_usage"])

    def test_sans(self):
        pem = _build_certificate(sans=["example.com", "www.example.com"])
        metadata = parse_certificate_metadata(pem)
        self.assertEqual(metadata["san"], ["example.com", "www.example.com"])

    def test_no_sans_defaults_empty(self):
        pem = _build_certificate()
        metadata = parse_certificate_metadata(pem)
        self.assertEqual(metadata["san"], [])

    def test_expired_certificate_status(self):
        pem = _build_certificate(days_valid=-30)
        metadata = parse_certificate_metadata(pem)
        self.assertEqual(metadata["status"], "expired")

    def test_invalid_pem_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_certificate_metadata("not a certificate")


if __name__ == "__main__":
    unittest.main()
