"""
uPKI RA Server - Certificate Metadata Parsing.

Parses an issued certificate's PEM body into the flat metadata shape the
inventory index (`upki_ra.storage.InventoryStorage`/`upki_ra.schemas.Certificate`)
needs: subject/organization/issuer/validity/key type/key usage/SANs/status.

This is intentionally separate from `upki_ra.utils.common`'s CSR-focused
helpers (`extract_cn_from_csr`, etc.) since it operates on issued
certificates, not requests.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import Certificate as X509Certificate
from cryptography.x509 import Name, load_pem_x509_certificate
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier

# KeyUsage extension attribute name -> Upkiweb `keyUsage` string.
_KEY_USAGE_FIELDS: list[tuple[str, str]] = [
    ("digital_signature", "digitalSignature"),
    ("content_commitment", "nonRepudiation"),
    ("key_encipherment", "keyEncipherment"),
    ("data_encipherment", "dataEncipherment"),
    ("key_agreement", "keyAgreement"),
    ("key_cert_sign", "keyCertSign"),
    ("crl_sign", "cRLSign"),
]

_EC_CURVE_KEY_TYPES: dict[str, str] = {
    "secp256r1": "ECDSA-P256",
    "secp384r1": "ECDSA-P384",
}

_CN_PATTERN = re.compile(r"CN=([^,/]+)", re.IGNORECASE)


def extract_cn_from_dn(dn: str) -> str | None:
    """Extract the Common Name from a DN string.

    Tolerates both RFC4514 (``CN=x,O=y``) and OpenSSL-style (``/CN=x/O=y``)
    formats, since both appear across this codebase's call sites.

    Args:
        dn: Distinguished Name string.

    Returns:
        The Common Name value, or None if not found.
    """
    match = _CN_PATTERN.search(dn)
    return match.group(1).strip() if match else None


def _attribute_value(name: Name, oid: ObjectIdentifier) -> str | None:
    for attribute in name:
        if attribute.oid == oid:
            value = attribute.value
            return value.decode("utf-8") if isinstance(value, bytes) else value
    return None


def _key_type(cert: X509Certificate) -> str:
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA-{public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return _EC_CURVE_KEY_TYPES.get(public_key.curve.name, f"ECDSA-{public_key.curve.name}")
    return "UNKNOWN"


def _key_usage(cert: X509Certificate) -> list[str]:
    try:
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except Exception:
        return []

    usages = [label for attribute, label in _KEY_USAGE_FIELDS if getattr(extension, attribute, False)]
    # encipher_only/decipher_only are only meaningful (and only readable without
    # raising) when key_agreement is set.
    if getattr(extension, "key_agreement", False):
        if getattr(extension, "encipher_only", False):
            usages.append("encipherOnly")
        if getattr(extension, "decipher_only", False):
            usages.append("decipherOnly")
    return usages


def _sans(cert: X509Certificate) -> list[str]:
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except Exception:
        return []

    names = []
    for name in extension:
        value = getattr(name, "value", None)
        names.append(str(value) if value is not None else str(name))
    return names


def compute_status(valid_to: datetime, *, revoked: bool = False, now: datetime | None = None) -> str:
    """Derive a ``valid|expired|revoked`` status from validity + revocation state.

    Args:
        valid_to: Certificate expiry date.
        revoked: Whether the certificate is currently revoked.
        now: Reference time (defaults to the current UTC time), mainly for tests.

    Returns:
        "revoked", "expired" or "valid".
    """
    if revoked:
        return "revoked"
    current = now or datetime.now(UTC)
    if valid_to.tzinfo is None:
        valid_to = valid_to.replace(tzinfo=UTC)
    return "valid" if valid_to > current else "expired"


def format_serial(serial_number: int) -> str:
    """Format an integer serial number as uppercase colon-separated hex.

    Args:
        serial_number: Certificate serial number.

    Returns:
        E.g. ``"AB:CD:01"``.
    """
    hex_str = format(serial_number, "x")
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    return ":".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2)).upper()


def parse_certificate_metadata(cert_pem: str) -> dict[str, Any]:
    """Parse a PEM certificate into an `InventoryStorage.upsert_certificate` row.

    Args:
        cert_pem: Certificate in PEM format (a leading/trailing CA chain
            appended to the same string is tolerated - only the first
            certificate block is parsed).

    Returns:
        Dict with keys serial, dn, common_name, organization, issuer_dn,
        key_type, key_usage, san, valid_from, valid_to, status.
        `ca_id`/`profile_id`/`source` are the caller's responsibility to
        fill in, since they aren't derivable from the certificate bytes alone.

    Raises:
        ValueError: If the certificate cannot be parsed.
    """
    try:
        cert = load_pem_x509_certificate(
            cert_pem.encode("utf-8") if isinstance(cert_pem, str) else cert_pem
        )
    except Exception as exc:
        raise ValueError(f"Invalid certificate: {exc}") from exc

    common_name = _attribute_value(cert.subject, NameOID.COMMON_NAME) or ""
    organization = _attribute_value(cert.subject, NameOID.ORGANIZATION_NAME)
    issuer_cn = _attribute_value(cert.issuer, NameOID.COMMON_NAME)

    valid_from = cert.not_valid_before_utc
    valid_to = cert.not_valid_after_utc

    return {
        "serial": format_serial(cert.serial_number),
        "dn": cert.subject.rfc4514_string(),
        "common_name": common_name,
        "organization": organization,
        "issuer_dn": issuer_cn or cert.issuer.rfc4514_string(),
        "key_type": _key_type(cert),
        "key_usage": _key_usage(cert),
        "san": _sans(cert),
        "valid_from": valid_from.isoformat(),
        "valid_to": valid_to.isoformat(),
        "status": compute_status(valid_to),
        "pem": cert_pem if isinstance(cert_pem, str) else cert_pem.decode("utf-8"),
    }
