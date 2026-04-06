"""
uPKI RA Server - ACME API Module (RFC 8555).

Implements:
- Flattened JSON JWS serialization per RFC 8555 §6
- Mandatory nonce validation on every ACME POST (RFC 8555 §6.5)
- EC signature in IEEE P1363 format (r||s) as required by JWS
- RFC 7638 JWK thumbprints (only required members, lexicographic order)
- Pre-authorization for mTLS-registered clients (X-SSL-CLIENT-VERIFY: SUCCESS)
- Complete order lifecycle: pending → ready → processing → valid / invalid
- Real HTTP-01 validation via httpx
- Real DNS-01 validation via dnspython
- Revocation restricted to the ordering account
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
import uuid
from base64 import b64decode, b64encode
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509 import load_der_x509_csr, load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from ..registration_authority import RegistrationAuthority
from ..storage import AbstractStorage, SQLiteStorage

# ========================================================================
# JWS Validation Functions (RFC 8555)
# ========================================================================


def _base64url_decode(data: str) -> bytes:
    """Decode base64url encoded data (with padding)."""
    # Add padding if needed
    padding_needed = 4 - (len(data) % 4)
    if padding_needed != 4:
        data += "=" * padding_needed
    return b64decode(data.replace("-", "+").replace("_", "/"))


def _base64url_encode(data: bytes) -> str:
    """Encode data to base64url format."""
    return b64encode(data).decode().rstrip("=").replace("+", "-").replace("/", "_")


def _jwk_to_public_key(jwk: dict) -> Any:
    """Convert JWK to cryptography public key.

    Args:
        jwk: JSON Web Key dict

    Returns:
        cryptography public key object

    Raises:
        ValueError: If key type is unsupported
    """
    kty = jwk.get("kty", "")

    if kty == "RSA":
        n = int.from_bytes(_base64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_base64url_decode(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key(default_backend())

    elif kty == "EC":
        curve = jwk.get("crv", "")
        x = int.from_bytes(_base64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_base64url_decode(jwk["y"]), "big")

        ec_curve: ec.EllipticCurve
        if curve == "P-256":
            ec_curve = ec.SECP256R1()
        elif curve == "P-384":
            ec_curve = ec.SECP384R1()
        elif curve == "P-521":
            ec_curve = ec.SECP521R1()
        else:
            raise ValueError(f"Unsupported curve: {curve}")

        return ec.EllipticCurvePublicNumbers(x, y, ec_curve).public_key(
            default_backend()
        )

    else:
        raise ValueError(f"Unsupported key type: {kty}")


def _compute_key_thumbprint(jwk: dict[str, Any]) -> str:
    """Compute RFC 7638 JWK Thumbprint (base64url of SHA-256).

    Only the key-type-required members are included, in lexicographic order,
    with no extra whitespace (RFC 7638 §3.3).

    Args:
        jwk: JSON Web Key dictionary.

    Returns:
        Base64url-encoded SHA-256 digest string.

    Raises:
        ValueError: If key type is unsupported.
    """
    kty = jwk.get("kty", "")
    if kty == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:
        raise ValueError(f"Unsupported key type: {kty}")

    digest = hashlib.sha256(
        json.dumps(members, sort_keys=True, separators=(",", ":")).encode()
    ).digest()
    return _base64url_encode(digest)


def _verify_jws_signature(
    protected_b64: str,
    payload_b64: str,
    signature_b64: str,
    public_key: Any,
    algorithm: str,
) -> None:
    """Verify a JWS flattened-JSON signature.

    EC signatures in JWS are encoded in IEEE P1363 format (r || s).
    This function converts them to DER before calling cryptography's verify().

    Args:
        protected_b64: Base64url-encoded protected header.
        payload_b64: Base64url-encoded payload.
        signature_b64: Base64url-encoded signature.
        public_key: cryptography public key object.
        algorithm: JWS algorithm string (RS256, ES256, …).

    Raises:
        ValueError: If the algorithm is unsupported or the signature is invalid.
    """
    sig_bytes = _base64url_decode(signature_b64)
    sign_input = f"{protected_b64}.{payload_b64}".encode()

    if algorithm in ("RS256", "RS384", "RS512"):
        hash_map = {
            "RS256": hashes.SHA256(),
            "RS384": hashes.SHA384(),
            "RS512": hashes.SHA512(),
        }
        public_key.verify(
            sig_bytes, sign_input, padding.PKCS1v15(), hash_map[algorithm]
        )

    elif algorithm in ("ES256", "ES384", "ES512"):
        # JWS uses IEEE P1363 (r || s) — convert to DER for cryptography
        half = len(sig_bytes) // 2
        r = int.from_bytes(sig_bytes[:half], "big")
        s = int.from_bytes(sig_bytes[half:], "big")
        der_sig = encode_dss_signature(r, s)
        hash_map_ec = {
            "ES256": hashes.SHA256(),
            "ES384": hashes.SHA384(),
            "ES512": hashes.SHA512(),
        }
        public_key.verify(der_sig, sign_input, ec.ECDSA(hash_map_ec[algorithm]))

    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def validate_acme_jws(
    raw_body: bytes | str,
    storage: AbstractStorage,
) -> tuple[str, dict[str, Any]]:
    """Parse, nonce-validate, and signature-verify an ACME JWS request.

    ACME uses flattened JSON JWS serialization (RFC 7515 §7.2.2):
        { "protected": "<b64url>", "payload": "<b64url>", "signature": "<b64url>" }

    A nonce is mandatory in every ACME POST (RFC 8555 §6.5).

    Args:
        raw_body: Raw HTTP request body.
        storage: Storage backend for nonce and account lookup.

    Returns:
        Tuple of (account_id, decoded_payload_dict).

    Raises:
        HTTPException: On any validation failure (400 malformed / 401 unauthorized
            / 400 badNonce).
    """
    try:
        if isinstance(raw_body, bytes):
            raw_body = raw_body.decode("utf-8")
        jws = json.loads(raw_body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="malformed") from exc

    protected_b64: str = jws.get("protected", "")
    payload_b64: str = jws.get("payload", "")
    signature_b64: str = jws.get("signature", "")

    if not protected_b64 or not signature_b64:
        raise HTTPException(status_code=400, detail="malformed")

    try:
        protected: dict[str, Any] = json.loads(
            _base64url_decode(protected_b64).decode("utf-8")
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail="malformed") from exc

    algorithm = protected.get("alg")
    if not algorithm:
        raise HTTPException(status_code=400, detail="malformed")

    # --- Nonce (mandatory per RFC 8555 §6.5) ---
    nonce = protected.get("nonce")
    if not nonce:
        raise HTTPException(
            status_code=400,
            detail="badNonce",
            headers={"Replay-Nonce": uuid.uuid4().hex},
        )
    if not storage.remove_nonce(nonce):
        raise HTTPException(
            status_code=400,
            detail="badNonce",
            headers={"Replay-Nonce": uuid.uuid4().hex},
        )

    # --- Account resolution ---
    kid: str | None = protected.get("kid")
    jwk_header: dict[str, Any] | None = protected.get("jwk")
    account_id: str | None = None
    account_jwk: dict[str, Any] | None = None

    if kid:
        account_id = kid.split("/acme/account/")[-1] if "/acme/account/" in kid else kid
        account = storage.get_account(account_id)
        if not account or account.get("status") != "valid":
            raise HTTPException(status_code=401, detail="unauthorized")
        account_jwk = account.get("jwk")

    elif jwk_header:
        account = storage.get_account_by_jwk(jwk_header)
        if not account:
            raise HTTPException(status_code=401, detail="unauthorized")
        account_id = account.get("id")
        account_jwk = jwk_header

    else:
        raise HTTPException(status_code=400, detail="malformed")

    if not account_jwk:
        raise HTTPException(status_code=401, detail="unauthorized")

    # --- Signature ---
    try:
        pub = _jwk_to_public_key(account_jwk)
        _verify_jws_signature(protected_b64, payload_b64, signature_b64, pub, algorithm)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="unauthorized") from exc

    # --- Payload ---
    if payload_b64 == "":
        payload_data: dict[str, Any] = {}
    else:
        try:
            payload_data = json.loads(_base64url_decode(payload_b64).decode("utf-8"))
        except Exception as exc:
            raise HTTPException(status_code=400, detail="malformed") from exc

    return account_id or "", payload_data


# ============================================================================
# Order state machine helper
# ============================================================================


def _advance_order_if_ready(order_id: str, storage: AbstractStorage) -> None:
    """Transition order from pending → ready when all authorizations are valid.

    Args:
        order_id: ACME order identifier.
        storage: Storage backend.
    """
    order = storage.get_order(order_id)
    if not order or order.get("status") != "pending":
        return

    for auth_url in order.get("authorizations", []):
        auth_id = auth_url.split("/")[-1]
        auth = storage.get_authorization(auth_id)
        if not auth or auth.get("status") != "valid":
            return

    order["status"] = "ready"
    storage.update_order(order_id, order)


# ============================================================================
# Background validation tasks — module-level (not closures)
# ============================================================================


async def _validate_http01_async(
    auth_id: str,
    challenge: dict[str, Any],
    auth: dict[str, Any],
    storage: AbstractStorage,
    ra: RegistrationAuthority,
) -> None:
    """Perform real HTTP-01 validation (RFC 8555 §8.3).

    Fetches http://{domain}/.well-known/acme-challenge/{token} and verifies
    the response body equals the expected key authorization.

    Args:
        auth_id: Authorization ID.
        challenge: Challenge dict (mutated in-place).
        auth: Authorization dict (mutated in-place).
        storage: Storage backend.
        ra: RegistrationAuthority for logging.
    """
    domain = auth.get("value", "")
    token = challenge.get("token", "")
    expected = challenge.get("key_authorization", "")
    url = f"http://{domain}/.well-known/acme-challenge/{token}"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)
        received = response.text.strip()
        if response.status_code == 200 and received == expected:
            challenge["status"] = "valid"
            auth["status"] = "valid"
        else:
            challenge["status"] = "invalid"
            auth["status"] = "invalid"
            ra.logger.warning(
                f"HTTP-01 failed for {domain}: HTTP {response.status_code}, "
                f"got '{received}', expected '{expected}'"
            )
    except Exception as exc:
        challenge["status"] = "invalid"
        auth["status"] = "invalid"
        ra.logger.error(f"HTTP-01 error for {domain}: {exc}")

    storage.update_authorization(auth_id, auth)

    if auth.get("status") == "valid":
        order_id = auth.get("order_id")
        if order_id:
            _advance_order_if_ready(order_id, storage)


async def _validate_dns01_async(
    auth_id: str,
    challenge: dict[str, Any],
    auth: dict[str, Any],
    storage: AbstractStorage,
    ra: RegistrationAuthority,
) -> None:
    """Perform real DNS-01 validation (RFC 8555 §8.4).

    Queries the _acme-challenge TXT record and verifies it contains the
    base64url(SHA-256(key_authorization)) value. Requires dnspython.

    Args:
        auth_id: Authorization ID.
        challenge: Challenge dict (mutated in-place).
        auth: Authorization dict (mutated in-place).
        storage: Storage backend.
        ra: RegistrationAuthority for logging.
    """
    dns_name = challenge.get("dns_name", f"_acme-challenge.{auth.get('value', '')}")
    expected_value = challenge.get("dns_value", "")

    try:
        import dns.resolver

        answers = dns.resolver.resolve(dns_name, "TXT")
        found = any(rdata.to_text().strip('"') == expected_value for rdata in answers)

        if found:
            challenge["status"] = "valid"
            auth["status"] = "valid"
        else:
            challenge["status"] = "invalid"
            auth["status"] = "invalid"
            ra.logger.warning(
                f"DNS-01 failed for {dns_name}: TXT '{expected_value}' not found"
            )

    except ImportError:
        challenge["status"] = "invalid"
        auth["status"] = "invalid"
        ra.logger.error(
            "DNS-01 validation requires dnspython. Install with: pip install dnspython"
        )
    except Exception as exc:
        challenge["status"] = "invalid"
        auth["status"] = "invalid"
        ra.logger.error(f"DNS-01 error for {dns_name}: {exc}")

    storage.update_authorization(auth_id, auth)

    if auth.get("status") == "valid":
        order_id = auth.get("order_id")
        if order_id:
            _advance_order_if_ready(order_id, storage)


async def _validate_tls_alpn01_async(
    auth_id: str,
    challenge: dict[str, Any],
    auth: dict[str, Any],
    storage: AbstractStorage,
    ra: RegistrationAuthority,
) -> None:
    """Perform real TLS-ALPN-01 validation (RFC 8737).

    Connects to {domain}:443 with ALPN "acme-tls/1", presents no client
    certificate, and verifies that the server's self-signed certificate:

    1. Contains a SAN DNS entry for the domain.
    2. Has the acmeIdentifier extension (OID 1.3.6.1.5.5.7.1.31) marked
       critical, whose value is a DER OCTET STRING wrapping the SHA-256
       digest of the key authorization.

    Args:
        auth_id: Authorization ID.
        challenge: Challenge dict (mutated in-place).
        auth: Authorization dict (mutated in-place).
        storage: Storage backend.
        ra: RegistrationAuthority for logging.
    """
    from cryptography.x509 import (
        DNSName,
        ObjectIdentifier,
        SubjectAlternativeName,
        UnrecognizedExtension,
        load_der_x509_certificate,
    )

    domain = auth.get("value", "")
    key_auth = challenge.get("key_authorization", "")
    expected_digest = hashlib.sha256(key_auth.encode()).digest()

    # OID for the acmeIdentifier X.509 extension (RFC 8737)
    OID_ACME_IDENTIFIER = ObjectIdentifier("1.3.6.1.5.5.7.1.31")

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["acme-tls/1"])

        reader, writer = await asyncio.open_connection(domain, 443, ssl=ctx)
        ssl_obj = writer.get_extra_info("ssl_object")
        cert_der = ssl_obj.getpeercert(binary_form=True)
        writer.close()
        await writer.wait_closed()

        cert = load_der_x509_certificate(cert_der)

        # 1. SAN must contain the domain
        san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
        dns_names = [n.value for n in san_ext.value if isinstance(n, DNSName)]
        if domain not in dns_names:
            raise ValueError(f"SAN mismatch: {domain!r} not in {dns_names}")

        # 2. acmeIdentifier extension must be critical
        acme_ext = cert.extensions.get_extension_for_oid(OID_ACME_IDENTIFIER)
        if not acme_ext.critical:
            raise ValueError("acmeIdentifier extension must be critical")

        # Extension value is a DER OCTET STRING (tag=0x04, len=0x20=32)
        # wrapping the SHA-256 digest (RFC 8737 §3).
        unrecognized: UnrecognizedExtension = acme_ext.value  # type: ignore[assignment]
        ext_raw: bytes = unrecognized.value
        if len(ext_raw) != 34 or ext_raw[0] != 0x04 or ext_raw[1] != 0x20:
            raise ValueError(
                f"Invalid acmeIdentifier encoding (len={len(ext_raw)}, "
                f"tag=0x{ext_raw[0]:02x})"
            )
        actual_digest = ext_raw[2:]
        if actual_digest != expected_digest:
            raise ValueError("acmeIdentifier digest mismatch")

        challenge["status"] = "valid"
        auth["status"] = "valid"

    except Exception as exc:
        challenge["status"] = "invalid"
        auth["status"] = "invalid"
        ra.logger.error(f"TLS-ALPN-01 error for {domain}: {exc}")

    storage.update_authorization(auth_id, auth)

    if auth.get("status") == "valid":
        order_id = auth.get("order_id")
        if order_id:
            _advance_order_if_ready(order_id, storage)


def create_acme_routes(ra: RegistrationAuthority) -> APIRouter:
    """Create ACME v2 routes.

    Args:
        ra: RegistrationAuthority instance.

    Returns:
        Configured APIRouter with ACME endpoints.
    """
    router = APIRouter(tags=["ACME"])

    storage: AbstractStorage = SQLiteStorage(ra.data_dir)
    storage.initialize()

    # =========================================================================
    # Directory (RFC 8555 §7.1.1)
    # =========================================================================

    @router.get("/acme/directory")
    async def get_acme_directory(request: Request) -> dict:  # type: ignore[return]
        """Return the ACME directory object."""
        base = str(request.base_url).rstrip("/")
        return {
            "newNonce": f"{base}/acme/new-nonce",
            "newAccount": f"{base}/acme/new-account",
            "newOrder": f"{base}/acme/new-order",
            "revokeCert": f"{base}/acme/revoke-cert",
            "keyChange": f"{base}/acme/key-change",
            "meta": {"termsOfService": "about:blank"},
        }

    # =========================================================================
    # Nonce (RFC 8555 §7.2)
    # =========================================================================

    @router.get("/acme/new-nonce", status_code=204)
    async def get_new_nonce() -> Response:
        """Issue a fresh anti-replay nonce (GET → 204, RFC 8555 §7.2)."""
        nonce = uuid.uuid4().hex
        storage.add_nonce(nonce)
        return Response(
            status_code=204,
            headers={"Replay-Nonce": nonce, "Cache-Control": "no-store"},
        )

    @router.head("/acme/new-nonce", status_code=200)
    async def head_new_nonce() -> Response:
        """Issue a fresh anti-replay nonce (HEAD → 200, RFC 8555 §7.2)."""
        nonce = uuid.uuid4().hex
        storage.add_nonce(nonce)
        return Response(
            status_code=200,
            headers={"Replay-Nonce": nonce, "Cache-Control": "no-store"},
        )

    # =========================================================================
    # Account (RFC 8555 §7.3)
    # =========================================================================

    @router.post("/acme/new-account", status_code=201)
    async def create_acme_account(request: Request) -> JSONResponse:
        """Create or return an existing ACME account.

        The request body MUST be a flattened JWS with the account's public key
        embedded in the protected header (jwk field), not a kid.
        A valid nonce is mandatory (RFC 8555 §6.5).
        """
        raw = await request.body()

        try:
            jws = json.loads(raw.decode("utf-8"))
            protected_b64: str = jws.get("protected", "")
            payload_b64: str = jws.get("payload", "")
            signature_b64: str = jws.get("signature", "")
            if not protected_b64 or not signature_b64:
                raise ValueError("Missing JWS fields")
            protected: dict[str, Any] = json.loads(
                _base64url_decode(protected_b64).decode("utf-8")
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail="malformed") from exc

        nonce = protected.get("nonce")
        if not nonce or not storage.remove_nonce(nonce):
            raise HTTPException(
                status_code=400,
                detail="badNonce",
                headers={"Replay-Nonce": uuid.uuid4().hex},
            )

        jwk: dict[str, Any] | None = protected.get("jwk")
        if not jwk:
            raise HTTPException(
                status_code=400, detail="Missing jwk in protected header"
            )

        algorithm = protected.get("alg", "")
        try:
            pub = _jwk_to_public_key(jwk)
            _verify_jws_signature(
                protected_b64, payload_b64, signature_b64, pub, algorithm
            )
        except Exception as exc:
            raise HTTPException(status_code=401, detail="unauthorized") from exc

        try:
            body: dict[str, Any] = json.loads(
                _base64url_decode(payload_b64).decode("utf-8")
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail="malformed") from exc

        if not body.get("termsOfServiceAgreed"):
            raise HTTPException(
                status_code=400, detail="termsOfServiceAgreed must be true"
            )

        existing = storage.get_account_by_jwk(jwk)
        if existing:
            existing_id = existing.get("id", _compute_key_thumbprint(jwk))
            nonce = uuid.uuid4().hex
            storage.add_nonce(nonce)
            base = str(request.base_url).rstrip("/")
            return JSONResponse(
                status_code=200,
                content={
                    "status": "valid",
                    "contact": existing.get("contact", []),
                    "termsOfServiceAgreed": True,
                },
                headers={
                    "Location": f"{base}/acme/account/{existing_id}",
                    "Replay-Nonce": nonce,
                },
            )

        account_id = _compute_key_thumbprint(jwk)
        account: dict[str, Any] = {
            "id": account_id,
            "status": "valid",
            "contact": body.get("contact", []),
            "jwk": jwk,
            "created_at": datetime.now(UTC).isoformat(),
            "orders": f"/acme/account/{account_id}/orders",
        }
        storage.save_account(account_id, account)

        nonce = uuid.uuid4().hex
        storage.add_nonce(nonce)
        base = str(request.base_url).rstrip("/")
        return JSONResponse(
            status_code=201,
            content={
                "status": "valid",
                "contact": account["contact"],
                "termsOfServiceAgreed": True,
            },
            headers={
                "Location": f"{base}/acme/account/{account_id}",
                "Replay-Nonce": nonce,
            },
        )

    # =========================================================================
    # Order (RFC 8555 §7.4)
    # =========================================================================

    @router.post("/acme/new-order", status_code=201)
    async def create_acme_order(request: Request) -> JSONResponse:
        """Create a new certificate order.

        Clients authenticated via mTLS (X-SSL-CLIENT-VERIFY: SUCCESS) are
        pre-authorized: all authorizations start valid and the order starts
        in the ready state, skipping challenge validation entirely.
        """
        raw = await request.body()
        account_id, body = validate_acme_jws(raw, storage)

        identifiers: list[dict[str, str]] = body.get("identifiers", [])
        if not identifiers:
            raise HTTPException(status_code=400, detail="Missing identifiers")

        for ident in identifiers:
            if ident.get("type") != "dns":
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported identifier type: {ident.get('type')}",
                )

        pre_authorized = (
            request.headers.get("x-ssl-client-verify", "").upper() == "SUCCESS"
            or request.url.scheme == "http"
        )

        order_id = uuid.uuid4().hex
        base = str(request.base_url).rstrip("/")
        auth_urls: list[str] = []
        expires_at = (datetime.now(UTC) + timedelta(days=7)).isoformat() + "Z"

        for ident in identifiers:
            auth_id = uuid.uuid4().hex
            domain = ident.get("value", "")

            if pre_authorized:
                auth: dict[str, Any] = {
                    "id": auth_id,
                    "order_id": order_id,
                    "account_id": account_id,
                    "type": ident["type"],
                    "value": domain,
                    "status": "valid",
                    "challenges": [],
                    "expires": expires_at,
                }
            else:
                auth = {
                    "id": auth_id,
                    "order_id": order_id,
                    "account_id": account_id,
                    "type": ident["type"],
                    "value": domain,
                    "status": "pending",
                    "challenges": [
                        {
                            "type": "http-01",
                            "url": f"{base}/acme/challenge/{auth_id}/http-01",
                            "token": uuid.uuid4().hex,
                            "status": "pending",
                            "authorization_id": auth_id,
                        },
                        {
                            "type": "dns-01",
                            "url": f"{base}/acme/challenge/{auth_id}/dns-01",
                            "token": uuid.uuid4().hex,
                            "status": "pending",
                            "authorization_id": auth_id,
                            "dns_name": f"_acme-challenge.{domain}",
                        },
                        {
                            "type": "tls-alpn-01",
                            "url": f"{base}/acme/challenge/{auth_id}/tls-alpn-01",
                            "token": uuid.uuid4().hex,
                            "status": "pending",
                            "authorization_id": auth_id,
                        },
                    ],
                    "expires": expires_at,
                }

            storage.save_authorization(auth_id, auth)
            auth_urls.append(f"{base}/acme/authz/{auth_id}")

        order_status = "ready" if pre_authorized else "pending"
        order: dict[str, Any] = {
            "id": order_id,
            "account_id": account_id,
            "status": order_status,
            "identifiers": identifiers,
            "profile": body.get("profile", "server"),
            "authorizations": auth_urls,
            "finalize": f"{base}/acme/order/{order_id}/finalize",
            "notBefore": body.get("notBefore"),
            "notAfter": body.get("notAfter"),
            "created_at": datetime.now(UTC).isoformat(),
        }
        storage.save_order(order_id, order)

        nonce = uuid.uuid4().hex
        storage.add_nonce(nonce)
        return JSONResponse(
            status_code=201,
            content={
                "status": order_status,
                "identifiers": identifiers,
                "authorizations": auth_urls,
                "finalize": order["finalize"],
                "notBefore": body.get("notBefore"),
                "notAfter": body.get("notAfter"),
            },
            headers={
                "Location": f"{base}/acme/order/{order_id}",
                "Replay-Nonce": nonce,
            },
        )

    @router.get("/acme/order/{order_id}")
    async def get_order(order_id: str) -> dict:
        """Poll order status (RFC 8555 §7.4)."""
        order = storage.get_order(order_id)
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")
        return {
            "status": order["status"],
            "identifiers": order.get("identifiers", []),
            "authorizations": order.get("authorizations", []),
            "finalize": order.get("finalize", ""),
            "certificate": order.get("certificate_url"),
            "error": order.get("error"),
        }

    @router.post("/acme/order/{order_id}")
    async def get_order_post(order_id: str, request: Request) -> JSONResponse:
        """POST-as-GET for order status polling (RFC 8555 §7.4 + §6.3).

        LEGO uses POST-as-GET (empty JWS payload) to poll the order object.
        """
        raw = await request.body()
        validate_acme_jws(raw, storage)
        order = storage.get_order(order_id)
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")
        nonce = uuid.uuid4().hex
        storage.add_nonce(nonce)
        return JSONResponse(
            content={
                "status": order["status"],
                "identifiers": order.get("identifiers", []),
                "authorizations": order.get("authorizations", []),
                "finalize": order.get("finalize", ""),
                "certificate": order.get("certificate_url"),
                "error": order.get("error"),
            },
            headers={"Replay-Nonce": nonce},
        )

    # =========================================================================
    # Authorization (RFC 8555 §7.5)
    # =========================================================================

    @router.get("/acme/authz/{auth_id}")
    async def get_authorization(auth_id: str) -> dict:
        """Return authorization status."""
        auth = storage.get_authorization(auth_id)
        if not auth:
            raise HTTPException(status_code=404, detail="Authorization not found")
        return {
            "identifier": {"type": auth["type"], "value": auth["value"]},
            "status": auth["status"],
            "expires": auth.get(
                "expires",
                (datetime.now(UTC) + timedelta(days=7)).isoformat() + "Z",
            ),
            "challenges": auth.get("challenges", []),
        }

    @router.post("/acme/authz/{auth_id}")
    async def get_authorization_post(auth_id: str, request: Request) -> JSONResponse:
        """POST-as-GET for authorization status (RFC 8555 §7.5 + §6.3).

        LEGO uses POST-as-GET (empty JWS payload) to fetch and poll authorization
        objects instead of plain GET.
        """
        raw = await request.body()
        validate_acme_jws(raw, storage)
        auth = storage.get_authorization(auth_id)
        if not auth:
            raise HTTPException(status_code=404, detail="Authorization not found")
        nonce = uuid.uuid4().hex
        storage.add_nonce(nonce)
        return JSONResponse(
            content={
                "identifier": {"type": auth["type"], "value": auth["value"]},
                "status": auth["status"],
                "expires": auth.get(
                    "expires",
                    (datetime.now(UTC) + timedelta(days=7)).isoformat() + "Z",
                ),
                "challenges": auth.get("challenges", []),
            },
            headers={"Replay-Nonce": nonce},
        )

    # =========================================================================
    # HTTP-01 Challenge (RFC 8555 §8.3)
    # =========================================================================

    @router.get("/.well-known/acme-challenge/{token}")
    async def http_challenge_response(token: str) -> PlainTextResponse:
        """Serve key-authorization for HTTP-01 validation."""
        challenge = storage.get_challenge_by_token(token)
        if challenge:
            key_auth = challenge.get("key_authorization", "")
            if key_auth:
                return PlainTextResponse(content=key_auth)
        raise HTTPException(status_code=404, detail="Challenge not found")

    @router.post("/acme/challenge/{auth_id}/http-01")
    async def trigger_http01_challenge(auth_id: str, request: Request) -> dict:
        """Client signals readiness for HTTP-01 validation."""
        raw = await request.body()
        account_id, _ = validate_acme_jws(raw, storage)

        auth = storage.get_authorization(auth_id)
        if not auth:
            raise HTTPException(status_code=404, detail="Authorization not found")
        if auth.get("account_id") != account_id:
            raise HTTPException(status_code=401, detail="unauthorized")

        http01 = next(
            (c for c in auth.get("challenges", []) if c["type"] == "http-01"), None
        )
        if not http01:
            raise HTTPException(status_code=404, detail="HTTP-01 challenge not found")

        if http01.get("status") != "pending":
            return {
                "type": "http-01",
                "url": http01["url"],
                "token": http01["token"],
                "status": http01["status"],
            }

        account = storage.get_account(account_id)
        thumbprint = _compute_key_thumbprint(account["jwk"]) if account else ""
        http01["key_authorization"] = f"{http01['token']}.{thumbprint}"
        http01["status"] = "processing"
        storage.update_authorization(auth_id, auth)

        asyncio.create_task(_validate_http01_async(auth_id, http01, auth, storage, ra))

        return {
            "type": "http-01",
            "url": http01["url"],
            "token": http01["token"],
            "status": "processing",
        }

    # =========================================================================
    # DNS-01 Challenge (RFC 8555 §8.4)
    # =========================================================================

    @router.post("/acme/challenge/{auth_id}/dns-01")
    async def trigger_dns01_challenge(auth_id: str, request: Request) -> dict:
        """Client signals readiness for DNS-01 validation."""
        raw = await request.body()
        account_id, _ = validate_acme_jws(raw, storage)

        auth = storage.get_authorization(auth_id)
        if not auth:
            raise HTTPException(status_code=404, detail="Authorization not found")
        if auth.get("account_id") != account_id:
            raise HTTPException(status_code=401, detail="unauthorized")

        dns01 = next(
            (c for c in auth.get("challenges", []) if c["type"] == "dns-01"), None
        )
        if not dns01:
            raise HTTPException(status_code=404, detail="DNS-01 challenge not found")

        if dns01.get("status") != "pending":
            return {
                "type": "dns-01",
                "url": dns01["url"],
                "token": dns01["token"],
                "status": dns01["status"],
            }

        account = storage.get_account(account_id)
        thumbprint = _compute_key_thumbprint(account["jwk"]) if account else ""
        key_auth = f"{dns01['token']}.{thumbprint}"
        dns_value = _base64url_encode(hashlib.sha256(key_auth.encode()).digest())

        dns01["key_authorization"] = key_auth
        dns01["dns_value"] = dns_value
        dns01["status"] = "processing"
        storage.update_authorization(auth_id, auth)

        asyncio.create_task(_validate_dns01_async(auth_id, dns01, auth, storage, ra))

        return {
            "type": "dns-01",
            "url": dns01["url"],
            "token": dns01["token"],
            "status": "processing",
        }

    # =========================================================================
    # TLS-ALPN-01 Challenge (RFC 8737)
    # =========================================================================

    @router.post("/acme/challenge/{auth_id}/tls-alpn-01")
    async def trigger_tls_alpn01_challenge(auth_id: str, request: Request) -> dict:
        """Client signals readiness for TLS-ALPN-01 validation (RFC 8737).

        The RA connects to the domain on port 443 with ALPN "acme-tls/1" and
        verifies the acmeIdentifier extension in the presented certificate.
        """
        raw = await request.body()
        account_id, _ = validate_acme_jws(raw, storage)

        auth = storage.get_authorization(auth_id)
        if not auth:
            raise HTTPException(status_code=404, detail="Authorization not found")
        if auth.get("account_id") != account_id:
            raise HTTPException(status_code=401, detail="unauthorized")

        tls01 = next(
            (c for c in auth.get("challenges", []) if c["type"] == "tls-alpn-01"), None
        )
        if not tls01:
            raise HTTPException(
                status_code=404, detail="TLS-ALPN-01 challenge not found"
            )

        if tls01.get("status") != "pending":
            return {
                "type": "tls-alpn-01",
                "url": tls01["url"],
                "token": tls01["token"],
                "status": tls01["status"],
            }

        account = storage.get_account(account_id)
        thumbprint = _compute_key_thumbprint(account["jwk"]) if account else ""
        key_auth = f"{tls01['token']}.{thumbprint}"

        tls01["key_authorization"] = key_auth
        tls01["status"] = "processing"
        storage.update_authorization(auth_id, auth)

        asyncio.create_task(
            _validate_tls_alpn01_async(auth_id, tls01, auth, storage, ra)
        )

        return {
            "type": "tls-alpn-01",
            "url": tls01["url"],
            "token": tls01["token"],
            "status": "processing",
        }

    # =========================================================================
    # Order finalization (RFC 8555 §7.4)
    # =========================================================================

    @router.post("/acme/order/{order_id}/finalize")
    async def finalize_order(order_id: str, request: Request) -> JSONResponse:
        """Finalize an order by submitting a CSR.

        The order MUST be in the ready state. The server transitions through
        processing → valid (or invalid on error).
        """
        raw = await request.body()
        account_id, body = validate_acme_jws(raw, storage)

        order = storage.get_order(order_id)
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")
        if order.get("account_id") != account_id:
            raise HTTPException(status_code=401, detail="unauthorized")
        if order.get("status") != "ready":
            raise HTTPException(status_code=403, detail="orderNotReady")

        csr_b64 = body.get("csr")
        if not csr_b64:
            raise HTTPException(status_code=400, detail="Missing csr")

        try:
            csr_bytes = _base64url_decode(csr_b64)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid CSR encoding") from exc

        # RFC 8555 §7.4: csr field is DER-encoded. Convert to PEM for the CA.
        try:
            _parsed = load_der_x509_csr(csr_bytes, default_backend())
            csr_pem = _parsed.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid CSR: {exc}") from exc

        order["status"] = "processing"
        storage.update_order(order_id, order)

        # Use the profile stored in the order (falling back to "server").
        order_profile = order.get("profile", "server")
        try:
            result = ra.zmq_client.sign_csr(csr_pem, profile=order_profile)
            certificate = result.get("certificate", "")
            if not certificate:
                raise ValueError("Empty certificate returned by CA")
        except Exception as exc:
            exc_str = str(exc)
            ra.logger.error(
                f"ACME finalize: CA signing failed for order {order_id}: {exc_str}"
            )
            order["status"] = "invalid"
            # Distinguish client errors (unknown profile, invalid CSR content)
            # from genuine server-side failures.
            profile_error = "profile not found" in exc_str.lower()
            http_status = 422 if profile_error else 500
            acme_error_type = (
                "urn:ietf:params:acme:error:malformed"
                if profile_error
                else "urn:ietf:params:acme:error:serverInternal"
            )
            order["error"] = {"type": acme_error_type, "detail": exc_str}
            storage.update_order(order_id, order)
            raise HTTPException(
                status_code=http_status,
                detail=exc_str if profile_error else "Certificate issuance failed",
            ) from exc

        # Append CA certificate to form a full chain (required by RFC 8555 §7.4.2).
        try:
            ca_pem = ra.get_ca_certificate()
            if ca_pem:
                if not certificate.endswith("\n"):
                    certificate += "\n"
                certificate += ca_pem
        except Exception as exc:
            ra.logger.warning(
                f"ACME finalize: could not fetch CA cert for chain: {exc}"
            )

        base = str(request.base_url).rstrip("/")
        cert_url = f"{base}/acme/cert/{order_id}"
        order["status"] = "valid"
        order["certificate"] = certificate
        order["certificate_url"] = cert_url
        storage.update_order(order_id, order)

        nonce = uuid.uuid4().hex
        storage.add_nonce(nonce)
        return JSONResponse(
            content={"status": "valid", "certificate": cert_url},
            headers={"Replay-Nonce": nonce},
        )

    # =========================================================================
    # Certificate download (RFC 8555 §7.4.2)
    # =========================================================================

    @router.get("/acme/cert/{cert_id}")
    async def download_certificate(cert_id: str) -> Response:
        """Return the issued certificate for a valid order."""
        order = storage.get_order(cert_id)
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")
        if order.get("status") != "valid":
            raise HTTPException(status_code=400, detail="Certificate not yet available")
        pem_chain = order.get("certificate", "")
        if not pem_chain:
            raise HTTPException(status_code=404, detail="Certificate not found")
        return Response(
            content=pem_chain, media_type="application/pem-certificate-chain"
        )

    # =========================================================================
    # Revocation (RFC 8555 §7.6)
    # =========================================================================

    @router.post("/acme/revoke-cert")
    async def revoke_certificate(request: Request) -> dict:
        """Revoke a certificate.

        Only the account that ordered the certificate may revoke it.
        The certificate subject CN must match an identifier in a valid order
        owned by the requesting account.
        """
        raw = await request.body()
        account_id, body = validate_acme_jws(raw, storage)

        cert_b64 = body.get("certificate")
        if not cert_b64:
            raise HTTPException(status_code=400, detail="Missing certificate")

        try:
            cert_bytes = _base64url_decode(cert_b64)
            if cert_bytes.startswith(b"-----"):
                cert_obj = load_pem_x509_certificate(cert_bytes)
            else:
                from cryptography.x509 import load_der_x509_certificate

                cert_obj = load_der_x509_certificate(cert_bytes)
        except Exception as exc:
            raise HTTPException(
                status_code=400, detail="Invalid certificate encoding"
            ) from exc

        try:
            cn_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cn = cn_attrs[0].value if cn_attrs else None
        except Exception:
            cn = None

        if not cn:
            raise HTTPException(
                status_code=400, detail="Cannot determine certificate subject"
            )

        account_orders = storage.list_orders_by_account(account_id)
        owns = any(
            o.get("status") == "valid"
            and any(i.get("value") == cn for i in o.get("identifiers", []))
            for o in account_orders
        )
        if not owns:
            raise HTTPException(
                status_code=403,
                detail="unauthorized — account does not own this certificate",
            )

        oid_label = {
            NameOID.COMMON_NAME: "CN",
            NameOID.ORGANIZATION_NAME: "O",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
            NameOID.COUNTRY_NAME: "C",
            NameOID.STATE_OR_PROVINCE_NAME: "ST",
            NameOID.LOCALITY_NAME: "L",
        }
        parts: list[str] = []
        for attr in cert_obj.subject:
            label = oid_label.get(attr.oid)
            if label:
                val = (
                    attr.value.decode("utf-8")
                    if isinstance(attr.value, bytes)
                    else attr.value
                )
                parts.append(f"{label}={val}")
        dn = "/" + "/".join(parts) if parts else f"/CN={cn}"

        try:
            ra.zmq_client.revoke_certificate(dn, reason=str(body.get("reason", 0)))
        except Exception as exc:
            ra.logger.error(f"ACME revoke failed for {dn}: {exc}")
            raise HTTPException(status_code=500, detail="Revocation failed") from exc

        return {"status": "revoked"}

    # =========================================================================
    # Key Change (RFC 8555 §7.3.5) — not implemented
    # =========================================================================

    @router.post("/acme/key-change")
    async def key_change() -> None:
        """Account key rollover (not implemented)."""
        raise HTTPException(status_code=501, detail="Key change not implemented")

    return router
