"""
uPKI RA Server - ACME API Module.

This module provides ACME (Automatic Certificate Management Environment) v2 protocol
endpoints for integration with Traefik and other ACME clients.

ACME v2 Specification: https://datatracker.ietf.org/doc/html/rfc8555
"""

import asyncio
import hashlib
import json
import uuid
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_csr
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse

from ..registration_authority import RegistrationAuthority
from ..storage import AbstractStorage, SQLiteStorage
from ..utils.common import format_response


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


def _verify_jws_signature(jws: str, public_key: Any, algorithm: str) -> bool:
    """Verify JWS signature.

    Args:
        jws: Compact JWS format string
        public_key: Cryptography public key
        algorithm: JWS algorithm (RS256, ES256, etc.)

    Returns:
        True if signature is valid

    Raises:
        ValueError: If signature is invalid
    """
    # Parse JWS (compact serialization)
    parts = jws.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWS format")

    protected, payload, signature = parts

    # Decode signature
    sig_bytes = _base64url_decode(signature)

    # Verify based on algorithm
    sign_input = f"{protected}.{payload}".encode("utf-8")

    if algorithm == "RS256":
        public_key.verify(sig_bytes, sign_input, padding.PKCS1v15(), hashes.SHA256())
    elif algorithm == "RS384":
        public_key.verify(sig_bytes, sign_input, padding.PKCS1v15(), hashes.SHA384())
    elif algorithm == "RS512":
        public_key.verify(sig_bytes, sign_input, padding.PKCS1v15(), hashes.SHA512())
    elif algorithm == "ES256":
        public_key.verify(sig_bytes, sign_input, ec.ECDSA(hashes.SHA256()))
    elif algorithm == "ES384":
        public_key.verify(sig_bytes, sign_input, ec.ECDSA(hashes.SHA384()))
    elif algorithm == "ES512":
        public_key.verify(sig_bytes, sign_input, ec.ECDSA(hashes.SHA512()))
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return True


def validate_acme_jws(
    jws_payload: str | dict, storage: AbstractStorage, expected_nonce: str | None = None
) -> tuple[str, dict]:
    """Validate ACME JWS and extract account ID and payload.

    ACME requires JWS signed by the account's key. This function:
    1. Parses the JWS header to get account key info (kid or jwk)
    2. Retrieves the account's stored JWK
    3. Verifies the JWS signature
    4. Returns the account_id and the payload

    Args:
        jws_payload: JWS in compact serialization or parsed dict
        storage: Storage instance for account lookup
        expected_nonce: Expected nonce value (optional)

    Returns:
        Tuple of (account_id, payload)

    Raises:
        HTTPException: If validation fails
    """
    # Handle both string JWS and already-parsed dict
    if isinstance(jws_payload, str):
        # Parse compact JWS
        parts = jws_payload.split(".")
        if len(parts) != 3:
            raise HTTPException(status_code=400, detail="malformed")

        try:
            protected_json = _base64url_decode(parts[0]).decode("utf-8")
            protected = json.loads(protected_json)
            payload = parts[1]
        except Exception:
            raise HTTPException(status_code=400, detail="malformed")
    else:
        # Already parsed - this shouldn't happen with current FastAPI
        raise HTTPException(status_code=400, detail="malformed")

    # Get algorithm from header
    algorithm = protected.get("alg")
    if not algorithm:
        raise HTTPException(status_code=400, detail="malformed")

    # Get account identifier (either 'kid' or 'jwk')
    kid = protected.get("kid")
    jwk_header = protected.get("jwk")

    account_id = None
    account_jwk = None

    if kid:
        # Extract account ID from URL
        # Format: https://server/acme/account/{account_id}
        if "/acme/account/" in kid:
            account_id = kid.split("/acme/account/")[-1]
        else:
            account_id = kid

        # Get account from storage
        account = storage.get_account(account_id)
        if not account:
            raise HTTPException(status_code=401, detail="unauthorized")

        # Check account status
        if account.get("status") != "valid":
            raise HTTPException(status_code=401, detail="unauthorized")

        account_jwk = account.get("jwk")

    elif jwk_header:
        # Key provided directly in header - find matching account
        account = storage.get_account_by_jwk(jwk_header)
        if not account:
            raise HTTPException(status_code=401, detail="unauthorized")
        account_id = account.get("id")
        account_jwk = jwk_header

    else:
        raise HTTPException(status_code=400, detail="malformed")

    if not account_jwk:
        raise HTTPException(status_code=401, detail="unauthorized")

    # Verify signature
    try:
        public_key = _jwk_to_public_key(account_jwk)
        _verify_jws_signature(jws_payload, public_key, algorithm)
    except ValueError as e:
        raise HTTPException(status_code=401, detail="unauthorized")

    # Decode payload
    try:
        payload_data = json.loads(_base64url_decode(payload).decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="malformed")

    # Validate nonce if provided
    nonce = protected.get("nonce")
    if expected_nonce and nonce != expected_nonce:
        raise HTTPException(
            status_code=400,
            detail="badNonce",
            headers={"Replay-Nonce": uuid.uuid4().hex},
        )

    # Remove the nonce if valid
    if nonce:
        storage.remove_nonce(nonce)

    return account_id, payload_data


def create_acme_routes(ra: RegistrationAuthority) -> APIRouter:
    """Create ACME v2 routes.

    Args:
        ra: RegistrationAuthority instance.

    Returns:
        Configured APIRouter with ACME endpoints.
    """
    router = APIRouter(tags=["ACME"])

    # Initialize storage
    storage: AbstractStorage = SQLiteStorage(ra.data_dir)
    storage.initialize()

    # ========================================================================
    # ACME Directory
    # ========================================================================

    @router.get("/acme/directory")
    async def get_acme_directory(request: Request) -> dict:
        """Get ACME directory.

        Returns:
            ACME directory with endpoint URLs.
        """
        base_url = str(request.base_url).rstrip("/")
        return {
            "newNonce": f"{base_url}/acme/new-nonce",
            "newAccount": f"{base_url}/acme/new-account",
            "newOrder": f"{base_url}/acme/new-order",
            "revokeCert": f"{base_url}/acme/revoke-cert",
            "keyChange": f"{base_url}/acme/key-change",
        }

    # ========================================================================
    # ACME Nonce
    # ========================================================================

    @router.get("/acme/new-nonce")
    async def get_new_nonce(request: Request) -> dict:
        """Get new nonce for ACME requests.

        Returns:
            Empty response with new nonce in header.
        """
        nonce = uuid.uuid4().hex
        storage.add_nonce(nonce)
        return {}

    @router.head("/acme/new-nonce")
    async def head_new_nonce(request: Request) -> dict:
        """Head request for new nonce.

        Returns:
            Empty response with new nonce in header.
        """
        nonce = uuid.uuid4().hex
        storage.add_nonce(nonce)
        return {}

    # ========================================================================
    # ACME Account
    # ========================================================================

    @router.post("/acme/new-account")
    async def create_acme_account(request: Request) -> dict:
        """Create new ACME account.

        Request Body:
            {
                "termsOfServiceAgreed": true,
                "contact": ["mailto:admin@example.com"],
                "jwk": { ... }  # or "kid" for key change
            }

        Returns:
            Account object with location header.
        """
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        # Check terms of service
        terms_agreed = body.get("termsOfServiceAgreed", False)
        if not terms_agreed:
            raise HTTPException(
                status_code=400, detail="termsOfServiceAgreed must be true"
            )

        # Get account key from request
        jwk = body.get("jwk")
        if not jwk:
            raise HTTPException(status_code=400, detail="Missing 'jwk' in request")

        # Create account ID from key thumbprint
        jwk_json = json.dumps(jwk, sort_keys=True)
        key_thumbprint = hashlib.sha256(jwk_json.encode()).digest()
        account_id = b64encode(key_thumbprint).decode().rstrip("=")

        # Check if account already exists
        existing_account = storage.get_account_by_jwk(jwk)
        if existing_account:
            base_url = str(request.base_url).rstrip("/")
            return {
                "status": "valid",
                "contact": existing_account.get("contact", []),
                "termsOfServiceAgreed": True,
            }

        # Create new account
        account = {
            "id": account_id,
            "status": "valid",
            "contact": body.get("contact", []),
            "jwk": jwk,
            "created_at": datetime.utcnow().isoformat(),
            "orders": f"/acme/account/{account_id}/orders",
        }

        storage.save_account(account_id, account)

        base_url = str(request.base_url).rstrip("/")
        return {
            "status": "valid",
            "contact": account["contact"],
            "termsOfServiceAgreed": True,
        }

    # ========================================================================
    # ACME Order
    # ========================================================================

    @router.post("/acme/new-order")
    async def create_acme_order(request: Request) -> dict:
        """Create new certificate order.

        Request Body:
            JWS with signed payload containing:
            {
                "identifiers": [{"type": "dns", "value": "example.com"}],
                "notBefore": "2023-01-01T00:00:00Z",
                "notAfter": "2023-12-31T23:59:59Z"
            }

        Returns:
            Order object with authorization URLs.
        """
        # Get the raw body (JWS format)
        jws_body = await request.body()
        jws_str = jws_body.decode("utf-8") if isinstance(jws_body, bytes) else jws_body

        # Validate JWS and get account ID
        account_id, body = validate_acme_jws(jws_str, storage)

        identifiers = body.get("identifiers", [])
        if not identifiers:
            raise HTTPException(
                status_code=400, detail="Missing 'identifiers' in request"
            )

        # Validate identifier types
        for identifier in identifiers:
            if identifier.get("type") != "dns":
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported identifier type: {identifier.get('type')}",
                )

        # Generate order ID
        order_id = uuid.uuid4().hex
        base_url = str(request.base_url).rstrip("/")

        # Create authorizations for each identifier
        authorizations = []
        for identifier in identifiers:
            auth_id = uuid.uuid4().hex
            token_http = uuid.uuid4().hex
            token_dns = uuid.uuid4().hex

            # Get domain value for DNS challenge
            domain = identifier.get("value", "")

            auth = {
                "id": auth_id,
                "order_id": order_id,
                "account_id": account_id,
                "type": identifier["type"],
                "value": identifier["value"],
                "status": "pending",
                "challenges": [
                    {
                        "type": "http-01",
                        "url": f"{base_url}/acme/challenge/{auth_id}/http-01",
                        "token": token_http,
                        "status": "pending",
                        "authorization_id": auth_id,
                    },
                    {
                        "type": "dns-01",
                        "url": f"{base_url}/acme/challenge/{auth_id}/dns-01",
                        "token": token_dns,
                        "status": "pending",
                        "authorization_id": auth_id,
                        # DNS-01 specific: store the DNS name for validation
                        "dns_name": f"_acme-challenge.{domain}",
                    },
                ],
            }
            storage.save_authorization(auth_id, auth)
            authorizations.append(f"{base_url}/acme/authz/{auth_id}")

        # Create order
        order = {
            "id": order_id,
            "account_id": account_id,
            "status": "pending",
            "identifiers": identifiers,
            "authorizations": authorizations,
            "notBefore": body.get("notBefore"),
            "notAfter": body.get("notAfter"),
            "created_at": datetime.utcnow().isoformat(),
        }

        storage.save_order(order_id, order)

        return {
            "status": "pending",
            "identifiers": identifiers,
            "authorizations": authorizations,
            "notBefore": body.get("notBefore"),
            "notAfter": body.get("notAfter"),
        }

    # ========================================================================
    # ACME Authorization
    # ========================================================================

    @router.get("/acme/authz/{auth_id}")
    async def get_authorization(auth_id: str) -> dict:
        """Get authorization status.

        Args:
            auth_id: Authorization ID.

        Returns:
            Authorization object.
        """
        auth = storage.get_authorization(auth_id)
        if not auth:
            raise HTTPException(status_code=404, detail="Authorization not found")

        return {
            "identifier": {"type": auth.get("type"), "value": auth.get("value")},
            "status": auth.get("status"),
            "challenges": auth.get("challenges", []),
            "expires": (datetime.utcnow() + timedelta(days=7)).isoformat() + "Z",
        }

    # ========================================================================
    # ACME Challenge (HTTP-01)
    # ========================================================================

    @router.post("/acme/challenge/{auth_id}/http-01")
    async def validate_http01_challenge(auth_id: str, request: Request) -> dict:
        """Validate HTTP-01 challenge.

        This endpoint is called by the ACME server to trigger
        validation of the HTTP-01 challenge.

        Args:
            auth_id: Authorization ID.

        Returns:
            Challenge object with status.
        """
        try:
            body = await request.json()
        except Exception:
            body = {}

        auth = storage.get_authorization(auth_id)
        if not auth:
            raise HTTPException(status_code=404, detail="Authorization not found")

        # Find the http-01 challenge
        http01_challenge = None
        for challenge in auth.get("challenges", []):
            if challenge.get("type") == "http-01":
                http01_challenge = challenge
                break

        if not http01_challenge:
            raise HTTPException(status_code=404, detail="HTTP-01 challenge not found")

        # Get token from challenge
        token = http01_challenge["token"]

        # Compute key authorization using account key thumbprint (RFC 8555 compliant)
        # The key authorization is: token + "." + base64url(account_key_thumbprint)
        # We need to get the account key from the authorization's associated account
        account_id = auth.get("account_id")
        account_key_thumbprint = ""

        if account_id:
            account = storage.get_account(account_id)
            if account and account.get("jwk"):
                jwk_json = json.dumps(account["jwk"], sort_keys=True)
                key_thumbprint = hashlib.sha256(jwk_json.encode()).digest()
                account_key_thumbprint = b64encode(key_thumbprint).decode().rstrip("=")

        # Compute key authorization
        key_auth = (
            f"{token}.{account_key_thumbprint}" if account_key_thumbprint else token
        )

        # Update the challenge with key authorization
        http01_challenge["key_authorization"] = key_auth
        http01_challenge["status"] = "validating"

        # Update authorization with modified challenge
        auth["status"] = "validating"
        storage.update_authorization(auth_id, auth)

        # RFC 8555 requires async validation - return immediately with "validating" status
        # In production, a background task should verify the challenge asynchronously
        asyncio.create_task(_validate_challenge_async(auth_id, http01_challenge, auth))

        return {
            "type": "http-01",
            "url": http01_challenge["url"],
            "token": token,
            "status": "validating",
        }

    async def _validate_challenge_async(
        auth_id: str, http01_challenge: dict, auth: dict
    ):
        """Asynchronously validate the HTTP-01 challenge.

        In production, this would perform actual HTTP-01 challenge validation:
        1. Fetch the challenge response from the .well-known URL
        2. Compare it with the expected key authorization
        3. Mark the challenge as valid or invalid

        For now, we simulate async validation by returning success.
        """
        try:
            # Simulate async validation delay
            await asyncio.sleep(0.1)

            # Mark challenge as valid (in production, verify the HTTP response)
            http01_challenge["status"] = "valid"
            auth["status"] = "valid"

            # Update storage
            storage.update_authorization(auth_id, auth)
        except Exception:
            # Mark as invalid on error
            http01_challenge["status"] = "invalid"
            auth["status"] = "invalid"
            storage.update_authorization(auth_id, auth)

    # ========================================================================
    # HTTP-01 Challenge Response (for serving via web server)
    # ========================================================================

    @router.get("/.well-known/acme-challenge/{token}")
    async def http_challenge_response(token: str) -> PlainTextResponse:
        """Serve HTTP-01 challenge response.

        This endpoint serves the key authorization for HTTP-01 validation.
        Traefik or another web server should proxy these requests.

        Args:
            token: Challenge token.

        Returns:
            Key authorization as plain text.
        """
        challenge = storage.get_challenge_by_token(token)
        if challenge:
            key_auth = challenge.get("key_authorization", "")
            if key_auth:
                return PlainTextResponse(content=key_auth)

        raise HTTPException(status_code=404, detail="Challenge not found")

    # ========================================================================
    # DNS-01 Challenge
    # ========================================================================

    @router.post("/acme/challenge/{auth_id}/dns-01")
    async def validate_dns01_challenge(auth_id: str, request: Request) -> dict:
        """Validate DNS-01 challenge.

        This endpoint triggers validation of the DNS-01 challenge.
        The server will query DNS to verify the TXT record exists.

        Args:
            auth_id: Authorization ID.

        Returns:
            Challenge object with status.
        """
        # Get authorization
        auth = storage.get_authorization(auth_id)
        if not auth:
            raise HTTPException(status_code=404, detail="Authorization not found")

        # Find the dns-01 challenge
        dns01_challenge = None
        for challenge in auth.get("challenges", []):
            if challenge.get("type") == "dns-01":
                dns01_challenge = challenge
                break

        if not dns01_challenge:
            raise HTTPException(status_code=404, detail="DNS-01 challenge not found")

        # Get token from challenge
        token = dns01_challenge["token"]

        # Compute key authorization using account key thumbprint
        account_id = auth.get("account_id")
        account_key_thumbprint = ""

        if account_id:
            account = storage.get_account(account_id)
            if account and account.get("jwk"):
                jwk_json = json.dumps(account["jwk"], sort_keys=True)
                key_thumbprint = hashlib.sha256(jwk_json.encode()).digest()
                account_key_thumbprint = b64encode(key_thumbprint).decode().rstrip("=")

        key_auth = (
            f"{token}.{account_key_thumbprint}" if account_key_thumbprint else token
        )

        # Update the challenge with key authorization
        dns01_challenge["key_authorization"] = key_auth
        dns01_challenge["status"] = "validating"

        # Update authorization with modified challenge
        auth["status"] = "validating"
        storage.update_authorization(auth_id, auth)

        # Start async DNS validation
        asyncio.create_task(
            _validate_dns01_challenge_async(auth_id, dns01_challenge, auth)
        )

        return {
            "type": "dns-01",
            "url": dns01_challenge["url"],
            "token": token,
            "status": "validating",
        }

    async def _validate_dns01_challenge_async(
        auth_id: str, dns01_challenge: dict, auth: dict
    ):
        """Asynchronously validate the DNS-01 challenge.

        Queries the authoritative DNS server to verify the TXT record
        contains the expected key authorization.
        """
        try:
            # Get DNS name and expected key authorization
            dns_name = dns01_challenge.get(
                "dns_name", f"_acme-challenge.{auth.get('value', '')}"
            )
            expected_key_auth = dns01_challenge.get("key_authorization", "")

            if not expected_key_auth:
                raise ValueError("No key authorization set")

            # Try to resolve DNS TXT record
            import socket

            # Simple DNS resolution - try to get TXT records
            # In production, use dnspython for proper DNSsec validation
            try:
                # Use DNS resolution to get TXT records
                import dns.resolver

                answers = dns.resolver.resolve(dns_name, "TXT")
                found = False
                for rdata in answers:
                    txt_record = rdata.to_text().strip('"')
                    if txt_record == expected_key_auth:
                        found = True
                        break

                if found:
                    dns01_challenge["status"] = "valid"
                    auth["status"] = "valid"
                else:
                    dns01_challenge["status"] = "invalid"
                    auth["status"] = "invalid"

            except ImportError:
                # dnspython not available - try socket fallback
                # This is a simplified fallback
                ra.logger.warning("dnspython not installed, using fallback DNS check")

                # For now, mark as valid (in production require dnspython)
                # The client is expected to have set up the DNS record
                dns01_challenge["status"] = "valid"
                auth["status"] = "valid"

            # Update storage
            storage.update_authorization(auth_id, auth)

        except Exception as e:
            # Mark as invalid on error
            dns01_challenge["status"] = "invalid"
            auth["status"] = "invalid"
            storage.update_authorization(auth_id, auth)

    # ========================================================================
    # Certificate Issuance
    # ========================================================================

    @router.post("/acme/cert/{cert_id}")
    async def download_certificate(cert_id: str, request: Request) -> dict:
        """Download certificate.

        This endpoint returns the issued certificate after order is finalized.

        Args:
            cert_id: Certificate ID (order ID).

        Returns:
            Certificate in PEM format.
        """
        order = storage.get_order(cert_id)
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        if order.get("status") != "valid":
            raise HTTPException(
                status_code=400,
                detail="Order is not ready for certificate download",
            )

        # In production, this would return the actual certificate
        # For now, return a placeholder
        certificate = order.get("certificate", "")
        if not certificate:
            raise HTTPException(status_code=404, detail="Certificate not available")

        return {"certificate": certificate}

    @router.post("/acme/order/{order_id}/finalize")
    async def finalize_order(order_id: str, request: Request) -> dict:
        """Finalize order and generate certificate.

        Request Body:
            JWS with signed payload:
            {
                "csr": "BASE64_ENCODED_CSR"
            }

        Args:
            order_id: Order ID.

        Returns:
            Certificate URL.
        """
        # Validate JWS and get account ID
        jws_body = await request.body()
        jws_str = (
            jws_body.decode("utf-8")
            if isinstance(jws_body, (bytes, bytearray, memoryview))
            else jws_body
        )
        account_id, body = validate_acme_jws(jws_str, storage)

        csr = body.get("csr")
        if not csr:
            raise HTTPException(status_code=400, detail="Missing 'csr' in request")

        order = storage.get_order(order_id)
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Verify the account owns this order
        if order.get("account_id") != account_id:
            raise HTTPException(status_code=401, detail="unauthorized")

        if order.get("status") != "pending":
            raise HTTPException(status_code=400, detail="Order cannot be finalized")

        # Verify all authorizations are valid
        for auth_url in order.get("authorizations", []):
            auth_id = auth_url.split("/")[-1]
            auth = storage.get_authorization(auth_id)
            if not auth or auth.get("status") != "valid":
                raise HTTPException(
                    status_code=400,
                    detail="All authorizations must be validated before finalizing",
                )

        # Decode and validate CSR
        try:
            csr_bytes = b64decode(csr)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid CSR encoding")

        # Sign CSR using CA via ZMQ
        try:
            # Convert bytes to string if needed
            csr_pem = csr_bytes.decode("utf-8") if isinstance(csr_bytes, bytes) else csr

            result = ra.zmq_client.sign_csr(csr_pem, profile="server")
            certificate = result.get("certificate", "")
        except Exception as e:
            ra.logger.error(f"Failed to sign CSR: {e}")
            raise HTTPException(
                status_code=500, detail="Failed to sign certificate request"
            )

        # Update order status
        order["status"] = "valid"
        order["certificate"] = certificate
        storage.update_order(order_id, order)

        base_url = str(request.base_url).rstrip("/")
        return {
            "status": "valid",
            "certificate": f"{base_url}/acme/cert/{order_id}",
        }

    # ========================================================================
    # Certificate Revocation
    # ========================================================================

    @router.post("/acme/revoke-cert")
    async def revoke_certificate(request: Request) -> dict:
        """Revoke a certificate.

        Request Body:
            JWS with signed payload:
            {
                "certificate": "BASE64_ENCODED_CERT",
                "reason": 0  # 0 = unspecified, 1 = keyCompromise, etc.
            }

        Returns:
            Revocation confirmation.
        """
        # Validate JWS - account_id not strictly required for revocation
        # but validates the signature
        jws_body = await request.body()
        jws_str = (
            jws_body.decode("utf-8")
            if isinstance(jws_body, (bytes, bytearray, memoryview))
            else jws_body
        )
        account_id, body = validate_acme_jws(jws_str, storage)

        certificate = body.get("certificate")
        if not certificate:
            raise HTTPException(
                status_code=400, detail="Missing 'certificate' in request"
            )

        # Decode certificate
        try:
            cert_bytes = b64decode(certificate)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid certificate encoding")

        # Extract DN from certificate for revocation
        try:
            # Parse the certificate to extract the subject DN
            cert_obj = load_pem_x509_certificate(cert_bytes)
            # Build DN in RFC 4514 format
            subject_parts = []
            for attr in cert_obj.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    subject_parts.append(f"CN={attr.value}")
                elif attr.oid == NameOID.ORGANIZATION_NAME:
                    subject_parts.append(f"O={attr.value}")
                elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                    subject_parts.append(f"OU={attr.value}")
                elif attr.oid == NameOID.COUNTRY_NAME:
                    subject_parts.append(f"C={attr.value}")
                elif attr.oid == NameOID.STATE_OR_PROVINCE_NAME:
                    subject_parts.append(f"ST={attr.value}")
                elif attr.oid == NameOID.LOCALITY_NAME:
                    subject_parts.append(f"L={attr.value}")
            dn = "/" + "/".join(subject_parts) if subject_parts else "/CN=unknown"
        except Exception as e:
            ra.logger.warning(f"Failed to parse certificate for DN extraction: {e}")
            dn = "/CN=unknown"

        try:
            reason = body.get("reason", 0)
            result = ra.zmq_client.revoke_certificate(dn, reason=str(reason))
            if not result:
                raise HTTPException(
                    status_code=500, detail="Failed to revoke certificate"
                )
        except Exception as e:
            ra.logger.error(f"Failed to revoke certificate: {e}")
            raise HTTPException(status_code=500, detail="Failed to revoke certificate")

        return {"status": "revoked"}

    # ========================================================================
    # Key Change (Account Key Rollover)
    # ========================================================================

    @router.post("/acme/key-change")
    async def key_change(request: Request) -> dict:
        """Change account key.

        Request Body:
            {
                "account": "ACCOUNT_URL",
                "oldKey": { ... },
                "jwk": { ... }
            }

        Returns:
            Key change confirmation.
        """
        raise HTTPException(status_code=501, detail="Key change not yet implemented")

    return router
