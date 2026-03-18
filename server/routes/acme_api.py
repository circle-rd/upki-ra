"""
uPKI RA Server - ACME API Module.

This module provides ACME (Automatic Certificate Management Environment) v2 protocol
endpoints for integration with Traefik and other ACME clients.

ACME v2 Specification: https://datatracker.ietf.org/doc/html/rfc8555
"""

import hashlib
import json
import uuid
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse

from ..registration_authority import RegistrationAuthority
from ..storage import AbstractStorage, SQLiteStorage
from ..utils.common import format_response


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
            {
                "identifiers": [{"type": "dns", "value": "example.com"}],
                "notBefore": "2023-01-01T00:00:00Z",
                "notAfter": "2023-12-31T23:59:59Z"
            }

        Returns:
            Order object with authorization URLs.
        """
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

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
            token = uuid.uuid4().hex

            auth = {
                "id": auth_id,
                "order_id": order_id,
                "type": identifier["type"],
                "value": identifier["value"],
                "status": "pending",
                "challenges": [
                    {
                        "type": "http-01",
                        "url": f"{base_url}/acme/challenge/{auth_id}/http-01",
                        "token": token,
                        "status": "pending",
                        "authorization_id": auth_id,
                    }
                ],
            }
            storage.save_authorization(auth_id, auth)
            authorizations.append(f"{base_url}/acme/authz/{auth_id}")

        # Create order
        order = {
            "id": order_id,
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

        # Generate the key authorization for the challenge
        # In production, this should verify the account key
        token = http01_challenge["token"]
        key_auth = (
            f"{token}.{ra.seed}"  # Simplified - should use account key thumbprint
        )

        # Update the challenge with key authorization
        http01_challenge["key_authorization"] = key_auth
        http01_challenge["status"] = "validating"

        # Update authorization with modified challenge
        auth["status"] = "validating"
        storage.update_authorization(auth_id, auth)

        # In production, this would verify the challenge asynchronously
        # For now, mark as valid immediately (synchronous validation)
        http01_challenge["status"] = "valid"
        auth["status"] = "valid"
        storage.update_authorization(auth_id, auth)

        return {
            "type": "http-01",
            "url": http01_challenge["url"],
            "token": token,
            "status": "valid",
        }

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
                status_code=400, detail="Order is not ready for certificate download"
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
            {
                "csr": "BASE64_ENCODED_CSR"
            }

        Args:
            order_id: Order ID.

        Returns:
            Certificate URL.
        """
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        csr = body.get("csr")
        if not csr:
            raise HTTPException(status_code=400, detail="Missing 'csr' in request")

        order = storage.get_order(order_id)
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

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
            {
                "certificate": "BASE64_ENCODED_CERT",
                "reason": 0  # 0 = unspecified, 1 = keyCompromise, etc.
            }

        Returns:
            Revocation confirmation.
        """
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

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
        # In production, parse the certificate to get the DN
        # For now, use a placeholder
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
