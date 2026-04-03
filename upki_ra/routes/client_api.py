"""
uPKI RA Server - Client API Routes.

This module provides the client REST API endpoints for the RA server.
These endpoints require mTLS authentication with client certificate
and allow clients to manage their own certificates (renew/revoke).
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..core.upki_error import (
    AuthenticationError,
    CAConnectionError,
    CertificateError,
    UPKIError,
    ValidationError,
)
from ..registration_authority import RegistrationAuthority
from ..utils.common import format_error, format_response


def create_client_routes(ra: RegistrationAuthority) -> APIRouter:
    """Create client API routes with RA instance.

    Args:
        ra: RegistrationAuthority instance.

    Returns:
        Configured FastAPI APIRouter.
    """
    router = APIRouter(prefix="", tags=["client"])

    # Pydantic models for request bodies
    class RenewRequest(BaseModel):
        """Certificate renewal request."""

        profile: str = Field(default="client", description="Certificate profile")

    class RevokeRequest(BaseModel):
        """Certificate revocation request."""

        reason: str = Field(default="unspecified", description="Revocation reason")

    async def require_client_auth(request: Request) -> dict:
        """Dependency to require TLS authentication for clients."""
        try:
            # Extract certificate info from request headers
            ssl_client_cert = request.headers.get("X-SSL-CLIENT-CERT")
            ssl_client_verify = request.headers.get("X-SSL-CLIENT-VERIFY", "FAIL")
            ssl_client_s_dn = request.headers.get("X-SSL-CLIENT-S-DN", "")
            ssl_client_i_dn = request.headers.get("X-SSL-CLIENT-I-DN", "")

            # Authenticate client certificate (no admin check for client routes)
            cert_info = ra.tls_auth.authenticate_request(
                ssl_client_cert=ssl_client_cert,
                ssl_client_verify=ssl_client_verify,
                ssl_client_s_dn=ssl_client_s_dn,
                ssl_client_i_dn=ssl_client_i_dn,
            )

            # Store cert info for later use
            request.state.cert_info = cert_info

            return cert_info
        except AuthenticationError as e:
            raise HTTPException(
                status_code=401,
                detail=format_error(str(e), e.code, 401),
            ) from e
        except Exception as e:
            ra.logger.exception("Authentication error")
            raise HTTPException(
                status_code=401,
                detail=format_error("Authentication failed", "AUTH_ERROR", 401),
            ) from e

    @router.post("/renew")
    async def renew_certificate(
        request: Request,
        data: RenewRequest | None = None,
        _auth: dict = Depends(require_client_auth),
    ) -> dict:
        """Renew own certificate.

        Requires: mTLS authentication with valid client certificate.

        Request Body (optional):
            profile: Certificate profile to use for renewal.

        Returns:
            JSON response with new certificate.
        """
        try:
            # Get client DN from certificate
            cert_info = request.state.cert_info
            dn = cert_info.get("subject", "")

            if not dn:
                raise HTTPException(
                    status_code=400,
                    detail=format_error(
                        "Unable to determine client DN", "INVALID_CERT", 400
                    ),
                )

            profile = data.profile if data else "client"

            ra.logger.info(f"Processing certificate renewal for: {dn}")

            # Renew certificate
            result = ra.renew(dn=dn)

            return format_response(
                status="success",
                data={
                    "certificate": result.get("certificate"),
                    "dn": dn,
                    "serial": result.get("serial"),
                    "profile": profile,
                },
            )

        except ValidationError as e:
            raise HTTPException(
                status_code=400,
                detail=format_error(str(e), "VALIDATION_ERROR", 400),
            ) from e
        except CertificateError as e:
            raise HTTPException(
                status_code=404,
                detail=format_error(str(e), "NOT_FOUND", 404),
            ) from e
        except CAConnectionError as e:
            raise HTTPException(
                status_code=503,
                detail=format_error(str(e), "CA_ERROR", 503),
            ) from e
        except UPKIError as e:
            raise HTTPException(
                status_code=500,
                detail=format_error(str(e), e.code, 500),
            ) from e
        except Exception as e:
            ra.logger.exception("Unexpected error in renew_certificate endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.post("/revoke")
    async def revoke_certificate(
        request: Request,
        data: RevokeRequest,
        _auth: dict = Depends(require_client_auth),
    ) -> dict:
        """Revoke own certificate.

        Requires: mTLS authentication with valid client certificate.

        Request Body:
            reason: Revocation reason (optional).

        Returns:
            JSON response with revocation status.
        """
        try:
            # Get client DN from certificate
            cert_info = request.state.cert_info
            dn = cert_info.get("subject", "")

            if not dn:
                raise HTTPException(
                    status_code=400,
                    detail=format_error(
                        "Unable to determine client DN", "INVALID_CERT", 400
                    ),
                )

            reason = data.reason

            ra.logger.info(f"Processing certificate revocation for: {dn}")

            # Revoke certificate
            result = ra.revoke(dn=dn, reason=reason)

            if result:
                return format_response(
                    status="success", message="Certificate revoked successfully"
                )
            else:
                raise HTTPException(
                    status_code=400,
                    detail=format_error(
                        "Failed to revoke certificate", "OPERATION_FAILED", 400
                    ),
                )

        except ValidationError as e:
            raise HTTPException(
                status_code=400,
                detail=format_error(str(e), "VALIDATION_ERROR", 400),
            ) from e
        except CertificateError as e:
            raise HTTPException(
                status_code=404,
                detail=format_error(str(e), "NOT_FOUND", 404),
            ) from e
        except CAConnectionError as e:
            raise HTTPException(
                status_code=503,
                detail=format_error(str(e), "CA_ERROR", 503),
            ) from e
        except UPKIError as e:
            raise HTTPException(
                status_code=500,
                detail=format_error(str(e), e.code, 500),
            ) from e
        except Exception as e:
            ra.logger.exception("Unexpected error in revoke_certificate endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.get("/certificate")
    async def get_my_certificate(
        request: Request, _auth: dict = Depends(require_client_auth)
    ) -> dict:
        """Get own certificate details.

        Requires: mTLS authentication with valid client certificate.

        Returns:
            JSON response with certificate details.
        """
        try:
            # Get client DN from certificate
            cert_info = request.state.cert_info
            dn = cert_info.get("subject", "")

            if not dn:
                raise HTTPException(
                    status_code=400,
                    detail=format_error(
                        "Unable to determine client DN", "INVALID_CERT", 400
                    ),
                )

            # Get certificate details
            result = ra.view_certificate(dn=dn)

            return format_response(status="success", data=result)

        except ValidationError as e:
            raise HTTPException(
                status_code=400,
                detail=format_error(str(e), "VALIDATION_ERROR", 400),
            ) from e
        except CertificateError as e:
            raise HTTPException(
                status_code=404,
                detail=format_error(str(e), "NOT_FOUND", 404),
            ) from e
        except CAConnectionError as e:
            raise HTTPException(
                status_code=503,
                detail=format_error(str(e), "CA_ERROR", 503),
            ) from e
        except UPKIError as e:
            raise HTTPException(
                status_code=500,
                detail=format_error(str(e), e.code, 500),
            ) from e
        except Exception as e:
            ra.logger.exception("Unexpected error in get_my_certificate endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.get("/status")
    async def get_status(
        request: Request, _auth: dict = Depends(require_client_auth)
    ) -> dict:
        """Get own certificate status.

        Requires: mTLS authentication with valid client certificate.

        Returns:
            JSON response with certificate status.
        """
        try:
            # Get client DN from certificate
            cert_info = request.state.cert_info
            dn = cert_info.get("subject", "")

            if not dn:
                raise HTTPException(
                    status_code=400,
                    detail=format_error(
                        "Unable to determine client DN", "INVALID_CERT", 400
                    ),
                )

            # Get certificate details
            cert_data = ra.view_certificate(dn=dn)

            # Get OCSP status
            serial = cert_data.get("serial")
            ocsp_status = None

            if serial:
                try:
                    ocsp_status = ra.check_ocsp(serial=serial)
                except Exception:
                    pass

            return format_response(
                status="success",
                data={
                    "dn": dn,
                    "serial": serial,
                    "status": cert_data.get("status", "unknown"),
                    "ocsp": ocsp_status,
                },
            )

        except ValidationError as e:
            raise HTTPException(
                status_code=400,
                detail=format_error(str(e), "VALIDATION_ERROR", 400),
            ) from e
        except CertificateError as e:
            raise HTTPException(
                status_code=404,
                detail=format_error(str(e), "NOT_FOUND", 404),
            ) from e
        except CAConnectionError as e:
            raise HTTPException(
                status_code=503,
                detail=format_error(str(e), "CA_ERROR", 503),
            ) from e
        except UPKIError as e:
            raise HTTPException(
                status_code=500,
                detail=format_error(str(e), e.code, 500),
            ) from e
        except Exception as e:
            ra.logger.exception("Unexpected error in get_status endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    return router
