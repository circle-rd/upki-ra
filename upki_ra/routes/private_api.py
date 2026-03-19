"""
uPKI RA Server - Private API Routes.

This module provides the private (admin) REST API endpoints for the RA server.
These endpoints require mTLS authentication with admin certificate.
"""

from base64 import b64decode

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..core.upki_error import (
    AuthenticationError,
    AuthorizationError,
    CAConnectionError,
    UPKIError,
    ValidationError,
)
from ..registration_authority import RegistrationAuthority
from ..utils.common import format_error, format_response, validate_required_fields


def create_private_routes(ra: RegistrationAuthority) -> APIRouter:
    """Create private API routes with RA instance.

    Args:
        ra: RegistrationAuthority instance.

    Returns:
        Configured FastAPI APIRouter.
    """
    router = APIRouter(prefix="/", tags=["private"])

    # Pydantic models for request bodies
    class RegisterNodeRequest(BaseModel):
        """Register node request."""

        cn: str = Field(..., description="Common Name for the node")
        profile: str = Field(default="server", description="Certificate profile")
        sans: list[str] = Field(
            default_factory=list, description="Subject Alternative Names"
        )

    class AddAdminsRequest(BaseModel):
        """Add admins request."""

        admins: list[str] = Field(..., description="List of admin DNs to add")

    async def require_tls_auth(request: Request) -> dict:
        """Dependency to require TLS authentication."""
        try:
            # Extract certificate info from request headers
            ssl_client_cert = request.headers.get("X-SSL-CLIENT-CERT")
            ssl_client_verify = request.headers.get("X-SSL-CLIENT-VERIFY", "FAIL")
            ssl_client_s_dn = request.headers.get("X-SSL-CLIENT-S-DN", "")
            ssl_client_i_dn = request.headers.get("X-SSL-CLIENT-I-DN", "")

            # Authenticate client certificate
            cert_info = ra.tls_auth.authenticate_request(
                ssl_client_cert=ssl_client_cert,
                ssl_client_verify=ssl_client_verify,
                ssl_client_s_dn=ssl_client_s_dn,
                ssl_client_i_dn=ssl_client_i_dn,
            )

            # Check admin authorization
            dn = cert_info.get("subject", "")
            ra.tls_auth.authorize_admin(dn)

            # Store cert info for later use
            request.state.cert_info = cert_info

            return cert_info
        except (AuthenticationError, AuthorizationError) as e:
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

    @router.get("/nodes")
    async def list_nodes(
        request: Request, _auth: dict = Depends(require_tls_auth)
    ) -> dict:
        """List all registered nodes.

        Requires: mTLS authentication with admin certificate.

        Returns:
            JSON response with node list.
        """
        try:
            # Query nodes from CA via ZMQ
            nodes = ra.zmq_client.list_nodes()
            return format_response(status="success", data={"nodes": nodes})

        except Exception as e:
            ra.logger.exception("Unexpected error in list_nodes endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.post("/nodes")
    async def register_node(
        request: Request,
        data: RegisterNodeRequest,
        _auth: dict = Depends(require_tls_auth),
    ) -> dict:
        """Register a new node.

        Requires: mTLS authentication with admin certificate.

        Request Body:
            cn: Common Name for the node.
            profile: Certificate profile (default: server).
            sans: Optional Subject Alternative Names.

        Returns:
            JSON response with registration details.
        """
        try:
            # Validate required fields
            error = validate_required_fields(data.model_dump(), ["cn"])
            if error:
                raise HTTPException(
                    status_code=400,
                    detail=format_error(error, "VALIDATION_ERROR", 400),
                )

            cn = data.cn
            profile = data.profile
            sans = data.sans

            # Register node with CA
            result = ra.zmq_client.register_node(
                seed=ra.seed, cn=cn, profile=profile, sans=sans
            )

            return format_response(status="success", data={"node": result})

        except ValidationError as e:
            raise HTTPException(
                status_code=400,
                detail=format_error(str(e), "VALIDATION_ERROR", 400),
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
            ra.logger.exception("Unexpected error in register_node endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.delete("/nodes/{cn:path}")
    async def delete_node(
        request: Request, cn: str, _auth: dict = Depends(require_tls_auth)
    ) -> dict:
        """Delete a node.

        Requires: mTLS authentication with admin certificate.

        Path Parameters:
            cn: URL-encoded Common Name of the node.

        Returns:
            JSON response with deletion status.
        """
        try:
            from urllib.parse import unquote

            cn = unquote(cn)

            # Get node details to obtain DN
            node = ra.zmq_client.get_node(cn)
            if not node or not node.get("dn"):
                raise HTTPException(
                    status_code=404,
                    detail=format_error("Node not found", "NOT_FOUND", 404),
                )

            # Delete node from CA via ZMQ
            dn = node["dn"]
            result = ra.zmq_client.delete_node(dn)

            if not result:
                raise HTTPException(
                    status_code=500,
                    detail=format_error("Failed to delete node", "DELETE_FAILED", 500),
                )

            return format_response(status="success", message="Node deleted")

        except Exception as e:
            ra.logger.exception("Unexpected error in delete_node endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.get("/admins")
    async def list_admins(
        request: Request, _auth: dict = Depends(require_tls_auth)
    ) -> dict:
        """List all administrators.

        Requires: mTLS authentication with admin certificate.

        Returns:
            JSON response with admin list.
        """
        try:
            admins = ra.zmq_client.list_admins()

            return format_response(
                status="success", data={"admins": [{"dn": dn} for dn in admins]}
            )

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
            ra.logger.exception("Unexpected error in list_admins endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.post("/admins")
    async def add_admins(
        request: Request,
        data: AddAdminsRequest,
        _auth: dict = Depends(require_tls_auth),
    ) -> dict:
        """Add administrators.

        Requires: mTLS authentication with admin certificate.

        Request Body:
            admins: List of admin DNs to add.

        Returns:
            JSON response with status.
        """
        try:
            admins = data.admins

            if not admins:
                raise HTTPException(
                    status_code=400,
                    detail=format_error("No admins provided", "VALIDATION_ERROR", 400),
                )

            # Add each admin
            results = []
            for dn in admins:
                try:
                    result = ra.add_admin(dn)
                    results.append({"dn": dn, "success": result})
                except Exception as e:
                    results.append({"dn": dn, "success": False, "error": str(e)})

            return format_response(status="success", data={"results": results})

        except ValidationError as e:
            raise HTTPException(
                status_code=400,
                detail=format_error(str(e), "VALIDATION_ERROR", 400),
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
            ra.logger.exception("Unexpected error in add_admins endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.delete("/admins/{dn:path}")
    async def remove_admin(
        request: Request, dn: str, _auth: dict = Depends(require_tls_auth)
    ) -> dict:
        """Remove an administrator.

        Requires: mTLS authentication with admin certificate.

        Path Parameters:
            dn: Base64-encoded Distinguished Name of admin to remove.

        Returns:
            JSON response with status.
        """
        try:
            # Decode base64 DN
            try:
                dn = b64decode(dn).decode("utf-8")
            except Exception:
                pass  # Use as-is if not base64

            result = ra.remove_admin(dn)

            if result:
                return format_response(status="success", message="Admin removed")
            else:
                raise HTTPException(
                    status_code=400,
                    detail=format_error(
                        "Failed to remove admin", "OPERATION_FAILED", 400
                    ),
                )

        except ValidationError as e:
            raise HTTPException(
                status_code=400,
                detail=format_error(str(e), "VALIDATION_ERROR", 400),
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
            ra.logger.exception("Unexpected error in remove_admin endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.post("/crl/generate")
    async def generate_crl(
        request: Request, _auth: dict = Depends(require_tls_auth)
    ) -> dict:
        """Generate new CRL.

        Requires: mTLS authentication with admin certificate.

        Returns:
            JSON response with new CRL.
        """
        try:
            crl = ra.generate_crl()

            return format_response(status="success", data={"crl": crl})

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
            ra.logger.exception("Unexpected error in generate_crl endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.get("/config")
    async def get_config(
        request: Request, _auth: dict = Depends(require_tls_auth)
    ) -> dict:
        """Get RA configuration.

        Requires: mTLS authentication with admin certificate.

        Returns:
            JSON response with configuration (sensitive data redacted).
        """
        try:
            # Return non-sensitive config
            config = {
                "ca_host": ra.ca_host,
                "ca_port": ra.ca_port,
                "data_dir": ra.data_dir,
                "registered": ra.is_registered(),
            }

            return format_response(status="success", data=config)

        except Exception as e:
            ra.logger.exception("Unexpected error in get_config endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.get("/options")
    async def get_options(
        request: Request, _auth: dict = Depends(require_tls_auth)
    ) -> dict:
        """Get allowed certificate parameters.

        Returns allowed values for certificate generation including
        key types, key lengths, digests, and profiles.

        Requires: mTLS authentication with admin certificate.

        Returns:
            JSON response with allowed options.
        """
        try:
            # Get available profiles
            profiles = ra.list_profiles()

            # Define allowed options (these could come from CA in a full implementation)
            options = {
                "key_types": [
                    {"type": "rsa", "sizes": [1024, 2048, 4096]},
                    {"type": "ec", "curves": ["prime256v1", "secp384r1"]},
                ],
                "digests": ["sha256", "sha384", "sha512"],
                "profiles": profiles.get("profiles", []),
                "validity_days": {
                    "min": 1,
                    "max": 3650,
                    "default": 365,
                },
            }

            return format_response(status="success", data=options)

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
            ra.logger.exception("Unexpected error in get_options endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    return router
