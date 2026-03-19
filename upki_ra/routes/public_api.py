"""
uPKI RA Server - Public API Routes.

This module provides the public REST API endpoints for the RA server.
These endpoints do not require authentication and are available to all clients.
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ..core.upki_error import (
    CAConnectionError,
    CertificateError,
    UPKIError,
    ValidationError,
)
from ..registration_authority import RegistrationAuthority
from ..utils.common import format_error, format_response, validate_required_fields


def create_public_routes(ra: RegistrationAuthority) -> APIRouter:
    """Create public API routes with RA instance.

    Args:
        ra: RegistrationAuthority instance.

    Returns:
        Configured FastAPI APIRouter.
    """
    router = APIRouter(prefix="/", tags=["public"])

    # Pydantic models for request bodies
    class CertifyRequest(BaseModel):
        """Certificate enrollment request."""

        csr: str = Field(..., description="Certificate Signing Request in PEM format")
        profile: str = Field(default="server", description="Certificate profile")

    class OCSPRequest(BaseModel):
        """OCSP status check request."""

        serial: str = Field(..., description="Certificate serial number")

    @router.get("/health")
    async def health() -> dict:
        """Health check endpoint.

        Returns:
            JSON response with server status.
        """
        return format_response(status="success", data={"status": "healthy"})

    @router.post("/certify")
    async def certify(request: Request, data: CertifyRequest) -> dict:
        """Certificate enrollment endpoint.

        This endpoint accepts a CSR and returns a signed certificate.

        Request Body:
            csr: Certificate Signing Request in PEM format.
            profile: Certificate profile (default: server).

        Returns:
            JSON response with signed certificate.
        """
        try:
            # Validate required fields
            error = validate_required_fields(data.model_dump(), ["csr"])
            if error:
                raise HTTPException(
                    status_code=400,
                    detail=format_error(error, "VALIDATION_ERROR", 400),
                )

            csr = data.csr
            profile = data.profile

            # Process certificate request
            result = ra.certify(csr=csr, profile=profile)

            return format_response(
                status="success",
                data={
                    "certificate": result.get("certificate"),
                    "dn": result.get("dn"),
                    "serial": result.get("serial"),
                    "profile": profile,
                },
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
            ra.logger.exception("Unexpected error in certify endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.get("/certs/{node:path}")
    async def get_certificate(request: Request, node: str) -> dict:
        """Get certificate or CA certificate by node/DN.

        Path Parameters:
            node: URL-encoded Distinguished Name or special value (ca.crt, crl.pem).

        Returns:
            JSON response with certificate/CRL content.
        """
        try:
            from urllib.parse import unquote

            node = unquote(node)

            # Handle special cases for CDP (Certificate Distribution Point)
            if node == "ca.crt":
                # Return CA certificate
                ca_cert = ra.get_ca_certificate()
                return format_response(status="success", data={"certificate": ca_cert})
            elif node == "crl.pem":
                # Return CRL
                crl = ra.get_crl()
                return format_response(status="success", data={"crl": crl})
            else:
                # Treat as DN and get certificate
                result = ra.view_certificate(dn=node)
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
            ra.logger.exception("Unexpected error in get_certificate endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.get("/certs")
    async def list_certificates(request: Request) -> dict:
        """List all certificates.

        Returns:
            JSON response with certificate list.
        """
        try:
            # Query certificates from CA via ZMQ (list_nodes returns certificates)
            nodes = ra.zmq_client.list_nodes()
            return format_response(status="success", data={"certificates": nodes})

        except Exception as e:
            ra.logger.exception("Unexpected error in list_certificates endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.get("/ca")
    async def get_ca(request: Request) -> dict:
        """Get CA certificate.

        Returns:
            JSON response with CA certificate.
        """
        try:
            ca_cert = ra.get_ca_certificate()

            return format_response(status="success", data={"certificate": ca_cert})

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
            ra.logger.exception("Unexpected error in get_ca endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.get("/crl")
    async def get_crl(request: Request) -> dict:
        """Get Certificate Revocation List.

        Returns:
            JSON response with CRL.
        """
        try:
            crl = ra.get_crl()

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
            ra.logger.exception("Unexpected error in get_crl endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.get("/profiles")
    async def list_profiles(request: Request) -> dict:
        """List available certificate profiles.

        Returns:
            JSON response with available profiles.
        """
        try:
            profiles = ra.list_profiles()

            return format_response(status="success", data=profiles)

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
            ra.logger.exception("Unexpected error in list_profiles endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.get("/profiles/{profile_name}")
    async def get_profile(request: Request, profile_name: str) -> dict:
        """Get profile details.

        Path Parameters:
            profile_name: Name of the profile.

        Returns:
            JSON response with profile details.
        """
        try:
            profile = ra.get_profile(profile_name)

            return format_response(status="success", data=profile)

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
            ra.logger.exception("Unexpected error in get_profile endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.get("/magic/{profile}")
    async def get_magic_command(request: Request, profile: str) -> dict:
        """Generate openssl command for certificate generation.

        This endpoint returns an openssl command that can be used
        to generate a CSR for the specified profile.

        Path Parameters:
            profile: Certificate profile name.

        Returns:
            JSON response with openssl command.
        """
        try:
            # Get profile details
            profile_data = ra.get_profile(profile)

            # Build openssl command based on profile
            key_type = profile_data.get("key_type", "rsa:2048")
            digest = profile_data.get("digest", "sha256")

            # Generate openssl command
            if ":" in key_type:
                key_type_parts = key_type.split(":")
                key_algo = key_type_parts[0]
                key_len = key_type_parts[1] if len(key_type_parts) > 1 else "2048"
            else:
                key_algo = key_type
                key_len = "2048"

            if key_algo.lower() == "rsa":
                keygen_cmd = f"openssl genrsa -out key.pem {key_len}"
                csr_cmd = f"openssl req -new -key key.pem -out csr.pem -subj '/CN=YourName/O=YourOrg' -{digest}"
            elif key_algo.lower() == "ec":
                keygen_cmd = "openssl ecparam -genkey -name prime256v1 -out key.pem"
                csr_cmd = f"openssl req -new -key key.pem -out csr.pem -subj '/CN=YourName/O=YourOrg' -{digest}"
            else:
                keygen_cmd = f"# Unsupported key type: {key_algo}"
                csr_cmd = f"# Use appropriate command for {key_algo}"

            return format_response(
                status="success",
                data={
                    "profile": profile,
                    "commands": {
                        "generate_key": keygen_cmd,
                        "generate_csr": csr_cmd,
                    },
                },
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
            ra.logger.exception("Unexpected error in get_magic_command endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    @router.post("/ocsp")
    async def ocsp_check(request: Request, data: OCSPRequest) -> dict:
        """OCSP status check endpoint.

        Request Body:
            serial: Certificate serial number.

        Returns:
            JSON response with OCSP status.
        """
        try:
            # Validate required fields
            error = validate_required_fields(data.model_dump(), ["serial"])
            if error:
                raise HTTPException(
                    status_code=400,
                    detail=format_error(error, "VALIDATION_ERROR", 400),
                )

            serial = data.serial
            result = ra.check_ocsp(serial=serial)

            return format_response(status="success", data=result)

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
            ra.logger.exception("Unexpected error in ocsp_check endpoint")
            raise HTTPException(
                status_code=500,
                detail=format_error("Internal server error", "INTERNAL_ERROR", 500),
            ) from e

    return router
