"""
uPKI RA Server - TLS Authentication Module.

This module provides mTLS (mutual TLS) authentication functionality
for securing private API endpoints.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps

from ..core.upki_error import AuthenticationError, AuthorizationError
from ..core.upki_logger import UPKILogger


@dataclass
class CertInfo:
    """Client certificate information."""

    subject: str
    issuer: str
    cert: str


class TLSAuth:
    """TLS authentication handler for mTLS connections.

    This class manages TLS certificate-based authentication for the RA server.
    It validates client certificates and checks authorization against admin lists.

    Attributes:
        ca_cert: Path to CA certificate for client cert validation.
        logger: Logger instance.
    """

    def __init__(
        self, ca_cert: str | None = None, logger: UPKILogger | None = None
    ) -> None:
        """Initialize TLS authentication.

        Args:
            ca_cert: Optional path to CA certificate file.
            logger: Optional logger instance.
        """
        self.ca_cert = ca_cert
        self.logger = logger or UPKILogger(name="upki-ra-tls")
        self._admin_dns: list[str] = []

    @property
    def admin_dns(self) -> list[str]:
        """Get list of authorized admin DNs."""
        return self._admin_dns

    @admin_dns.setter
    def admin_dns(self, dns: list[str]) -> None:
        """Set list of authorized admin DNs.

        Args:
            dns: List of admin Distinguished Names.
        """
        self._admin_dns = dns
        self.logger.info(f"Admin DN list updated: {len(dns)} entries")

    def load_admin_dns(self, dns: list[str]) -> None:
        """Load admin DNs from a list.

        Args:
            dns: List of admin Distinguished Names.
        """
        self.admin_dns = dns

    def extract_client_cert_from_headers(
        self,
        ssl_client_cert: str | None = None,
        ssl_client_verify: str | None = None,
        ssl_client_s_dn: str | None = None,
        ssl_client_i_dn: str | None = None,
    ) -> dict[str, str] | None:
        """Extract client certificate information from request headers/env.

        This method extracts client certificate information from request headers
        or environment variables. It supports various ways the certificate
        can be passed (directly or via headers from reverse proxy).

        Args:
            ssl_client_cert: SSL_CLIENT_CERT header/value.
            ssl_client_verify: SSL_CLIENT_VERIFY header/value.
            ssl_client_s_dn: SSL_CLIENT_S_DN (subject) header/value.
            ssl_client_i_dn: SSL_CLIENT_I_DN (issuer) header/value.

        Returns:
            Dictionary containing certificate subject and issuer, or None.
        """
        if not ssl_client_cert:
            return None

        if ssl_client_verify != "SUCCESS":
            return None

        if not ssl_client_s_dn:
            return None

        return {
            "subject": ssl_client_s_dn,
            "issuer": ssl_client_i_dn or "",
            "cert": ssl_client_cert,
        }

    def extract_cn_from_dn(self, dn: str) -> str | None:
        """Extract Common Name from Distinguished Name.

        Args:
            dn: Distinguished Name string.

        Returns:
            Common Name if found, None otherwise.
        """
        match = re.search(r"CN=([^,]+)", dn)
        if match:
            return match.group(1)
        return None

    def extract_dn_components(self, dn: str) -> dict:
        """Extract components from Distinguished Name.

        Args:
            dn: Distinguished Name string.

        Returns:
            Dictionary of DN components (CN, O, OU, C, etc.).
        """
        components = {}
        pattern = r"([A-Za-z]+)=([^,]+)"

        for match in re.finditer(pattern, dn):
            key, value = match.groups()
            if key in components:
                if not isinstance(components[key], list):
                    components[key] = [components[key]]
                components[key].append(value)
            else:
                components[key] = value

        return components

    def is_admin(self, dn: str) -> bool:
        """Check if a DN is in the admin list.

        Args:
            dn: Distinguished Name to check.

        Returns:
            True if DN is authorized admin.
        """
        # Normalize DN for comparison
        dn_normalized = dn.strip().lower()

        for admin_dn in self._admin_dns:
            admin_normalized = admin_dn.strip().lower()
            if dn_normalized == admin_normalized:
                return True

        return False

    def authenticate_request(
        self,
        ssl_client_cert: str | None = None,
        ssl_client_verify: str | None = None,
        ssl_client_s_dn: str | None = None,
        ssl_client_i_dn: str | None = None,
    ) -> dict[str, str]:
        """Authenticate a request using TLS client certificate.

        Args:
            ssl_client_cert: SSL_CLIENT_CERT header/value.
            ssl_client_verify: SSL_CLIENT_VERIFY header/value.
            ssl_client_s_dn: SSL_CLIENT_S_DN (subject) header/value.
            ssl_client_i_dn: SSL_CLIENT_I_DN (issuer) header/value.

        Returns:
            Certificate info if authenticated.

        Raises:
            AuthenticationError: If authentication fails.
        """
        cert_info = self.extract_client_cert_from_headers(
            ssl_client_cert, ssl_client_verify, ssl_client_s_dn, ssl_client_i_dn
        )

        if not cert_info:
            self.logger.warning("No client certificate provided")
            raise AuthenticationError("Client certificate required")

        # Verify certificate has subject
        if not cert_info.get("subject"):
            self.logger.warning("Client certificate has no subject")
            raise AuthenticationError("Invalid client certificate")

        self.logger.debug(f"Authenticated client: {cert_info['subject']}")

        return cert_info

    def authorize_admin(self, dn: str) -> bool:
        """Authorize a DN for admin access.

        Args:
            dn: Distinguished Name to authorize.

        Returns:
            True if authorized.

        Raises:
            AuthorizationError: If not authorized.
        """
        if not self.is_admin(dn):
            self.logger.warning(f"Unauthorized admin access attempt: {dn}")
            raise AuthorizationError("Not authorized for admin access")

        return True


def tls_private(tls_auth: TLSAuth, require_admin: bool = True) -> Callable:
    """Decorator for TLS authentication on FastAPI routes.

    This decorator can be used to protect FastAPI routes with mTLS authentication.
    It validates the client certificate and optionally checks admin authorization.

    Args:
        tls_auth: TLSAuth instance for authentication.
        require_admin: If True, also check admin authorization.

    Returns:
        Decorator function.

    Example:
        @tls_private(tls_auth, require_admin=True)
        def protected_route():
            return {"status": "success"}
    """

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Get certificate info from request context (passed as kwargs)
                # FastAPI will inject the request object
                request = kwargs.get("_request")
                if request is None:
                    raise AuthenticationError("Request context missing")

                # Extract certificate info from request headers/environ
                ssl_client_cert = request.headers.get("X-SSL-CLIENT-CERT")
                ssl_client_verify = request.headers.get("X-SSL-CLIENT-VERIFY", "FAIL")
                ssl_client_s_dn = request.headers.get("X-SSL-CLIENT-S-DN", "")
                ssl_client_i_dn = request.headers.get("X-SSL-CLIENT-I-DN", "")

                # Authenticate client
                cert_info = tls_auth.authenticate_request(
                    ssl_client_cert=ssl_client_cert,
                    ssl_client_verify=ssl_client_verify,
                    ssl_client_s_dn=ssl_client_s_dn,
                    ssl_client_i_dn=ssl_client_i_dn,
                )

                if require_admin:
                    # Check admin authorization
                    dn = cert_info.get("subject", "")
                    tls_auth.authorize_admin(dn)

                # Store cert info in request state for later use
                request.state.cert_info = cert_info

                return f(*args, **kwargs)

            except (AuthenticationError, AuthorizationError):
                raise
            except Exception as e:
                tls_auth.logger.error(f"Authentication error: {e}")
                raise AuthenticationError("Authentication failed") from e

        return decorated_function

    return decorator


class CertificateValidator:
    """Certificate validation utilities.

    This class provides methods for validating certificates and CSRs.
    """

    # Valid certificate profiles
    VALID_PROFILES = ["server", "client", "ra", "ca", "user"]

    # Valid revocation reasons (RFC 5280)
    REVOCATION_REASONS = [
        "unspecified",
        "keyCompromise",
        "cACompromise",
        "affiliationChanged",
        "superseded",
        "cessationOfOperation",
        "certificateHold",
        "removeFromCRL",
    ]

    @staticmethod
    def validate_csr(csr: str) -> tuple[bool, str]:
        """Validate a CSR format.

        Args:
            csr: CSR in PEM format.

        Returns:
            Tuple of (is_valid, error_message).
        """
        if not csr:
            return False, "CSR is empty"

        # Check for PEM header
        if "-----BEGIN CERTIFICATE REQUEST-----" not in csr:
            return False, "Invalid CSR format: missing PEM header"

        if "-----END CERTIFICATE REQUEST-----" not in csr:
            return False, "Invalid CSR format: missing PEM footer"

        # Basic validation - CSR should be reasonable length
        if len(csr) < 100:
            return False, "CSR is too short"

        if len(csr) > 10000:
            return False, "CSR is too long"

        return True, ""

    @staticmethod
    def validate_profile(profile: str) -> tuple[bool, str]:
        """Validate a certificate profile.

        Args:
            profile: Profile name to validate.

        Returns:
            Tuple of (is_valid, error_message).
        """
        if not profile:
            return False, "Profile is required"

        if profile.lower() not in CertificateValidator.VALID_PROFILES:
            return False, f"Invalid profile: {profile}"

        return True, ""

    @staticmethod
    def validate_san(san: str) -> tuple[bool, str]:
        """Validate a Subject Alternative Name.

        Args:
            san: SAN value to validate.

        Returns:
            Tuple of (is_valid, error_message).
        """
        if not san:
            return False, "SAN is empty"

        # Basic length check
        if len(san) > 253:
            return False, "SAN is too long (max 253 characters)"

        return True, ""

    @staticmethod
    def validate_revocation_reason(reason: str) -> tuple[bool, str]:
        """Validate a revocation reason.

        Args:
            reason: Revocation reason to validate.

        Returns:
            Tuple of (is_valid, error_message).
        """
        if not reason:
            # Default reason is acceptable
            return True, ""

        if reason.lower() not in CertificateValidator.REVOCATION_REASONS:
            return False, f"Invalid revocation reason: {reason}"

        return True, ""
