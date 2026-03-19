"""
uPKI RA Server - Core Error Handling Module.

This module provides custom exception classes for the uPKI RA Server.
All exceptions follow a consistent pattern for error handling across the application.
"""



class UPKIError(Exception):
    """Base exception class for all uPKI RA Server errors.

    This is the parent class for all custom exceptions in the uPKI system.
    It provides a consistent interface for error handling and logging.
    """

    def __init__(self, message: str, code: str | None = None) -> None:
        """Initialize the UPKIError.

        Args:
            message: Human-readable error message describing the error.
            code: Optional error code for programmatic error identification.
        """
        super().__init__(message)
        self.message = message
        self.code = code or "UPKI_ERROR"

    def __str__(self) -> str:
        """Return string representation of the error."""
        return f"[{self.code}] {self.message}"

    def to_dict(self) -> dict:
        """Convert error to dictionary format for JSON responses.

        Returns:
            Dictionary containing error code and message.
        """
        return {"status": "error", "code": self.code, "message": self.message}


class AuthenticationError(UPKIError):
    """Exception raised when authentication fails.

    This exception is raised when a client fails to provide valid credentials
    or when certificate-based authentication fails.
    """

    def __init__(self, message: str = "Authentication failed") -> None:
        """Initialize the AuthenticationError.

        Args:
            message: Human-readable error message describing the authentication failure.
        """
        super().__init__(message, code="AUTH_ERROR")


class AuthorizationError(UPKIError):
    """Exception raised when authorization fails.

    This exception is raised when a client is authenticated but not authorized
    to access a specific resource or perform a specific operation.
    """

    def __init__(self, message: str = "Authorization failed") -> None:
        """Initialize the AuthorizationError.

        Args:
            message: Human-readable error message describing the authorization failure.
        """
        super().__init__(message, code="AUTHZ_ERROR")


class ValidationError(UPKIError):
    """Exception raised when input validation fails.

    This exception is raised when client-provided data fails validation checks,
    such as invalid CSR format, missing required fields, or invalid certificate profiles.
    """

    def __init__(self, message: str = "Validation failed") -> None:
        """Initialize the ValidationError.

        Args:
            message: Human-readable error message describing the validation failure.
        """
        super().__init__(message, code="VALIDATION_ERROR")


class CAConnectionError(UPKIError):
    """Exception raised when communication with CA server fails.

    This exception is raised when the RA server cannot communicate with the
    CA server via ZMQ, including connection failures, timeouts, or protocol errors.
    """

    def __init__(self, message: str = "CA connection failed") -> None:
        """Initialize the CAConnectionError.

        Args:
            message: Human-readable error message describing the connection failure.
        """
        super().__init__(message, code="CA_CONNECTION_ERROR")


class CertificateError(UPKIError):
    """Exception raised for certificate-related errors.

    This exception is raised for general certificate processing errors,
    including parsing, encoding, or validation failures.
    """

    def __init__(self, message: str = "Certificate error") -> None:
        """Initialize the CertificateError.

        Args:
            message: Human-readable error message describing the certificate error.
        """
        super().__init__(message, code="CERTIFICATE_ERROR")


class RegistrationError(UPKIError):
    """Exception raised during node/RA registration.

    This exception is raised when the RA server fails to register with the CA
    or when node registration fails.
    """

    def __init__(self, message: str = "Registration failed") -> None:
        """Initialize the RegistrationError.

        Args:
            message: Human-readable error message describing the registration failure.
        """
        super().__init__(message, code="REGISTRATION_ERROR")


class ConfigurationError(UPKIError):
    """Exception raised for configuration-related errors.

    This exception is raised when the RA server configuration is invalid
    or missing required configuration parameters.
    """

    def __init__(self, message: str = "Configuration error") -> None:
        """Initialize the ConfigurationError.

        Args:
            message: Human-readable error message describing the configuration error.
        """
        super().__init__(message, code="CONFIG_ERROR")


class NotFoundError(UPKIError):
    """Exception raised when a requested resource is not found.

    This exception is raised when a client requests a resource that does not exist,
    such as a non-existent certificate or profile.
    """

    def __init__(self, message: str = "Resource not found") -> None:
        """Initialize the NotFoundError.

        Args:
            message: Human-readable error message describing the missing resource.
        """
        super().__init__(message, code="NOT_FOUND")


class ConflictError(UPKIError):
    """Exception raised when a resource conflict occurs.

    This exception is raised when attempting to create a resource that already exists,
    such as registering a node with a duplicate CN.
    """

    def __init__(self, message: str = "Resource conflict") -> None:
        """Initialize the ConflictError.

        Args:
            message: Human-readable error message describing the conflict.
        """
        super().__init__(message, code="CONFLICT")


class RevocationError(UPKIError):
    """Exception raised during certificate revocation operations.

    This exception is raised when certificate revocation fails,
    including attempting to revoke a non-existent or already-revoked certificate.
    """

    def __init__(self, message: str = "Revocation failed") -> None:
        """Initialize the RevocationError.

        Args:
            message: Human-readable error message describing the revocation failure.
        """
        super().__init__(message, code="REVOCATION_ERROR")
