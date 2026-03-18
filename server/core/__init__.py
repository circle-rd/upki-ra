"""
uPKI RA Server - Core Module.

This module provides core functionality for the RA server including
error handling and logging.
"""

from .upki_error import (
    AuthenticationError,
    AuthorizationError,
    CAConnectionError,
    CertificateError,
    ConfigurationError,
    ConflictError,
    NotFoundError,
    RegistrationError,
    RevocationError,
    UPKIError,
    ValidationError,
)
from .upki_logger import UPKILogger, get_logger

__all__ = [
    # Error classes
    "UPKIError",
    "AuthenticationError",
    "AuthorizationError",
    "ValidationError",
    "CAConnectionError",
    "CertificateError",
    "RegistrationError",
    "ConfigurationError",
    "NotFoundError",
    "ConflictError",
    "RevocationError",
    # Logger
    "UPKILogger",
    "get_logger",
]
