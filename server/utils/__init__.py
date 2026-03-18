"""
uPKI RA Server - Utilities Module.

This module provides utility functions and classes for the RA server.
"""

from .common import (
    build_dn,
    compute_sha256,
    decode_base64,
    encode_base64,
    ensure_directory,
    extract_cn_from_csr,
    format_error,
    format_response,
    get_file_extension,
    is_pem_format,
    normalize_dn,
    parse_dn,
    parse_pem,
    read_file,
    read_json_file,
    sanitize_filename,
    validate_required_fields,
    write_file,
    write_json_file,
)
from .tlsauth import CertificateValidator, TLSAuth, tls_private
from .tools import RegistrationClient, ZMQClient

__all__ = [
    # Common utilities
    "ensure_directory",
    "read_file",
    "write_file",
    "read_json_file",
    "write_json_file",
    "encode_base64",
    "decode_base64",
    "parse_pem",
    "extract_cn_from_csr",
    "build_dn",
    "parse_dn",
    "compute_sha256",
    "normalize_dn",
    "format_response",
    "format_error",
    "validate_required_fields",
    "sanitize_filename",
    "get_file_extension",
    "is_pem_format",
    # TLS authentication
    "TLSAuth",
    "tls_private",
    "CertificateValidator",
    # ZMQ tools
    "ZMQClient",
    "RegistrationClient",
]
