"""
uPKI RA Server - Common Utilities Module.

This module provides common utility functions used throughout the RA server.
"""

import base64
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from cryptography.x509.oid import NameOID, ExtensionOID


def ensure_directory(path: str) -> None:
    """Ensure a directory exists, creating it if necessary.

    Args:
        path: Directory path to ensure exists.
    """
    Path(path).mkdir(parents=True, exist_ok=True)


def read_file(path: str) -> str | None:
    """Read contents of a file.

    Args:
        path: Path to file to read.

    Returns:
        File contents as string, or None if file doesn't exist.
    """
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None
    except Exception:
        return None


def write_file(path: str, content: str, mode: int = 0o644) -> bool:
    """Write contents to a file.

    Args:
        path: Path to file to write.
        content: Content to write.
        mode: File permissions (default: 0o644).

    Returns:
        True if successful, False otherwise.
    """
    try:
        ensure_directory(os.path.dirname(path))
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, mode)
        return True
    except Exception:
        return False


def read_json_file(path: str) -> dict[str, Any] | None:
    """Read and parse a JSON file.

    Args:
        path: Path to JSON file.

    Returns:
        Parsed JSON as dictionary, or None if file doesn't exist or is invalid.
    """
    content = read_file(path)
    if content is None:
        return None

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return None


def write_json_file(path: str, data: dict[str, Any], indent: int = 2) -> bool:
    """Write data to a JSON file.

    Args:
        path: Path to JSON file.
        data: Dictionary to write as JSON.
        indent: JSON indentation level (default: 2).

    Returns:
        True if successful, False otherwise.
    """
    try:
        content = json.dumps(data, indent=indent)
        return write_file(path, content)
    except Exception:
        return False


def encode_base64(data: bytes) -> str:
    """Encode bytes to base64 string.

    Args:
        data: Bytes to encode.

    Returns:
        Base64-encoded string.
    """
    return base64.b64encode(data).decode("ascii")


def decode_base64(data: str) -> bytes | None:
    """Decode base64 string to bytes.

    Args:
        data: Base64-encoded string.

    Returns:
        Decoded bytes, or None if invalid.
    """
    try:
        return base64.b64decode(data)
    except Exception:
        return None


def parse_pem(pem: str, pem_type: str = "CERTIFICATE") -> list[str] | None:
    """Parse PEM content and extract certificates/keys.

    Args:
        pem: PEM content to parse.
        pem_type: Type of PEM to extract (CERTIFICATE, CERTIFICATE REQUEST, etc.).

    Returns:
        List of PEM blocks, or None if none found.
    """
    pattern = rf"-----BEGIN {pem_type}-----(.*?)-----END {pem_type}-----"
    matches = re.findall(pattern, pem, re.DOTALL)

    if not matches:
        return None

    return [
        f"-----BEGIN {pem_type}-----\n{match.strip()}\n-----END {pem_type}-----"
        for match in matches
    ]


def extract_cn_from_csr(csr: str) -> str | None:
    """Extract Common Name from a CSR using cryptography library.

    This function properly parses the CSR to extract the CN using the
    cryptography library instead of regex parsing.

    Args:
        csr: CSR in PEM format.

    Returns:
        Common Name if found, None otherwise.

    Raises:
        ValueError: If the CSR is invalid or cannot be parsed.
    """
    try:
        from cryptography.x509 import load_pem_x509_csr

        # Load the CSR using cryptography
        csr_obj = load_pem_x509_csr(
            csr.encode("utf-8") if isinstance(csr, str) else csr
        )

        # Get the subject
        subject = csr_obj.subject

        # Find the CN attribute
        for attribute in subject:
            if attribute.oid == NameOID.COMMON_NAME:
                return attribute.value

        return None

    except Exception:
        # Fallback to regex for edge cases
        match = re.search(r"CN=([^,\n]+)", csr)
        if match:
            return match.group(1)
        return None


def extract_subject_from_csr(csr: str) -> dict[str, str] | None:
    """Extract full subject from a CSR using cryptography library.

    Args:
        csr: CSR in PEM format.

    Returns:
        Dictionary of subject components (CN, O, OU, C, ST, L) if found, None otherwise.
    """
    try:
        from cryptography.x509 import load_pem_x509_csr

        csr_obj = load_pem_x509_csr(
            csr.encode("utf-8") if isinstance(csr, str) else csr
        )

        subject = csr_obj.subject
        result = {}

        for attribute in subject:
            if attribute.oid == NameOID.COMMON_NAME:
                result["CN"] = attribute.value
            elif attribute.oid == NameOID.ORGANIZATION_NAME:
                result["O"] = attribute.value
            elif attribute.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                result["OU"] = attribute.value
            elif attribute.oid == NameOID.COUNTRY_NAME:
                result["C"] = attribute.value
            elif attribute.oid == NameOID.STATE_OR_PROVINCE_NAME:
                result["ST"] = attribute.value
            elif attribute.oid == NameOID.LOCALITY_NAME:
                result["L"] = attribute.value

        return result if result else None

    except Exception:
        return None


def extract_sans_from_csr(csr: str) -> list[str] | None:
    """Extract Subject Alternative Names from a CSR.

    Args:
        csr: CSR in PEM format.

    Returns:
        List of SAN strings (DNS names, IP addresses) if found, None otherwise.
    """
    try:
        from cryptography.x509 import load_pem_x509_csr

        csr_obj = load_pem_x509_csr(
            csr.encode("utf-8") if isinstance(csr, str) else csr
        )

        # Get the extensions
        extensions = csr_obj.extensions

        # Find the SAN extension
        for ext in extensions:
            if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                sans = []
                san_ext = ext.value
                for name in san_ext:
                    # Handle both DNSName and IPAddress types
                    if hasattr(name, "value"):
                        sans.append(name.value)
                    else:
                        sans.append(str(name))
                return sans if sans else None

        return None

    except Exception:
        return None


def build_dn(components: dict[str, str]) -> str:
    """Build a Distinguished Name from components.

    Args:
        components: Dictionary of DN components (CN, O, OU, C, ST, L).

    Returns:
        Distinguished Name string.
    """
    parts = []

    # Order matters for DN
    order = ["C", "ST", "L", "O", "OU", "CN"]

    for key in order:
        if key in components:
            parts.append(f"{key}={components[key]}")

    # Add any remaining components
    for key, value in components.items():
        if key not in order:
            parts.append(f"{key}={value}")

    return "/".join(parts)


def parse_dn(dn: str) -> dict[str, str]:
    """Parse a Distinguished Name into components.

    Args:
        dn: Distinguished Name string.

    Returns:
        Dictionary of DN components.
    """
    components = {}

    # Match key=value pairs
    pattern = r"([A-Za-z]+)=([^/\n]+)"
    for match in re.finditer(pattern, dn):
        key, value = match.groups()
        components[key] = value.strip()

    return components


def compute_sha256(data: str) -> str:
    """Compute SHA-256 hash of data.

    Args:
        data: String to hash.

    Returns:
        Hex-encoded SHA-256 hash.
    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def normalize_dn(dn: str) -> str:
    """Normalize a Distinguished Name for comparison.

    Args:
        dn: Distinguished Name string.

    Returns:
        Normalized DN string.
    """
    # Remove extra whitespace, lowercase
    dn = re.sub(r"\s+", "", dn)
    dn = dn.lower()
    return dn


def format_response(
    status: str = "success", data: Any = None, message: str = "", **kwargs
) -> dict[str, Any]:
    """Format a standard API response.

    Args:
        status: Response status (success/error).
        data: Response data.
        message: Optional message.
        **kwargs: Additional response fields.

    Returns:
        Formatted response dictionary.
    """
    response = {"status": status}

    if data is not None:
        response["data"] = data

    if message:
        response["message"] = message

    response.update(kwargs)

    return response


def format_error(message: str, code: str = "ERROR", status_code: int = 500) -> tuple:
    """Format a standard error response.

    Args:
        message: Error message.
        code: Error code.
        status_code: HTTP status code.

    Returns:
        Tuple of (response_dict, status_code).
    """
    return ({"status": "error", "code": code, "message": message}, status_code)


def validate_required_fields(data: dict[str, Any], required: list[str]) -> str | None:
    """Validate that required fields are present in data.

    Args:
        data: Dictionary to validate.
        required: List of required field names.

    Returns:
        Error message if validation fails, None if successful.
    """
    missing = [field for field in required if field not in data or not data[field]]

    if missing:
        return f"Missing required fields: {', '.join(missing)}"

    return None


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename to remove potentially dangerous characters.

    Args:
        filename: Original filename.

    Returns:
        Sanitized filename.
    """
    # Remove path separators and dangerous characters
    filename = re.sub(r'[/\\:*?"<>|]', "", filename)

    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[: 255 - len(ext)] + ext

    return filename


def get_file_extension(path: str) -> str:
    """Get the file extension from a path.

    Args:
        path: File path.

    Returns:
        File extension (without dot), or empty string.
    """
    _, ext = os.path.splitext(path)
    return ext.lstrip(".")


def is_pem_format(data: str) -> bool:
    """Check if data is in PEM format.

    Args:
        data: String to check.

    Returns:
        True if data appears to be PEM format.
    """
    return "-----BEGIN" in data and "-----END" in data
