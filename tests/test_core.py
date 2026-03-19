"""
uPKI RA Server - Core Module Unit Tests.

Unit tests for core components (error handling, logging).
"""

import logging
import os
import shutil
import tempfile
import unittest

from upki_ra.core.upki_error import (
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
from upki_ra.core.upki_logger import UPKILogger, get_logger


class TestUPKIError(unittest.TestCase):
    """Test cases for UPKI error classes."""

    def test_base_error(self):
        """Test base UPKIError class."""
        error = UPKIError("Test error message")
        self.assertEqual(error.message, "Test error message")
        self.assertEqual(error.code, "UPKI_ERROR")
        self.assertEqual(str(error), "[UPKI_ERROR] Test error message")

    def test_base_error_with_code(self):
        """Test base UPKIError with custom code."""
        error = UPKIError("Test error", code="CUSTOM_CODE")
        self.assertEqual(error.code, "CUSTOM_CODE")

    def test_to_dict(self):
        """Test error to_dict method."""
        error = UPKIError("Test error")
        result = error.to_dict()

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "UPKI_ERROR")
        self.assertEqual(result["message"], "Test error")

    def test_authentication_error(self):
        """Test AuthenticationError."""
        error = AuthenticationError("Auth failed")
        self.assertEqual(error.code, "AUTH_ERROR")

    def test_authorization_error(self):
        """Test AuthorizationError."""
        error = AuthorizationError("Not authorized")
        self.assertEqual(error.code, "AUTHZ_ERROR")

    def test_validation_error(self):
        """Test ValidationError."""
        error = ValidationError("Invalid input")
        self.assertEqual(error.code, "VALIDATION_ERROR")

    def test_ca_connection_error(self):
        """Test CAConnectionError."""
        error = CAConnectionError("Connection failed")
        self.assertEqual(error.code, "CA_CONNECTION_ERROR")

    def test_certificate_error(self):
        """Test CertificateError."""
        error = CertificateError("Certificate issue")
        self.assertEqual(error.code, "CERTIFICATE_ERROR")

    def test_registration_error(self):
        """Test RegistrationError."""
        error = RegistrationError("Registration failed")
        self.assertEqual(error.code, "REGISTRATION_ERROR")

    def test_configuration_error(self):
        """Test ConfigurationError."""
        error = ConfigurationError("Config issue")
        self.assertEqual(error.code, "CONFIG_ERROR")

    def test_not_found_error(self):
        """Test NotFoundError."""
        error = NotFoundError("Resource not found")
        self.assertEqual(error.code, "NOT_FOUND")

    def test_conflict_error(self):
        """Test ConflictError."""
        error = ConflictError("Resource conflict")
        self.assertEqual(error.code, "CONFLICT")

    def test_revocation_error(self):
        """Test RevocationError."""
        error = RevocationError("Revocation failed")
        self.assertEqual(error.code, "REVOCATION_ERROR")


class TestUPKILogger(unittest.TestCase):
    """Test cases for UPKILogger class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_logger_creation(self):
        """Test logger creation."""
        logger = UPKILogger(name="test-logger")
        self.assertEqual(logger.name, "test-logger")

    def test_logger_with_file(self):
        """Test logger with file output."""
        log_file = os.path.join(self.temp_dir, "test.log")
        logger = UPKILogger(name="test-logger", log_file=log_file)

        logger.info("Test message")

        # Check file was created
        self.assertTrue(os.path.exists(log_file))

    def test_logger_default_format(self):
        """Test default log format."""
        logger = UPKILogger(name="test-logger")

        # Should have default format
        self.assertEqual(
            logger.DEFAULT_FORMAT,
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

    def test_get_logger_factory(self):
        """Test get_logger factory function."""
        logger = get_logger(name="factory-test", log_dir=self.temp_dir)

        self.assertEqual(logger.name, "factory-test")
        self.assertTrue(logger.log_file is not None)

    def test_log_levels(self):
        """Test different log levels."""
        log_file = os.path.join(self.temp_dir, "levels.log")
        logger = UPKILogger(name="test-levels", log_file=log_file, level=logging.DEBUG)

        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")
        logger.critical("Critical message")

        # All should work without errors
        self.assertTrue(os.path.exists(log_file))


if __name__ == "__main__":
    unittest.main()
