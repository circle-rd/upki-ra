"""
uPKI RA Server - Registration Authority Core Module.

This module provides the core RegistrationAuthority class that manages
all RA operations including certificate enrollment, revocation, and renewal.
"""

import os
from typing import Any

from .core.upki_error import (
    CAConnectionError,
    CertificateError,
    RegistrationError,
    RevocationError,
    ValidationError,
)
from .core.upki_logger import UPKILogger
from .utils.common import (
    ensure_directory,
    read_json_file,
    write_json_file,
)
from .utils.tlsauth import CertificateValidator, TLSAuth
from .utils.tools import RegistrationClient, ZMQClient


class RegistrationAuthority:
    """Core class for the uPKI Registration Authority.

    This class manages all RA operations including:
    - Certificate enrollment (CSR signing)
    - Certificate renewal
    - Certificate revocation
    - Node registration
    - Administrator management
    - CA communication via ZMQ

    Attributes:
        data_dir: Path to RA data directory.
        host: CA server hostname.
        port: CA server port.
        logger: Logger instance.
    """

    DEFAULT_DATA_DIR = os.path.expanduser("~/.upki/ra")
    DEFAULT_CA_HOST = "127.0.0.1"
    DEFAULT_CA_PORT = 5000

    def __init__(
        self,
        data_dir: str | None = None,
        ca_host: str = DEFAULT_CA_HOST,
        ca_port: int = DEFAULT_CA_PORT,
        logger: UPKILogger | None = None,
    ) -> None:
        """Initialize the Registration Authority.

        Args:
            data_dir: Path to RA data directory (default: ~/.upki/ra).
            ca_host: CA server hostname (default: 127.0.0.1).
            ca_port: CA server port (default: 5000).
            logger: Optional logger instance.

        Raises:
            ConfigurationError: If initialization fails.
        """
        self.data_dir = data_dir or self.DEFAULT_DATA_DIR
        self.ca_host = ca_host
        self.ca_port = ca_port

        self.logger = logger or UPKILogger(name="upki-ra")

        # Ensure data directory exists
        ensure_directory(self.data_dir)

        # Initialize ZMQ client
        self._zmq_client: ZMQClient | None = None
        self._reg_client: RegistrationClient | None = None

        # Initialize TLS authentication
        self._tls_auth: TLSAuth | None = None

        # Configuration
        self._config: dict[str, Any] = {}
        self._load_config()

        # Initialize admin list
        self._admin_dns: list[str] = []

        self.logger.info(f"Registration Authority initialized at {self.data_dir}")

    @property
    def zmq_client(self) -> ZMQClient:
        """Get or create ZMQ client instance."""
        if self._zmq_client is None:
            self._zmq_client = ZMQClient(
                host=self.ca_host, port=self.ca_port, logger=self.logger
            )
        return self._zmq_client

    @property
    def reg_client(self) -> RegistrationClient:
        """Get or create registration client instance."""
        if self._reg_client is None:
            self._reg_client = RegistrationClient(host=self.ca_host, logger=self.logger)
        return self._reg_client

    @property
    def tls_auth(self) -> TLSAuth:
        """Get or create TLS authentication instance."""
        if self._tls_auth is None:
            ca_cert = os.path.join(self.data_dir, "ca.crt")
            self._tls_auth = TLSAuth(ca_cert=ca_cert, logger=self.logger)
            self._tls_auth.admin_dns = self._admin_dns
        return self._tls_auth

    @property
    def seed(self) -> str:
        """Get the RA registration seed.

        Returns:
            The registration seed stored in config, or empty string if not registered.
        """
        seed = self._config.get("seed", "")
        return seed if isinstance(seed, str) else ""

    def _load_config(self) -> None:
        """Load configuration from file."""
        config_path = os.path.join(self.data_dir, "config.json")
        config = read_json_file(config_path)

        if config:
            self._config = config
            self.logger.info("Configuration loaded")
        else:
            self._config = {}
            self.logger.info("No configuration file found, using defaults")

    def _save_config(self) -> None:
        """Save configuration to file."""
        config_path = os.path.join(self.data_dir, "config.json")
        write_json_file(config_path, self._config)
        self.logger.debug("Configuration saved")

    def _get_ca_cert_path(self) -> str:
        """Get path to CA certificate."""
        return os.path.join(self.data_dir, "ca.crt")

    def _get_crl_path(self) -> str:
        """Get path to CRL file."""
        return os.path.join(self.data_dir, "crl.pem")

    def is_registered(self) -> bool:
        """Check if RA is registered with CA.

        Returns:
            True if RA has valid certificates from CA.
        """
        ra_cert = os.path.join(self.data_dir, "ra.crt")
        ra_key = os.path.join(self.data_dir, "ra.key")

        return os.path.exists(ra_cert) and os.path.exists(ra_key)

    # -------------------------------------------------------------------------
    # Registration
    # -------------------------------------------------------------------------

    def register_with_ca(self, seed: str, cn: str) -> dict[str, Any]:
        """Register RA with CA server.

        Args:
            seed: Registration seed.
            cn: RA Common Name.

        Returns:
            Registration response data.

        Raises:
            RegistrationError: If registration fails.
        """
        if not seed:
            raise ValidationError("Registration seed is required")

        if not cn:
            raise ValidationError("Common Name is required")

        try:
            self.logger.info(f"Registering RA with CA: {cn}")

            response = self.reg_client.register_ra(seed=seed, cn=cn, profile="ra")

            # Save registration status
            self._config["registered"] = True
            self._config["ra_cn"] = cn
            self._save_config()

            self.logger.info(f"RA registered successfully: {cn}")
            return response

        except Exception as e:
            self.logger.error(f"Registration failed: {e}")
            raise RegistrationError(f"Failed to register with CA: {e}") from e

    def load_admin_dns(self, dns: list[str]) -> None:
        """Load admin DNs from CA.

        Args:
            dns: List of admin Distinguished Names.
        """
        self._admin_dns = dns
        if self._tls_auth:
            self._tls_auth.admin_dns = dns
        self.logger.info(f"Loaded {len(dns)} admin DNs")

    def sync_admins_from_ca(self) -> list[str]:
        """Synchronize admin list from CA.

        Returns:
            List of admin DNs.

        Raises:
            CAConnectionError: If communication with CA fails.
        """
        try:
            admins = self.zmq_client.list_admins()
            self.load_admin_dns(admins)
            return admins
        except CAConnectionError:
            raise
        except Exception as e:
            self.logger.error(f"Failed to sync admins: {e}")
            return self._admin_dns

    # -------------------------------------------------------------------------
    # Certificate Operations
    # -------------------------------------------------------------------------

    def certify(self, csr: str, profile: str = "server") -> dict[str, Any]:
        """Sign a certificate request (certify).

        This is the main certificate enrollment endpoint. The CSR is validated
        and forwarded to the CA for signing.

        Args:
            csr: CSR in PEM format.
            profile: Certificate profile to use.

        Returns:
            Dictionary containing certificate, DN, and serial number.

        Raises:
            ValidationError: If CSR or profile is invalid.
            CAConnectionError: If communication with CA fails.
        """
        # Validate CSR
        is_valid, error = CertificateValidator.validate_csr(csr)
        if not is_valid:
            raise ValidationError(error)

        # Validate profile
        is_valid, error = CertificateValidator.validate_profile(profile)
        if not is_valid:
            raise ValidationError(error)

        try:
            self.logger.info(f"Processing certificate request for profile: {profile}")

            response = self.zmq_client.sign_csr(csr=csr, profile=profile)

            self.logger.info(f"Certificate signed successfully: {response.get('dn')}")
            return response

        except CAConnectionError:
            raise
        except Exception as e:
            self.logger.error(f"Certification failed: {e}")
            raise CertificateError(f"Failed to sign certificate: {e}") from e

    def renew(self, dn: str) -> dict[str, Any]:
        """Renew a certificate.

        Args:
            dn: Distinguished Name of certificate to renew.

        Returns:
            Dictionary containing new certificate and serial number.

        Raises:
            ValidationError: If DN is invalid.
            NotFoundError: If certificate not found.
            CAConnectionError: If communication with CA fails.
        """
        if not dn:
            raise ValidationError("Distinguished Name is required")

        try:
            self.logger.info(f"Renewing certificate: {dn}")

            response = self.zmq_client.renew_certificate(dn=dn)

            self.logger.info("Certificate renewed successfully")
            return response

        except CAConnectionError:
            raise
        except Exception as e:
            self.logger.error(f"Renewal failed: {e}")
            raise CertificateError(f"Failed to renew certificate: {e}") from e

    def revoke(self, dn: str, reason: str = "unspecified") -> bool:
        """Revoke a certificate.

        Args:
            dn: Distinguished Name of certificate to revoke.
            reason: Revocation reason.

        Returns:
            True if revocation successful.

        Raises:
            ValidationError: If DN or reason is invalid.
            NotFoundError: If certificate not found.
            CAConnectionError: If communication with CA fails.
        """
        if not dn:
            raise ValidationError("Distinguished Name is required")

        # Validate reason
        is_valid, error = CertificateValidator.validate_revocation_reason(reason)
        if not is_valid:
            raise ValidationError(error)

        try:
            self.logger.info(f"Revoking certificate: {dn} (reason: {reason})")

            result = self.zmq_client.revoke_certificate(dn=dn, reason=reason)

            self.logger.info("Certificate revoked successfully")
            return result

        except CAConnectionError:
            raise
        except Exception as e:
            self.logger.error(f"Revocation failed: {e}")
            raise RevocationError(f"Failed to revoke certificate: {e}") from e

    def unrevoke(self, dn: str) -> bool:
        """Unrevoke a certificate.

        Args:
            dn: Distinguished Name of certificate to unrevoke.

        Returns:
            True if unrevocation successful.

        Raises:
            ValidationError: If DN is invalid.
            NotFoundError: If certificate not found.
            CAConnectionError: If communication with CA fails.
        """
        if not dn:
            raise ValidationError("Distinguished Name is required")

        try:
            self.logger.info(f"Unrevoking certificate: {dn}")

            result = self.zmq_client.unrevoke_certificate(dn=dn)

            self.logger.info("Certificate unrevoked successfully")
            return result

        except CAConnectionError:
            raise
        except Exception as e:
            self.logger.error(f"Unrevocation failed: {e}")
            raise RevocationError(f"Failed to unrevoke certificate: {e}") from e

    def view_certificate(self, dn: str) -> dict[str, Any]:
        """View certificate details.

        Args:
            dn: Distinguished Name of certificate.

        Returns:
            Certificate details.

        Raises:
            ValidationError: If DN is invalid.
            NotFoundError: If certificate not found.
            CAConnectionError: If communication with CA fails.
        """
        if not dn:
            raise ValidationError("Distinguished Name is required")

        try:
            return self.zmq_client.view_certificate(dn=dn)
        except CAConnectionError:
            raise
        except Exception as e:
            self.logger.error(f"Failed to view certificate: {e}")
            raise CertificateError(f"Failed to view certificate: {e}") from e

    # -------------------------------------------------------------------------
    # CA Certificate and CRL
    # -------------------------------------------------------------------------

    def get_ca_certificate(self) -> str:
        """Get CA certificate.

        Returns:
            CA certificate in PEM format.

        Raises:
            CAConnectionError: If communication with CA fails.
        """
        try:
            return self.zmq_client.get_ca()
        except CAConnectionError:
            raise
        except Exception as e:
            self.logger.error(f"Failed to get CA certificate: {e}")
            raise CertificateError(f"Failed to get CA certificate: {e}") from e

    def get_crl(self) -> str:
        """Get current CRL.

        Returns:
            CRL in PEM format.

        Raises:
            CAConnectionError: If communication with CA fails.
        """
        try:
            return self.zmq_client.get_crl()
        except CAConnectionError:
            raise
        except Exception as e:
            self.logger.error(f"Failed to get CRL: {e}")
            raise CertificateError(f"Failed to get CRL: {e}") from e

    def generate_crl(self) -> str:
        """Generate new CRL.

        Returns:
            New CRL in PEM format.

        Raises:
            CAConnectionError: If communication with CA fails.
        """
        try:
            return self.zmq_client.generate_crl()
        except CAConnectionError:
            raise
        except Exception as e:
            self.logger.error(f"Failed to generate CRL: {e}")
            raise CertificateError(f"Failed to generate CRL: {e}") from e

    # -------------------------------------------------------------------------
    # Profiles
    # -------------------------------------------------------------------------

    def list_profiles(self) -> dict[str, Any]:
        """List available certificate profiles.

        Returns:
            Dictionary of available profiles.

        Raises:
            CAConnectionError: If communication with CA fails.
        """
        try:
            return self.zmq_client.list_profiles()
        except CAConnectionError:
            raise
        except Exception as e:
            self.logger.error(f"Failed to list profiles: {e}")
            raise CertificateError(f"Failed to list profiles: {e}") from e

    def get_profile(self, profile_name: str) -> dict[str, Any]:
        """Get profile details.

        Args:
            profile_name: Name of profile.

        Returns:
            Profile details.

        Raises:
            ValidationError: If profile name is invalid.
            CAConnectionError: If communication with CA fails.
        """
        try:
            return self.zmq_client.get_profile(profile_name)
        except CAConnectionError:
            raise
        except Exception as e:
            self.logger.error(f"Failed to get profile: {e}")
            raise CertificateError(f"Failed to get profile: {e}") from e

    # -------------------------------------------------------------------------
    # OCSP
    # -------------------------------------------------------------------------

    def check_ocsp(self, serial: str) -> dict[str, Any]:
        """Check OCSP status of a certificate.

        Args:
            serial: Certificate serial number.

        Returns:
            OCSP status.

        Raises:
            ValidationError: If serial is invalid.
            CAConnectionError: If communication with CA fails.
        """
        if not serial:
            raise ValidationError("Serial number is required")

        try:
            return self.zmq_client.ocsp_check(serial=serial)
        except CAConnectionError:
            raise
        except Exception as e:
            self.logger.error(f"OCSP check failed: {e}")
            raise CertificateError(f"OCSP check failed: {e}") from e

    # -------------------------------------------------------------------------
    # Admin Management
    # -------------------------------------------------------------------------

    def add_admin(self, dn: str) -> bool:
        """Add an administrator.

        Args:
            dn: Distinguished Name of admin to add.

        Returns:
            True if successful.

        Raises:
            ValidationError: If DN is invalid.
            CAConnectionError: If communication with CA fails.
        """
        if not dn:
            raise ValidationError("Distinguished Name is required")

        try:
            result = self.zmq_client.add_admin(dn=dn)

            if result:
                self._admin_dns.append(dn)
                if self._tls_auth:
                    self._tls_auth.admin_dns = self._admin_dns

            return result

        except CAConnectionError:
            raise
        except Exception as e:
            self.logger.error(f"Failed to add admin: {e}")
            raise CertificateError(f"Failed to add admin: {e}") from e

    def remove_admin(self, dn: str) -> bool:
        """Remove an administrator.

        Args:
            dn: Distinguished Name of admin to remove.

        Returns:
            True if successful.

        Raises:
            ValidationError: If DN is invalid.
            CAConnectionError: If communication with CA fails.
        """
        if not dn:
            raise ValidationError("Distinguished Name is required")

        try:
            result = self.zmq_client.remove_admin(dn=dn)

            if result and dn in self._admin_dns:
                self._admin_dns.remove(dn)
                if self._tls_auth:
                    self._tls_auth.admin_dns = self._admin_dns

            return result

        except CAConnectionError:
            raise
        except Exception as e:
            self.logger.error(f"Failed to remove admin: {e}")
            raise CertificateError(f"Failed to remove admin: {e}") from e

    # -------------------------------------------------------------------------
    # Cleanup
    # -------------------------------------------------------------------------

    def shutdown(self) -> None:
        """Shutdown RA and cleanup resources."""
        self.logger.info("Shutting down RA...")

        if self._zmq_client:
            self._zmq_client.close()
            self._zmq_client = None

        if self._reg_client:
            self._reg_client.close()
            self._reg_client = None

        self.logger.info("RA shutdown complete")
