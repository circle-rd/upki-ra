"""
uPKI RA Server - ZMQ Tools Module.

This module provides ZMQ client functionality for communicating with the CA server.
It implements the CA-ZMQ protocol as defined in the protocol documentation.
"""

import json
from typing import Any

import zmq

from ..core.upki_error import CAConnectionError, UPKIError
from ..core.upki_logger import UPKILogger


class ZMQClient:
    """ZMQ client for communicating with the CA server.

    This class implements the REQ/REP pattern for communicating with the CA server
    via ZeroMQ. It handles connection management, message serialization, and error handling.

    Attributes:
        host: CA server hostname or IP address.
        port: CA server port number.
        timeout: Request timeout in milliseconds.
        logger: Logger instance for debugging.
    """

    # Default CA server configuration
    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 5000
    DEFAULT_TIMEOUT = 5000  # 5 seconds

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        timeout: int = DEFAULT_TIMEOUT,
        logger: UPKILogger | None = None,
    ) -> None:
        """Initialize the ZMQ client.

        Args:
            host: CA server hostname or IP address (default: 127.0.0.1).
            port: CA server port number (default: 5000).
            timeout: Request timeout in milliseconds (default: 5000).
            logger: Optional logger instance.
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.logger = logger or UPKILogger(name="upki-ra-zmq")
        self._socket: zmq.Socket | None = None
        self._context: zmq.Context | None = None

    @property
    def connection_url(self) -> str:
        """Get the ZMQ connection URL.

        Returns:
            Connection URL in format tcp://host:port.
        """
        return f"tcp://{self.host}:{self.port}"

    def _get_socket(self) -> zmq.Socket:
        """Get or create a ZMQ socket.

        Returns:
            ZMQ socket instance.

        Raises:
            CAConnectionError: If socket creation fails.
        """
        if self._socket is None:
            try:
                self._context = zmq.Context()
                self._socket = self._context.socket(zmq.REQ)
                if self._socket is None:
                    raise CAConnectionError("Failed to create ZMQ socket")
                self._socket.setsockopt(zmq.RCVTIMEO, self.timeout)
                self._socket.setsockopt(zmq.SNDTIMEO, self.timeout)
                self._socket.connect(self.connection_url)
                self.logger.debug(f"Connected to CA at {self.connection_url}")
            except zmq.ZMQError as e:
                self.logger.error(f"Failed to connect to CA: {e}")
                raise CAConnectionError(f"Failed to connect to CA: {e}") from e

        return self._socket

    def _send_message(
        self, task: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Send a message to the CA server and wait for response.

        Args:
            task: Task name to execute.
            params: Optional parameters for the task.

        Returns:
            Response dictionary from CA server.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error response.
        """
        message = {"TASK": task, "params": params or {}}

        try:
            socket = self._get_socket()

            # Send request
            self.logger.debug(f"Sending task: {task} with params: {params}")
            socket.send_string(json.dumps(message))

            # Receive response
            response_str = socket.recv_string()
            response = json.loads(response_str)

            self.logger.debug(f"Received response: {response}")

            # Check for error response
            if response.get("EVENT") == "UPKI ERROR":
                error_msg = response.get("MSG", "Unknown error")
                raise UPKIError(error_msg)

            return response

        except zmq.ZMQError as e:
            self.logger.error(f"ZMQ error: {e}")
            raise CAConnectionError(f"Communication with CA failed: {e}") from e
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON response: {e}")
            raise CAConnectionError(f"Invalid response from CA: {e}") from e

    def close(self) -> None:
        """Close the ZMQ connection."""
        if self._socket:
            self._socket.close()
            self._socket = None
        if self._context:
            self._context.term()
            self._context = None
        self.logger.debug("ZMQ connection closed")

    # -------------------------------------------------------------------------
    # CA Operations
    # -------------------------------------------------------------------------

    def get_ca(self) -> str:
        """Get CA certificate.

        Returns:
            CA certificate in PEM format.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("get_ca")
        return response.get("DATA", "")

    def get_crl(self) -> str:
        """Get current CRL.

        Returns:
            CRL in base64-encoded DER format.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("get_crl")
        return response.get("DATA", "")

    def generate_crl(self) -> str:
        """Generate new CRL.

        Returns:
            New CRL in base64-encoded DER format.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("generate_crl")
        return response.get("DATA", "")

    def list_profiles(self) -> dict[str, Any]:
        """List available certificate profiles.

        Returns:
            Dictionary of available profiles.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("list_profiles")
        return response.get("DATA", {})

    def get_profile(self, profile_name: str) -> dict[str, Any]:
        """Get details of a specific profile.

        Args:
            profile_name: Name of the profile to retrieve.

        Returns:
            Profile details dictionary.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("get_profile", {"profile": profile_name})
        return response.get("DATA", {})

    def sign_csr(self, csr: str, profile: str = "server") -> dict[str, Any]:
        """Sign a CSR.

        Args:
            csr: CSR in PEM format.
            profile: Certificate profile to use (default: server).

        Returns:
            Dictionary containing certificate and serial number.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("sign", {"csr": csr, "profile": profile})
        return response.get("DATA", {})

    def register_node(
        self, seed: str, cn: str, profile: str = "ra", sans: list | None = None
    ) -> dict[str, Any]:
        """Register a new node.

        Args:
            seed: Registration seed for validation.
            cn: Common Name for the node.
            profile: Certificate profile (default: ra).
            sans: Optional list of Subject Alternative Names.

        Returns:
            Dictionary containing registration details.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        params = {"seed": seed, "cn": cn, "profile": profile}
        if sans:
            params["sans"] = sans

        response = self._send_message("register", params)
        return response.get("DATA", {})

    def renew_certificate(self, dn: str) -> dict[str, Any]:
        """Renew a certificate.

        Args:
            dn: Distinguished Name of the certificate to renew.

        Returns:
            Dictionary containing new certificate and serial number.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("renew", {"dn": dn})
        return response.get("DATA", {})

    def revoke_certificate(self, dn: str, reason: str = "unspecified") -> bool:
        """Revoke a certificate.

        Args:
            dn: Distinguished Name of the certificate to revoke.
            reason: Revocation reason (default: unspecified).

        Returns:
            True if revocation was successful.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("revoke", {"dn": dn, "reason": reason})
        return response.get("DATA", False)

    def unrevoke_certificate(self, dn: str) -> bool:
        """Unrevoke a certificate.

        Args:
            dn: Distinguished Name of the certificate to unrevoke.

        Returns:
            True if unrevocation was successful.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("unrevoke", {"dn": dn})
        return response.get("DATA", False)

    def view_certificate(self, dn: str) -> dict[str, Any]:
        """View certificate details.

        Args:
            dn: Distinguished Name of the certificate.

        Returns:
            Certificate details dictionary.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("view", {"dn": dn})
        return response.get("DATA", {})

    def ocsp_check(self, serial: str) -> dict[str, Any]:
        """Check OCSP status of a certificate.

        Args:
            serial: Certificate serial number.

        Returns:
            OCSP status dictionary.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("ocsp_check", {"serial": serial})
        return response.get("DATA", {})

    # -------------------------------------------------------------------------
    # Admin Operations
    # -------------------------------------------------------------------------

    def list_admins(self) -> list:
        """List all administrators.

        Returns:
            List of administrator DNs.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("list_admins")
        return response.get("DATA", [])

    def add_admin(self, dn: str) -> bool:
        """Add an administrator.

        Args:
            dn: Distinguished Name of the administrator.

        Returns:
            True if successful.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("add_admin", {"dn": dn})
        return response.get("DATA", False)

    def remove_admin(self, dn: str) -> bool:
        """Remove an administrator.

        Args:
            dn: Distinguished Name of the administrator.

        Returns:
            True if successful.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("remove_admin", {"dn": dn})
        return response.get("DATA", False)

    # -------------------------------------------------------------------------
    # Node Operations
    # -------------------------------------------------------------------------

    def list_nodes(self) -> list:
        """List all nodes/certificates managed by the CA.

        Returns:
            List of node dictionaries with dn, cn, profile, state, serial.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("list_nodes")
        return response.get("DATA", [])

    def get_node(self, cn: str) -> dict[str, Any]:
        """Get details of a specific node.

        Args:
            cn: Common Name of the node.

        Returns:
            Node details dictionary.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("get_node", {"cn": cn})
        return response.get("DATA", {})

    def delete_node(self, dn: str) -> bool:
        """Delete a node/certificate.

        Args:
            dn: Distinguished Name of the node to delete.

        Returns:
            True if deletion was successful.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("delete", {"dn": dn})
        return response.get("DATA", False)


class RegistrationClient(ZMQClient):
    """ZMQ client for RA registration with CA server.

    This class extends ZMQClient to use the registration endpoint (port 5001)
    for initial RA registration.
    """

    # Registration endpoint uses port 5001
    DEFAULT_PORT = 5001

    def __init__(
        self,
        host: str = ZMQClient.DEFAULT_HOST,
        timeout: int = ZMQClient.DEFAULT_TIMEOUT,
        logger: UPKILogger | None = None,
    ) -> None:
        """Initialize the registration client.

        Args:
            host: CA server hostname or IP address.
            timeout: Request timeout in milliseconds.
            logger: Optional logger instance.
        """
        super().__init__(
            host=host, port=self.DEFAULT_PORT, timeout=timeout, logger=logger
        )

    def register_ra(self, seed: str, cn: str, profile: str = "ra") -> dict[str, Any]:
        """Register RA with CA server.

        Args:
            seed: Registration seed for validation.
            cn: Common Name for the RA node.
            profile: Certificate profile (default: ra).

        Returns:
            Registration response dictionary.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message(
            "register", {"seed": seed, "cn": cn, "profile": profile}
        )
        return response.get("DATA", {})

    def get_status(self) -> dict[str, Any]:
        """Get registration status.

        Returns:
            Status dictionary.

        Raises:
            CAConnectionError: If communication fails.
            UPKIError: If CA returns an error.
        """
        response = self._send_message("status")
        return response.get("DATA", {})
