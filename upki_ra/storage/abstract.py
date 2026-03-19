"""
uPKI RA Server - Abstract Storage Module.

This module defines the abstract base class for all storage implementations.
"""

from abc import ABC, abstractmethod
from typing import Any


class AbstractStorage(ABC):
    """Abstract base class for storage implementations.

    This class defines the interface that all storage backends must implement.
    It provides methods for storing and retrieving ACME-related data including
    nonces, accounts, orders, authorizations, and challenges.

    Attributes:
        data_dir: The directory where storage files are kept.
    """

    def __init__(self, data_dir: str) -> None:
        """Initialize the storage backend.

        Args:
            data_dir: The directory where storage files should be kept.
        """
        self.data_dir = data_dir

    @abstractmethod
    def initialize(self) -> None:
        """Initialize the storage backend.

        This method should be called once at startup to create
        necessary tables or files.
        """

    # ========================================================================
    # Nonce Management
    # ========================================================================

    @abstractmethod
    def add_nonce(self, nonce: str) -> bool:
        """Add a nonce to the storage.

        Args:
            nonce: The nonce value to store.

        Returns:
            True if successful, False otherwise.
        """

    @abstractmethod
    def remove_nonce(self, nonce: str) -> bool:
        """Remove and validate a nonce.

        Args:
            nonce: The nonce value to remove and validate.

        Returns:
            True if the nonce was valid and removed, False otherwise.
        """

    @abstractmethod
    def get_nonce_count(self) -> int:
        """Get the count of stored nonces.

        Returns:
            The number of nonces currently stored.
        """

    # ========================================================================
    # Account Management
    # ========================================================================

    @abstractmethod
    def save_account(self, account_id: str, data: dict[str, Any]) -> bool:
        """Save an ACME account.

        Args:
            account_id: The unique account identifier.
            data: The account data to store.

        Returns:
            True if successful, False otherwise.
        """

    @abstractmethod
    def get_account(self, account_id: str) -> dict[str, Any] | None:
        """Retrieve an ACME account.

        Args:
            account_id: The unique account identifier.

        Returns:
            The account data if found, None otherwise.
        """

    @abstractmethod
    def get_account_by_jwk(self, jwk: dict[str, Any]) -> dict[str, Any] | None:
        """Retrieve an ACME account by JWK.

        Args:
            jwk: The JSON Web Key to search for.

        Returns:
            The account data if found, None otherwise.
        """

    @abstractmethod
    def update_account(self, account_id: str, data: dict[str, Any]) -> bool:
        """Update an ACME account.

        Args:
            account_id: The unique account identifier.
            data: The updated account data.

        Returns:
            True if successful, False otherwise.
        """

    @abstractmethod
    def list_accounts(self) -> list[dict[str, Any]]:
        """List all ACME accounts.

        Returns:
            A list of all account data.
        """

    # ========================================================================
    # Order Management
    # ========================================================================

    @abstractmethod
    def save_order(self, order_id: str, data: dict[str, Any]) -> bool:
        """Save an ACME order.

        Args:
            order_id: The unique order identifier.
            data: The order data to store.

        Returns:
            True if successful, False otherwise.
        """

    @abstractmethod
    def get_order(self, order_id: str) -> dict[str, Any] | None:
        """Retrieve an ACME order.

        Args:
            order_id: The unique order identifier.

        Returns:
            The order data if found, None otherwise.
        """

    @abstractmethod
    def update_order(self, order_id: str, data: dict[str, Any]) -> bool:
        """Update an ACME order.

        Args:
            order_id: The unique order identifier.
            data: The updated order data.

        Returns:
            True if successful, False otherwise.
        """

    @abstractmethod
    def list_orders(self) -> list[dict[str, Any]]:
        """List all ACME orders.

        Returns:
            A list of all order data.
        """

    # ========================================================================
    # Authorization Management
    # ========================================================================

    @abstractmethod
    def save_authorization(self, auth_id: str, data: dict[str, Any]) -> bool:
        """Save an ACME authorization.

        Args:
            auth_id: The unique authorization identifier.
            data: The authorization data to store.

        Returns:
            True if successful, False otherwise.
        """

    @abstractmethod
    def get_authorization(self, auth_id: str) -> dict[str, Any] | None:
        """Retrieve an ACME authorization.

        Args:
            auth_id: The unique authorization identifier.

        Returns:
            The authorization data if found, None otherwise.
        """

    @abstractmethod
    def update_authorization(self, auth_id: str, data: dict[str, Any]) -> bool:
        """Update an ACME authorization.

        Args:
            auth_id: The unique authorization identifier.
            data: The updated authorization data.

        Returns:
            True if successful, False otherwise.
        """

    @abstractmethod
    def list_authorizations(self) -> list[dict[str, Any]]:
        """List all ACME authorizations.

        Returns:
            A list of all authorization data.
        """

    # ========================================================================
    # Challenge Management
    # ========================================================================

    @abstractmethod
    def save_challenge(self, challenge_id: str, data: dict[str, Any]) -> bool:
        """Save an ACME challenge.

        Args:
            challenge_id: The unique challenge identifier.
            data: The challenge data to store.

        Returns:
            True if successful, False otherwise.
        """

    @abstractmethod
    def get_challenge(self, challenge_id: str) -> dict[str, Any] | None:
        """Retrieve an ACME challenge.

        Args:
            challenge_id: The unique challenge identifier.

        Returns:
            The challenge data if found, None otherwise.
        """

    @abstractmethod
    def get_challenge_by_token(self, token: str) -> dict[str, Any] | None:
        """Retrieve an ACME challenge by token.

        Args:
            token: The challenge token.

        Returns:
            The challenge data if found, None otherwise.
        """

    @abstractmethod
    def update_challenge(self, challenge_id: str, data: dict[str, Any]) -> bool:
        """Update an ACME challenge.

        Args:
            challenge_id: The unique challenge identifier.
            data: The updated challenge data.

        Returns:
            True if successful, False otherwise.
        """
