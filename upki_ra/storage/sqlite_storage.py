"""
uPKI RA Server - SQLite Storage Module.

This module provides SQLite-based storage implementation for persisting ACME data.
"""

import json
import os
import sqlite3
from typing import Any

from .abstract import AbstractStorage


class SQLiteStorage(AbstractStorage):
    """SQLite-based storage for ACME data.

    This class implements the AbstractStorage interface using SQLite as the
    backing store. It creates a local database file in the data directory
    for persisting nonces, accounts, orders, authorizations, and challenges.

    Attributes:
        data_dir: The directory where the SQLite database file is kept.
        db_path: The full path to the SQLite database file.
    """

    def __init__(self, data_dir: str) -> None:
        """Initialize the SQLite storage backend.

        Args:
            data_dir: The directory where the database file should be kept.
        """
        super().__init__(data_dir)
        self.db_path = os.path.join(data_dir, "acme.db")
        self._connection: sqlite3.Connection | None = None

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create a database connection.

        Returns:
            A SQLite connection object.

        Raises:
            sqlite3.Error: If connection cannot be established.
        """
        if self._connection is None:
            # Ensure directory exists
            os.makedirs(self.data_dir, exist_ok=True)
            self._connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self._connection.row_factory = sqlite3.Row
            # Enable WAL mode for better concurrency
            self._connection.execute("PRAGMA journal_mode=WAL")
            # Enable foreign keys
            self._connection.execute("PRAGMA foreign_keys=ON")
        return self._connection

    def __enter__(self) -> "SQLiteStorage":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - ensures connection is closed."""
        self.close()

    def initialize(self) -> None:
        """Initialize the storage backend.

        Creates all necessary database tables if they don't exist.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Create nonces table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS nonces (
                nonce TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Create accounts table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                jwk TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Create orders table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (account_id) REFERENCES accounts(id)
            )
            """
        )

        # Create authorizations table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS authorizations (
                id TEXT PRIMARY KEY,
                order_id TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (order_id) REFERENCES orders(id)
            )
            """
        )

        # Create challenges table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS challenges (
                id TEXT PRIMARY KEY,
                authorization_id TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (authorization_id) REFERENCES authorizations(id)
            )
            """
        )

        conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    # ========================================================================
    # Nonce Management
    # ========================================================================

    def add_nonce(self, nonce: str) -> bool:
        """Add a nonce to the storage.

        Args:
            nonce: The nonce value to store.

        Returns:
            True if successful, False otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO nonces (nonce) VALUES (?)", (nonce,))
            conn.commit()
            return True
        except sqlite3.Error:
            return False

    def remove_nonce(self, nonce: str) -> bool:
        """Remove and validate a nonce.

        Args:
            nonce: The nonce value to remove and validate.

        Returns:
            True if the nonce was valid and removed, False otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM nonces WHERE nonce = ?", (nonce,))
            deleted = cursor.rowcount > 0
            conn.commit()
            return deleted
        except sqlite3.Error:
            return False

    def get_nonce_count(self) -> int:
        """Get the count of stored nonces.

        Returns:
            The number of nonces currently stored.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM nonces")
            result = cursor.fetchone()
            return result[0] if result else 0
        except sqlite3.Error:
            return 0

    # ========================================================================
    # Account Management
    # ========================================================================

    def save_account(self, account_id: str, data: dict[str, Any]) -> bool:
        """Save an ACME account.

        Args:
            account_id: The unique account identifier.
            data: The account data to store.

        Returns:
            True if successful, False otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            jwk = json.dumps(data.get("jwk", {}))
            account_data = json.dumps(data)
            cursor.execute(
                "INSERT INTO accounts (id, jwk, data) VALUES (?, ?, ?)",
                (account_id, jwk, account_data),
            )
            conn.commit()
            return True
        except sqlite3.Error:
            return False

    def get_account(self, account_id: str) -> dict[str, Any] | None:
        """Retrieve an ACME account.

        Args:
            account_id: The unique account identifier.

        Returns:
            The account data if found, None otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM accounts WHERE id = ?", (account_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None
        except sqlite3.Error:
            return None

    def get_account_by_jwk(self, jwk: dict[str, Any]) -> dict[str, Any] | None:
        """Retrieve an ACME account by JWK.

        Args:
            jwk: The JSON Web Key to search for.

        Returns:
            The account data if found, None otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            jwk_json = json.dumps(jwk, sort_keys=True)
            cursor.execute("SELECT data FROM accounts WHERE jwk = ?", (jwk_json,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None
        except sqlite3.Error:
            return None

    def update_account(self, account_id: str, data: dict[str, Any]) -> bool:
        """Update an ACME account.

        Args:
            account_id: The unique account identifier.
            data: The updated account data.

        Returns:
            True if successful, False otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            account_data = json.dumps(data)
            cursor.execute(
                "UPDATE accounts SET data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (account_data, account_id),
            )
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error:
            return False

    def list_accounts(self) -> list[dict[str, Any]]:
        """List all ACME accounts.

        Returns:
            A list of all account data.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM accounts")
            rows = cursor.fetchall()
            return [json.loads(row[0]) for row in rows]
        except sqlite3.Error:
            return []

    # ========================================================================
    # Order Management
    # ========================================================================

    def save_order(self, order_id: str, data: dict[str, Any]) -> bool:
        """Save an ACME order.

        Args:
            order_id: The unique order identifier.
            data: The order data to store.

        Returns:
            True if successful, False otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            account_id = data.get("account_id", "")
            order_data = json.dumps(data)
            cursor.execute(
                "INSERT INTO orders (id, account_id, data) VALUES (?, ?, ?)",
                (order_id, account_id, order_data),
            )
            conn.commit()
            return True
        except sqlite3.Error:
            return False

    def get_order(self, order_id: str) -> dict[str, Any] | None:
        """Retrieve an ACME order.

        Args:
            order_id: The unique order identifier.

        Returns:
            The order data if found, None otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM orders WHERE id = ?", (order_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None
        except sqlite3.Error:
            return None

    def update_order(self, order_id: str, data: dict[str, Any]) -> bool:
        """Update an ACME order.

        Args:
            order_id: The unique order identifier.
            data: The updated order data.

        Returns:
            True if successful, False otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            order_data = json.dumps(data)
            cursor.execute(
                "UPDATE orders SET data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (order_data, order_id),
            )
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error:
            return False

    def list_orders(self) -> list[dict[str, Any]]:
        """List all ACME orders.

        Returns:
            A list of all order data.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM orders")
            rows = cursor.fetchall()
            return [json.loads(row[0]) for row in rows]
        except sqlite3.Error:
            return []

    # ========================================================================
    # Authorization Management
    # ========================================================================

    def save_authorization(self, auth_id: str, data: dict[str, Any]) -> bool:
        """Save an ACME authorization.

        Args:
            auth_id: The unique authorization identifier.
            data: The authorization data to store.

        Returns:
            True if successful, False otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            order_id = data.get("order_id", "")
            auth_data = json.dumps(data)
            cursor.execute(
                "INSERT INTO authorizations (id, order_id, data) VALUES (?, ?, ?)",
                (auth_id, order_id, auth_data),
            )
            conn.commit()
            return True
        except sqlite3.Error:
            return False

    def get_authorization(self, auth_id: str) -> dict[str, Any] | None:
        """Retrieve an ACME authorization.

        Args:
            auth_id: The unique authorization identifier.

        Returns:
            The authorization data if found, None otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM authorizations WHERE id = ?", (auth_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None
        except sqlite3.Error:
            return None

    def update_authorization(self, auth_id: str, data: dict[str, Any]) -> bool:
        """Update an ACME authorization.

        Args:
            auth_id: The unique authorization identifier.
            data: The updated authorization data.

        Returns:
            True if successful, False otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            auth_data = json.dumps(data)
            cursor.execute(
                "UPDATE authorizations SET data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (auth_data, auth_id),
            )
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error:
            return False

    def list_authorizations(self) -> list[dict[str, Any]]:
        """List all ACME authorizations.

        Returns:
            A list of all authorization data.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM authorizations")
            rows = cursor.fetchall()
            return [json.loads(row[0]) for row in rows]
        except sqlite3.Error:
            return []

    # ========================================================================
    # Challenge Management
    # ========================================================================

    def save_challenge(self, challenge_id: str, data: dict[str, Any]) -> bool:
        """Save an ACME challenge.

        Args:
            challenge_id: The unique challenge identifier.
            data: The challenge data to store.

        Returns:
            True if successful, False otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            authorization_id = data.get("authorization_id", "")
            challenge_data = json.dumps(data)
            cursor.execute(
                "INSERT INTO challenges (id, authorization_id, data) VALUES (?, ?, ?)",
                (challenge_id, authorization_id, challenge_data),
            )
            conn.commit()
            return True
        except sqlite3.Error:
            return False

    def get_challenge(self, challenge_id: str) -> dict[str, Any] | None:
        """Retrieve an ACME challenge.

        Args:
            challenge_id: The unique challenge identifier.

        Returns:
            The challenge data if found, None otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM challenges WHERE id = ?", (challenge_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None
        except sqlite3.Error:
            return None

    def get_challenge_by_token(self, token: str) -> dict[str, Any] | None:
        """Retrieve an ACME challenge by token.

        Args:
            token: The challenge token.

        Returns:
            The challenge data if found, None otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            # Search in the JSON data for the token
            cursor.execute("SELECT id, data FROM challenges")
            rows = cursor.fetchall()
            for row in rows:
                data = json.loads(row[1])
                if data.get("token") == token:
                    return data
            return None
        except sqlite3.Error:
            return None

    def update_challenge(self, challenge_id: str, data: dict[str, Any]) -> bool:
        """Update an ACME challenge.

        Args:
            challenge_id: The unique challenge identifier.
            data: The updated challenge data.

        Returns:
            True if successful, False otherwise.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            challenge_data = json.dumps(data)
            cursor.execute(
                "UPDATE challenges SET data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (challenge_data, challenge_id),
            )
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error:
            return False
