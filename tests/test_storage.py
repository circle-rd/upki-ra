"""
uPKI RA Server - Storage Unit Tests.

Unit tests for SQLite storage implementation.
"""

import shutil
import tempfile
import unittest

from server.storage import SQLiteStorage


class TestSQLiteStorage(unittest.TestCase):
    """Test cases for SQLite storage implementation."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage = SQLiteStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        """Clean up test fixtures."""
        if self.storage:
            self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ========================================================================
    # Nonce Management Tests
    # ========================================================================

    def test_add_nonce(self):
        """Test adding a nonce."""
        result = self.storage.add_nonce("test-nonce-123")
        self.assertTrue(result)

        # Verify nonce count
        count = self.storage.get_nonce_count()
        self.assertEqual(count, 1)

    def test_add_multiple_nonces(self):
        """Test adding multiple nonces."""
        self.storage.add_nonce("nonce-1")
        self.storage.add_nonce("nonce-2")
        self.storage.add_nonce("nonce-3")

        count = self.storage.get_nonce_count()
        self.assertEqual(count, 3)

    def test_remove_nonce(self):
        """Test removing a nonce."""
        self.storage.add_nonce("test-nonce")

        # Remove the nonce
        result = self.storage.remove_nonce("test-nonce")
        self.assertTrue(result)

        # Verify nonce is removed
        count = self.storage.get_nonce_count()
        self.assertEqual(count, 0)

    def test_remove_nonexistent_nonce(self):
        """Test removing a nonexistent nonce."""
        result = self.storage.remove_nonce("nonexistent")
        self.assertFalse(result)

    def test_nonce_count_empty(self):
        """Test nonce count on empty storage."""
        count = self.storage.get_nonce_count()
        self.assertEqual(count, 0)

    # ========================================================================
    # Account Management Tests
    # ========================================================================

    def test_save_account(self):
        """Test saving an account."""
        account_data = {
            "status": "valid",
            "jwk": {"kty": "RSA", "n": "test", "e": "AQAB"},
            "contact": ["mailto:test@example.com"],
            "created_at": "2024-01-01T00:00:00Z",
        }

        result = self.storage.save_account("account-123", account_data)
        self.assertTrue(result)

    def test_get_account(self):
        """Test retrieving an account."""
        account_data = {
            "status": "valid",
            "jwk": {"kty": "RSA", "n": "test", "e": "AQAB"},
            "contact": ["mailto:test@example.com"],
        }

        self.storage.save_account("account-123", account_data)

        retrieved = self.storage.get_account("account-123")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["status"], "valid")
        self.assertEqual(retrieved["jwk"]["kty"], "RSA")

    def test_get_nonexistent_account(self):
        """Test retrieving a nonexistent account."""
        result = self.storage.get_account("nonexistent")
        self.assertIsNone(result)

    def test_update_account(self):
        """Test updating an account."""
        account_data = {
            "status": "valid",
            "jwk": {"kty": "RSA", "n": "test", "e": "AQAB"},
        }

        self.storage.save_account("account-123", account_data)

        # Update the account
        updated_data = {
            "status": "deactivated",
            "jwk": {"kty": "RSA", "n": "test", "e": "AQAB"},
        }

        result = self.storage.update_account("account-123", updated_data)
        self.assertTrue(result)

        # Verify the update
        retrieved = self.storage.get_account("account-123")
        self.assertEqual(retrieved["status"], "deactivated")

    def test_list_accounts(self):
        """Test listing all accounts."""
        # Create multiple accounts
        self.storage.save_account("account-1", {"status": "valid", "jwk": {}})
        self.storage.save_account("account-2", {"status": "valid", "jwk": {}})

        accounts = self.storage.list_accounts()
        self.assertEqual(len(accounts), 2)

    def test_list_accounts_empty(self):
        """Test listing accounts when none exist."""
        accounts = self.storage.list_accounts()
        self.assertEqual(len(accounts), 0)

    # ========================================================================
    # Order Management Tests
    # ========================================================================

    def test_save_order(self):
        """Test saving an order."""
        # First create an account
        self.storage.save_account("account-123", {"status": "valid", "jwk": {}})

        order_data = {
            "status": "pending",
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "account_id": "account-123",
        }

        result = self.storage.save_order("order-123", order_data)
        self.assertTrue(result)

    def test_get_order(self):
        """Test retrieving an order."""
        self.storage.save_account("account-123", {"status": "valid", "jwk": {}})

        order_data = {
            "status": "pending",
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "account_id": "account-123",
        }

        self.storage.save_order("order-123", order_data)

        retrieved = self.storage.get_order("order-123")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["status"], "pending")

    def test_get_nonexistent_order(self):
        """Test retrieving a nonexistent order."""
        result = self.storage.get_order("nonexistent")
        self.assertIsNone(result)

    def test_update_order(self):
        """Test updating an order."""
        self.storage.save_account("account-123", {"status": "valid", "jwk": {}})

        order_data = {
            "status": "pending",
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "account_id": "account-123",
        }

        self.storage.save_order("order-123", order_data)

        # Update the order
        updated_data = {
            "status": "ready",
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "account_id": "account-123",
        }

        result = self.storage.update_order("order-123", updated_data)
        self.assertTrue(result)

        # Verify the update
        retrieved = self.storage.get_order("order-123")
        self.assertEqual(retrieved["status"], "ready")

    def test_list_orders(self):
        """Test listing all orders."""
        self.storage.save_account("account-123", {"status": "valid", "jwk": {}})

        self.storage.save_order(
            "order-1", {"status": "pending", "account_id": "account-123"}
        )
        self.storage.save_order(
            "order-2", {"status": "valid", "account_id": "account-123"}
        )

        orders = self.storage.list_orders()
        self.assertEqual(len(orders), 2)

    # ========================================================================
    # Authorization Management Tests
    # ========================================================================

    def test_save_authorization(self):
        """Test saving an authorization."""
        # Create account and order
        self.storage.save_account("account-123", {"status": "valid", "jwk": {}})
        self.storage.save_order(
            "order-123", {"status": "pending", "account_id": "account-123"}
        )

        auth_data = {
            "status": "pending",
            "identifier": {"type": "dns", "value": "example.com"},
            "order_id": "order-123",
        }

        result = self.storage.save_authorization("auth-123", auth_data)
        self.assertTrue(result)

    def test_get_authorization(self):
        """Test retrieving an authorization."""
        self.storage.save_account("account-123", {"status": "valid", "jwk": {}})
        self.storage.save_order(
            "order-123", {"status": "pending", "account_id": "account-123"}
        )

        auth_data = {
            "status": "pending",
            "identifier": {"type": "dns", "value": "example.com"},
            "order_id": "order-123",
        }

        self.storage.save_authorization("auth-123", auth_data)

        retrieved = self.storage.get_authorization("auth-123")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["status"], "pending")

    def test_get_nonexistent_authorization(self):
        """Test retrieving a nonexistent authorization."""
        result = self.storage.get_authorization("nonexistent")
        self.assertIsNone(result)

    def test_update_authorization(self):
        """Test updating an authorization."""
        self.storage.save_account("account-123", {"status": "valid", "jwk": {}})
        self.storage.save_order(
            "order-123", {"status": "pending", "account_id": "account-123"}
        )

        auth_data = {
            "status": "pending",
            "identifier": {"type": "dns", "value": "example.com"},
            "order_id": "order-123",
        }

        self.storage.save_authorization("auth-123", auth_data)

        # Update the authorization
        updated_data = {
            "status": "valid",
            "identifier": {"type": "dns", "value": "example.com"},
            "order_id": "order-123",
        }

        result = self.storage.update_authorization("auth-123", updated_data)
        self.assertTrue(result)

        # Verify the update
        retrieved = self.storage.get_authorization("auth-123")
        self.assertEqual(retrieved["status"], "valid")

    def test_list_authorizations(self):
        """Test listing all authorizations."""
        self.storage.save_account("account-123", {"status": "valid", "jwk": {}})
        self.storage.save_order(
            "order-123", {"status": "pending", "account_id": "account-123"}
        )

        self.storage.save_authorization(
            "auth-1", {"status": "pending", "order_id": "order-123"}
        )
        self.storage.save_authorization(
            "auth-2", {"status": "valid", "order_id": "order-123"}
        )

        authorizations = self.storage.list_authorizations()
        self.assertEqual(len(authorizations), 2)

    # ========================================================================
    # Challenge Management Tests
    # ========================================================================

    def test_save_challenge(self):
        """Test saving a challenge."""
        # Create account, order, and authorization
        self.storage.save_account("account-123", {"status": "valid", "jwk": {}})
        self.storage.save_order(
            "order-123", {"status": "pending", "account_id": "account-123"}
        )
        self.storage.save_authorization(
            "auth-123", {"status": "pending", "order_id": "order-123"}
        )

        challenge_data = {
            "type": "http-01",
            "token": "test-token",
            "status": "pending",
            "authorization_id": "auth-123",
        }

        result = self.storage.save_challenge("challenge-123", challenge_data)
        self.assertTrue(result)

    def test_get_challenge(self):
        """Test retrieving a challenge."""
        self.storage.save_account("account-123", {"status": "valid", "jwk": {}})
        self.storage.save_order(
            "order-123", {"status": "pending", "account_id": "account-123"}
        )
        self.storage.save_authorization(
            "auth-123", {"status": "pending", "order_id": "order-123"}
        )

        challenge_data = {
            "type": "http-01",
            "token": "test-token",
            "status": "pending",
            "authorization_id": "auth-123",
        }

        self.storage.save_challenge("challenge-123", challenge_data)

        retrieved = self.storage.get_challenge("challenge-123")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["type"], "http-01")
        self.assertEqual(retrieved["token"], "test-token")

    def test_get_nonexistent_challenge(self):
        """Test retrieving a nonexistent challenge."""
        result = self.storage.get_challenge("nonexistent")
        self.assertIsNone(result)

    def test_get_challenge_by_token(self):
        """Test retrieving a challenge by token."""
        self.storage.save_account("account-123", {"status": "valid", "jwk": {}})
        self.storage.save_order(
            "order-123", {"status": "pending", "account_id": "account-123"}
        )
        self.storage.save_authorization(
            "auth-123", {"status": "pending", "order_id": "order-123"}
        )

        challenge_data = {
            "type": "http-01",
            "token": "unique-test-token",
            "status": "pending",
            "authorization_id": "auth-123",
        }

        self.storage.save_challenge("challenge-123", challenge_data)

        retrieved = self.storage.get_challenge_by_token("unique-test-token")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["token"], "unique-test-token")

    def test_get_challenge_by_nonexistent_token(self):
        """Test retrieving a challenge by nonexistent token."""
        result = self.storage.get_challenge_by_token("nonexistent-token")
        self.assertIsNone(result)

    def test_update_challenge(self):
        """Test updating a challenge."""
        self.storage.save_account("account-123", {"status": "valid", "jwk": {}})
        self.storage.save_order(
            "order-123", {"status": "pending", "account_id": "account-123"}
        )
        self.storage.save_authorization(
            "auth-123", {"status": "pending", "order_id": "order-123"}
        )

        challenge_data = {
            "type": "http-01",
            "token": "test-token",
            "status": "pending",
            "authorization_id": "auth-123",
        }

        self.storage.save_challenge("challenge-123", challenge_data)

        # Update the challenge
        updated_data = {
            "type": "http-01",
            "token": "test-token",
            "status": "valid",
            "authorization_id": "auth-123",
        }

        result = self.storage.update_challenge("challenge-123", updated_data)
        self.assertTrue(result)

        # Verify the update
        retrieved = self.storage.get_challenge("challenge-123")
        self.assertEqual(retrieved["status"], "valid")

    # ========================================================================
    # Context Manager Tests
    # ========================================================================

    def test_context_manager(self):
        """Test using storage as context manager."""
        with SQLiteStorage(self.temp_dir) as storage:
            storage.initialize()
            storage.add_nonce("test-nonce")

            count = storage.get_nonce_count()
            self.assertEqual(count, 1)

        # After exiting context, storage should be closed
        # Trying to use it should work since it's reconnected


class TestStorageDataIntegrity(unittest.TestCase):
    """Test cases for data integrity in storage."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage = SQLiteStorage(self.temp_dir)
        self.storage.initialize()

    def tearDown(self):
        """Clean up test fixtures."""
        if self.storage:
            self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_jwk_json_storage(self):
        """Test that JWK is stored as JSON."""
        jwk = {"kty": "RSA", "n": "test-modulus", "e": "AQAB", "alg": "RS256"}

        account_data = {"status": "valid", "jwk": jwk}

        self.storage.save_account("account-123", account_data)

        # Retrieve and verify
        retrieved = self.storage.get_account("account-123")
        self.assertEqual(retrieved["jwk"]["kty"], "RSA")
        self.assertEqual(retrieved["jwk"]["alg"], "RS256")

    def test_complex_order_data(self):
        """Test storing complex order data."""
        self.storage.save_account("account-123", {"status": "valid", "jwk": {}})

        order_data = {
            "status": "pending",
            "identifiers": [
                {"type": "dns", "value": "example.com"},
                {"type": "dns", "value": "www.example.com"},
            ],
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": "2024-12-31T23:59:59Z",
            "account_id": "account-123",
            "authorizations": ["auth-1", "auth-2"],
            "finalize": "https://example.com/acme/order/order-123/finalize",
        }

        self.storage.save_order("order-123", order_data)

        retrieved = self.storage.get_order("order-123")
        self.assertEqual(len(retrieved["identifiers"]), 2)
        self.assertEqual(len(retrieved["authorizations"]), 2)


if __name__ == "__main__":
    unittest.main()
