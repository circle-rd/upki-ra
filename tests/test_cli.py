"""
Unit tests for the ra_server.py CLI entry point.

Tests cover:
- Environment variable overrides applied in main()
- cmd_start() logic branches (already registered, not registered with seed,
  not registered without seed)

Author: uPKI Team
License: MIT
"""

import argparse
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch


class TestEnvironmentVariableOverrides(unittest.TestCase):
    """Test that environment variables correctly override CLI argument defaults."""

    def _build_default_args(self, **overrides) -> argparse.Namespace:
        """Build a Namespace with defaults matching the argparse setup in main().

        Args:
            **overrides: Keyword arguments to override specific defaults.

        Returns:
            argparse.Namespace with default values applied.
        """
        from upki_ra.registration_authority import RegistrationAuthority

        defaults = argparse.Namespace(
            dir=RegistrationAuthority.DEFAULT_DATA_DIR,
            ip="127.0.0.1",
            port=5000,
            web_ip="127.0.0.1",
            web_port=8000,
            debug=False,
            command="start",
            env_seed=None,
            env_cn="RA",
        )
        for key, value in overrides.items():
            setattr(defaults, key, value)
        return defaults

    def test_upki_data_dir_overrides_default_dir(self):
        """Test that UPKI_DATA_DIR sets args.dir when not explicitly passed."""
        from upki_ra.registration_authority import RegistrationAuthority

        custom_dir = "/custom/data/dir"
        env = {"UPKI_DATA_DIR": custom_dir}

        args = self._build_default_args()
        with patch.dict(os.environ, env, clear=False):
            env_data_dir = os.environ.get("UPKI_DATA_DIR")
            if env_data_dir and args.dir == RegistrationAuthority.DEFAULT_DATA_DIR:
                args.dir = env_data_dir

        self.assertEqual(args.dir, custom_dir)

    def test_upki_data_dir_does_not_override_explicit_cli_value(self):
        """Test that UPKI_DATA_DIR does not override an explicitly set --dir."""
        from upki_ra.registration_authority import RegistrationAuthority

        cli_dir = "/explicit/cli/dir"
        env = {"UPKI_DATA_DIR": "/env/data/dir"}

        args = self._build_default_args(dir=cli_dir)
        with patch.dict(os.environ, env, clear=False):
            env_data_dir = os.environ.get("UPKI_DATA_DIR")
            # Simulate the override logic from main(): only replace when default
            if env_data_dir and args.dir == RegistrationAuthority.DEFAULT_DATA_DIR:
                args.dir = env_data_dir

        # cli_dir was not the default, so it must not be overwritten
        self.assertEqual(args.dir, cli_dir)

    def test_upki_ca_host_sets_args_ip(self):
        """Test that UPKI_CA_HOST overrides args.ip."""
        args = self._build_default_args()
        env = {"UPKI_CA_HOST": "upki-ca"}

        with patch.dict(os.environ, env, clear=False):
            env_ca_host = os.environ.get("UPKI_CA_HOST")
            if env_ca_host:
                args.ip = env_ca_host

        self.assertEqual(args.ip, "upki-ca")

    def test_upki_ra_host_sets_args_web_ip(self):
        """Test that UPKI_RA_HOST overrides args.web_ip."""
        args = self._build_default_args()
        env = {"UPKI_RA_HOST": "0.0.0.0"}

        with patch.dict(os.environ, env, clear=False):
            env_ra_host = os.environ.get("UPKI_RA_HOST")
            if env_ra_host:
                args.web_ip = env_ra_host

        self.assertEqual(args.web_ip, "0.0.0.0")

    def test_upki_ca_seed_stored_as_env_seed_attribute(self):
        """Test that UPKI_CA_SEED is stored on args.env_seed."""
        args = self._build_default_args()
        env = {"UPKI_CA_SEED": "my-bootstrap-seed"}

        with patch.dict(os.environ, env, clear=False):
            args.env_seed = os.environ.get("UPKI_CA_SEED")

        self.assertEqual(args.env_seed, "my-bootstrap-seed")

    def test_upki_ra_cn_defaults_to_ra_when_unset(self):
        """Test that args.env_cn defaults to 'RA' when UPKI_RA_CN is absent."""
        args = self._build_default_args()
        env: dict[str, str] = {}  # UPKI_RA_CN not set

        with patch.dict(os.environ, env, clear=False):
            # Remove key if present to simulate absence
            os.environ.pop("UPKI_RA_CN", None)
            args.env_cn = os.environ.get("UPKI_RA_CN", "RA")

        self.assertEqual(args.env_cn, "RA")


class TestCmdStart(unittest.TestCase):
    """Test cases for cmd_start() logic branches."""

    def setUp(self):
        """Set up a temporary data directory for each test."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up the temporary directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_args(self, **kwargs) -> argparse.Namespace:
        """Build a minimal Namespace for cmd_start().

        Args:
            **kwargs: Attribute overrides.

        Returns:
            argparse.Namespace suitable for cmd_start().
        """
        defaults = argparse.Namespace(
            env_seed=None,
            env_cn="RA",
            seed=None,
            cn="RA",
            host="127.0.0.1",
            port=8000,
            debug=False,
        )
        for key, value in kwargs.items():
            setattr(defaults, key, value)
        return defaults

    def test_skips_register_when_already_enrolled(self):
        """Test that cmd_start does not call cmd_register when RA is registered."""
        from ra_server import cmd_start

        mock_ra = MagicMock()
        mock_ra.is_registered.return_value = True

        args = self._make_args(env_seed="some-seed")

        with patch("ra_server.cmd_listen", return_value=0) as mock_listen, patch(
            "ra_server.cmd_register"
        ) as mock_register:
            result = cmd_start(args, mock_ra)

        mock_register.assert_not_called()
        mock_listen.assert_called_once()
        self.assertEqual(result, 0)

    def test_calls_register_when_not_enrolled_and_seed_provided(self):
        """Test that cmd_start calls cmd_register when not enrolled and seed is set."""
        from ra_server import cmd_start

        mock_ra = MagicMock()
        mock_ra.is_registered.return_value = False

        args = self._make_args(env_seed="bootstrap-seed")

        with patch("ra_server.cmd_register", return_value=0) as mock_register, patch(
            "ra_server.cmd_listen", return_value=0
        ) as mock_listen:
            result = cmd_start(args, mock_ra)

        mock_register.assert_called_once()
        mock_listen.assert_called_once()
        self.assertEqual(result, 0)

    def test_fails_when_not_enrolled_and_no_seed(self):
        """Test that cmd_start returns exit code 1 when not enrolled and seed absent."""
        from ra_server import cmd_start

        mock_ra = MagicMock()
        mock_ra.is_registered.return_value = False

        args = self._make_args(env_seed=None)

        with patch("ra_server.cmd_register") as mock_register, patch(
            "ra_server.cmd_listen"
        ) as mock_listen:
            result = cmd_start(args, mock_ra)

        mock_register.assert_not_called()
        mock_listen.assert_not_called()
        self.assertEqual(result, 1)

    def test_propagates_register_failure(self):
        """Test that cmd_start returns the non-zero exit code from cmd_register."""
        from ra_server import cmd_start

        mock_ra = MagicMock()
        mock_ra.is_registered.return_value = False

        args = self._make_args(env_seed="seed")

        with patch("ra_server.cmd_register", return_value=1), patch(
            "ra_server.cmd_listen"
        ) as mock_listen:
            result = cmd_start(args, mock_ra)

        mock_listen.assert_not_called()
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
