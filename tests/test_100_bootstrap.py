"""
Functional bootstrap tests for upki-ra.

These tests launch real CA and RA processes as subprocesses and verify
end-to-end auto-bootstrap behaviour:
1. RA starts, registers with the CA, and serves HTTP.
2. RA restart (certs already present) skips registration.
3. RA exits with a non-zero code when not registered and no seed is given.

The upki-ca package (path dev dependency) must be installed for these tests.

Author: uPKI Team
License: MIT
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Generator
from typing import Optional

import pytest
import yaml

# Paths to the two CLI entry points
CA_SERVER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "Circle",
    "upki",
    "ca_server.py",
)
RA_SERVER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "ra_server.py"
)

# Ports used exclusively by these tests to avoid collisions
_CA_PORT = 14000
_REG_PORT = 14001  # always CA_PORT + 1
_RA_PORT = 14080
_TEST_SEED = "bootstrap-functional-test-seed-42"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _wait_for_port(host: str, port: int, timeout: float = 30.0) -> bool:
    """Poll a TCP port until reachable or timeout expires.

    Args:
        host: Hostname or IP address to connect to.
        port: TCP port number.
        timeout: Maximum number of seconds to wait.

    Returns:
        bool: True if port became reachable within timeout, False otherwise.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def _wait_for_http(url: str, timeout: float = 30.0) -> bool:
    """Poll an HTTP URL until it returns HTTP 200 or timeout expires.

    Args:
        url: Full HTTP URL to GET.
        timeout: Maximum number of seconds to wait.

    Returns:
        bool: True if a 200 response was received within timeout.
    """
    import urllib.error
    import urllib.request

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    return False


def _write_ca_config(data_dir: str, port: int = _CA_PORT) -> None:
    """Write a minimal ca.config.yml overriding the port.

    Args:
        data_dir: Directory in which to write ca.config.yml.
        port: CA ZMQ listener port.
    """
    os.makedirs(data_dir, exist_ok=True)
    config_path = os.path.join(data_dir, "ca.config.yml")
    with open(config_path, "w") as f:
        yaml.safe_dump({"host": "127.0.0.1", "port": port}, f)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def work_dir() -> Generator[str, None, None]:
    """Provide a fresh temporary directory, removed after each test.

    Yields:
        str: Path to the temporary directory.
    """
    tmp = tempfile.mkdtemp(prefix="upki_bootstrap_test_")
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture()
def ca_process(work_dir: str) -> Generator[subprocess.Popen, None, None]:
    """Start a real CA process and wait for both ZMQ sockets to be ready.

    Yields:
        subprocess.Popen: The running CA process.
    """
    ca_dir = os.path.join(work_dir, "ca")
    _write_ca_config(ca_dir, port=_CA_PORT)

    env = os.environ.copy()
    env["UPKI_CA_SEED"] = _TEST_SEED
    env["UPKI_CA_HOST"] = "127.0.0.1"

    proc = subprocess.Popen(
        [sys.executable, CA_SERVER_PATH, "--path", ca_dir, "start"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    ca_ready = _wait_for_port("127.0.0.1", _CA_PORT)
    reg_ready = _wait_for_port("127.0.0.1", _REG_PORT)
    if not (ca_ready and reg_ready):
        proc.terminate()
        proc.wait(timeout=5)
        pytest.fail("CA process did not become ready within timeout")

    yield proc

    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture()
def ra_dir(work_dir: str) -> str:
    """Return a dedicated RA data directory inside work_dir.

    Args:
        work_dir: Parent temporary directory.

    Returns:
        str: Path to the RA data directory.
    """
    ra_data = os.path.join(work_dir, "ra")
    os.makedirs(ra_data, exist_ok=True)
    return ra_data


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRABootstrap:
    """End-to-end tests for ra_server.py start auto-bootstrap."""

    def test_ra_start_registers_and_serves(
        self, ca_process: subprocess.Popen, ra_dir: str
    ) -> None:
        """Test full bootstrap: RA registers with CA then serves HTTP health check.

        Steps:
        1. CA is already running (fixture).
        2. RA is launched with UPKI_CA_SEED set.
        3. RA must register with the CA, start uvicorn, and respond to
           GET /api/v1/health with HTTP 200.
        """
        env = os.environ.copy()
        env["UPKI_DATA_DIR"] = ra_dir
        env["UPKI_CA_HOST"] = "127.0.0.1"
        env["UPKI_CA_PORT"] = str(_CA_PORT)
        env["UPKI_CA_SEED"] = _TEST_SEED
        env["UPKI_RA_HOST"] = "127.0.0.1"
        env["UPKI_RA_PORT"] = str(_RA_PORT)

        ra_proc = subprocess.Popen(
            [sys.executable, RA_SERVER_PATH, "start"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            health_url = f"http://127.0.0.1:{_RA_PORT}/api/v1/health"
            healthy = _wait_for_http(health_url, timeout=40.0)
            assert healthy, f"RA health endpoint {health_url} never returned 200"

            # RA cert and key must have been written
            assert os.path.exists(os.path.join(ra_dir, "ra.crt"))
            assert os.path.exists(os.path.join(ra_dir, "ra.key"))
            assert os.path.exists(os.path.join(ra_dir, "ca.crt"))
        finally:
            ra_proc.terminate()
            ra_proc.wait(timeout=5)

    def test_ra_start_is_idempotent_on_restart(
        self, ca_process: subprocess.Popen, ra_dir: str
    ) -> None:
        """Test that restarting the RA with existing certs skips registration.

        On the second start the RA must not attempt to contact port 14001 again
        (registration is skipped) and must still serve HTTP correctly.
        """
        env = os.environ.copy()
        env["UPKI_DATA_DIR"] = ra_dir
        env["UPKI_CA_HOST"] = "127.0.0.1"
        env["UPKI_CA_PORT"] = str(_CA_PORT)
        env["UPKI_CA_SEED"] = _TEST_SEED
        env["UPKI_RA_HOST"] = "127.0.0.1"
        env["UPKI_RA_PORT"] = str(_RA_PORT)

        # -- First start: registers and serves
        ra_proc = subprocess.Popen(
            [sys.executable, RA_SERVER_PATH, "start"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        health_url = f"http://127.0.0.1:{_RA_PORT}/api/v1/health"
        _wait_for_http(health_url, timeout=40.0)
        ra_proc.terminate()
        ra_proc.wait(timeout=5)

        # Certs on disk after first start
        assert os.path.exists(os.path.join(ra_dir, "ra.crt"))

        # -- Second start: certs already present, registration must be skipped
        # Pass a wrong seed to prove registration is not attempted
        env2 = env.copy()
        env2["UPKI_CA_SEED"] = "wrong-seed-should-not-be-used"

        ra_proc2 = subprocess.Popen(
            [sys.executable, RA_SERVER_PATH, "start"],
            env=env2,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            healthy = _wait_for_http(health_url, timeout=30.0)
            assert healthy, "RA did not start correctly on second boot"
        finally:
            ra_proc2.terminate()
            ra_proc2.wait(timeout=5)

    def test_ra_start_fails_without_seed_when_not_registered(self, ra_dir: str) -> None:
        """Test that the RA exits with a non-zero code when no seed is given.

        No CA process is needed here because the RA must fail before trying
        to contact the CA.
        """
        env = os.environ.copy()
        env["UPKI_DATA_DIR"] = ra_dir
        env["UPKI_RA_HOST"] = "127.0.0.1"
        env["UPKI_RA_PORT"] = str(_RA_PORT)
        # Explicitly unset the seed
        env.pop("UPKI_CA_SEED", None)

        result = subprocess.run(
            [sys.executable, RA_SERVER_PATH, "start"],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )

        assert result.returncode != 0, (
            f"Expected non-zero exit code but got 0.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert "UPKI_CA_SEED" in result.stderr or "not registered" in result.stderr
