"""
uPKI RA Server - WebSocket Connection Manager Unit Tests.
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock

from upki_ra.services.websocket_manager import ConnectionManager


class TestConnectionManagerSync(unittest.TestCase):
    """Test cases not requiring a running event loop."""

    def test_broadcast_nowait_without_running_loop_is_a_noop(self):
        manager = ConnectionManager()
        # No event loop running in this plain sync test - must not raise.
        manager.broadcast_nowait("certificate.issued", {"id": "s1"})

    def test_disconnect_unknown_connection_is_a_noop(self):
        manager = ConnectionManager()
        manager.disconnect(MagicMock())  # never connected - must not raise

    def test_connection_count_initially_zero(self):
        self.assertEqual(ConnectionManager().connection_count, 0)


class TestConnectionManagerAsync(unittest.IsolatedAsyncioTestCase):
    """Test cases requiring a running event loop."""

    async def test_connect_registers_and_accepts(self):
        manager = ConnectionManager()
        ws = AsyncMock()
        await manager.connect(ws)
        ws.accept.assert_awaited_once()
        self.assertEqual(manager.connection_count, 1)

    async def test_broadcast_sends_envelope_to_all_connections(self):
        manager = ConnectionManager()
        ws1, ws2 = AsyncMock(), AsyncMock()
        await manager.connect(ws1)
        await manager.connect(ws2)

        await manager.broadcast("certificate.issued", {"id": "s1"})

        for ws in (ws1, ws2):
            ws.send_json.assert_awaited_once()
            message = ws.send_json.await_args.args[0]
            self.assertEqual(message["type"], "certificate.issued")
            self.assertEqual(message["data"], {"id": "s1"})
            self.assertIn("ts", message)

    async def test_broadcast_with_no_connections_is_a_noop(self):
        manager = ConnectionManager()
        await manager.broadcast("certificate.issued", {})  # must not raise

    async def test_broadcast_drops_dead_connections(self):
        manager = ConnectionManager()
        alive, dead = AsyncMock(), AsyncMock()
        dead.send_json.side_effect = RuntimeError("connection closed")
        await manager.connect(alive)
        await manager.connect(dead)

        await manager.broadcast("certificate.issued", {})

        self.assertEqual(manager.connection_count, 1)
        alive.send_json.assert_awaited_once()

    async def test_broadcast_nowait_schedules_broadcast_on_running_loop(self):
        manager = ConnectionManager()
        ws = AsyncMock()
        await manager.connect(ws)

        manager.broadcast_nowait("certificate.issued", {"id": "s1"})
        # broadcast_nowait only schedules a task; give it a turn to run.
        await asyncio.sleep(0)

        ws.send_json.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
