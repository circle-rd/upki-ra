"""
uPKI RA Server - WebSocket Connection Manager.

Broadcasts state-change notifications to connected `uPKI-app` frontend
clients over a single multiplexed `/ws` channel (see
uPKI-app/docs/FRONTEND_DATA_REQUIREMENTS.md §4). Every event is a
"please refetch/patch" notification, not the source of truth - a dropped
connection never leaves the UI silently stale as long as it refetches on
reconnect.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    """Tracks connected WebSocket clients and broadcasts JSON events to them."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        self._connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        """Unregister a WebSocket connection (already closed/closing)."""
        if websocket in self._connections:
            self._connections.remove(websocket)

    @property
    def connection_count(self) -> int:
        """Number of currently connected clients."""
        return len(self._connections)

    async def broadcast(self, event_type: str, data: Any) -> None:
        """Send an event to every connected client, dropping dead ones.

        Args:
            event_type: Dotted event name, e.g. "certificate.issued".
            data: JSON-serializable payload (typically a schema's
                ``model_dump(by_alias=True, mode="json")``).
        """
        if not self._connections:
            return

        message = {
            "type": event_type,
            "data": data,
            "ts": datetime.now(UTC).isoformat(),
        }
        dead: list[WebSocket] = []
        for connection in self._connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for connection in dead:
            self.disconnect(connection)

    def broadcast_nowait(self, event_type: str, data: Any) -> None:
        """Best-effort, non-async broadcast for use from sync code paths.

        Schedules the actual send as a background task on the running
        event loop; silently does nothing if there is no running loop
        (e.g. sync tests/CLI contexts) - broadcasting is a nice-to-have
        notification, never a required side effect of a PKI operation.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self.broadcast(event_type, data))
