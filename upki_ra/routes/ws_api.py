"""
uPKI RA Server - WebSocket Routes.

Single multiplexed `/ws` channel pushing state-change notifications to
connected `uPKI-app` frontend clients (see
uPKI-app/docs/FRONTEND_DATA_REQUIREMENTS.md §4). Unauthenticated for now,
same demo-mode rationale as the other new inventory routes - see
`inventory_api.py`'s module docstring.
"""

from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..registration_authority import RegistrationAuthority


def create_ws_routes(ra: RegistrationAuthority) -> APIRouter:
    """Create the WebSocket route with RA instance.

    Args:
        ra: RegistrationAuthority instance.

    Returns:
        Configured FastAPI APIRouter.
    """
    router = APIRouter(tags=["websocket"])

    @router.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket) -> None:
        """Accept a WebSocket connection and keep it registered until it drops.

        Inbound client messages are not part of the current protocol and
        are simply discarded; this connection only ever receives broadcasts.
        """
        await ra.ws_manager.connect(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            ra.ws_manager.disconnect(websocket)

    return router
