"""
uPKI RA Server - Routes Module.

This module provides the REST API routes for the RA server.
"""

from .acme_api import create_acme_routes
from .client_api import create_client_routes
from .inventory_api import create_inventory_routes
from .private_api import create_private_routes
from .public_api import create_public_routes
from .ws_api import create_ws_routes

__all__ = [
    "create_public_routes",
    "create_private_routes",
    "create_client_routes",
    "create_acme_routes",
    "create_inventory_routes",
    "create_ws_routes",
]
