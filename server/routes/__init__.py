"""
uPKI RA Server - Routes Module.

This module provides the REST API routes for the RA server.
"""

from .client_api import create_client_routes
from .private_api import create_private_routes
from .public_api import create_public_routes

__all__ = ["create_public_routes", "create_private_routes", "create_client_routes"]
