#!/usr/bin/env python3
"""
uPKI RA Server - Main Entry Point.

This is the main entry point for the uPKI Registration Authority Server.
It provides CLI commands for initialization, registration, and running the server.

Usage:
    python ra_server.py init                      # Initialize RA
    python ra_server.py register -s <seed>        # Register with CA
    python ra_server.py listen -i 127.0.0.1 -p 8000  # Start server
    python ra_server.py crl                       # Update CRL
"""

import argparse
import os
import sys

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from server.core import UPKIError, get_logger
from server.registration_authority import RegistrationAuthority
from server.routes import (
    create_acme_routes,
    create_client_routes,
    create_private_routes,
    create_public_routes,
)


def create_app(ra: RegistrationAuthority) -> FastAPI:
    """Create and configure FastAPI application.

    Args:
        ra: RegistrationAuthority instance.

    Returns:
        Configured FastAPI application.
    """
    app = FastAPI(
        title="uPKI RA Server",
        description="Registration Authority for uPKI PKI",
        version="1.0.0",
    )

    # Register API routers
    app.include_router(create_acme_routes(ra), prefix="/acme")
    app.include_router(create_public_routes(ra), prefix="/api/v1")
    app.include_router(create_private_routes(ra), prefix="/api/v1/private")
    app.include_router(create_client_routes(ra), prefix="/api/v1/client")

    # Error handlers
    @app.exception_handler(UPKIError)
    async def handle_upki_error(request: Request, error: UPKIError):
        # Extract status code - UPKIError.code is a string, use default 500
        status_code = 500
        return JSONResponse(
            status_code=status_code,
            content=error.to_dict(),
        )

    @app.exception_handler(404)
    async def handle_not_found(request: Request, error: Exception):
        return JSONResponse(
            status_code=404,
            content={"status": "error", "message": "Not found"},
        )

    @app.exception_handler(500)
    async def handle_internal_error(request: Request, error: Exception):
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": "Internal server error"},
        )

    return app


def cmd_init(args, ra: RegistrationAuthority) -> int:
    """Initialize RA data directory.

    Args:
        args: Command-line arguments.
        ra: RegistrationAuthority instance.

    Returns:
        Exit code (0 for success).
    """
    ra.logger.info("Initializing RA data directory...")

    # Create data directory structure
    data_dir = ra.data_dir
    ra.logger.info(f"Data directory: {data_dir}")

    # Check if already initialized
    if ra.is_registered():
        ra.logger.warning("RA is already registered")
        print("RA is already registered")
        return 0

    print(f"RA initialized at: {data_dir}")
    print("Next steps:")
    print("  1. Register with CA: python ra_server.py register -s <seed>")
    print("  2. Start server: python ra_server.py listen")

    return 0


def cmd_register(args, ra: RegistrationAuthority) -> int:
    """Register RA with CA server.

    Args:
        args: Command-line arguments.
        ra: RegistrationAuthority instance.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    seed = args.seed
    cn = args.cn

    if not seed:
        print("Error: Registration seed is required", file=sys.stderr)
        print("Use: python ra_server.py register -s <seed>", file=sys.stderr)
        return 1

    if not cn:
        cn = "RA"  # Default CN

    try:
        ra.logger.info(f"Registering RA with CA: {cn}")

        result = ra.register_with_ca(seed=seed, cn=cn)

        print("RA registered successfully!")
        print(f"  CN: {result.get('cn')}")
        print(f"  Profile: {result.get('profile')}")
        print(f"  Status: {result.get('status')}")

        # Save seed for node registration
        ra._config["seed"] = seed
        ra._save_config()

        return 0

    except UPKIError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        ra.logger.exception("Registration failed")
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_listen(args, ra: RegistrationAuthority) -> int:
    """Start the RA server.

    Args:
        args: Command-line arguments.
        ra: RegistrationAuthority instance.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    host = args.host
    port = args.port
    debug = args.debug

    # Check if registered
    if not ra.is_registered():
        print("Error: RA is not registered with CA", file=sys.stderr)
        print("Please run: python ra_server.py register -s <seed>", file=sys.stderr)
        return 1

    try:
        # Sync admin list from CA
        ra.sync_admins_from_ca()

        # Create FastAPI app
        app = create_app(ra)

        ra.logger.info(f"Starting RA server on {host}:{port}")
        print(f"Starting uPKI RA Server on http://{host}:{port}")
        print("Press Ctrl+C to stop")

        # Run server using uvicorn
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level="debug" if debug else "info",
        )

        return 0

    except Exception as e:
        ra.logger.exception("Server failed to start")
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_crl(args, ra: RegistrationAuthority) -> int:
    """Update CRL from CA.

    Args:
        args: Command-line arguments.
        ra: RegistrationAuthority instance.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    try:
        ra.logger.info("Generating CRL...")

        crl = ra.generate_crl()

        # Save CRL
        crl_path = os.path.join(ra.data_dir, "crl.pem")
        with open(crl_path, "w") as f:
            f.write(crl)

        print(f"CRL updated successfully: {crl_path}")

        return 0

    except UPKIError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        ra.logger.exception("CRL update failed")
        print(f"Error: {e}", file=sys.stderr)
        return 1


def main():
    """Main entry point for RA server."""
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="uPKI Registration Authority Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-d",
        "--dir",
        default=RegistrationAuthority.DEFAULT_DATA_DIR,
        help="RA data directory (default: ~/.upki/ra)",
    )
    parser.add_argument(
        "-i", "--ip", default="127.0.0.1", help="CA server IP (default: 127.0.0.1)"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=5000, help="CA server port (default: 5000)"
    )
    parser.add_argument(
        "--web-ip", default="127.0.0.1", help="Web server IP (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--web-port", type=int, default=8000, help="Web server port (default: 8000)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Init command
    subparsers.add_parser("init", help="Initialize RA")

    # Register command
    register_parser = subparsers.add_parser("register", help="Register with CA")
    register_parser.add_argument(
        "-s", "--seed", required=True, help="Registration seed"
    )
    register_parser.add_argument("-c", "--cn", help="RA Common Name (default: RA)")

    # Listen command
    subparsers.add_parser("listen", help="Start RA server")

    # CRL command
    subparsers.add_parser("crl", help="Update CRL")

    args = parser.parse_args()

    # Create logger
    logger = get_logger(log_dir=args.dir)

    # Create RA instance
    ra = RegistrationAuthority(
        data_dir=args.dir, ca_host=args.ip, ca_port=args.port, logger=logger
    )

    # Execute command
    if args.command == "init":
        return cmd_init(args, ra)
    elif args.command == "register":
        return cmd_register(args, ra)
    elif args.command == "listen":
        # Update web server settings
        args.host = args.web_ip
        args.port = args.web_port
        return cmd_listen(args, ra)
    elif args.command == "crl":
        return cmd_crl(args, ra)
    else:
        # Default: start server
        args.host = args.web_ip
        args.port = args.web_port
        return cmd_listen(args, ra)


if __name__ == "__main__":
    sys.exit(main())
