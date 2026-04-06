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

from upki_ra.core import UPKIError, get_logger
from upki_ra.registration_authority import RegistrationAuthority
from upki_ra.routes import (
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
    app.include_router(create_acme_routes(ra), prefix="")
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

    @app.exception_handler(HTTPException)
    async def handle_http_exception(request: Request, error: HTTPException):
        # ACME endpoints must return RFC 7807 Problem Details with integer status
        # (LEGO/Go unmarshals the 'status' field as int).
        if request.url.path.startswith("/acme/"):
            return JSONResponse(
                status_code=error.status_code,
                content={
                    "type": "urn:ietf:params:acme:error:malformed",
                    "detail": str(error.detail),
                    "status": error.status_code,
                },
            )
        return JSONResponse(
            status_code=error.status_code,
            content={"status": "error", "message": str(error.detail)},
        )

    @app.exception_handler(404)
    async def handle_not_found(request: Request, error: Exception):
        if request.url.path.startswith("/acme/"):
            return JSONResponse(
                status_code=404,
                content={
                    "type": "urn:ietf:params:acme:error:malformed",
                    "detail": "Not found",
                    "status": 404,
                },
            )
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

        result = ra.register_with_ca(seed=seed, cn=cn, sans=getattr(args, "sans", None))

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
    tls_enabled: bool = getattr(args, "env_tls", False)

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

        scheme = "https" if tls_enabled else "http"
        ra.logger.info(f"Starting RA server on {host}:{port} (TLS={tls_enabled})")
        print(f"Starting uPKI RA Server on {scheme}://{host}:{port}")
        print("Press Ctrl+C to stop")

        uvicorn_kwargs: dict = {
            "host": host,
            "port": port,
            "log_level": "debug" if debug else "info",
        }
        if tls_enabled:
            uvicorn_kwargs["ssl_certfile"] = os.path.join(ra.data_dir, "ra.crt")
            uvicorn_kwargs["ssl_keyfile"] = os.path.join(ra.data_dir, "ra.key")

        # Run server using uvicorn
        uvicorn.run(app, **uvicorn_kwargs)

        return 0

    except Exception as e:
        ra.logger.exception("Server failed to start")
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_start(args: argparse.Namespace, ra: RegistrationAuthority) -> int:
    """Auto-bootstrap: register with CA if needed, then start the server.

    On **first boot** (no ``ra.crt``/``ra.key`` on the data volume):
      - Reads the registration seed from ``args.env_seed`` (set from the
        ``UPKI_CA_SEED`` environment variable).
      - Calls :func:`cmd_register` to enrol with the CA.

    On **subsequent boots** (certs already present on the data volume):
      - Skips registration and goes straight to :func:`cmd_listen`.

    Args:
        args: Command-line arguments.
        ra: RegistrationAuthority instance.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    if not ra.is_registered():
        seed = getattr(args, "env_seed", None)
        if not seed:
            print(
                "Error: RA is not registered and UPKI_CA_SEED is not set.",
                file=sys.stderr,
            )
            print(
                "Set the UPKI_CA_SEED environment variable with the CA registration seed.",
                file=sys.stderr,
            )
            return 1
        args.seed = seed
        args.cn = getattr(args, "env_cn", "RA")
        # Build SANs list from the UPKI_RA_SANS env var so the RA certificate
        # contains the DNS names required for HTTPS hostname validation.
        sans_env: str = getattr(args, "env_sans", "") or ""
        args.sans = (
            [{"type": "DNS", "value": name.strip()} for name in sans_env.split(",") if name.strip()]
            if sans_env
            else None
        )
        ret = cmd_register(args, ra)
        if ret != 0:
            return ret

    return cmd_listen(args, ra)


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

    # Start command (default Docker entrypoint: register if needed, then listen)
    subparsers.add_parser(
        "start", help="Auto-bootstrap: register if needed, then start server"
    )

    # CRL command
    subparsers.add_parser("crl", help="Update CRL")

    args = parser.parse_args()

    # ── Environment variable overrides ────────────────────────────────────────
    # CLI flags take precedence; env vars fill in when flags are at their defaults.
    env_data_dir = os.environ.get("UPKI_DATA_DIR")
    if env_data_dir and args.dir == RegistrationAuthority.DEFAULT_DATA_DIR:
        args.dir = env_data_dir

    env_ca_host = os.environ.get("UPKI_CA_HOST")
    if env_ca_host:
        args.ip = env_ca_host

    env_ca_port = os.environ.get("UPKI_CA_PORT")
    if env_ca_port:
        args.port = int(env_ca_port)

    env_ra_host = os.environ.get("UPKI_RA_HOST")
    if env_ra_host:
        args.web_ip = env_ra_host

    env_ra_port = os.environ.get("UPKI_RA_PORT")
    if env_ra_port:
        args.web_port = int(env_ra_port)

    # Seed and CN for auto-registration (used by the start command)
    args.env_seed = os.environ.get("UPKI_CA_SEED")
    args.env_cn = os.environ.get("UPKI_RA_CN", "RA")
    # TLS: when true, uvicorn serves HTTPS using the RA's own certificate.
    args.env_tls = os.environ.get("UPKI_RA_TLS", "false").lower() == "true"
    # SANs: comma-separated DNS names to embed in the RA certificate.
    # Required when UPKI_RA_TLS is true so Go 1.15+ can validate the hostname.
    args.env_sans = os.environ.get("UPKI_RA_SANS", "")
    # ─────────────────────────────────────────────────────────────────────────

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
    elif args.command == "start" or args.command is None:
        # start is the default when no subcommand is given
        args.host = args.web_ip
        args.port = args.web_port
        return cmd_start(args, ra)
    elif args.command == "crl":
        return cmd_crl(args, ra)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
