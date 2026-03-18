# uPKI RA Server

Registration Authority (RA) Server for the uPKI Public Key Infrastructure system.

## Overview

The uPKI RA Server provides a REST API for certificate enrollment, renewal, and revocation. It acts as an intermediary between clients and the Certificate Authority (CA), handling:

- Certificate enrollment via CSR signing
- Certificate renewal
- Certificate revocation
- Node registration
- Administrator management
- CRL distribution
- OCSP responder integration

## Architecture

```
┌─────────────┐     mTLS      ┌─────────────┐     ZMQ      ┌─────────────┐
│   Clients   │──────────────▶│  RA Server  │──────────────▶│  CA Server  │
└─────────────┘               └─────────────┘               └─────────────┘
   - Public API                     - Public API
     /certify                        /health
     /certs/*                        /certify
     /crl                           /certs/*
     /ocsp                          /crl
                                   /profiles
                                   /ocsp

                                 - Private API (Admin mTLS)
                                   /nodes
                                   /admins
                                   /crl/generate

                                 - Client API (Client mTLS)
                                   /renew
                                   /revoke
                                   /certificate
```

## Requirements

- Python 3.11+
- Flask >= 2.0
- Flask-CORS >= 3.0
- pyzmq >= 20.0
- cryptography >= 3.0
- pyyaml >= 5.0

## Installation

```bash
# Install from source
cd upki-ra
pip install -e .

# Or install dependencies only
pip install -r requirements.txt
```

## Quick Start

### 1. Initialize RA

```bash
python ra_server.py init
```

### 2. Register with CA

```bash
python ra_server.py register -s <registration_seed>
```

### 3. Start the server

```bash
# Default: http://127.0.0.1:8000
python ra_server.py listen

# Custom host and port
python ra_server.py listen --web-ip 0.0.0.0 --web-port 8443
```

## CLI Commands

| Command                                  | Description                  |
| ---------------------------------------- | ---------------------------- |
| `python ra_server.py init`               | Initialize RA data directory |
| `python ra_server.py register -s <seed>` | Register with CA             |
| `python ra_server.py listen`             | Start RA server              |
| `python ra_server.py crl`                | Update CRL                   |

### Options

| Argument       | Default       | Description       |
| -------------- | ------------- | ----------------- |
| `-d`, `--dir`  | `~/.upki/ra/` | RA data directory |
| `-i`, `--ip`   | `127.0.0.1`   | CA server IP      |
| `-p`, `--port` | `5000`        | CA server port    |
| `--web-ip`     | `127.0.0.1`   | Web server IP     |
| `--web-port`   | `8000`        | Web server port   |
| `--debug`      | false         | Enable debug mode |

## API Endpoints

### Public API

| Endpoint                  | Method | Description             |
| ------------------------- | ------ | ----------------------- |
| `/api/v1/health`          | GET    | Health check            |
| `/api/v1/certify`         | POST   | Enroll certificate      |
| `/api/v1/certs/<dn>`      | GET    | Get certificate details |
| `/api/v1/certs`           | GET    | List certificates       |
| `/api/v1/ca`              | GET    | Get CA certificate      |
| `/api/v1/crl`             | GET    | Get CRL                 |
| `/api/v1/profiles`        | GET    | List profiles           |
| `/api/v1/profiles/<name>` | GET    | Get profile details     |
| `/api/v1/ocsp`            | POST   | Check OCSP status       |

### Private API (Admin mTLS)

| Endpoint                       | Method | Description   |
| ------------------------------ | ------ | ------------- |
| `/api/v1/private/nodes`        | GET    | List nodes    |
| `/api/v1/private/nodes`        | POST   | Register node |
| `/api/v1/private/nodes/<cn>`   | DELETE | Delete node   |
| `/api/v1/private/admins`       | GET    | List admins   |
| `/api/v1/private/admins`       | POST   | Add admins    |
| `/api/v1/private/admins/<dn>`  | DELETE | Remove admin  |
| `/api/v1/private/crl/generate` | POST   | Generate CRL  |
| `/api/v1/private/config`       | GET    | Get config    |

### Client API (Client mTLS)

| Endpoint                     | Method | Description            |
| ---------------------------- | ------ | ---------------------- |
| `/api/v1/client/renew`       | POST   | Renew certificate      |
| `/api/v1/client/revoke`      | POST   | Revoke certificate     |
| `/api/v1/client/certificate` | GET    | Get own certificate    |
| `/api/v1/client/status`      | GET    | Get certificate status |

## Configuration

### Data Directory

Default: `~/.upki/ra/`

```
~/.upki/ra/
├── ca.crt           # CA certificate
├── crl.pem          # CRL
├── ra.key           # RA private key
├── ra.crt           # RA certificate
├── ra.csr           # RA CSR
├── config.json      # Configuration
└── .ra.log          # Log file
```

## Development

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=server
```

### Code Structure

```
upki-ra/
├── ra_server.py              # Main entry point
├── setup.py                  # Package setup
├── server/
│   ├── __init__.py
│   ├── registrationAuthority.py  # Core RA class
│   ├── core/
│   │   ├── __init__.py
│   │   ├── upkiError.py      # Exception classes
│   │   └── upkiLogger.py     # Logging
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── publicAPI.py      # Public endpoints
│   │   ├── privateAPI.py     # Admin endpoints
│   │   └── clientAPI.py       # Client endpoints
│   └── utils/
│       ├── __init__.py
│       ├── common.py          # Utilities
│       ├── tlsauth.py         # TLS authentication
│       └── tools.py           # ZMQ client
└── tests/
    ├── __init__.py
    ├── test_core.py
    ├── test_utils.py
    └── test_routes.py
```

## Security

- **mTLS Authentication**: Private and client APIs require TLS client certificates
- **Admin Authorization**: Admin endpoints require certificates with DNs in the admin list
- **Certificate Validation**: All CSR and certificates are validated before processing
- **Audit Logging**: All operations are logged for auditing

## License

MIT License
