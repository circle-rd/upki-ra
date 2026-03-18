# uPKI RA Server - Traefik Integration Configuration

## Integration Architecture

There are two methods to integrate uPKI with Traefik:

### Method 1: Cert-manager (Recommended for Kubernetes)

For Kubernetes environments, use cert-manager with uPKI as the ACME server:

```yaml
# cert-manager-issuer.yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: upki-issuer
spec:
  acme:
    server: https://ra.example.com/acme/directory
    email: admin@example.com
    privateKeySecretRef:
      name: upki-account-key
    solvers:
      - http01:
          ingressClassName: traefik
```

### Method 2: Traefik with File Provider

For direct integration with Traefik:

```yaml
# traefik-dynamic.yaml
tls:
  stores:
    default:
      defaultCertificate:
        certFile: /certs/tls.crt
        keyFile: /certs/tls.key
```

## Docker Compose Configuration

Complete deployment example:

```yaml
# docker-compose.yaml
version: "3.8"

services:
  upki-ra:
    image: upki-ra:latest
    ports:
      - "8000:8000"
    volumes:
      - ./data:/data
    environment:
      - CA_HOST=upki-ca
      - CA_PORT=5000
    networks:
      - upki

  traefik:
    image: traefik:v3.0
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - ./traefik.yml:/etc/traefik/traefik.yml:ro
      - ./certs:/certs:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on:
      - upki-ra
    networks:
      - upki

networks:
  upki:
    driver: bridge
```

## Traefik Configuration (traefik.yml)

```yaml
api:
  dashboard: true
  insecure: true

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https

  websecure:
    address: ":443"
    http:
      tls:
        certResolver: myresolver

certificatesResolvers:
  myresolver:
    acme:
      email: admin@example.com
      storage: /certs/acme.json
      httpChallenge:
        entryPoint: web
```

## Direct Integration (without cert-manager)

Since Traefik does not natively support custom ACME servers, you can:

1. **Generate certificates via uPKI API**:

```bash
# Create CSR
openssl req -new -newkey rsa:2048 -nodes \
  -keyout domain.key -out domain.csr \
  -subj "/C=FR/O=Company/CN=example.com"

# Submit CSR to uPKI
curl -X POST https://ra.example.com/api/v1/certify \
  -H "Content-Type: application/json" \
  -d '{"csr": "-----BEGIN CERTIFICATE REQUEST-----\n...", "profile": "server"}'
```

2. **Use certificates with Traefik**:

- Deploy certificates in a directory
- Configure Traefik to use them via file provider

## Environment Variables for uPKI RA

```bash
# Server Configuration
CA_HOST=127.0.0.1        # CA server host
CA_PORT=5000             # CA server port
WEB_IP=0.0.0.0           # Web server listen IP
WEB_PORT=8000            # Web server listen port

# Data Directory
DATA_DIR=~/.upki/ra      # Data directory

# Debug Options
DEBUG=false              # Debug mode
```

## Available ACME Endpoints

Once the server is started, the following endpoints are available:

| Endpoint                              | Method   | Description                |
| ------------------------------------- | -------- | -------------------------- |
| `/acme/directory`                     | GET      | ACME directory             |
| `/acme/new-nonce`                     | GET/HEAD | New nonce                  |
| `/acme/new-account`                   | POST     | Create account             |
| `/acme/new-order`                     | POST     | Create order               |
| `/acme/authz/{id}`                    | GET      | Authorization status       |
| `/acme/challenge/{id}/http-01`        | POST     | Validate HTTP-01 challenge |
| `/.well-known/acme-challenge/{token}` | GET      | HTTP-01 challenge response |
| `/acme/cert/{cert_id}`                | POST     | Download certificate       |
| `/acme/revoke-cert`                   | POST     | Revoke certificate         |
