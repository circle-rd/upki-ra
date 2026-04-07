FROM python:3.12-slim as builder

WORKDIR /build

RUN pip install poetry

COPY pyproject.toml poetry.lock README.md ./
RUN poetry config virtualenvs.create false \
    && poetry install --only main --no-root

FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY . .

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Docker deployment defaults — override in docker-compose when needed.
# UPKI_RA_TLS: serve HTTPS using the RA certificate (required by Traefik/LEGO).
# UPKI_RA_SANS: DNS SANs embedded in the RA cert at first registration.
#   "upki-ra" matches the conventional Docker Compose service name so that
#   Go 1.15+ hostname validation succeeds when Traefik connects to the RA.
#   Override with the actual service name if the container is renamed.
ENV UPKI_RA_TLS=true
ENV UPKI_RA_SANS=upki-ra

EXPOSE 8000

# The healthcheck adapts to UPKI_RA_TLS: uses HTTPS (cert not verified) when
# TLS is enabled, plain HTTP otherwise.
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
    CMD python -c "\
    import os, urllib.request, ssl; \
    t = os.getenv('UPKI_RA_TLS', 'false').lower() == 'true'; \
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); \
    c.check_hostname = False; \
    c.verify_mode = ssl.CERT_NONE; \
    urllib.request.urlopen(('https' if t else 'http') + '://127.0.0.1:8000/api/v1/health', context=c if t else None)"

# Default command: auto-bootstrap (register if needed) then start server
CMD ["python", "ra_server.py", "start"]
