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

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')"

# Default command: auto-bootstrap (register if needed) then start server
CMD ["python", "ra_server.py", "start"]
