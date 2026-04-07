---
title: uPKI RA
navigation: false
---

# ACME v2 for private networks.

uPKI RA is a fully compliant **ACME v2 Registration Authority** (RFC 8555) that connects your internal infrastructure to a self-hosted CA. Use Traefik, cert-manager, or any ACME client — no Let's Encrypt required.

[Get Started](/docs/getting-started/introduction) · [GitHub](https://github.com/circle-rd/upki-ra)

## Why uPKI RA?

:::card-group
::card{title="RFC 8555 compliant" icon="i-lucide-shield-check"}
Full ACME v2 implementation — new-account, new-order, challenges, certificate issuance and revocation.
::
::card{title="Auto-bootstrap" icon="i-lucide-rocket"}
First `start` automatically registers the RA with the CA and issues its own mTLS certificate.
::
::card{title="mTLS by default" icon="i-lucide-lock"}
Mutual TLS protects all admin and client endpoints. Docker image ships with TLS enabled by default.
::
::card{title="Traefik native" icon="i-lucide-layers"}
Works out of the box as a Traefik ACME provider. Point `caServer` at the RA and you're done.
::
::card{title="Air-gapped friendly" icon="i-lucide-wifi-off"}
Zero internet dependency. Deploy behind a firewall, in a DMZ, or in a fully isolated network.
::
::card{title="SQLite state" icon="i-lucide-database"}
ACME state (accounts, orders, authorizations) stored in SQLite. Simple, reliable, zero operational overhead.
::
:::
