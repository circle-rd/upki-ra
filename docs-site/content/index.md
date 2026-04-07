---
title: uPKI RA
navigation: false
layout: page
---

## ::hero

announcement:
title: 'Traefik native integration'
icon: '🚀'
to: /docs/guides/traefik-integration
actions:

- name: Get Started
  to: /docs/getting-started/introduction
- name: GitHub
  variant: ghost
  to: https://github.com/circle-rd/upki-ra
  leftIcon: 'lucide:github'

---

#title
ACME v2 for\nprivate networks.

#description
uPKI RA is a fully compliant **ACME v2 Registration Authority** (RFC 8555) that connects your internal infrastructure to a self-hosted CA. Use Traefik, cert-manager, or any ACME client — no Let's Encrypt required.
::

::card-grid
#title
Why uPKI RA?

#root
:ellipsis

#default
::card

---

icon: lucide:shield-check

---

#title
RFC 8555 compliant
#description
Full ACME v2 implementation — new-account, new-order, challenges, certificate issuance and revocation.
::

::card

---

icon: lucide:rocket

---

#title
Auto-bootstrap
#description
First `start` automatically registers the RA with the CA and issues its own mTLS certificate.
::

::card

---

icon: lucide:lock

---

#title
mTLS by default
#description
Mutual TLS protects all admin and client endpoints. Docker image ships with TLS enabled by default.
::

::card

---

icon: lucide:layers

---

#title
Traefik native
#description
Works out of the box as a Traefik ACME provider. Point `caServer` at the RA and you're done.
::

::card

---

icon: lucide:wifi-off

---

#title
Air-gapped friendly
#description
Zero internet dependency. Deploy behind a firewall, in a DMZ, or in a fully isolated network.
::

::card

---

icon: lucide:database

---

#title
SQLite state
#description
ACME state (accounts, orders, authorizations) stored in SQLite. Simple, reliable, zero operational overhead.
::
::
