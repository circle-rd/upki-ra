---
seo:
  title: uPKI RA — ACME v2 Registration Authority
  description: ACME v2 Registration Authority for private networks — RFC 8555 without Let's Encrypt.
---

:::u-page-hero
#title
ACME v2 for private networks.

#description
uPKI RA is a fully compliant **ACME v2 Registration Authority** (RFC 8555) that connects your internal infrastructure to a self-hosted CA. Use Traefik, cert-manager, or any ACME client — no Let's Encrypt required.

#links
::::u-button{to="/docs/getting-started/introduction" size="xl" trailing-icon="i-lucide-arrow-right" color="neutral"}
Get Started
::::

::::u-button{to="https://github.com/circle-rd/upki-ra" target="_blank" size="xl" variant="outline" color="neutral" icon="i-simple-icons-github"}
Star on GitHub
::::
:::

:::u-page-section
#title
Why uPKI RA?

#features
::::u-page-feature{icon="i-lucide-shield-check" title="RFC 8555 compliant" description="Full ACME v2 implementation — new-account, new-order, challenges, certificate issuance and revocation."}
::::
::::u-page-feature{icon="i-lucide-rocket" title="Auto-bootstrap" description="First start automatically registers the RA with the CA and issues its own mTLS certificate."}
::::
::::u-page-feature{icon="i-lucide-lock" title="mTLS by default" description="Mutual TLS protects all admin and client endpoints. Docker image ships with TLS enabled by default."}
::::
::::u-page-feature{icon="i-lucide-layers" title="Traefik native" description="Works out of the box as a Traefik ACME provider. Point caServer at the RA and you're done."}
::::
::::u-page-feature{icon="i-lucide-wifi-off" title="Air-gapped friendly" description="Zero internet dependency. Deploy behind a firewall, in a DMZ, or in a fully isolated network."}
::::
::::u-page-feature{icon="i-lucide-database" title="SQLite state" description="ACME state (accounts, orders, authorizations) stored in SQLite. Simple, reliable, zero operational overhead."}
::::
:::
