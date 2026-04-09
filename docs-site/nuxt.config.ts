export default defineNuxtConfig({
  extends: ["docus"],
  app: {
    baseURL: process.env.NUXT_APP_BASE_URL ?? "/upki-ra/",
  },
  site: {
    url: process.env.NUXT_SITE_URL ?? "https://docs.circle-cyber.com/upki-ra",
  },
  llms: {
    title: "uPKI RA",
    description:
      "ACME v2 Registration Authority for private networks — RFC 8555 without Let's Encrypt.",
    full: {
      title: "uPKI RA — Complete Documentation",
      description:
        "Complete documentation for uPKI RA, a fully compliant ACME v2 Registration Authority for private networks.",
    },
  },
});
