export default defineAppConfig({
  docus: {
    title: "uPKI RA",
    description:
      "ACME v2 Registration Authority for private networks — RFC 8555 without Let's Encrypt.",
    image: "/cover.png",
    socials: {
      github: "circle-rd/upki-ra",
    },
    github: {
      dir: "docs-site/content",
      branch: "main",
      repo: "upki-ra",
      owner: "circle-rd",
      edit: true,
    },
    aside: {
      level: 0,
      collapsed: false,
      exclude: [],
    },
    main: {
      padded: true,
      fluid: false,
    },
    header: {
      logo: false,
      showLinkIcon: true,
      exclude: [],
      fluid: false,
    },
    footer: {
      iconLinks: [
        {
          href: "https://github.com/circle-rd/upki-ra",
          icon: "simple-icons:github",
        },
      ],
    },
  },
});
