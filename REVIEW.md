# tokenpeek — Build Review

This file exists only to create a reviewable PR. All code is already deployed on `main`.

**Merge this PR to acknowledge the build.** Closing without merging is also fine.

## Links

- **GitHub Pages:** https://ben-gy.github.io/tokenpeek/ *(redirects to custom domain once DNS is set)*
- **Custom domain:** https://tokenpeek.benrichardson.dev *(live after DNS + cert below)*

## What it is

The offline alternative to online "JWT decoder" sites. tokenpeek decodes and
inspects JSON Web Tokens, verifies their signatures (HMAC / RSA / RSA-PSS /
ECDSA / EdDSA) with Web Crypto, cracks weak HMAC secrets in a Web Worker, and
forges/generates tokens and keypairs — all entirely in the browser. Nothing is
uploaded; the token, secrets and keys never leave the tab.

## DNS setup required

Add in Cloudflare (`benrichardson.dev` zone):

| Type | Name | Target | Proxy |
|------|------|--------|-------|
| CNAME | `tokenpeek` | `ben-gy.github.io` | DNS only (grey cloud) |

*(This was provisioned automatically during the build; the table documents it.)*

Then trigger cert issuance:
```bash
gh api repos/ben-gy/tokenpeek/pages -X PUT -f cname=""
sleep 3
gh api repos/ben-gy/tokenpeek/pages -X PUT -f cname="tokenpeek.benrichardson.dev"
```
