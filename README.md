# tokenpeek

**The offline JWT toolkit — decode, inspect, verify, crack weak secrets and forge JSON Web Tokens entirely in your browser. Nothing is ever uploaded.**

Live: https://tokenpeek.benrichardson.dev

---

## what it is

Pasting a production access token into a random "JWT decoder" website is a real
security risk: that token can carry live credentials and personal data, and you
have no idea what the server on the other end does with it. tokenpeek is the
offline alternative. It does everything the popular online decoders do — and a
few things they don't — with a hard guarantee: **your token, secrets and keys
never leave the tab.**

Drop in a JWT and tokenpeek splits it on its dots, base64url-decodes the header
and payload, and renders every claim with human-readable timestamps and a live
expiry badge. Then it goes further:

- **Verify** the signature with the browser's Web Crypto engine — HMAC
  (HS256/384/512) with a shared secret, or RSA / RSA-PSS / ECDSA / EdDSA with a
  public key you paste as PEM or JWK.
- **Crack** weak HMAC secrets. For HS-family tokens, tokenpeek runs the
  signature against a built-in wordlist of ~144 known-weak secrets (plus your
  own list) inside a Web Worker, with a live throughput readout. A hit means the
  signing secret is guessable and must be rotated — perfect for auditing your
  own APIs.
- **Forge** a token: edit the header/payload and re-sign it to mint test
  fixtures, or **generate** a fresh RSA/EC keypair as PEM and JWK.

It's built for developers, API engineers and security folks who work with JWTs
and would rather not trust a third party with them.

## how it works

```
        ┌─────────────── your browser tab (nothing leaves) ───────────────┐
 paste ─┤                                                                  │
        │  decodeJwt()          split on ".", base64url-decode → JSON      │
        │      │                                                           │
        │      ├─► analyzeClaims()   standard claims, exp/nbf verdicts     │
        │      │                                                           │
        │      ├─► verify        Web Crypto subtle.verify(alg, key, …)     │
        │      │                                                           │
        │      ├─► crack ──────► Web Worker: loop candidates,              │
        │      │                 subtle.verify per secret, stream progress │
        │      │                                                           │
        │      └─► forge/keygen  subtle.sign / subtle.generateKey          │
        └──────────────────────────────────────────────────────────────────┘
```

The compact JWS wire format is `base64url(header) . base64url(payload) .
base64url(signature)`. The **signing input** is the exact ASCII string
`header.payload`; the signature is a MAC/signature over those bytes. tokenpeek
never re-encodes the header/payload it verifies — it checks the signature over
the original bytes, so a valid token stays valid.

All decoding and claim analysis in [`src/jwt.ts`](./src/jwt.ts) is pure and
dependency-free. All crypto in [`src/crypto.ts`](./src/crypto.ts) goes through
`crypto.subtle`. The crack loop runs in [`src/worker.ts`](./src/worker.ts) so the
main thread never freezes.

## browser APIs used

- **Web Crypto (`crypto.subtle`)** — `verify`, `sign`, `importKey`,
  `exportKey`, `generateKey` for HMAC, RSASSA-PKCS1-v1_5, RSA-PSS, ECDSA and
  Ed25519. This is the essential pillar: real signature verification and signing.
- **Web Workers** — the weak-secret crack runs off the main thread and streams
  determinate progress + throughput back via `postMessage`.
- **Clipboard API** — paste a token, copy decoded JSON / keys / forged tokens.
- **Drag & Drop + File API** — drop a `.txt`/`.jwt` file to load a token.
- **Service Worker (PWA)** — once loaded, tokenpeek works fully offline.

## security / privacy model

**Protected**

- The token — decoded entirely in-tab, never uploaded, never stored, never put
  in the URL.
- Any secret, PEM or JWK you paste to verify, crack or sign — used only in
  memory by Web Crypto, never transmitted.
- Generated private keys — created in your browser; they exist only until you
  close the tab (or download them yourself).

**Not protected**

- The first page load comes from GitHub Pages' CDN, which sees your IP and that
  you opened tokenpeek — but never your token. After first load the PWA runs
  offline.
- A JWT is **not** encrypted. Anyone holding the token can read its claims;
  tokenpeek just shows you that plainly.
- The crack wordlist only catches **weak** secrets. "Not found" is not proof a
  secret is strong.

**Trust model**

- The static bundle (hash-pinned by the GitHub Pages deploy) and the TLS chain
  to GitHub Pages.
- No third-party fonts or trackers; your tokens never leave the device. A strict
  CSP meta tag allows only the app itself plus the cookie-less Cloudflare Web
  Analytics beacon (anonymous page-view counts — no personal data).
- No JWKS is fetched over the network — you paste the key, so no third party
  ever learns which key you're checking.

## stack

- Vite 6 + vanilla TypeScript (no framework)
- `vite-plugin-pwa` for the offline service worker
- Vitest for unit tests (42 tests across decoding + crypto round-trips)
- GitHub Pages for hosting, deployed via GitHub Actions

No runtime dependencies. No cookies, no fingerprinting, no third-party fonts.
The only analytics is Cloudflare Web Analytics — anonymous, cookie-less
page-view counts; no personal data, no cross-site tracking.

## local development

```bash
npm install
npm run dev      # vite dev server on :5173
npm test         # run the vitest suite
npm run build    # produce dist/ for deploy
npm run preview  # serve dist/ locally
```

## deploying

A push to `main` triggers [`.github/workflows/deploy.yml`](./.github/workflows/deploy.yml),
which runs tests, builds, and deploys `dist/` to GitHub Pages. The custom domain
is set via [`public/CNAME`](./public/CNAME) — point a `CNAME` DNS record for
`tokenpeek.benrichardson.dev` at `ben-gy.github.io`.

## license

MIT — see [LICENSE](./LICENSE).
