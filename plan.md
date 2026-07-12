# Tool Plan: tokenpeek

## Overview
- **Name:** tokenpeek
- **Repo name:** tokenpeek
- **Tagline:** Decode, inspect, verify, crack and forge JSON Web Tokens entirely in your browser — nothing is ever uploaded.

## Problem It Solves
A developer is debugging an auth flow at 11pm. They have a JWT that a service rejected and they need to see what's inside it, whether it's expired, and whether the signature actually verifies against the secret/public key they think it should. Their instinct is to paste it into jwt.io or one of the dozens of "JWT decoder online" sites. But that token is a **production access token** — it may contain a real user id, email, scopes, and (for HS256) it is signed with a secret that, if leaked, lets an attacker mint tokens for anyone. Pasting it into a remote site is a genuine security incident. tokenpeek is the offline answer: same workflow, but every byte stays in the tab.

It also answers a second, sharper question security engineers Google: **"is my JWT secret weak?"** HS256 tokens signed with guessable secrets (`secret`, `password`, `your-256-bit-secret`) are a top API vulnerability. tokenpeek runs the token's signature against a built-in weak-secret wordlist in a Web Worker — a local, offline `jwt_tool`/`hashcat`-style crack — so you can find out before an attacker does.

## Why This Must Be Client-Side
- **Sensitive-data handling.** JWTs routinely carry PII and bearer credentials. The whole value proposition is that the token (and any secret/private key you paste to verify or crack it) never leaves the device.
- **No-account friction.** Instant, no sign-up, works offline once loaded — a PWA you can use on a locked-down machine.
- **Trust.** A security tool that phones home is a contradiction. Offline-by-construction is the only honest design.

## Browser APIs / Libraries Used
| API / Library | What it does for us | Fallback if unsupported |
|---------------|----------------------|-------------------------|
| Web Crypto `subtle.verify` | Verify HS/RS/PS/ES/EdDSA signatures | N/A — core requirement |
| Web Crypto `subtle.sign` | Forge/sign tokens for testing | N/A — core requirement |
| Web Crypto `subtle.importKey` (raw/spki/pkcs8/jwk) | Import secrets, PEM and JWK keys | Clear error if key malformed |
| Web Crypto `subtle.generateKey` + `exportKey` | Generate RSA / EC keypairs as PEM/JWK | Hide keygen if unavailable |
| Web Workers | Offload the HMAC wordlist crack (CPU-bound) | Falls back to main-thread loop |
| TextEncoder / TextDecoder + base64url | Decode/encode token segments | N/A |
| Clipboard API | Paste token, copy outputs | Manual select/copy |
| Web Share API | Share decoded summary (mobile) | Hidden if absent |
| Service Worker (PWA) | Offline use after first load | Works online without it |

## Workflow (input → process → output)
1. User pastes a JWT (textarea, clipboard button, Cmd/Ctrl+V, or drag-drops a `.txt`/`.jwt` file).
2. Tool decodes it instantly: colour-split token, pretty-printed header + payload, and a claims table with human-readable timestamps and an expiry badge. Optionally the user verifies the signature (secret or public key), runs the weak-secret crack (worker, determinate progress + throughput), forges a modified token, or generates a keypair.
3. User copies the decoded JSON / verified result / forged token, or shares a summary. Nothing was sent anywhere.

## Non-Goals
- No remote JWKS fetch in v1 (that's a network call to a third party — paste the key instead; noted in Threat Model).
- No token *storage*/history — decoded tokens are never persisted (privacy).
- No encryption of JWE / nested tokens v1 (JWS only).
- No account system ever, no cloud sync ever.

## Target Audience
Backend/full-stack developers and application-security engineers debugging or auditing auth — on a laptop, often with a *real* production token in hand, aware that pasting it into a random website is risky. Technical, terminal-comfortable, value speed and trustworthiness over hand-holding.

## Style Direction
**Tone:** technical, precise, confidence-inspiring.
**Colour palette:** dark, desaturated slate with a cyan/teal accent and three semantic segment colours (header = magenta, payload = cyan, signature = amber) echoing the familiar jwt.io split so the tool reads as "the offline one". Green/amber/red for verify/expiry status.
**UI density:** dense (dev tool).
**Dark/light theme:** dark (technical / security audience).
**Reference tools for feel:** jwt.io (the colour-split token), jwt_tool (the crack feature), Dropwell (our shell: topbar meta, event drawer, statusbar).

## Technical Architecture
- **Stack:** Vanilla TypeScript + Vite. No React — state is simple (one token + a few panels).
- **Key libraries:** none at runtime beyond the Vite/PWA tooling. All crypto is native Web Crypto; base64url is hand-rolled. (Zero runtime npm dependencies — a deliberate trust signal.)
- **Worker strategy:** single dedicated Web Worker for the HMAC weak-secret crack, streaming progress via postMessage; main-thread fallback if Worker construction fails.
- **Storage:** none for token data. localStorage only for UI prefs (last active tab, theme). Service Worker cache for offline shell.

## Privacy & Trust Model
**Protected**
- The token itself — decoded entirely in-tab; never sent over the network; never written to localStorage or the URL.
- Any secret, PEM, or JWK you paste to verify/crack/sign — used only in-memory by Web Crypto.
- Generated private keys — created in your browser, never transmitted.

**Not protected**
- The initial page load is fetched from GitHub Pages' CDN (which sees your IP and that you loaded tokenpeek — not your token). After first load the PWA works fully offline.
- A JWT is *not* encrypted — anyone you hand the token to can read its claims. tokenpeek just makes that visible.
- The built-in crack wordlist only catches *weak* secrets; a "not found" result is not proof a secret is strong.

**Trust surface**
- The static site bundle (hash-pinned via the GitHub Pages deploy) and the TLS chain between you and GitHub Pages.
- Zero third-party scripts, fonts, analytics, or trackers. CSP restricts network to `'self'`.

## UX Required Surfaces
- Paste/drop input surface (textarea + clipboard button + Cmd/Ctrl+V + file drop + sample token).
- Colour-split token view (header/payload/signature) like jwt.io.
- Claims table: standard-claim recognition, human timestamps, live expiry countdown + badge.
- Verify panel: auto-detected alg, secret or public-key (PEM/JWK) input, pass/fail with reason.
- Crack panel (HMAC only): built-in wordlist + custom list, Web Worker, determinate progress with secrets/s throughput.
- Sign/forge panel: editable header+payload JSON, secret/private key, produces a new token.
- Keygen panel: generate RSA/EC keypair, export PEM, copy/download.
- Event log drawer (Dropwell pattern).
- How-It-Works modal, Threat Model modal, About modal (benrichardson.dev attribution).
- Output delivery: copy-to-clipboard everywhere, Web Share for summary, download for keys.
- Keyboard shortcuts: Escape (close modal), Cmd/Ctrl+V (paste token), Enter (verify in verify panel).
- Glossary tooltips for JWT jargon (claim, alg, kid, SPKI, JWK, HMAC, nbf…).
- Sticky footer "Built by benrichardson.dev".
