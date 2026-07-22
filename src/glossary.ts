// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Ben Richardson — https://benrichardson.dev
// Additional terms under AGPL-3.0 section 7(b) apply; see ADDITIONAL-TERMS.md.
/**
 * glossary.ts — jargon → plain-English definitions, plus a click-to-define
 * tooltip system. Any element with `data-term="key"` becomes a glossary link.
 */

export const GLOSSARY: Record<string, string> = {
  jwt: 'JSON Web Token — a compact, URL-safe token of three base64url parts (header.payload.signature) used to carry claims between parties.',
  jws: 'JSON Web Signature — the signed form of a JWT. tokenpeek works with JWS compact serialization (three dot-separated parts).',
  claim: 'A piece of information asserted about a subject, stored as a key/value pair in the token payload (e.g. "sub", "email", "role").',
  header: 'The first segment. Declares the signing algorithm ("alg") and token type ("typ"), and may carry a key id ("kid").',
  payload: 'The second segment. A JSON object of claims — the actual data the token conveys. It is not encrypted; anyone can read it.',
  signature: 'The third segment. A MAC or digital signature over "header.payload" that proves the token was issued by a holder of the key.',
  alg: 'The algorithm used to sign the token, e.g. HS256 (HMAC-SHA-256), RS256 (RSA), or ES256 (ECDSA).',
  kid: 'Key ID — an optional header hint telling the verifier which key was used, so it can pick the right one from a set.',
  hmac: 'Hash-based Message Authentication Code — a symmetric signature: the same secret both signs and verifies. HS256/384/512 use HMAC.',
  hs256: 'HMAC with SHA-256. Symmetric: signed and verified with a shared secret. If that secret is weak, anyone can forge tokens.',
  rs256: 'RSA signature with SHA-256. Asymmetric: signed with a private key, verified with the public key.',
  es256: 'ECDSA signature over the P-256 curve with SHA-256. Asymmetric, with much shorter keys than RSA.',
  eddsa: 'Edwards-curve Digital Signature Algorithm (Ed25519). A fast, modern asymmetric signature scheme.',
  spki: 'SubjectPublicKeyInfo — the standard DER/PEM encoding of a public key (the "-----BEGIN PUBLIC KEY-----" block).',
  pkcs8: 'The standard DER/PEM encoding of a private key (the "-----BEGIN PRIVATE KEY-----" block).',
  jwk: 'JSON Web Key — a key represented as a JSON object (e.g. {"kty":"RSA","n":"…","e":"AQAB"}). A private JWK includes a "d" field.',
  pem: 'A base64 key wrapped in "-----BEGIN …-----" / "-----END …-----" lines. tokenpeek reads SPKI public and PKCS#8 private PEM.',
  exp: 'Expiration time — a Unix timestamp after which the token must be rejected.',
  nbf: 'Not Before — a Unix timestamp before which the token is not yet valid.',
  iat: 'Issued At — the Unix timestamp when the token was created.',
  sub: 'Subject — who the token is about (typically a user id).',
  iss: 'Issuer — who created and signed the token.',
  aud: 'Audience — who the token is intended for; verifiers should check they are the intended audience.',
  jti: 'JWT ID — a unique identifier for the token, useful for revocation or replay prevention.',
  base64url: 'A URL-safe base64 variant using "-" and "_" instead of "+" and "/", with padding removed. JWT segments are base64url.',
  none: 'The "alg":"none" unsecured JWT — no signature at all. Accepting these is a classic vulnerability; tokenpeek shows them but flags them.',
};

let tooltipEl: HTMLElement | null = null;

function ensureTooltip(): HTMLElement {
  if (!tooltipEl) {
    tooltipEl = document.createElement('div');
    tooltipEl.className = 'glossary-tip';
    tooltipEl.setAttribute('role', 'tooltip');
    document.body.appendChild(tooltipEl);
  }
  return tooltipEl;
}

function hideTooltip(): void {
  tooltipEl?.classList.remove('visible');
}

/** Wire up global click handling for [data-term] glossary links. */
export function initGlossary(): void {
  document.addEventListener('click', (e) => {
    const target = e.target as HTMLElement;
    const link = target.closest<HTMLElement>('[data-term]');
    if (!link) {
      hideTooltip();
      return;
    }
    const term = link.dataset.term?.toLowerCase() ?? '';
    const def = GLOSSARY[term];
    if (!def) return;
    e.preventDefault();
    e.stopPropagation();

    const tip = ensureTooltip();
    tip.innerHTML = `<strong>${term}</strong><span>${def}</span>`;
    tip.classList.add('visible');

    const rect = link.getBoundingClientRect();
    const tipRect = tip.getBoundingClientRect();
    let left = rect.left + window.scrollX;
    left = Math.min(left, window.scrollX + window.innerWidth - tipRect.width - 12);
    left = Math.max(left, window.scrollX + 8);
    let top = rect.bottom + window.scrollY + 8;
    if (rect.bottom + tipRect.height + 16 > window.innerHeight) {
      top = rect.top + window.scrollY - tipRect.height - 8;
    }
    tip.style.left = `${left}px`;
    tip.style.top = `${top}px`;
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') hideTooltip();
  });
  window.addEventListener('scroll', hideTooltip, { passive: true });
}

/** Build a glossary link span for a term. */
export function term(label: string, key = label): string {
  return `<span class="glossary-link" data-term="${key.toLowerCase()}" role="button" tabindex="0">${label}</span>`;
}
