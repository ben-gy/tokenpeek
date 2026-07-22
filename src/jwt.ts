// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Ben Richardson — https://benrichardson.dev
// Additional terms under AGPL-3.0 section 7(b) apply; see ADDITIONAL-TERMS.md.
/**
 * jwt.ts — pure, dependency-free JWT (JWS compact) decoding and claim analysis.
 *
 * Nothing here touches the network, the DOM, or Web Crypto. Everything is a
 * pure function so it can be exhaustively unit-tested in Node/jsdom.
 */

import type { ClaimAnalysis, ClaimRow, ClaimStatus, DecodedJwt, JwsAlg } from './types';

// ---------- base64url ----------

const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Decode a base64url (or plain base64) string into raw bytes. */
export function base64UrlToBytes(input: string): Uint8Array {
  // Normalise base64url → base64 and strip whitespace.
  let s = input.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  // Reject characters that aren't valid base64 once normalised.
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
    throw new Error('segment is not valid base64url');
  }
  // Re-pad to a multiple of 4.
  const pad = s.length % 4;
  if (pad === 1) throw new Error('segment has an invalid base64url length');
  if (pad) s += '='.repeat(4 - pad);

  const len = (s.length / 4) * 3 - (s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (let i = 0; i < s.length; i += 4) {
    const a = B64_CHARS.indexOf(s[i]);
    const b = B64_CHARS.indexOf(s[i + 1]);
    const c = s[i + 2] === '=' ? -1 : B64_CHARS.indexOf(s[i + 2]);
    const d = s[i + 3] === '=' ? -1 : B64_CHARS.indexOf(s[i + 3]);
    out[o++] = (a << 2) | (b >> 4);
    if (c !== -1) out[o++] = ((b & 15) << 4) | (c >> 2);
    if (d !== -1) out[o++] = ((c & 3) << 6) | d;
  }
  return out;
}

/** Decode a base64url segment into a UTF-8 string. */
export function base64UrlToString(input: string): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(base64UrlToBytes(input));
}

/** Encode raw bytes (or a UTF-8 string) as base64url with no padding. */
export function bytesToBase64Url(input: Uint8Array | string): string {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  let s = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    s += B64_CHARS[a >> 2];
    s += B64_CHARS[((a & 3) << 4) | (b >> 4)];
    s += i + 1 < bytes.length ? B64_CHARS[((b & 15) << 2) | (c >> 6)] : '';
    s += i + 2 < bytes.length ? B64_CHARS[c & 63] : '';
  }
  return s.replace(/\+/g, '-').replace(/\//g, '_');
}

/** Encode an object as a base64url JSON segment (compact, no whitespace). */
export function jsonToSegment(obj: unknown): string {
  return bytesToBase64Url(JSON.stringify(obj));
}

// ---------- decode ----------

const KNOWN_ALGS: ReadonlySet<string> = new Set<JwsAlg>([
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'EdDSA', 'none',
]);

/** True for the HMAC family that the crack feature can attack. */
export function isHmacAlg(alg: unknown): alg is 'HS256' | 'HS384' | 'HS512' {
  return alg === 'HS256' || alg === 'HS384' || alg === 'HS512';
}

/**
 * Decode a compact JWT. Throws a descriptive Error if it isn't a well-formed
 * token (wrong segment count, bad base64, non-JSON header/payload).
 */
export function decodeJwt(token: string): DecodedJwt {
  const raw = token.trim();
  if (!raw) throw new Error('no token supplied');

  const segments = raw.split('.');
  if (segments.length !== 3) {
    throw new Error(
      `expected 3 dot-separated segments, found ${segments.length}` +
        (segments.length === 5 ? ' — this looks like a JWE (encrypted), not a JWS' : ''),
    );
  }
  const [headerB64, payloadB64, signatureB64] = segments;
  if (!headerB64 || !payloadB64) {
    throw new Error('header or payload segment is empty');
  }

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(base64UrlToString(headerB64));
  } catch {
    throw new Error('header is not valid base64url-encoded JSON');
  }
  if (typeof header !== 'object' || header === null || Array.isArray(header)) {
    throw new Error('header is not a JSON object');
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(base64UrlToString(payloadB64));
  } catch {
    throw new Error('payload is not valid base64url-encoded JSON');
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new Error('payload is not a JSON object');
  }

  let signatureBytes: Uint8Array = new Uint8Array(0);
  if (signatureB64) {
    signatureBytes = base64UrlToBytes(signatureB64);
  }

  const algRaw = header['alg'];
  const alg = typeof algRaw === 'string' ? algRaw : null;

  return {
    raw,
    parts: { header: headerB64, payload: payloadB64, signature: signatureB64 },
    header,
    payload,
    signatureBytes,
    signingInput: `${headerB64}.${payloadB64}`,
    alg,
  };
}

/** Whether the token's declared alg is one tokenpeek recognises. */
export function isKnownAlg(alg: string | null): boolean {
  return alg !== null && KNOWN_ALGS.has(alg);
}

// ---------- claim analysis ----------

const STANDARD_CLAIMS: Record<string, string> = {
  iss: 'Issuer',
  sub: 'Subject',
  aud: 'Audience',
  exp: 'Expires',
  nbf: 'Not before',
  iat: 'Issued at',
  jti: 'JWT ID',
};

const TIME_CLAIMS = new Set(['exp', 'nbf', 'iat', 'auth_time', 'updated_at']);

function formatAbsolute(seconds: number): string {
  const d = new Date(seconds * 1000);
  if (Number.isNaN(d.getTime())) return String(seconds);
  return d.toISOString().replace('.000Z', 'Z');
}

/** Human relative duration, e.g. "in 4m 12s" or "3d 2h ago". */
export function formatRelative(deltaMs: number): string {
  const past = deltaMs < 0;
  let s = Math.floor(Math.abs(deltaMs) / 1000);
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  const parts: string[] = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  if (!d && (s || parts.length === 0)) parts.push(`${s}s`);
  const body = parts.slice(0, 2).join(' ');
  return past ? `${body} ago` : `in ${body}`;
}

/**
 * Analyse a payload's claims: render values, recognise standard claims,
 * resolve timestamps and produce an overall expiry verdict.
 */
export function analyzeClaims(payload: Record<string, unknown>, nowMs: number): ClaimAnalysis {
  const rows: ClaimRow[] = [];
  let expiry: ClaimAnalysis['expiry'] = { kind: 'none' };

  for (const [key, raw] of Object.entries(payload)) {
    const label = STANDARD_CLAIMS[key] ?? key;
    let display: string;
    let status: ClaimStatus = STANDARD_CLAIMS[key] ? 'neutral' : 'neutral';
    let note: string | undefined;

    if (TIME_CLAIMS.has(key) && typeof raw === 'number' && Number.isFinite(raw)) {
      const atMs = raw * 1000;
      display = `${formatAbsolute(raw)}  (${formatRelative(atMs - nowMs)})`;
      if (key === 'exp') {
        if (atMs <= nowMs) {
          status = 'bad';
          note = 'token has expired';
        } else {
          status = 'ok';
          note = `valid for ${formatRelative(atMs - nowMs).replace('in ', '')}`;
        }
      } else if (key === 'nbf') {
        if (atMs > nowMs) {
          status = 'warn';
          note = 'not valid yet';
        }
      }
    } else if (typeof raw === 'object' && raw !== null) {
      display = JSON.stringify(raw);
    } else {
      display = String(raw);
    }

    rows.push({ key, label, display, raw, status, note });
  }

  // Overall expiry verdict from exp / nbf.
  const exp = payload['exp'];
  const nbf = payload['nbf'];
  if (typeof nbf === 'number' && nbf * 1000 > nowMs) {
    expiry = { kind: 'not-yet-valid', inMs: nbf * 1000 - nowMs, at: nbf * 1000 };
  } else if (typeof exp === 'number') {
    const atMs = exp * 1000;
    if (atMs <= nowMs) expiry = { kind: 'expired', agoMs: nowMs - atMs, at: atMs };
    else expiry = { kind: 'valid', expiresInMs: atMs - nowMs, at: atMs };
  }

  // Sort: standard claims first (in canonical order), then the rest alphabetically.
  const order = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];
  rows.sort((a, b) => {
    const ia = order.indexOf(a.key);
    const ib = order.indexOf(b.key);
    if (ia !== -1 && ib !== -1) return ia - ib;
    if (ia !== -1) return -1;
    if (ib !== -1) return 1;
    return a.key.localeCompare(b.key);
  });

  return { rows, expiry };
}

/** Pretty-print a JSON object with stable 2-space indentation. */
export function prettyJson(obj: unknown): string {
  return JSON.stringify(obj, null, 2);
}
