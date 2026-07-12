import { describe, expect, it } from 'vitest';
import {
  base64UrlToBytes,
  base64UrlToString,
  bytesToBase64Url,
  jsonToSegment,
  decodeJwt,
  isHmacAlg,
  isKnownAlg,
  analyzeClaims,
  formatRelative,
  prettyJson,
} from '../src/jwt';

const SAMPLE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
  '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ' +
  '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

describe('base64url', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const encoded = bytesToBase64Url(bytes);
    expect(encoded).not.toMatch(/[+/=]/); // url-safe, unpadded
    expect(base64UrlToBytes(encoded)).toEqual(bytes);
  });

  it('round-trips utf-8 strings including emoji', () => {
    const s = 'héllo · 世界 · 🔐';
    expect(base64UrlToString(bytesToBase64Url(s))).toBe(s);
  });

  it('decodes standard base64 with padding too', () => {
    // "sub" JSON fragment in standard base64 with +/ and padding
    expect(base64UrlToString('eyJhIjoxfQ==')).toBe('{"a":1}');
  });

  it('rejects an invalid base64url length', () => {
    expect(() => base64UrlToBytes('abcde')).toThrow(/length/);
  });

  it('rejects illegal characters', () => {
    expect(() => base64UrlToBytes('****')).toThrow(/base64url/);
  });

  it('encodes objects to compact segments', () => {
    const seg = jsonToSegment({ a: 1, b: 'x' });
    expect(base64UrlToString(seg)).toBe('{"a":1,"b":"x"}');
  });
});

describe('decodeJwt', () => {
  it('decodes a well-formed HS256 token', () => {
    const d = decodeJwt(SAMPLE);
    expect(d.header).toEqual({ alg: 'HS256', typ: 'JWT' });
    expect(d.payload).toMatchObject({ sub: '1234567890', name: 'John Doe', iat: 1516239022 });
    expect(d.alg).toBe('HS256');
    expect(d.signingInput).toBe(`${d.parts.header}.${d.parts.payload}`);
    expect(d.signatureBytes.length).toBeGreaterThan(0);
  });

  it('trims surrounding whitespace', () => {
    expect(decodeJwt(`  \n${SAMPLE}\n `).alg).toBe('HS256');
  });

  it('throws on empty input', () => {
    expect(() => decodeJwt('   ')).toThrow(/no token/);
  });

  it('throws when there are not three segments', () => {
    expect(() => decodeJwt('a.b')).toThrow(/3 dot-separated/);
  });

  it('recognises a 5-part JWE and says so', () => {
    expect(() => decodeJwt('a.b.c.d.e')).toThrow(/JWE/);
  });

  it('throws on a non-JSON header', () => {
    const bad = `${bytesToBase64Url('not json')}.${jsonToSegment({ a: 1 })}.sig`;
    expect(() => decodeJwt(bad)).toThrow(/header is not valid/);
  });

  it('throws on a non-object payload (JSON array)', () => {
    const bad = `${jsonToSegment({ alg: 'HS256' })}.${jsonToSegment([1, 2, 3])}.sig`;
    expect(() => decodeJwt(bad)).toThrow(/payload is not a JSON object/);
  });

  it('handles an unsecured token with an empty signature', () => {
    const tok = `${jsonToSegment({ alg: 'none' })}.${jsonToSegment({ sub: 'x' })}.`;
    const d = decodeJwt(tok);
    expect(d.alg).toBe('none');
    expect(d.signatureBytes.length).toBe(0);
  });
});

describe('alg helpers', () => {
  it('classifies HMAC algs', () => {
    expect(isHmacAlg('HS256')).toBe(true);
    expect(isHmacAlg('HS512')).toBe(true);
    expect(isHmacAlg('RS256')).toBe(false);
    expect(isHmacAlg('none')).toBe(false);
    expect(isHmacAlg(null)).toBe(false);
  });

  it('recognises known algs', () => {
    expect(isKnownAlg('ES384')).toBe(true);
    expect(isKnownAlg('none')).toBe(true);
    expect(isKnownAlg('BOGUS')).toBe(false);
    expect(isKnownAlg(null)).toBe(false);
  });
});

describe('analyzeClaims', () => {
  const now = 1_700_000_000_000; // fixed "now" in ms

  it('flags an expired token', () => {
    const a = analyzeClaims({ exp: 1_600_000_000 }, now);
    expect(a.expiry.kind).toBe('expired');
    const row = a.rows.find((r) => r.key === 'exp');
    expect(row?.status).toBe('bad');
  });

  it('reports a valid, unexpired token', () => {
    const a = analyzeClaims({ exp: 1_800_000_000 }, now);
    expect(a.expiry.kind).toBe('valid');
    const row = a.rows.find((r) => r.key === 'exp');
    expect(row?.status).toBe('ok');
  });

  it('detects a not-yet-valid (nbf) token', () => {
    const a = analyzeClaims({ nbf: 1_800_000_000, exp: 1_900_000_000 }, now);
    expect(a.expiry.kind).toBe('not-yet-valid');
  });

  it('has no expiry verdict when exp/nbf are absent', () => {
    const a = analyzeClaims({ sub: 'x' }, now);
    expect(a.expiry.kind).toBe('none');
  });

  it('orders standard claims before custom ones', () => {
    const a = analyzeClaims({ zebra: 1, sub: 'x', iat: 1, aud: 'a' }, now);
    const keys = a.rows.map((r) => r.key);
    expect(keys.indexOf('sub')).toBeLessThan(keys.indexOf('iat'));
    expect(keys.indexOf('aud')).toBeLessThan(keys.indexOf('zebra'));
    expect(keys[keys.length - 1]).toBe('zebra');
  });

  it('renders nested object claims as JSON', () => {
    const a = analyzeClaims({ realm_access: { roles: ['admin'] } }, now);
    const row = a.rows.find((r) => r.key === 'realm_access');
    expect(row?.display).toBe('{"roles":["admin"]}');
  });
});

describe('formatRelative', () => {
  it('formats future durations', () => {
    expect(formatRelative(65_000)).toBe('in 1m 5s');
  });
  it('formats past durations', () => {
    expect(formatRelative(-3_600_000)).toBe('1h ago');
  });
  it('formats days', () => {
    expect(formatRelative(2 * 86_400_000 + 3 * 3_600_000)).toBe('in 2d 3h');
  });
});

describe('prettyJson', () => {
  it('indents with two spaces', () => {
    expect(prettyJson({ a: 1 })).toBe('{\n  "a": 1\n}');
  });
});
