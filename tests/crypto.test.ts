import { describe, expect, it } from 'vitest';
import {
  isSymmetric,
  specFor,
  verifyWithMaterial,
  signToken,
  generateKeyPair,
  tryHmacSecret,
} from '../src/crypto';
import { decodeJwt } from '../src/jwt';

const SAMPLE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
  '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ' +
  '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
const SAMPLE_SECRET = 'your-256-bit-secret';

describe('spec helpers', () => {
  it('identifies symmetric vs asymmetric', () => {
    expect(isSymmetric('HS256')).toBe(true);
    expect(isSymmetric('RS256')).toBe(false);
    expect(isSymmetric('ES256')).toBe(false);
  });

  it('resolves an alg spec', () => {
    expect(specFor('ES256')).toMatchObject({ family: 'ECDSA', namedCurve: 'P-256' });
  });

  it('throws on an unsupported alg', () => {
    expect(() => specFor('XX999')).toThrow(/unsupported/);
  });
});

describe('HMAC verify against the canonical token', () => {
  it('verifies the sample token with the correct secret', async () => {
    const d = decodeJwt(SAMPLE);
    expect(await verifyWithMaterial('HS256', SAMPLE_SECRET, d.signingInput, d.signatureBytes)).toBe(true);
  });

  it('rejects the sample token with a wrong secret', async () => {
    const d = decodeJwt(SAMPLE);
    expect(await verifyWithMaterial('HS256', 'not-the-secret', d.signingInput, d.signatureBytes)).toBe(false);
  });

  it('tryHmacSecret agrees with verifyWithMaterial', async () => {
    const d = decodeJwt(SAMPLE);
    expect(await tryHmacSecret('HS256', d.signingInput, d.signatureBytes, SAMPLE_SECRET)).toBe(true);
    expect(await tryHmacSecret('HS256', d.signingInput, d.signatureBytes, 'nope')).toBe(false);
  });
});

describe('HMAC sign → decode → verify round-trip', () => {
  for (const alg of ['HS256', 'HS384', 'HS512'] as const) {
    it(`round-trips ${alg}`, async () => {
      const secret = 'a-test-secret-for-' + alg;
      const token = await signToken(alg, secret, {}, { sub: 'abc', n: 42 });
      const d = decodeJwt(token);
      expect(d.alg).toBe(alg);
      expect(d.payload).toMatchObject({ sub: 'abc', n: 42 });
      expect(await verifyWithMaterial(alg, secret, d.signingInput, d.signatureBytes)).toBe(true);
      expect(await verifyWithMaterial(alg, secret + 'x', d.signingInput, d.signatureBytes)).toBe(false);
    });
  }

  it('produces an unsecured token for alg none', async () => {
    const token = await signToken('none', '', {}, { sub: 'x' });
    expect(token.endsWith('.')).toBe(true);
    const d = decodeJwt(token);
    expect(d.alg).toBe('none');
    expect(d.signatureBytes.length).toBe(0);
  });
});

describe('asymmetric keygen → sign → verify', () => {
  for (const alg of ['ES256', 'RS256'] as const) {
    it(`generates a keypair and round-trips ${alg}`, async () => {
      const kp = await generateKeyPair(alg);
      expect(kp.publicPem).toContain('BEGIN PUBLIC KEY');
      expect(kp.privatePem).toContain('BEGIN PRIVATE KEY');

      // sign with the private PEM, verify with the public PEM
      const token = await signToken(alg, kp.privatePem, {}, { sub: 'pk-test' });
      const d = decodeJwt(token);
      expect(await verifyWithMaterial(alg, kp.publicPem, d.signingInput, d.signatureBytes)).toBe(true);

      // also verify with the exported public JWK
      expect(await verifyWithMaterial(alg, kp.publicJwk, d.signingInput, d.signatureBytes)).toBe(true);
    });
  }

  it('rejects generating a keypair for an HMAC alg', async () => {
    await expect(generateKeyPair('HS256')).rejects.toThrow(/shared secret/);
  });

  it('a public key cannot be used to sign', async () => {
    const kp = await generateKeyPair('ES256');
    await expect(signToken('ES256', kp.publicPem, {}, { a: 1 })).rejects.toThrow(/PRIVATE/);
  });
});

describe('key material validation', () => {
  it('rejects HMAC verification with a non-string secret', async () => {
    await expect(verifyWithMaterial('HS256', { not: 'a string' }, 'a.b', new Uint8Array())).rejects.toThrow(
      /secret string/,
    );
  });

  it('rejects garbage key material', async () => {
    await expect(verifyWithMaterial('ES256', 'total garbage', 'a.b', new Uint8Array([1]))).rejects.toThrow();
  });
});
