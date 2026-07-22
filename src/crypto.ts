// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Ben Richardson — https://benrichardson.dev
// Additional terms under AGPL-3.0 section 7(b) apply; see ADDITIONAL-TERMS.md.
/**
 * crypto.ts — all Web Crypto operations: signature verification, signing
 * (forging), key import (secret / PEM / JWK) and keypair generation.
 *
 * Pure with respect to the DOM and network — only `globalThis.crypto.subtle`
 * is used, so the round-trip paths are testable under Node's webcrypto.
 */

import type { JwsAlg } from './types';
import { base64UrlToBytes, bytesToBase64Url, jsonToSegment } from './jwt';

function subtle(): SubtleCrypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c || !c.subtle) {
    throw new Error('Web Crypto (crypto.subtle) is not available in this environment');
  }
  return c.subtle;
}

interface AlgSpec {
  family: 'HMAC' | 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' | 'ECDSA' | 'Ed25519';
  hash?: 'SHA-256' | 'SHA-384' | 'SHA-512';
  namedCurve?: 'P-256' | 'P-384' | 'P-521';
  saltLength?: number;
}

const SPECS: Record<string, AlgSpec> = {
  HS256: { family: 'HMAC', hash: 'SHA-256' },
  HS384: { family: 'HMAC', hash: 'SHA-384' },
  HS512: { family: 'HMAC', hash: 'SHA-512' },
  RS256: { family: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  RS384: { family: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
  RS512: { family: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
  PS256: { family: 'RSA-PSS', hash: 'SHA-256', saltLength: 32 },
  PS384: { family: 'RSA-PSS', hash: 'SHA-384', saltLength: 48 },
  PS512: { family: 'RSA-PSS', hash: 'SHA-512', saltLength: 64 },
  ES256: { family: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' },
  ES384: { family: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' },
  ES512: { family: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' },
  EdDSA: { family: 'Ed25519' },
};

export function specFor(alg: string): AlgSpec {
  const spec = SPECS[alg];
  if (!spec) throw new Error(`unsupported algorithm: ${alg}`);
  return spec;
}

/** True if `alg` uses a symmetric secret rather than a key pair. */
export function isSymmetric(alg: string): boolean {
  return SPECS[alg]?.family === 'HMAC';
}

/** The `algorithm` object passed to importKey. */
function importParams(spec: AlgSpec): AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams {
  switch (spec.family) {
    case 'HMAC':
      return { name: 'HMAC', hash: spec.hash! };
    case 'RSASSA-PKCS1-v1_5':
      return { name: 'RSASSA-PKCS1-v1_5', hash: spec.hash! };
    case 'RSA-PSS':
      return { name: 'RSA-PSS', hash: spec.hash! };
    case 'ECDSA':
      return { name: 'ECDSA', namedCurve: spec.namedCurve! };
    case 'Ed25519':
      return { name: 'Ed25519' };
  }
}

/** The `algorithm` object passed to sign / verify. */
function sigParams(spec: AlgSpec): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
  switch (spec.family) {
    case 'HMAC':
      return { name: 'HMAC' };
    case 'RSASSA-PKCS1-v1_5':
      return { name: 'RSASSA-PKCS1-v1_5' };
    case 'RSA-PSS':
      return { name: 'RSA-PSS', saltLength: spec.saltLength! };
    case 'ECDSA':
      return { name: 'ECDSA', hash: spec.hash! };
    case 'Ed25519':
      return { name: 'Ed25519' };
  }
}

function pemBody(pem: string): { label: string; bytes: Uint8Array } {
  const m = pem.match(/-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/);
  if (!m) throw new Error('not a valid PEM block (missing BEGIN/END markers)');
  return { label: m[1].trim(), bytes: base64UrlToBytes(m[2].replace(/\s+/g, '')) };
}

function asJwk(material: string | object): JsonWebKey | null {
  if (typeof material === 'object') return material as JsonWebKey;
  const trimmed = material.trim();
  if (trimmed.startsWith('{')) {
    try {
      return JSON.parse(trimmed) as JsonWebKey;
    } catch {
      throw new Error('looks like JWK but is not valid JSON');
    }
  }
  return null;
}

/**
 * Import a key for the given algorithm and usage.
 * - HMAC: `material` is the raw secret string.
 * - Asymmetric: `material` is a PEM block (SPKI public / PKCS8 private) or a JWK
 *   (object or JSON string). The usage must match the key kind.
 */
export async function importKey(
  alg: string,
  material: string | object,
  usage: 'verify' | 'sign',
): Promise<CryptoKey> {
  const spec = specFor(alg);

  if (spec.family === 'HMAC') {
    if (typeof material !== 'string') throw new Error('HMAC needs a secret string');
    const bytes = new TextEncoder().encode(material);
    return subtle().importKey('raw', bytes, importParams(spec) as HmacImportParams, false, [usage]);
  }

  const jwk = asJwk(material);
  if (jwk) {
    const isPrivate = typeof jwk.d === 'string' && jwk.d.length > 0;
    if (usage === 'sign' && !isPrivate) throw new Error('signing needs a private JWK (with a "d" parameter)');
    if (usage === 'verify' && isPrivate) {
      // A private JWK can still verify — derive intent from usage, keep public bits only.
    }
    return subtle().importKey('jwk', jwk, importParams(spec), false, [usage]);
  }

  if (typeof material === 'string' && material.includes('-----BEGIN')) {
    const { label, bytes } = pemBody(material);
    const isPrivatePem = label.includes('PRIVATE');
    if (usage === 'sign' && !isPrivatePem) throw new Error('signing needs a PRIVATE KEY PEM (PKCS#8)');
    if (usage === 'verify' && isPrivatePem) throw new Error('verification needs a PUBLIC KEY PEM (SPKI)');
    const format = isPrivatePem ? 'pkcs8' : 'spki';
    return subtle().importKey(format, bytes as BufferSource, importParams(spec), false, [usage]);
  }

  throw new Error('key must be an HMAC secret, a PEM block, or a JWK');
}

/** Verify a signature over `signingInput` against `signatureBytes`. */
export async function verify(
  alg: string,
  key: CryptoKey,
  signingInput: string,
  signatureBytes: Uint8Array,
): Promise<boolean> {
  const spec = specFor(alg);
  const data = new TextEncoder().encode(signingInput);
  return subtle().verify(sigParams(spec), key, signatureBytes as BufferSource, data);
}

/** High-level: import the supplied key material and verify in one call. */
export async function verifyWithMaterial(
  alg: string,
  material: string | object,
  signingInput: string,
  signatureBytes: Uint8Array,
): Promise<boolean> {
  const key = await importKey(alg, material, 'verify');
  return verify(alg, key, signingInput, signatureBytes);
}

/** Sign header+payload to produce a complete compact JWT. */
export async function signToken(
  alg: string,
  material: string | object,
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): Promise<string> {
  const fullHeader = { alg, typ: 'JWT', ...header };
  const headerSeg = jsonToSegment(fullHeader);
  const payloadSeg = jsonToSegment(payload);
  const signingInput = `${headerSeg}.${payloadSeg}`;

  if (alg === 'none') return `${signingInput}.`;

  const spec = specFor(alg);
  const key = await importKey(alg, material, 'sign');
  const sig = await subtle().sign(sigParams(spec), key, new TextEncoder().encode(signingInput));
  return `${signingInput}.${bytesToBase64Url(new Uint8Array(sig))}`;
}

export interface GeneratedKeyPair {
  alg: JwsAlg;
  publicPem: string;
  privatePem: string;
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
}

function pemWrap(label: string, der: ArrayBuffer): string {
  const b64 = bytesToStdBase64(new Uint8Array(der));
  const lines = b64.match(/.{1,64}/g) ?? [b64];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

function bytesToStdBase64(bytes: Uint8Array): string {
  // bytesToBase64Url produces url-safe + unpadded; convert to standard PEM base64.
  let url = bytesToBase64Url(bytes).replace(/-/g, '+').replace(/_/g, '/');
  while (url.length % 4) url += '=';
  return url;
}

/** Generate an asymmetric key pair and export both PEM and JWK forms. */
export async function generateKeyPair(alg: string): Promise<GeneratedKeyPair> {
  const spec = specFor(alg);
  if (spec.family === 'HMAC') throw new Error('HMAC uses a shared secret, not a key pair');

  let genParams: RsaHashedKeyGenParams | EcKeyGenParams | AlgorithmIdentifier;
  switch (spec.family) {
    case 'RSASSA-PKCS1-v1_5':
    case 'RSA-PSS':
      genParams = {
        name: spec.family,
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: spec.hash!,
      };
      break;
    case 'ECDSA':
      genParams = { name: 'ECDSA', namedCurve: spec.namedCurve! };
      break;
    case 'Ed25519':
      genParams = { name: 'Ed25519' };
      break;
    default:
      throw new Error(`cannot generate a key pair for ${alg}`);
  }

  const pair = (await subtle().generateKey(genParams as AlgorithmIdentifier, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;

  const spki = await subtle().exportKey('spki', pair.publicKey);
  const pkcs8 = await subtle().exportKey('pkcs8', pair.privateKey);
  const publicJwk = await subtle().exportKey('jwk', pair.publicKey);
  const privateJwk = await subtle().exportKey('jwk', pair.privateKey);

  return {
    alg: alg as JwsAlg,
    publicPem: pemWrap('PUBLIC KEY', spki),
    privatePem: pemWrap('PRIVATE KEY', pkcs8),
    publicJwk,
    privateJwk,
  };
}

/**
 * Crack helper: test one HMAC secret against a precomputed signing input.
 * Importing per attempt keeps the API simple; the worker batches the calls.
 */
export async function tryHmacSecret(
  alg: 'HS256' | 'HS384' | 'HS512',
  signingInput: string,
  signatureBytes: Uint8Array,
  secret: string,
): Promise<boolean> {
  const key = await importKey(alg, secret, 'verify');
  return verify(alg, key, signingInput, signatureBytes);
}
