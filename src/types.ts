/** Shared types for tokenpeek. */

export type JwsAlg =
  | 'HS256' | 'HS384' | 'HS512'
  | 'RS256' | 'RS384' | 'RS512'
  | 'PS256' | 'PS384' | 'PS512'
  | 'ES256' | 'ES384' | 'ES512'
  | 'EdDSA'
  | 'none';

/** A fully parsed JWT (JWS compact serialization). */
export interface DecodedJwt {
  /** The original compact token string. */
  raw: string;
  /** The three (or two, for unsecured) base64url segments, as-typed. */
  parts: { header: string; payload: string; signature: string };
  /** Parsed protected header. */
  header: Record<string, unknown>;
  /** Parsed payload (claims). For non-JSON payloads this throws at decode. */
  payload: Record<string, unknown>;
  /** Raw signature bytes (empty for alg "none"). */
  signatureBytes: Uint8Array;
  /** The exact ASCII string that is signed: `${headerB64}.${payloadB64}`. */
  signingInput: string;
  /** The algorithm declared in the header, if any. */
  alg: JwsAlg | string | null;
}

export type ClaimStatus = 'ok' | 'warn' | 'bad' | 'neutral';

export interface ClaimRow {
  key: string;
  /** Human label for a recognised standard claim, else the raw key. */
  label: string;
  /** Display value (timestamps rendered as readable dates). */
  display: string;
  /** Raw value as stored. */
  raw: unknown;
  status: ClaimStatus;
  /** Short note, e.g. "expires in 4m" or "not a registered claim". */
  note?: string;
}

export interface ClaimAnalysis {
  rows: ClaimRow[];
  /** Overall expiry summary for the status bar. */
  expiry:
    | { kind: 'none' }
    | { kind: 'valid'; expiresInMs: number; at: number }
    | { kind: 'expired'; agoMs: number; at: number }
    | { kind: 'not-yet-valid'; inMs: number; at: number };
}

/** Worker → main messages for the HMAC crack. */
export type CrackProgress =
  | { type: 'progress'; tried: number; total: number; elapsedMs: number }
  | { type: 'found'; secret: string; tried: number; elapsedMs: number }
  | { type: 'exhausted'; tried: number; elapsedMs: number }
  | { type: 'error'; message: string };

/** Main → worker message to start a crack. */
export interface CrackRequest {
  signingInput: string;
  signatureBytes: Uint8Array;
  alg: 'HS256' | 'HS384' | 'HS512';
  candidates: string[];
}
