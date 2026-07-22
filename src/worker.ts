// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Ben Richardson — https://benrichardson.dev
// Additional terms under AGPL-3.0 section 7(b) apply; see ADDITIONAL-TERMS.md.
/**
 * worker.ts — HMAC weak-secret crack, run off the main thread.
 *
 * Receives a CrackRequest, tries each candidate secret against the token's
 * signature with Web Crypto, and streams progress / result back. The main
 * thread keeps painting a determinate progress bar with throughput.
 */

import { tryHmacSecret } from './crypto';
import type { CrackProgress, CrackRequest } from './types';

const post = (m: CrackProgress) => (self as unknown as Worker).postMessage(m);

self.onmessage = async (e: MessageEvent<CrackRequest>) => {
  const { signingInput, signatureBytes, alg, candidates } = e.data;
  const start = performance.now();
  let tried = 0;
  const total = candidates.length;

  try {
    for (const secret of candidates) {
      const ok = await tryHmacSecret(alg, signingInput, signatureBytes, secret);
      tried++;
      if (ok) {
        post({ type: 'found', secret, tried, elapsedMs: performance.now() - start });
        return;
      }
      // Report periodically so the UI stays lively without flooding postMessage.
      if (tried % 20 === 0 || tried === total) {
        post({ type: 'progress', tried, total, elapsedMs: performance.now() - start });
      }
    }
    post({ type: 'exhausted', tried, elapsedMs: performance.now() - start });
  } catch (err) {
    post({ type: 'error', message: err instanceof Error ? err.message : String(err) });
  }
};
