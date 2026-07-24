// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Ben Richardson — https://benrichardson.dev
// Additional terms under AGPL-3.0 section 7(b) apply; see ADDITIONAL-TERMS.md.
/**
 * main.ts — bootstraps tokenpeek, owns app state and wires the workflow:
 * paste → decode → inspect → verify → crack → forge. All heavy crypto lives in
 * crypto.ts / worker.ts; this file is orchestration and DOM.
 */

import './styles/main.css';

import { decodeJwt, analyzeClaims, isHmacAlg, isKnownAlg, prettyJson, formatRelative } from './jwt';
import { verifyWithMaterial, signToken, generateKeyPair, isSymmetric } from './crypto';
import { defaultWordlist } from './wordlist';
import { mountEventDrawer, emit } from './eventlog';
import { initGlossary, term } from './glossary';
import {
  mount,
  clear,
  h,
  icon,
  toast,
  copy,
  initModalTriggers,
  highlightJson,
  escapeHtml,
  formatCount,
} from './ui';
import type { CrackProgress, CrackRequest, DecodedJwt } from './types';

const ASYMMETRIC_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'];
const ALL_SIGN_ALGS = ['HS256', 'HS384', 'HS512', ...ASYMMETRIC_ALGS, 'none'];

/**
 * Canonical jwt.io demo token — HS256 signed with the weak secret
 * "your-256-bit-secret" (which is in the built-in wordlist, so the crack demo
 * finds it). Lets a first-time visitor exercise decode + verify + crack.
 */
const SAMPLE_TOKEN =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
  '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ' +
  '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

// ---------- app state ----------

let decoded: DecodedJwt | null = null;
let decodeTimer: number | null = null;
let crackWorker: Worker | null = null;
let activeTab: 'verify' | 'crack' | 'sign' | 'keys' = 'verify';
let verifySecretHint: string | null = null; // secret discovered by the cracker

// ---------- bootstrap ----------

function boot(): void {
  const drawer = document.getElementById('event-drawer');
  if (drawer) mountEventDrawer(drawer);
  initModalTriggers();
  initGlossary();
  renderShell();
  wireGlobalKeys();
  emit('system', 'ok', 'tokenpeek ready — everything runs locally, nothing is uploaded');
}

function renderShell(): void {
  const app = mount();
  clear(app);

  const input = h('textarea', {
    id: 'token-input',
    class: 'token-input',
    spellcheck: 'false',
    autocomplete: 'off',
    autocapitalize: 'off',
    rows: '4',
    'aria-label': 'JSON Web Token',
    placeholder: 'Paste a JSON Web Token here — eyJhbGciOi…',
  }) as HTMLTextAreaElement;

  const actions = h(
    'div',
    { class: 'input-actions' },
    toolButton('paste', 'paste', async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          input.value = text.trim();
          onTokenChanged(true);
          emit('ui', 'info', 'pasted from clipboard', { chars: text.trim().length });
        }
      } catch {
        toast('clipboard blocked — paste manually with Cmd/Ctrl+V');
      }
    }),
    toolButton('bolt', 'sample', () => {
      input.value = SAMPLE_TOKEN;
      onTokenChanged(true);
      emit('ui', 'info', 'loaded sample token');
    }),
    toolButton('trash', 'clear', () => {
      input.value = '';
      onTokenChanged(true);
      input.focus();
    }),
  );

  const card = h(
    'section',
    { class: 'input-card', id: 'input-card' },
    h(
      'div',
      { class: 'input-head' },
      h('label', { for: 'token-input', class: 'input-label' }, 'json web token'),
      actions,
    ),
    input,
    h('div', { class: 'parse-status', id: 'parse-status' }),
  );

  const results = h('section', { class: 'results', id: 'results', hidden: 'true' });

  app.appendChild(card);
  app.appendChild(results);

  input.addEventListener('input', () => onTokenChanged(false));
  wireDropZone(card, input);
  renderEmptyState();
}

// ---------- token change / decode ----------

function onTokenChanged(immediate: boolean): void {
  if (decodeTimer) {
    clearTimeout(decodeTimer);
    decodeTimer = null;
  }
  const run = () => decodeCurrent();
  if (immediate) run();
  else decodeTimer = window.setTimeout(run, 250);
}

function decodeCurrent(): void {
  const input = document.getElementById('token-input') as HTMLTextAreaElement | null;
  const status = document.getElementById('parse-status');
  const results = document.getElementById('results');
  if (!input || !status || !results) return;

  const raw = input.value.trim();
  verifySecretHint = null;
  stopCrack();

  if (!raw) {
    decoded = null;
    results.setAttribute('hidden', 'true');
    status.className = 'parse-status';
    status.innerHTML = '';
    renderEmptyState();
    setStatusBar(null);
    return;
  }

  try {
    decoded = decodeJwt(raw);
    status.className = 'parse-status ok';
    const known = isKnownAlg(decoded.alg);
    status.innerHTML = `decoded · alg <strong>${escapeHtml(String(decoded.alg))}</strong>${
      known ? '' : ' <span class="warn-inline">(unrecognised algorithm)</span>'
    }`;
    results.removeAttribute('hidden');
    renderResults(decoded);
    setStatusBar(decoded);
    emit('decode', 'ok', 'token decoded', {
      alg: String(decoded.alg),
      claims: Object.keys(decoded.payload).length,
    });
  } catch (err) {
    decoded = null;
    results.setAttribute('hidden', 'true');
    status.className = 'parse-status err';
    status.textContent = `✗ ${err instanceof Error ? err.message : String(err)}`;
    setStatusBar(null, { failed: true });
    emit('decode', 'err', err instanceof Error ? err.message : String(err));
  }
}

function renderEmptyState(): void {
  const results = document.getElementById('results');
  if (!results) return;
  results.removeAttribute('hidden');
  results.innerHTML = `
    <div class="empty-state">
      <div class="empty-badge">${badgeSvg()}</div>
      <h2>Everything happens in this tab</h2>
      <p>
        Paste a ${term('JWT', 'jwt')} to decode its ${term('header', 'header')},
        ${term('payload', 'payload')} and ${term('claims', 'claim')}, then
        ${term('verify', 'signature')} the signature, ${term('crack', 'hmac')} weak
        HMAC secrets or ${term('forge', 'alg')} a new token — all with the
        browser's ${term('Web Crypto', 'jws')} engine. Your token never leaves the device.
      </p>
      <button type="button" class="ghost-btn" id="empty-sample">load a sample token</button>
    </div>`;
  const btn = results.querySelector('#empty-sample');
  btn?.addEventListener('click', () => {
    const input = document.getElementById('token-input') as HTMLTextAreaElement | null;
    if (input) {
      input.value = SAMPLE_TOKEN;
      onTokenChanged(true);
      emit('ui', 'info', 'loaded sample token');
    }
  });
}

// ---------- results ----------

function renderResults(d: DecodedJwt): void {
  const results = document.getElementById('results');
  if (!results) return;
  clear(results);

  results.appendChild(renderTokenStrip(d));
  results.appendChild(renderSegments(d));
  results.appendChild(renderClaims(d));
  results.appendChild(renderTools(d));
}

function renderTokenStrip(d: DecodedJwt): HTMLElement {
  const strip = h('div', { class: 'token-strip', 'aria-label': 'colour-coded token' });
  strip.appendChild(h('span', { class: 'seg seg-h' }, d.parts.header));
  strip.appendChild(h('span', { class: 'seg-dot' }, '.'));
  strip.appendChild(h('span', { class: 'seg seg-p' }, d.parts.payload));
  strip.appendChild(h('span', { class: 'seg-dot' }, '.'));
  strip.appendChild(h('span', { class: 'seg seg-s' }, d.parts.signature || '∅'));

  const legend = h(
    'div',
    { class: 'strip-legend' },
    h('span', { class: 'lg lg-h' }, 'header'),
    h('span', { class: 'lg lg-p' }, 'payload'),
    h('span', { class: 'lg lg-s' }, 'signature'),
    (() => {
      const b = h('button', { type: 'button', class: 'mini-btn', title: 'copy token' });
      b.appendChild(icon('clipboard'));
      b.appendChild(document.createTextNode('copy'));
      b.addEventListener('click', () => copy(d.raw, 'token copied'));
      return b;
    })(),
  );

  return h('div', { class: 'panel strip-panel' }, strip, legend);
}

function renderSegments(d: DecodedJwt): HTMLElement {
  const cols = h('div', { class: 'decoded-cols' });
  cols.appendChild(jsonPanel('header', d.header));
  cols.appendChild(jsonPanel('payload', d.payload));
  return cols;
}

function jsonPanel(title: string, obj: Record<string, unknown>): HTMLElement {
  const pre = h('pre', { class: 'json', html: highlightJson(obj) });
  const copyBtn = h('button', { type: 'button', class: 'mini-btn', title: `copy ${title} JSON` });
  copyBtn.appendChild(icon('clipboard'));
  copyBtn.addEventListener('click', () => copy(prettyJson(obj), `${title} copied`));
  return h(
    'div',
    { class: `panel json-panel json-${title}` },
    h('div', { class: 'panel-head' }, h('span', { class: 'panel-title' }, title), copyBtn),
    pre,
  );
}

function renderClaims(d: DecodedJwt): HTMLElement {
  const analysis = analyzeClaims(d.payload, Date.now());
  const rows = analysis.rows
    .map((r) => {
      const isStd = r.label !== r.key;
      const keyCell = isStd
        ? `<span class="glossary-link" data-term="${r.key}">${escapeHtml(r.key)}</span> <span class="claim-label">${escapeHtml(r.label)}</span>`
        : escapeHtml(r.key);
      const note = r.note ? `<span class="claim-note ${r.status}">${escapeHtml(r.note)}</span>` : '';
      return `<tr class="claim-row status-${r.status}">
        <td class="claim-key">${keyCell}</td>
        <td class="claim-val"><code>${escapeHtml(r.display)}</code>${note}</td>
      </tr>`;
    })
    .join('');

  const panel = h('div', { class: 'panel claims-panel' });
  panel.innerHTML = `
    <div class="panel-head"><span class="panel-title">claims</span>
      <span class="panel-sub">${analysis.rows.length} field${analysis.rows.length === 1 ? '' : 's'}</span>
    </div>
    <table class="claims-table"><tbody>${rows}</tbody></table>`;
  return panel;
}

// ---------- tools (tabbed) ----------

function renderTools(d: DecodedJwt): HTMLElement {
  const wrap = h('div', { class: 'panel tools-panel' });
  const tabs: Array<{ id: typeof activeTab; label: string }> = [
    { id: 'verify', label: 'verify' },
    { id: 'crack', label: 'crack' },
    { id: 'sign', label: 'forge' },
    { id: 'keys', label: 'keygen' },
  ];
  const bar = h('div', { class: 'tabbar', role: 'tablist' });
  const body = h('div', { class: 'tab-body', id: 'tab-body' });

  for (const t of tabs) {
    const btn = h(
      'button',
      { type: 'button', class: `tab${t.id === activeTab ? ' active' : ''}`, role: 'tab', 'data-tab': t.id },
      t.label,
    );
    btn.addEventListener('click', () => {
      activeTab = t.id;
      bar.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      renderTab(d, body);
    });
    bar.appendChild(btn);
  }

  wrap.appendChild(bar);
  wrap.appendChild(body);
  renderTab(d, body);
  return wrap;
}

function renderTab(d: DecodedJwt, body: HTMLElement): void {
  clear(body);
  if (activeTab === 'verify') body.appendChild(renderVerify(d));
  else if (activeTab === 'crack') body.appendChild(renderCrack(d));
  else if (activeTab === 'sign') body.appendChild(renderSign(d));
  else body.appendChild(renderKeys());
}

// ----- verify -----

function renderVerify(d: DecodedJwt): HTMLElement {
  const alg = String(d.alg);

  if (alg === 'none') {
    return infoCard(
      'warn',
      'unsecured token',
      `This token declares <code>"alg":"none"</code> — it carries no signature at all. Any party can rewrite its claims. Accepting <code>none</code> tokens is a well-known vulnerability.`,
    );
  }
  if (!isKnownAlg(d.alg)) {
    return infoCard('warn', 'unknown algorithm', `tokenpeek can't verify <code>${escapeHtml(alg)}</code>.`);
  }

  const symmetric = isSymmetric(alg);
  const ta = h('textarea', {
    class: 'key-input',
    id: 'verify-material',
    rows: symmetric ? '2' : '6',
    spellcheck: 'false',
    autocomplete: 'off',
    placeholder: symmetric
      ? 'HMAC secret (the shared signing key)'
      : '-----BEGIN PUBLIC KEY-----\n…SPKI PEM… or a public JWK { "kty": … }',
  }) as HTMLTextAreaElement;
  if (verifySecretHint && symmetric) ta.value = verifySecretHint;

  const result = h('div', { class: 'verify-result', id: 'verify-result' });
  const btn = primaryButton('verify signature', async () => {
    const material = ta.value.trim();
    if (!material) {
      toast(symmetric ? 'enter the HMAC secret' : 'paste the public key');
      return;
    }
    result.className = 'verify-result pending';
    result.textContent = 'verifying…';
    emit('verify', 'info', 'verifying signature', { alg });
    try {
      const ok = await verifyWithMaterial(alg, material, d.signingInput, d.signatureBytes);
      if (ok) {
        result.className = 'verify-result ok';
        result.innerHTML = `${okSvg()} <div><strong>signature valid</strong><span>the ${symmetric ? 'secret' : 'key'} matches — this token is authentic and untampered.</span></div>`;
        setStatusBar(d, { verify: 'valid' });
        emit('verify', 'ok', 'signature valid', { alg });
      } else {
        result.className = 'verify-result bad';
        result.innerHTML = `${failSvg()} <div><strong>signature invalid</strong><span>the ${symmetric ? 'secret' : 'key'} does not match this token's signature.</span></div>`;
        setStatusBar(d, { verify: 'invalid' });
        emit('verify', 'warn', 'signature invalid', { alg });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      result.className = 'verify-result bad';
      result.innerHTML = `${failSvg()} <div><strong>could not verify</strong><span>${escapeHtml(msg)}</span></div>`;
      setStatusBar(d, { verify: 'error' });
      emit('verify', 'err', msg, { alg });
    }
  });

  const help = symmetric
    ? `HS-family tokens verify with the same secret used to sign them.`
    : `Paste the <em>public</em> key (SPKI PEM or a public JWK). The private key never has to touch tokenpeek.`;

  return h(
    'div',
    { class: 'tool-pane' },
    fieldLabel(symmetric ? 'shared secret' : 'public key', help),
    ta,
    h('div', { class: 'tool-actions' }, btn),
    result,
  );
}

// ----- crack -----

function renderCrack(d: DecodedJwt): HTMLElement {
  if (!isHmacAlg(d.alg)) {
    return infoCard(
      'info',
      'cracking applies to HMAC tokens',
      `This token uses <code>${escapeHtml(String(d.alg))}</code>, which is signed with a private key rather than a shared secret — there's no secret to guess. The cracker targets <code>HS256</code>/<code>HS384</code>/<code>HS512</code>.`,
    );
  }
  const alg = d.alg as 'HS256' | 'HS384' | 'HS512';
  const builtin = defaultWordlist();

  const useBuiltin = h('input', { type: 'checkbox', id: 'crack-builtin', checked: 'true' }) as HTMLInputElement;
  const custom = h('textarea', {
    class: 'key-input',
    id: 'crack-custom',
    rows: '3',
    spellcheck: 'false',
    placeholder: 'optional — your own candidate secrets, one per line',
  }) as HTMLTextAreaElement;

  const bar = h('div', { class: 'progress-track', hidden: 'true', id: 'crack-track' },
    h('div', { class: 'progress-fill', id: 'crack-fill' }));
  const stats = h('div', { class: 'crack-stats', id: 'crack-stats' });
  const result = h('div', { class: 'verify-result', id: 'crack-result' });

  const startBtn = primaryButton('start crack', () => {
    const list: string[] = [];
    if (useBuiltin.checked) list.push(...builtin);
    const extra = custom.value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    list.push(...extra);
    const candidates = [...new Set(list)];
    if (candidates.length === 0) {
      toast('add a wordlist or your own candidates');
      return;
    }
    startCrack(d, alg, candidates);
  });
  startBtn.id = 'crack-start';

  const stopBtn = h('button', { type: 'button', class: 'secondary-btn', id: 'crack-stop', hidden: 'true' }, 'stop');
  stopBtn.addEventListener('click', () => {
    stopCrack();
    setCrackRunning(false);
    emit('crack', 'warn', 'crack stopped by user');
  });

  return h(
    'div',
    { class: 'tool-pane' },
    infoNote(
      `Audit your own APIs: this runs the token's signature against ${formatCount(builtin.length)} known-weak secrets in a Web Worker. A hit means the signing secret is guessable and must be rotated. "Not found" is <em>not</em> proof a secret is strong.`,
    ),
    h('label', { class: 'check-row' }, useBuiltin, h('span', {}, `include built-in wordlist (${formatCount(builtin.length)} secrets)`)),
    fieldLabel('custom candidates', 'optional — tried in addition to the built-in list'),
    custom,
    h('div', { class: 'tool-actions' }, startBtn, stopBtn),
    bar,
    stats,
    result,
  );
}

function startCrack(d: DecodedJwt, alg: 'HS256' | 'HS384' | 'HS512', candidates: string[]): void {
  stopCrack();
  setCrackRunning(true);
  const track = document.getElementById('crack-track');
  const fill = document.getElementById('crack-fill');
  const stats = document.getElementById('crack-stats');
  const result = document.getElementById('crack-result');
  if (track) track.removeAttribute('hidden');
  if (result) {
    result.className = 'verify-result';
    result.innerHTML = '';
  }
  emit('crack', 'info', 'crack started', { alg, candidates: candidates.length });

  try {
    crackWorker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' });
  } catch (err) {
    emit('crack', 'err', 'could not start worker: ' + (err instanceof Error ? err.message : String(err)));
    setCrackRunning(false);
    return;
  }

  crackWorker.onmessage = (e: MessageEvent<CrackProgress>) => {
    const m = e.data;
    if (m.type === 'progress') {
      const pct = m.total ? Math.round((m.tried / m.total) * 100) : 0;
      if (fill) fill.style.width = `${pct}%`;
      const rate = m.elapsedMs > 0 ? Math.round((m.tried / m.elapsedMs) * 1000) : 0;
      if (stats) stats.textContent = `${formatCount(m.tried)} / ${formatCount(m.total)} tried · ${formatCount(rate)}/s`;
    } else if (m.type === 'found') {
      if (fill) fill.style.width = '100%';
      if (stats) stats.textContent = `cracked after ${formatCount(m.tried)} tries in ${(m.elapsedMs / 1000).toFixed(2)}s`;
      if (result) {
        result.className = 'verify-result bad';
        result.innerHTML = `${failSvg()} <div><strong>weak secret found</strong><span>this token is signed with <code class="found-secret">${escapeHtml(m.secret)}</code> — rotate it immediately.</span></div>`;
        const use = h('button', { type: 'button', class: 'secondary-btn', style: 'margin-top:10px' }, 'use in verify →');
        use.addEventListener('click', () => {
          verifySecretHint = m.secret;
          activeTab = 'verify';
          if (decoded) renderResults(decoded);
        });
        result.appendChild(use);
      }
      verifySecretHint = m.secret;
      emit('crack', 'warn', 'weak secret found', { secret: m.secret, tried: m.tried });
      setCrackRunning(false);
      stopCrack();
    } else if (m.type === 'exhausted') {
      if (fill) fill.style.width = '100%';
      if (stats) stats.textContent = `${formatCount(m.tried)} tried in ${(m.elapsedMs / 1000).toFixed(2)}s`;
      if (result) {
        result.className = 'verify-result ok';
        result.innerHTML = `${okSvg()} <div><strong>no weak secret found</strong><span>none of the ${formatCount(m.tried)} candidates matched. This does not prove the secret is strong.</span></div>`;
      }
      emit('crack', 'ok', 'no weak secret found', { tried: m.tried });
      setCrackRunning(false);
      stopCrack();
    } else if (m.type === 'error') {
      if (result) {
        result.className = 'verify-result bad';
        result.innerHTML = `${failSvg()} <div><strong>crack failed</strong><span>${escapeHtml(m.message)}</span></div>`;
      }
      emit('crack', 'err', m.message);
      setCrackRunning(false);
      stopCrack();
    }
  };
  crackWorker.onerror = (e) => {
    emit('crack', 'err', 'worker error: ' + e.message);
    setCrackRunning(false);
    stopCrack();
  };

  const req: CrackRequest = {
    signingInput: d.signingInput,
    signatureBytes: d.signatureBytes,
    alg,
    candidates,
  };
  crackWorker.postMessage(req);
}

function setCrackRunning(running: boolean): void {
  const start = document.getElementById('crack-start');
  const stop = document.getElementById('crack-stop');
  if (start) start.toggleAttribute('hidden', running);
  if (stop) stop.toggleAttribute('hidden', !running);
}

function stopCrack(): void {
  if (crackWorker) {
    crackWorker.terminate();
    crackWorker = null;
  }
}

// ----- sign / forge -----

function renderSign(d: DecodedJwt): HTMLElement {
  const headerTa = h('textarea', { class: 'key-input mono', id: 'sign-header', rows: '4', spellcheck: 'false' }, prettyJson(d.header)) as HTMLTextAreaElement;
  const payloadTa = h('textarea', { class: 'key-input mono', id: 'sign-payload', rows: '7', spellcheck: 'false' }, prettyJson(d.payload)) as HTMLTextAreaElement;

  const algSel = h('select', { class: 'select', id: 'sign-alg' }) as HTMLSelectElement;
  for (const a of ALL_SIGN_ALGS) {
    const opt = h('option', { value: a }, a) as HTMLOptionElement;
    if (a === d.alg) opt.selected = true;
    algSel.appendChild(opt);
  }

  const keyTa = h('textarea', {
    class: 'key-input',
    id: 'sign-key',
    rows: '3',
    spellcheck: 'false',
    placeholder: 'HMAC secret, or a PRIVATE key (PKCS#8 PEM / private JWK)',
  }) as HTMLTextAreaElement;

  const keyRow = h('div', { class: 'sign-key-row' }, fieldLabel('signing key', ''), keyTa);
  const syncKeyHint = () => {
    const a = algSel.value;
    if (a === 'none') {
      keyRow.setAttribute('hidden', 'true');
    } else {
      keyRow.removeAttribute('hidden');
      keyTa.placeholder = isSymmetric(a)
        ? 'HMAC secret (any string)'
        : 'PRIVATE key — PKCS#8 PEM (-----BEGIN PRIVATE KEY-----) or a private JWK';
    }
  };
  algSel.addEventListener('change', syncKeyHint);
  syncKeyHint();

  const out = h('div', { class: 'sign-output', id: 'sign-output' });

  const signBtn = primaryButton('sign token', async () => {
    let header: Record<string, unknown>;
    let payload: Record<string, unknown>;
    try {
      header = JSON.parse(headerTa.value || '{}');
      payload = JSON.parse(payloadTa.value || '{}');
    } catch (err) {
      out.className = 'sign-output bad';
      out.textContent = `header/payload is not valid JSON: ${err instanceof Error ? err.message : String(err)}`;
      return;
    }
    const alg = algSel.value;
    const material = keyTa.value.trim();
    if (alg !== 'none' && !material) {
      toast('enter a signing key');
      return;
    }
    emit('sign', 'info', 'signing token', { alg });
    try {
      const token = await signToken(alg, material, header, payload);
      out.className = 'sign-output ok';
      out.innerHTML = '';
      const pre = h('pre', { class: 'token-out' }, token);
      const copyBtn = h('button', { type: 'button', class: 'secondary-btn' }, 'copy token');
      copyBtn.addEventListener('click', () => copy(token, 'token copied'));
      const loadBtn = h('button', { type: 'button', class: 'secondary-btn' }, 'load into decoder ↑');
      loadBtn.addEventListener('click', () => {
        const input = document.getElementById('token-input') as HTMLTextAreaElement | null;
        if (input) {
          input.value = token;
          onTokenChanged(true);
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }
      });
      out.appendChild(pre);
      out.appendChild(h('div', { class: 'tool-actions' }, copyBtn, loadBtn));
      emit('sign', 'ok', 'token signed', { alg, bytes: token.length });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      out.className = 'sign-output bad';
      out.textContent = `could not sign: ${msg}`;
      emit('sign', 'err', msg, { alg });
    }
  });

  return h(
    'div',
    { class: 'tool-pane' },
    infoNote(
      `Edit the header or payload and re-sign to mint a test token. Handy for reproducing bugs or building fixtures — <strong>never</strong> paste a production private key you don't control into any web tool, including this one.`,
    ),
    h('div', { class: 'sign-grid' },
      h('div', {}, fieldLabel('header', ''), headerTa),
      h('div', {}, fieldLabel('payload', ''), payloadTa),
    ),
    h('div', { class: 'sign-controls' }, fieldLabel('algorithm', ''), algSel),
    keyRow,
    h('div', { class: 'tool-actions' }, signBtn),
    out,
  );
}

// ----- keygen -----

function renderKeys(): HTMLElement {
  const algSel = h('select', { class: 'select', id: 'gen-alg' }) as HTMLSelectElement;
  for (const a of ASYMMETRIC_ALGS) algSel.appendChild(h('option', { value: a }, a));

  const out = h('div', { class: 'keys-output', id: 'keys-output' });

  const genBtn = primaryButton('generate keypair', async () => {
    const alg = algSel.value;
    out.innerHTML = '<div class="verify-result pending">generating…</div>';
    emit('sign', 'info', 'generating keypair', { alg });
    try {
      const kp = await generateKeyPair(alg);
      out.innerHTML = '';
      out.appendChild(keyBlock('public key (PEM / SPKI)', kp.publicPem, `${alg}-public.pem`));
      out.appendChild(keyBlock('private key (PEM / PKCS#8)', kp.privatePem, `${alg}-private.pem`, true));
      out.appendChild(keyBlock('public JWK', prettyJson(kp.publicJwk), `${alg}-public.jwk.json`));
      out.appendChild(keyBlock('private JWK', prettyJson(kp.privateJwk), `${alg}-private.jwk.json`, true));
      emit('sign', 'ok', 'keypair generated', { alg });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      out.innerHTML = `<div class="verify-result bad">${failSvg()} <div><strong>generation failed</strong><span>${escapeHtml(msg)}</span></div></div>`;
      emit('sign', 'err', msg, { alg });
    }
  });

  return h(
    'div',
    { class: 'tool-pane' },
    infoNote(
      `Generate a fresh asymmetric keypair with Web Crypto to sign test tokens. Keys are created in this tab and never uploaded — but treat any private key you download as sensitive.`,
    ),
    h('div', { class: 'sign-controls' }, fieldLabel('algorithm', ''), algSel),
    h('div', { class: 'tool-actions' }, genBtn),
    out,
  );
}

function keyBlock(title: string, value: string, filename: string, secret = false): HTMLElement {
  const pre = h('pre', { class: 'token-out mono' }, value);
  const copyBtn = h('button', { type: 'button', class: 'mini-btn' });
  copyBtn.appendChild(icon('clipboard'));
  copyBtn.appendChild(document.createTextNode('copy'));
  copyBtn.addEventListener('click', () => copy(value, `${title} copied`));
  const dlBtn = h('button', { type: 'button', class: 'mini-btn' });
  dlBtn.appendChild(icon('download'));
  dlBtn.appendChild(document.createTextNode('download'));
  dlBtn.addEventListener('click', () => downloadText(filename, value));
  return h(
    'div',
    { class: `panel key-block${secret ? ' secret' : ''}` },
    h('div', { class: 'panel-head' },
      h('span', { class: 'panel-title' }, title),
      secret ? h('span', { class: 'secret-flag' }, 'keep private') : document.createTextNode(''),
      h('span', { class: 'spacer' }),
      copyBtn,
      dlBtn,
    ),
    pre,
  );
}

// ---------- status bar ----------

function setStatusBar(
  d: DecodedJwt | null,
  opts: { verify?: 'valid' | 'invalid' | 'error'; failed?: boolean } = {},
): void {
  const dot = document.getElementById('sb-status-dot');
  const label = document.getElementById('sb-status-label');
  const algEl = document.getElementById('sb-alg');
  const expEl = document.getElementById('sb-exp');
  const verifyEl = document.getElementById('sb-verify');
  if (!dot || !label || !algEl || !expEl || !verifyEl) return;

  if (!d) {
    dot.className = `dot-mini ${opts.failed ? 'bad' : 'idle'}`;
    label.textContent = opts.failed ? 'invalid token' : 'no token';
    algEl.textContent = '';
    expEl.textContent = '';
    verifyEl.textContent = '';
    return;
  }

  dot.className = 'dot-mini ok';
  label.textContent = 'decoded';
  algEl.textContent = `alg ${d.alg}`;

  const analysis = analyzeClaims(d.payload, Date.now());
  const e = analysis.expiry;
  if (e.kind === 'expired') {
    expEl.innerHTML = `<span class="sb-bad">expired ${escapeHtml(formatRelative(-e.agoMs))}</span>`;
  } else if (e.kind === 'valid') {
    expEl.innerHTML = `<span class="sb-ok">expires ${escapeHtml(formatRelative(e.expiresInMs))}</span>`;
  } else if (e.kind === 'not-yet-valid') {
    expEl.innerHTML = `<span class="sb-warn">not valid ${escapeHtml(formatRelative(e.inMs))}</span>`;
  } else {
    expEl.innerHTML = `<span class="sb-muted">no expiry</span>`;
  }

  if (opts.verify === 'valid') verifyEl.innerHTML = '<span class="sb-ok">✓ signature verified</span>';
  else if (opts.verify === 'invalid') verifyEl.innerHTML = '<span class="sb-bad">✗ signature invalid</span>';
  else if (opts.verify === 'error') verifyEl.innerHTML = '<span class="sb-warn">verify error</span>';
  else verifyEl.textContent = '';
}

// ---------- small builders ----------

function toolButton(ic: Parameters<typeof icon>[0], label: string, onClick: () => void): HTMLElement {
  const b = h('button', { type: 'button', class: 'tool-btn' });
  b.appendChild(icon(ic));
  b.appendChild(document.createTextNode(label));
  b.addEventListener('click', onClick);
  return b;
}

function primaryButton(label: string, onClick: () => void | Promise<void>): HTMLElement {
  const b = h('button', { type: 'button', class: 'primary-btn' }, label);
  b.addEventListener('click', () => {
    void onClick();
  });
  return b;
}

function fieldLabel(label: string, help: string): HTMLElement {
  const el = h('div', { class: 'field-label' }, h('span', {}, label));
  if (help) el.appendChild(h('span', { class: 'field-help', html: help }));
  return el;
}

function infoNote(html: string): HTMLElement {
  return h('p', { class: 'info-note', html });
}

function infoCard(kind: 'info' | 'warn', title: string, html: string): HTMLElement {
  return h(
    'div',
    { class: `tool-pane` },
    h('div', { class: `info-card ${kind}` }, h('strong', {}, title), h('span', { html })),
  );
}

// ---------- misc ----------

function downloadText(filename: string, text: string): void {
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  emit('ui', 'ok', 'downloaded ' + filename);
}

function wireDropZone(card: HTMLElement, input: HTMLTextAreaElement): void {
  const over = (e: DragEvent) => {
    e.preventDefault();
    card.classList.add('drag');
  };
  const leave = () => card.classList.remove('drag');
  card.addEventListener('dragover', over);
  card.addEventListener('dragleave', leave);
  card.addEventListener('drop', async (e) => {
    e.preventDefault();
    card.classList.remove('drag');
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    if (file.size > 512 * 1024) {
      toast('file too large for a token');
      return;
    }
    try {
      const text = await file.text();
      input.value = text.trim();
      onTokenChanged(true);
      emit('ui', 'info', 'loaded token from file', { name: file.name });
    } catch {
      toast('could not read file');
    }
  });
}

function wireGlobalKeys(): void {
  document.addEventListener('keydown', async (e) => {
    const target = e.target as HTMLElement;
    const inField = /^(INPUT|TEXTAREA|SELECT)$/.test(target?.tagName ?? '');
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'v' && !inField) {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          const input = document.getElementById('token-input') as HTMLTextAreaElement | null;
          if (input) {
            input.value = text.trim();
            onTokenChanged(true);
          }
        }
      } catch {
        /* clipboard blocked — ignore */
      }
    }
  });
  window.addEventListener('beforeunload', () => stopCrack());
}

// ---------- inline svg snippets ----------

function okSvg(): string {
  return `<svg class="rc-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="8 12 11 15 16 9"/></svg>`;
}
function failSvg(): string {
  return `<svg class="rc-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
}
function badgeSvg(): string {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`;
}
boot();
