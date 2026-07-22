// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Ben Richardson — https://benrichardson.dev
// Additional terms under AGPL-3.0 section 7(b) apply; see ADDITIONAL-TERMS.md.
/**
 * eventlog.ts — categorized live event trail rendered in the right drawer.
 *
 * A tiny singleton the rest of the app emits into. Builds trust by showing the
 * user exactly what tokenpeek is doing, locally, step by step.
 */

export type EventCategory = 'system' | 'decode' | 'verify' | 'crack' | 'sign' | 'ui';
export type EventLevel = 'info' | 'ok' | 'warn' | 'err';

export interface LogEvent {
  ts: number;
  cat: EventCategory;
  level: EventLevel;
  msg: string;
  meta?: Record<string, string | number>;
}

const ALL_CATS: EventCategory[] = ['system', 'ui', 'decode', 'verify', 'crack', 'sign'];
const MAX_EVENTS = 800;

let events: LogEvent[] = [];
let listeners: Array<(e: LogEvent) => void> = [];
const activeCats: Set<EventCategory> = new Set(ALL_CATS);
let listEl: HTMLElement | null = null;
let countEl: HTMLElement | null = null;
let autoScroll = true;

export function emit(
  cat: EventCategory,
  level: EventLevel,
  msg: string,
  meta?: Record<string, string | number>,
): void {
  const e: LogEvent = { ts: Date.now(), cat, level, msg, meta };
  events.push(e);
  if (events.length > MAX_EVENTS) {
    events.shift();
    if (listEl) {
      const first = listEl.querySelector('.event');
      if (first) first.remove();
    }
  }
  for (const l of listeners) l(e);
}

export function clearLog(): void {
  events = [];
  if (listEl) listEl.innerHTML = '';
  if (countEl) countEl.textContent = '0';
}

export function mountEventDrawer(container: HTMLElement): () => void {
  container.innerHTML = '';

  const head = document.createElement('div');
  head.className = 'drawer-head';
  head.innerHTML = `
    <div class="drawer-title">live event trail</div>
    <div class="drawer-controls">
      <span class="count"><strong id="ev-count">0</strong>&nbsp;events</span>
    </div>
  `;
  container.appendChild(head);

  const filters = document.createElement('div');
  filters.className = 'drawer-filters';
  for (const c of ALL_CATS) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'filter-pill on';
    btn.dataset.cat = c;
    btn.textContent = c;
    btn.addEventListener('click', () => {
      if (activeCats.has(c)) {
        activeCats.delete(c);
        btn.classList.remove('on');
      } else {
        activeCats.add(c);
        btn.classList.add('on');
      }
      reflow();
    });
    filters.appendChild(btn);
  }
  const clearBtn = document.createElement('button');
  clearBtn.type = 'button';
  clearBtn.className = 'filter-pill';
  clearBtn.style.marginLeft = 'auto';
  clearBtn.textContent = 'clear';
  clearBtn.addEventListener('click', () => clearLog());
  filters.appendChild(clearBtn);
  container.appendChild(filters);

  const list = document.createElement('div');
  list.className = 'drawer-list';
  container.appendChild(list);

  listEl = list;
  countEl = container.querySelector('#ev-count') as HTMLElement;

  list.addEventListener('scroll', () => {
    const nearBottom = list.scrollTop + list.clientHeight >= list.scrollHeight - 32;
    autoScroll = nearBottom;
  });

  reflow();

  const onEvent = (e: LogEvent) => {
    if (!activeCats.has(e.cat)) {
      bumpCount();
      return;
    }
    appendEvent(e);
    bumpCount();
  };
  listeners.push(onEvent);

  return () => {
    listeners = listeners.filter((l) => l !== onEvent);
    listEl = null;
    countEl = null;
  };
}

function bumpCount(): void {
  if (countEl) countEl.textContent = String(events.length);
}

function reflow(): void {
  if (!listEl) return;
  listEl.innerHTML = '';
  for (const e of events) {
    if (!activeCats.has(e.cat)) continue;
    appendEvent(e, false);
  }
  listEl.scrollTop = listEl.scrollHeight;
  bumpCount();
}

function appendEvent(e: LogEvent, scroll = true): void {
  if (!listEl) return;
  const row = document.createElement('div');
  row.className = 'event';
  row.dataset.cat = e.cat;
  row.dataset.level = e.level;

  const ts = document.createElement('span');
  ts.className = 'ts';
  ts.textContent = formatTs(e.ts);
  const cat = document.createElement('span');
  cat.className = 'cat';
  cat.textContent = e.cat;
  const msg = document.createElement('span');
  msg.className = 'msg';
  msg.textContent = e.msg;
  row.appendChild(ts);
  row.appendChild(cat);
  row.appendChild(msg);

  if (e.meta) {
    const meta = document.createElement('span');
    meta.className = 'meta';
    const parts: string[] = [];
    for (const [k, v] of Object.entries(e.meta)) {
      parts.push(`<span class="k">${escapeHtml(k)}</span>=<span class="v">${escapeHtml(String(v))}</span>`);
    }
    meta.innerHTML = parts.join(' · ');
    row.appendChild(meta);
  }

  listEl.appendChild(row);
  if (scroll && autoScroll) listEl.scrollTop = listEl.scrollHeight;
}

function formatTs(ts: number): string {
  const d = new Date(ts);
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  const s = String(d.getSeconds()).padStart(2, '0');
  const ms = String(d.getMilliseconds()).padStart(3, '0');
  return `${h}:${m}:${s}.${ms}`;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
