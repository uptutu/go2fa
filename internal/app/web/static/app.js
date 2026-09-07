// 2fa Web UI — vanilla JS, no framework. Talks to /api/* on the same origin.

/** @typedef {{id:string,issuer:string,account:string,algorithm:string,digits:number,period:number,code:string,remaining:number,group_id:number,group_name:string,notes?:string,has_backup:boolean}} Secret */
/** @typedef {{id:number,name:string,color:string,sort_order?:number,created_at?:string}} Group */

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));

/** In-memory caches */
const state = {
  secrets: /** @type {Secret[]} */ ([]),
  groups: /** @type {Group[]} */ ([]),
  filter: /** @type {{q:string,group:number|'unassigned'|null}} */ ({ q: '', group: null }),
  status: /** @type {any} */ (null),
};

/* -------- API -------- */

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { msg = (await res.text()) || msg; } catch (_) { /* ignore */ }
    throw new Error(msg);
  }
  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res.text();
}

/* -------- Utilities -------- */

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

function fmtAlgo(a) {
  return ({ SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' })[a] || a || '';
}

function visibleSecrets() {
  const q = state.filter.q.trim().toLowerCase();
  return state.secrets.filter((s) => {
    if (state.filter.group === 'unassigned') {
      if (s.group_id !== 0) return false;
    } else if (typeof state.filter.group === 'number' && state.filter.group > 0) {
      if (s.group_id !== state.filter.group) return false;
    }
    if (q) {
      const hay = `${s.issuer} ${s.account || ''} ${s.group_name || ''}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

/* -------- Toasts -------- */

const toastsEl = $('#toasts');
function toast(msg, kind = 'info', ms = 2400) {
  const el = document.createElement('div');
  el.className = `toast ${kind === 'good' ? 'good' : kind === 'bad' ? 'bad' : ''}`;
  el.innerHTML = `<span class="dot"></span><span>${escapeHtml(msg)}</span>`;
  toastsEl.appendChild(el);
  setTimeout(() => {
    el.style.transition = 'opacity .2s';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 220);
  }, ms);
}

/* -------- Status -------- */

function renderStatus() {
  const st = $('#status');
  const s = state.status;
  st.classList.remove('unlocked', 'locked', 'error');
  if (!s) {
    $('.label', st).textContent = 'loading…';
    $('.addr', st).textContent = '';
    return;
  }
  if (s.error) {
    st.classList.add('error');
    $('.label', st).textContent = 'error';
    $('.addr', st).textContent = s.error;
    return;
  }
  st.classList.add(s.unlocked ? 'unlocked' : 'locked');
  $('.label', st).textContent = `${s.unlocked ? 'Unlocked' : 'Locked'} · ${s.mode}`;
  $('.addr', st).textContent = s.addr ? ` · ${s.addr}` : '';
}

async function loadStatus() {
  try {
    state.status = await api('/api/status');
  } catch (e) {
    state.status = { error: /** @type any */ (e).message || String(e) };
  }
  renderStatus();
}

/* -------- Groups sidebar -------- */

function renderGroups() {
  const ul = $('#groups');
  ul.innerHTML = '';
  const total = state.secrets.length;
  const counts = new Map();
  let unassignedCount = 0;
  for (const s of state.secrets) {
    if (s.group_id === 0) unassignedCount += 1;
    else counts.set(s.group_id, (counts.get(s.group_id) || 0) + 1);
  }

  const items = [{ id: 0, name: 'All secrets', color: 'transparent', count: total }];
  if (unassignedCount > 0) items.push({ id: -1, name: 'Unassigned', color: 'transparent', count: unassignedCount });
  for (const g of state.groups) items.push({ ...g, count: counts.get(g.id) || 0 });

  for (const g of items) {
    const li = document.createElement('li');
    const btn = document.createElement('button');
    btn.type = 'button';
    const pressed = (g.id === 0 && state.filter.group === null)
      || (g.id === -1 && state.filter.group === 'unassigned')
      || (typeof state.filter.group === 'number' && state.filter.group === g.id);
    btn.setAttribute('aria-pressed', pressed ? 'true' : 'false');
    const swatch = g.id > 0 && g.color && g.color !== 'transparent'
      ? `<span class="swatch" style="background:${escapeHtml(g.color)}"></span>`
      : `<span class="swatch"></span>`;
    btn.innerHTML = `${swatch}<span>${escapeHtml(g.name)}</span><span class="count">${g.count}</span>`;
    btn.onclick = () => {
      state.filter.group = g.id === 0 ? null : g.id === -1 ? 'unassigned' : g.id;
      renderGroups();
      renderSecrets();
    };
    li.appendChild(btn);
    ul.appendChild(li);
  }
}

async function loadGroups() {
  try { state.groups = await api('/api/groups') || []; }
  catch (_) { state.groups = []; }
  renderGroups();
  renderGroupSelects();
}

/* -------- Group dropdowns in dialogs -------- */

function renderGroupSelects() {
  for (const sel of $$('#e-group')) {
    const cur = sel.value;
    sel.innerHTML = '<option value="0">Unassigned</option>';
    for (const g of state.groups) {
      const o = document.createElement('option');
      o.value = String(g.id);
      o.textContent = g.name;
      sel.appendChild(o);
    }
    sel.value = cur || '0';
  }
}

async function createGroup() {
  const name = prompt('Group name?');
  if (!name) return;
  try {
    await api('/api/groups', { method: 'POST', body: JSON.stringify({ name, color: '' }) });
    toast(`Group “${name}” created`, 'good');
    await refreshAll();
  } catch (e) { toast(`Create failed: ${e.message}`, 'bad'); }
}

/* -------- Secrets list -------- */

const secretsUl = $('#secrets');
const emptyEl = $('#empty');
const countEl = $('#count');

function renderSecrets() {
  const list = visibleSecrets();
  countEl.textContent = `${list.length} ${list.length === 1 ? 'secret' : 'secrets'}`;
  emptyEl.hidden = list.length > 0;
  secretsUl.hidden = list.length === 0;
  secretsUl.innerHTML = '';
  const RING_LEN = 2 * Math.PI * 16;
  for (const s of list) {
    const li = document.createElement('li');
    li.className = 'secret';
    if (s.remaining <= 0) li.classList.add('expired');
    else if (s.remaining <= 5) li.classList.add('expiring');

    const groupTag = s.group_id > 0 && s.group_name
      ? `<span class="tag">${escapeHtml(s.group_name)}</span>` : '';
    const digits = String(s.digits || 6);
    const codeFmt = digits === s.code.length ? s.code : (s.code + ' '.repeat(digits)).slice(0, digits);

    li.innerHTML = `
      <div class="ring" aria-hidden="true">
        <svg viewBox="0 0 40 40">
          <circle class="track" cx="20" cy="20" r="16"/>
          <circle class="progress" cx="20" cy="20" r="16"
                  stroke-dasharray="${RING_LEN.toFixed(2)}"
                  stroke-dashoffset="${(RING_LEN * (1 - s.remaining / s.period)).toFixed(2)}"/>
        </svg>
        <span class="num">${s.remaining}</span>
      </div>
      <div class="who">
        <div class="issuer">${escapeHtml(s.issuer || '(no issuer)')}${groupTag}</div>
        <div class="account">${escapeHtml(s.account || '')}${s.notes ? ' · ' + escapeHtml(s.notes) : ''}</div>
      </div>
      <div class="code-wrap">
        <button class="code" type="button" title="Click to copy" aria-label="Copy code ${digits} digits for ${escapeHtml(s.issuer)}">${escapeHtml(codeFmt)}</button>
        <span class="code-hint">${digits} digits · ${fmtAlgo(s.algorithm)} · ${s.period}s</span>
      </div>
      <div class="row-actions">
        <button class="icon-btn edit" type="button" aria-label="Edit ${escapeHtml(s.issuer)}" title="Edit">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 1 1 3 3L7 19l-4 1 1-4Z"/></svg>
        </button>
      </div>`;

    const codeBtn = $('.code', li);
    codeBtn.onclick = () => copyCode(s, codeBtn);
    $('.edit', li).onclick = () => openEdit(s);
    secretsUl.appendChild(li);
  }
}

async function copyCode(s, btn) {
  try {
    await navigator.clipboard.writeText(s.code);
    btn.classList.add('copied');
    btn.textContent = 'Copied!';
    // server-side touch (last_used) — fire and forget
    try { await api(`/api/code?id=${encodeURIComponent(s.id)}`); } catch (_) { /* ignore */ }
    toast('Code copied to clipboard', 'good');
    setTimeout(() => {
      btn.classList.remove('copied');
      const digits = String(s.digits || 6);
      const codeFmt = digits === s.code.length ? s.code : (s.code + ' '.repeat(digits)).slice(0, digits);
      btn.textContent = codeFmt;
    }, 900);
  } catch (e) {
    toast(`Copy failed: ${e.message}`, 'bad');
  }
}

/* -------- Add dialog -------- */

const addScrim = $('#dialog');
const editScrim = $('#edit-dialog');

function openAdd(prefillUri = '') {
  $('#dialog-err').textContent = '';
  if (prefillUri) {
    // QR-detected path: URI form
    $('#panel-uri').hidden = false;
    $('#panel-manual').hidden = true;
    $('#uri').value = prefillUri;
  } else {
    // Default: Manual form (Name + Secret)
    $('#panel-uri').hidden = true;
    $('#panel-manual').hidden = false;
    $('#issuer').value = '';
    $('#secret').value = '';
  }
  showScrim(addScrim);
  setTimeout(() => (prefillUri ? $('#uri') : $('#issuer')).focus(), 50);
}

async function saveAdd() {
  const err = $('#dialog-err');
  err.textContent = '';
  let body;
  if (!$('#panel-uri').hidden) {
    const uri = $('#uri').value.trim();
    if (!uri) { err.textContent = 'URI is required'; return; }
    body = { uri, group_id: 0 };
  } else {
    const issuer = $('#issuer').value.trim();
    const secret = $('#secret').value.trim();
    if (!issuer) { err.textContent = 'Name is required'; return; }
    if (!secret) { err.textContent = 'Secret is required'; return; }
    body = {
      issuer,
      account: '',
      secret,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      group_id: 0,
    };
  }
  const btn = $('#save-btn');
  btn.disabled = true;
  try {
    await api('/api/secrets', { method: 'POST', body: JSON.stringify(body) });
    toast('Secret added', 'good');
    hideScrim(addScrim);
    stopScan();
    await refreshAll();
  } catch (e) {
    err.textContent = e.message || String(e);
  } finally {
    btn.disabled = false;
  }
}

/* -------- Edit / delete dialog -------- */

/** @type {Secret|null} */ let editingId = null;

function openEdit(s) {
  editingId = s;
  $('#edit-err').textContent = '';
  $('#e-issuer').value = s.issuer || '';
  $('#e-account').value = s.account || '';
  $('#e-digits').value = String(s.digits || 6);
  $('#e-period').value = String(s.period || 30);
  $('#e-group').value = String(s.group_id || 0);
  $('#e-notes').value = s.notes || '';
  showScrim(editScrim);
  setTimeout(() => $('#e-issuer').focus(), 50);
}

async function saveEdit() {
  if (!editingId) return;
  const err = $('#edit-err');
  err.textContent = '';
  const patch = {
    issuer: $('#e-issuer').value.trim(),
    account: $('#e-account').value.trim(),
    notes: $('#e-notes').value,
    digits: Number($('#e-digits').value) || 6,
    period: Number($('#e-period').value) || 30,
    group_id: Number($('#e-group').value) || 0,
  };
  const btn = $('#edit-save-btn');
  btn.disabled = true;
  try {
    await api(`/api/secrets/${editingId.id}`, { method: 'PATCH', body: JSON.stringify(patch) });
    toast('Saved', 'good');
    hideScrim(editScrim);
    editingId = null;
    await refreshAll();
  } catch (e) {
    err.textContent = e.message || String(e);
  } finally {
    btn.disabled = false;
  }
}

async function deleteEditing() {
  if (!editingId) return;
  const ok = await confirmDialog(`Delete secret “${editingId.issuer}”? This cannot be undone.`);
  if (!ok) return;
  try {
    await api(`/api/secrets/${editingId.id}`, { method: 'DELETE' });
    toast('Secret deleted', 'good');
    hideScrim(editScrim);
    editingId = null;
    await refreshAll();
  } catch (e) {
    toast(`Delete failed: ${e.message}`, 'bad');
  }
}

/* -------- Confirm dialog -------- */

function confirmDialog(message) {
  return new Promise((resolve) => {
    const scrim = $('#confirm');
    $('#confirm-title').textContent = 'Please confirm';
    $('#confirm-body').textContent = message;
    const cleanup = (val) => {
      hideScrim(scrim);
      $$('[data-confirm]', scrim).forEach((b) => { b.onclick = null; });
      resolve(val);
    };
    $$('[data-confirm]', scrim).forEach((b) => {
      b.onclick = () => cleanup(b.dataset.confirm === 'yes');
    });
    showScrim(scrim);
  });
}

/* -------- Modal helpers -------- */

function showScrim(el) {
  el.hidden = false;
  // force reflow for transition
  void el.offsetWidth;
  el.classList.add('show');
  document.addEventListener('keydown', escClose);
}
function hideScrim(el) {
  el.classList.remove('show');
  setTimeout(() => { el.hidden = true; }, 180);
  document.removeEventListener('keydown', escClose);
}
function escClose(e) {
  if (e.key !== 'Escape') return;
  for (const el of [editScrim, addScrim, $('#confirm')]) {
    if (el && !el.hidden && el.classList.contains('show')) { hideScrim(el); return; }
  }
}

/* -------- QR scan -------- */

/** @type {MediaStream|null} */ let stream = null;
let scanTimer = 0;

async function startScan() {
  if (stream) { stopScan(); return; }
  // Ensure add dialog is open so the scanner has somewhere to render
  if (addScrim.hidden) openAdd('');
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    const v = document.createElement('video');
    v.autoplay = true; v.playsInline = true; v.muted = true;
    v.srcObject = stream;
    await v.play().catch(() => {});
    const hint = document.createElement('div');
    hint.className = 'hint'; hint.textContent = 'Point the camera at a QR code';
    const wrap = document.createElement('div');
    wrap.className = 'scanner';
    wrap.appendChild(v);
    wrap.appendChild(hint);
    const body = addScrim.querySelector('.body');
    body.insertBefore(wrap, body.firstChild);
    $('#scan-btn').textContent = 'Stop scan';
    tickScan(v);
  } catch (e) {
    toast(`Camera: ${e.message || e}`, 'bad');
    stream = null;
  }
}

function stopScan() {
  if (stream) { stream.getTracks().forEach((t) => t.stop()); stream = null; }
  $('#scan-btn').textContent = 'Scan QR';
  const wrap = addScrim.querySelector('.scanner');
  if (wrap) wrap.remove();
  if (scanTimer) { cancelAnimationFrame(scanTimer); scanTimer = 0; }
}

function tickScan(video) {
  if (!stream) return;
  const tick = () => {
    if (!stream) return;
    if (video.readyState >= video.HAVE_ENOUGH_DATA && typeof jsQR === 'function') {
      const c = document.createElement('canvas');
      c.width = video.videoWidth; c.height = video.videoHeight;
      const ctx = c.getContext('2d');
      ctx.drawImage(video, 0, 0, c.width, c.height);
      const code = jsQR(ctx.getImageData(0, 0, c.width, c.height).data, c.width, c.height);
      if (code && code.data) {
        if (code.data.startsWith('otpauth://')) {
          stopScan();
          openAdd(code.data);
          toast('QR detected — review and save', 'good');
          return;
        }
        toast('QR detected but not otpauth://', 'bad');
      }
    }
    scanTimer = requestAnimationFrame(tick);
  };
  scanTimer = requestAnimationFrame(tick);
}

/* -------- Refresh -------- */

async function refreshSecrets() {
  try {
    state.secrets = await api('/api/secrets') || [];
  } catch (e) {
    toast(`Failed to load: ${e.message}`, 'bad');
    state.secrets = [];
  }
  renderGroups();
  renderSecrets();
}

async function refreshAll() {
  await Promise.all([loadStatus(), loadGroups(), refreshSecrets()]);
}

/* -------- Boot -------- */

document.addEventListener('DOMContentLoaded', () => {
  $('#add-btn').addEventListener('click', () => openAdd(''));
  $('#scan-btn').addEventListener('click', startScan);
  $('#new-group-btn').addEventListener('click', createGroup);
  $('#lock-btn').addEventListener('click', () => {
    // No server lock endpoint exposed; reload clears secrets from memory.
    toast('Refreshing to clear in-memory secrets', 'good');
    setTimeout(() => location.reload(), 600);
  });

  // Search
  $('#q').addEventListener('input', (e) => {
    state.filter.q = /** @type {HTMLInputElement} */ (e.target).value;
    renderSecrets();
  });

  // Dialog wiring
  $$('#dialog [data-close]').forEach((b) => b.addEventListener('click', () => { hideScrim(addScrim); stopScan(); }));
  $$('#edit-dialog [data-close]').forEach((b) => b.addEventListener('click', () => hideScrim(editScrim)));
  $('#save-btn').addEventListener('click', saveAdd);
  $('#edit-save-btn').addEventListener('click', saveEdit);
  $('#delete-btn').addEventListener('click', deleteEditing);

  $('#uri').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) saveAdd();
  });

  // Click outside dialog content closes
  for (const sc of [addScrim, editScrim, $('#confirm')]) {
    sc.addEventListener('mousedown', (e) => {
      if (e.target === sc) {
        if (sc === addScrim) stopScan();
        hideScrim(sc);
      }
    });
  }

  refreshAll();
  setInterval(refreshSecrets, 1000);
  setInterval(loadStatus, 30000);
});