// 2fa Web UI — vanilla JS, no framework. Talks to /api/* on the same origin.

/** @typedef {{id:string,issuer:string,account:string,algorithm:string,digits:number,period:number,code:string,remaining:number,group_id:number,group_name:string,notes?:string,has_backup:boolean}} Secret */
/** @typedef {{id:number,name:string,color:string,sort_order?:number,created_at?:string}} Group */

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));

/* -------- i18n -------- */

const dict = {
  en: {
    app_title: '2fa — TOTP Vault',
    search_placeholder: 'Search issuer or account…',
    search_aria: 'Search secrets',
    lang_switch_aria: 'Language',
    groups_aria: 'Groups',
    new_group: '+ New group',
    add_secret: 'Add secret',
    scan_qr: 'Scan QR',
    stop_scan: 'Stop scan',
    lock: 'Lock',
    secrets_aria: 'Secrets',
    empty_title: 'No secrets yet',
    empty_body: 'Add your first TOTP entry to start generating one-time codes. Paste an otpauth:// URI, type one in manually, or scan a QR code.',
    empty_cta: 'Add your first secret',
    edit_secret: 'Edit secret',
    cancel: 'Cancel',
    save: 'Save',
    delete: 'Delete',
    confirm: 'Confirm',
    please_confirm: 'Please confirm',
    close_aria: 'Close',
    auth_title: 'Auth token required',
    auth_body: 'The server is bound to a non-loopback address. Paste the token printed by <code>2fa web</code> on the server terminal.',
    auth_token_label: 'Token',
    auth_submit: 'Unlock',
    uri_placeholder: 'otpauth://totp/Issuer:Account?secret=JBSWY3DPEHPK3PXP&issuer=Issuer',
    name_placeholder: 'Name',
    secret_placeholder: 'Secret',
    issuer_label: 'Issuer',
    account_label: 'Account',
    digits_label: 'Digits',
    period_label: 'Period',
    group_label: 'Group',
    unassigned: 'Unassigned',
    notes_label: 'Notes',
    all_secrets: 'All secrets',
    unassigned_group: 'Unassigned',
    no_issuer: '(no issuer)',
    code_aria: 'Copy code {digits} digits for {issuer}',
    edit_aria: 'Edit {issuer}',
    edit_title_attr: 'Edit',
    copy_title_attr: 'Click to copy',
    copied: 'Copied!',
    status_unlocked: 'Unlocked',
    status_locked: 'Locked',
    status_error: 'error',
    status_loading: 'loading…',
    toast_copied: 'Code copied to clipboard',
    toast_secret_added: 'Secret added',
    toast_saved: 'Saved',
    toast_secret_deleted: 'Secret deleted',
    toast_refresh: 'Refreshing to clear in-memory secrets',
    toast_copy_failed: 'Copy failed: {err}',
    toast_delete_failed: 'Delete failed: {err}',
    toast_create_failed: 'Create failed: {err}',
    toast_load_failed: 'Failed to load: {err}',
    toast_camera: 'Camera: {err}',
    toast_qr_ok: 'QR detected — review and save',
    toast_qr_bad: 'QR detected but not otpauth://',
    toast_group_created: 'Group “{name}” created',
    err_uri_required: 'URI is required',
    err_name_required: 'Name is required',
    err_secret_required: 'Secret is required',
    group_name_prompt: 'Group name?',
    scan_hint: 'Point the camera at a QR code',
    digits_tooltip: '{digits} digits',
    alg_sha1: 'SHA-1',
    alg_sha256: 'SHA-256',
    alg_sha512: 'SHA-512',
    select_all: 'Select all',
    export: 'Export',
    export_title: 'Export {n} secret | Export {n} secrets',
    export_body: 'Pick a format. otpauth:// is the simplest for sharing and re-importing.',
    export_format: 'Format',
    export_password: 'Password',
    export_password_help: 'Used to encrypt the .2fa file. The recipient needs the same password to decrypt.',
    export_download: 'Download',
    toast_export_done: 'Export downloaded',
    toast_export_failed: 'Export failed: {err}',
    err_export_password: 'Password required for .2fa export',
    generate: 'Generate',
    generate_title: 'Generate a random TOTP secret',
    advanced: 'Advanced',
    algorithm_label: 'Algorithm',
    length_label: 'Length (bytes)',
    qr_title: 'Scan with your phone',
    qr_hint: "Point your phone's TOTP app at the code, or copy the URI and import it manually.",
    qr_aria: 'Show QR code for {issuer}',
    qr_copied: 'URI copied',
    copy: 'Copy',
  },
  zh: {
    app_title: '2fa — TOTP 金库',
    search_placeholder: '搜索发行方或账号…',
    search_aria: '搜索条目',
    lang_switch_aria: '语言',
    groups_aria: '分组',
    new_group: '+ 新建分组',
    add_secret: '添加条目',
    scan_qr: '扫描二维码',
    stop_scan: '停止扫描',
    lock: '锁定',
    secrets_aria: '条目列表',
    empty_title: '还没有任何条目',
    empty_body: '添加第一个 TOTP 条目开始生成一次性验证码。可以粘贴 otpauth:// URI、手动输入,或扫描二维码。',
    empty_cta: '添加第一条条目',
    edit_secret: '编辑条目',
    cancel: '取消',
    save: '保存',
    delete: '删除',
    confirm: '确认',
    please_confirm: '请确认',
    close_aria: '关闭',
    auth_title: '需要身份令牌',
    auth_body: '服务器绑定在非本地地址。请粘贴 <code>2fa web</code> 在服务端终端上打印的令牌。',
    auth_token_label: '令牌',
    auth_submit: '解锁',
    uri_placeholder: 'otpauth://totp/发行方:账号?secret=JBSWY3DPEHPK3PXP&issuer=发行方',
    name_placeholder: '名称',
    secret_placeholder: '密钥',
    issuer_label: '发行方',
    account_label: '账号',
    digits_label: '位数',
    period_label: '周期(秒)',
    group_label: '分组',
    unassigned: '未分组',
    notes_label: '备注',
    all_secrets: '全部条目',
    unassigned_group: '未分组',
    no_issuer: '(无发行方)',
    code_aria: '复制 {digits} 位验证码,{issuer}',
    edit_aria: '编辑 {issuer}',
    edit_title_attr: '编辑',
    copy_title_attr: '点击复制',
    copied: '已复制!',
    status_unlocked: '已解锁',
    status_locked: '已锁定',
    status_error: '错误',
    status_loading: '加载中…',
    toast_copied: '验证码已复制到剪贴板',
    toast_secret_added: '条目已添加',
    toast_saved: '已保存',
    toast_secret_deleted: '条目已删除',
    toast_refresh: '刷新以清除内存中的条目',
    toast_copy_failed: '复制失败:{err}',
    toast_delete_failed: '删除失败:{err}',
    toast_create_failed: '创建失败:{err}',
    toast_load_failed: '加载失败:{err}',
    toast_camera: '摄像头:{err}',
    toast_qr_ok: '已识别二维码 — 请检查后保存',
    toast_qr_bad: '二维码不是 otpauth:// 格式',
    toast_group_created: '已创建分组 "{name}"',
    err_uri_required: 'URI 不能为空',
    err_name_required: '名称不能为空',
    err_secret_required: '密钥不能为空',
    group_name_prompt: '分组名称?',
    scan_hint: '将摄像头对准二维码',
    digits_tooltip: '{digits} 位',
    alg_sha1: 'SHA-1',
    alg_sha256: 'SHA-256',
    alg_sha512: 'SHA-512',
    select_all: '全选',
    export: '导出',
    export_title: '导出 {n} 条 | 导出 {n} 条',
    export_body: '选择格式。otpauth:// 适合分享或导入到其他 TOTP 应用。',
    export_format: '格式',
    export_password: '密码',
    export_password_help: '用于加密 .2fa 文件,接收方需要同一密码才能解密。',
    export_download: '下载',
    toast_export_done: '已下载导出文件',
    toast_export_failed: '导出失败:{err}',
    err_export_password: '.2fa 导出需要密码',
    generate: '生成',
    generate_title: '随机生成一个 TOTP 密钥',
    advanced: '高级',
    algorithm_label: '算法',
    length_label: '长度 (字节)',
    qr_title: '用手机扫描',
    qr_hint: '用手机 TOTP 应用扫描二维码,或复制 URI 手动导入。',
    qr_aria: '显示 {issuer} 的二维码',
    qr_copied: 'URI 已复制',
    copy: '复制',
  },
};

let lang0 = (localStorage.getItem('2fa.lang')
  || (/^zh/i.test(navigator.language) ? 'zh' : 'en'));

function t(key, vars) {
  let s = dict[lang0]?.[key] ?? dict.en[key] ?? key;
  if (vars) for (const k of Object.keys(vars)) s = s.split('{' + k + '}').join(String(vars[k]));
  return s;
}

/** Pick the plural form from a `|`-separated list (English 1 vs n). */
function tp(key, n, vars) {
  const raw = t(key, vars);
  const forms = raw.split('|').map((s) => s.trim());
  const form = forms.length === 1 ? forms[0] : (n === 1 ? forms[0] : forms[1] ?? forms[0]);
  return form.replace('{n}', String(n));
}

function applyI18n() {
  document.documentElement.lang = lang0;
  document.documentElement.dataset.lang = lang0;
  $$('[data-i18n]').forEach((el) => { el.textContent = t(el.dataset.i18n); });
  $$('[data-i18n-placeholder]').forEach((el) => { el.placeholder = t(el.dataset.i18nPlaceholder); });
  $$('[data-i18n-aria]').forEach((el) => { el.setAttribute('aria-label', t(el.dataset.i18nAria)); });
  $$('[data-i18n-title]').forEach((el) => { el.title = t(el.dataset.i18nTitle); });
  $$('.lang-switch [data-lang]').forEach((b) => {
    b.setAttribute('aria-pressed', b.dataset.lang === lang0 ? 'true' : 'false');
  });
}

/** In-memory caches */
const state = {
  secrets: /** @type {Secret[]} */ ([]),
  groups: /** @type {Group[]} */ ([]),
  filter: /** @type {{q:string,group:number|'unassigned'|null}} */ ({ q: '', group: null }),
  selected: /** @type {Set<string>} */ (new Set()),
  status: /** @type {any} */ (null),
};

/* -------- API -------- */

// Auth token, kept in sessionStorage so it disappears when the tab closes
// and is never written to disk with the rest of the browser profile.
let authToken = sessionStorage.getItem('2fa.token') || '';

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (authToken) headers['X-Auth-Token'] = authToken;
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401 && authToken !== '') {
    // Token was set but rejected — clear and prompt again.
    authToken = '';
    sessionStorage.removeItem('2fa.token');
  }
  if (res.status === 401 && path !== '/api/auth-check') {
    // No token (or wrong one): show the prompt and retry once on submit.
    const tok = await promptForToken();
    if (tok) {
      authToken = tok;
      sessionStorage.setItem('2fa.token', tok);
      return api(path, opts);
    }
    throw new Error('unauthorized');
  }
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { msg = (await res.text()) || msg; } catch (_) { /* ignore */ }
    throw new Error(msg);
  }
  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res.text();
}

function promptForToken() {
  return new Promise((resolve) => {
    const scrim = $('#auth');
    const input = $('#auth-token');
    $('#auth-err').textContent = '';
    input.value = '';
    showScrim(scrim);
    setTimeout(() => input.focus(), 50);
    const cleanup = (val) => {
      hideScrim(scrim);
      $$('[data-auth]', scrim).forEach((b) => { b.onclick = null; });
      input.onkeydown = null;
      resolve(val);
    };
    $$('[data-auth]', scrim).forEach((b) => {
      b.onclick = () => cleanup(b.dataset.auth === 'yes' ? input.value.trim() : null);
    });
    input.onkeydown = (e) => {
      if (e.key === 'Enter') { e.preventDefault(); cleanup(input.value.trim()); }
    };
  });
}

/* -------- Utilities -------- */

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

function fmtAlgo(a) {
  return ({ SHA1: t('alg_sha1'), SHA256: t('alg_sha256'), SHA512: t('alg_sha512') })[a] || a || '';
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
    $('.label', st).textContent = t('status_loading');
    $('.addr', st).textContent = '';
    return;
  }
  if (s.error) {
    st.classList.add('error');
    $('.label', st).textContent = t('status_error');
    $('.addr', st).textContent = s.error;
    return;
  }
  st.classList.add(s.unlocked ? 'unlocked' : 'locked');
  $('.label', st).textContent = `${s.unlocked ? t('status_unlocked') : t('status_locked')} · ${s.mode}`;
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

  const items = [{ id: 0, name: t('all_secrets'), color: 'transparent', count: total }];
  if (unassignedCount > 0) items.push({ id: -1, name: t('unassigned_group'), color: 'transparent', count: unassignedCount });
  for (const g of state.groups) items.push({ ...g, count: counts.get(g.id) || 0 });

  for (const g of items) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'chip';
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
    ul.appendChild(btn);
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
    sel.innerHTML = `<option value="0">${escapeHtml(t('unassigned'))}</option>`;
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
  const name = prompt(t('group_name_prompt'));
  if (!name) return;
  try {
    await api('/api/groups', { method: 'POST', body: JSON.stringify({ name, color: '' }) });
    toast(t('toast_group_created', { name }), 'good');
    await refreshAll();
  } catch (e) { toast(t('toast_create_failed', { err: e.message }), 'bad'); }
}

/* -------- Secrets list -------- */

const secretsUl = $('#secrets');
const emptyEl = $('#empty');

function renderSecrets() {
  const list = visibleSecrets();
  const trulyEmpty = state.secrets.length === 0; // no data at all → onboarding; filtered-empty keeps the existing copy
  emptyEl.hidden = !trulyEmpty;
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
    const checked = state.selected.has(s.id) ? 'checked' : '';

    li.innerHTML = `
      <label class="pick" onclick="event.stopPropagation()">
        <input type="checkbox" class="pick-cb" ${checked} aria-label="${escapeHtml(s.issuer)}">
      </label>
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
        <div class="issuer">${escapeHtml(s.issuer || t('no_issuer'))}${groupTag}</div>
        <div class="account">${escapeHtml(s.account || '')}${s.notes ? ' · ' + escapeHtml(s.notes) : ''}</div>
      </div>
      <div class="code-wrap">
        <button class="code" type="button" title="${escapeHtml(t('copy_title_attr'))}" aria-label="${escapeHtml(t('code_aria', { digits, issuer: s.issuer }))}">${escapeHtml(codeFmt)}</button>
      </div>
      <div class="row-actions">
        <button class="icon-btn qr-btn" type="button" data-id="${escapeHtml(s.id)}" aria-label="${escapeHtml(t('qr_aria', { issuer: s.issuer }))}" title="${escapeHtml(t('qr_title'))}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3z"/><path d="M20 14v3"/><path d="M14 20h3"/><path d="M20 20h1"/></svg>
        </button>
        <button class="icon-btn edit" type="button" aria-label="${escapeHtml(t('edit_aria', { issuer: s.issuer }))}" title="${escapeHtml(t('edit_title_attr'))}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 1 1 3 3L7 19l-4 1 1-4Z"/></svg>
        </button>
      </div>`;

    const codeBtn = $('.code', li);
    codeBtn.onclick = () => copyCode(s, codeBtn);
    $('.edit', li).onclick = () => openEdit(s);
    $('.pick-cb', li).onchange = (e) => {
      const on = /** @type {HTMLInputElement} */ (e.target).checked;
      if (on) state.selected.add(s.id); else state.selected.delete(s.id);
      updateSelectionUI();
    };
    secretsUl.appendChild(li);
  }
  updateSelectionUI();
}

// Refresh the toolbar export button + select-all checkbox without rebuilding
// every row. Cheap and avoids losing focus / scroll while typing in search.
function updateSelectionUI() {
  const visible = visibleSecrets();
  const ids = visible.map((s) => s.id);
  const selectedVisible = ids.filter((id) => state.selected.has(id)).length;
  const btn = $('#export-btn');
  const count = $('#export-count');
  btn.hidden = state.selected.size === 0;
  count.textContent = String(state.selected.size);
  document.body.classList.toggle('selecting', state.selected.size > 0);
  const sa = $('#select-all');
  if (!sa) return;
  sa.checked = selectedVisible > 0 && selectedVisible === ids.length;
  sa.indeterminate = selectedVisible > 0 && selectedVisible < ids.length;
}

async function copyCode(s, btn) {
  try {
    await navigator.clipboard.writeText(s.code);
    btn.classList.add('copied');
    btn.textContent = t('copied');
    // server-side touch (last_used) — fire and forget
    try { await api(`/api/code?id=${encodeURIComponent(s.id)}`); } catch (_) { /* ignore */ }
    toast(t('toast_copied'), 'good');
    setTimeout(() => {
      btn.classList.remove('copied');
      const digits = String(s.digits || 6);
      const codeFmt = digits === s.code.length ? s.code : (s.code + ' '.repeat(digits)).slice(0, digits);
      btn.textContent = codeFmt;
    }, 900);
  } catch (e) {
    toast(t('toast_copy_failed', { err: e.message }), 'bad');
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
    if (!uri) { err.textContent = t('err_uri_required'); return; }
    body = { uri, group_id: 0 };
  } else {
    const issuer = $('#issuer').value.trim();
    const secret = $('#secret').value.trim();
    if (!issuer) { err.textContent = t('err_name_required'); return; }
    if (!secret) { err.textContent = t('err_secret_required'); return; }
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
    toast(t('toast_secret_added'), 'good');
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
    toast(t('toast_saved'), 'good');
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
    toast(t('toast_secret_deleted'), 'good');
    hideScrim(editScrim);
    editingId = null;
    await refreshAll();
  } catch (e) {
    toast(t('toast_delete_failed', { err: e.message }), 'bad');
  }
}

/* -------- Confirm dialog -------- */

function confirmDialog(message) {
  return new Promise((resolve) => {
    const scrim = $('#confirm');
    $('#confirm-title').textContent = t('please_confirm');
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
  for (const el of [editScrim, addScrim, $('#confirm'), exportScrim]) {
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
    hint.className = 'hint'; hint.textContent = t('scan_hint');
    const wrap = document.createElement('div');
    wrap.className = 'scanner';
    wrap.appendChild(v);
    wrap.appendChild(hint);
    const body = addScrim.querySelector('.body');
    body.insertBefore(wrap, body.firstChild);
    $('#scan-btn span').textContent = t('stop_scan');
    tickScan(v);
  } catch (e) {
    toast(t('toast_camera', { err: e.message || e }), 'bad');
    stream = null;
  }
}

function stopScan() {
  if (stream) { stream.getTracks().forEach((t) => t.stop()); stream = null; }
  $('#scan-btn span').textContent = t('scan_qr');
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
          toast(t('toast_qr_ok'), 'good');
          return;
        }
        toast(t('toast_qr_bad'), 'bad');
      }
    }
    scanTimer = requestAnimationFrame(tick);
  };
  scanTimer = requestAnimationFrame(tick);
}

/* -------- Export -------- */

const exportScrim = $('#export-dialog');

function openExport() {
  $('#export-err').textContent = '';
  $('#exp-pw').value = '';
  $('#exp-format').value = 'otpauth';
  $('#exp-pw-row').hidden = true;
  $('#export-title').textContent = tp('export_title', state.selected.size);
  showScrim(exportScrim);
  setTimeout(() => $('#exp-format').focus(), 50);
}

async function doExport() {
  const err = $('#export-err');
  err.textContent = '';
  const fmt = $('#exp-format').value;
  const body = { format: fmt, ids: Array.from(state.selected) };
  if (fmt === '.2fa') {
    const pw = $('#exp-pw').value;
    if (!pw) { err.textContent = t('err_export_password'); return; }
    body.password = pw;
  }
  const btn = $('#export-go');
  btn.disabled = true;
  try {
    // api() returns parsed JSON or text; for binary .2fa we use raw fetch and
    // pipe the blob straight to a download link.
    const headers = { 'Content-Type': 'application/json' };
    if (authToken) headers['X-Auth-Token'] = authToken;
    const res = await fetch('/api/export', { method: 'POST', headers, body: JSON.stringify(body) });
    if (res.status === 401) {
      // piggy-back on api()'s prompt flow for token
      authToken = '';
      sessionStorage.removeItem('2fa.token');
      const tok = await promptForToken();
      if (tok) {
        authToken = tok;
        sessionStorage.setItem('2fa.token', tok);
        return doExport();
      }
      throw new Error('unauthorized');
    }
    if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
    const blob = await res.blob();
    const cd = res.headers.get('Content-Disposition') || '';
    const m = /filename="?([^"]+)"?/.exec(cd);
    const filename = (m && m[1]) || `export-${fmt}.bin`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    hideScrim(exportScrim);
    toast(t('toast_export_done'), 'good');
  } catch (e) {
    err.textContent = e.message || String(e);
    toast(t('toast_export_failed', { err: e.message || e }), 'bad');
  } finally {
    btn.disabled = false;
  }
}

/* -------- Refresh -------- */

async function refreshSecrets() {
  try {
    state.secrets = await api('/api/secrets') || [];
  } catch (e) {
    toast(t('toast_load_failed', { err: e.message }), 'bad');
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
  // Apply i18n first so all initial DOM is in the active language.
  applyI18n();

  // Language switcher
  $$('.lang-switch [data-lang]').forEach((b) => {
    b.addEventListener('click', () => {
      const next = b.dataset.lang;
      if (next === lang0) return;
      lang0 = next;
      localStorage.setItem('2fa.lang', lang0);
      applyI18n();
      // Re-render dynamic content so any cached text refreshes.
      renderGroups();
      renderGroupSelects();
      renderSecrets();
    });
  });

  $('#add-btn').addEventListener('click', () => openAdd(''));
  $('#scan-btn').addEventListener('click', startScan);
  $('#new-group-btn').addEventListener('click', createGroup);
  // Defensive: keep #lock-btn hidden. The HTML has `hidden` set, but CSS
  // (.btn = inline-flex) and stale embedded assets in older builds can
  // surface it. There is no server-side lock endpoint to invoke.
  const lockBtn = $('#lock-btn');
  if (lockBtn) lockBtn.hidden = true;
  lockBtn && lockBtn.addEventListener('click', () => {
    toast(t('toast_refresh'), 'good');
    setTimeout(() => location.reload(), 600);
  });

  // Select-all + export
  $('#select-all').addEventListener('change', (e) => {
    const on = /** @type {HTMLInputElement} */ (e.target).checked;
    for (const s of visibleSecrets()) {
      if (on) state.selected.add(s.id); else state.selected.delete(s.id);
    }
    // Re-render to reflect per-row checkbox state.
    renderSecrets();
  });
  $('#export-btn').addEventListener('click', openExport);
  $$('#export-dialog [data-close]').forEach((b) => b.addEventListener('click', () => hideScrim(exportScrim)));
  $('#export-go').addEventListener('click', doExport);
  $('#exp-format').addEventListener('change', (e) => {
    $('#exp-pw-row').hidden = /** @type {HTMLSelectElement} */ (e.target).value !== '.2fa';
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
  for (const sc of [addScrim, editScrim, $('#confirm'), exportScrim]) {
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

  /* -------- Liquid glass pointer sheen --------
   * Tracks pointer over glass surfaces and writes normalized (0-100) coords
   * into --mx / --my on the element. CSS uses those in conic-gradient + radial
   * sheen. Single rAF coalesces pointermove → style write; delegation keeps
   * listeners off every secret row.
   */
  const glassSel = '.glass, .chip, .btn, .secret, .dialog, .toast, .search, .lang-switch, .status, .empty';
  let sheenTarget = null;
  let sheenX = 50, sheenY = 30;
  let sheenRaf = 0;
  const flushSheen = () => {
    sheenRaf = 0;
    if (!sheenTarget || sheenTarget.isConnected === false) return;
    sheenTarget.style.setProperty('--mx', sheenX.toFixed(2) + '%');
    sheenTarget.style.setProperty('--my', sheenY.toFixed(2) + '%');
  };
  document.addEventListener('pointermove', (e) => {
    const el = e.target.closest && e.target.closest(glassSel);
    if (!el) return;
    sheenTarget = el;
    const r = el.getBoundingClientRect();
    sheenX = Math.max(0, Math.min(100, ((e.clientX - r.left) / r.width) * 100));
    sheenY = Math.max(0, Math.min(100, ((e.clientY - r.top) / r.height) * 100));
    if (!sheenRaf) sheenRaf = requestAnimationFrame(flushSheen);
  }, { passive: true });
  // Pointer leaving the document should reset so the highlight doesn't stick
  // on the last hovered element when the cursor leaves the window.
  document.addEventListener('pointerleave', () => {
    sheenTarget = null;
    if (sheenRaf) { cancelAnimationFrame(sheenRaf); sheenRaf = 0; }
  });

  /* -------- QR code for a secret --------
   * Asks the backend for the canonical otpauth:// URI (the seed never leaves
   * the server through the list endpoint, but this single-secret endpoint
   * re-emits the URI the user could already reconstruct from /api/export).
   * Renders the URI as a QR via the qrcode-generator library loaded before
   * this script.
   */
  const qrScrim = $('#qr-dialog');

  async function fetchOtpauthURI(id) {
    const res = await api(`/api/secrets/${encodeURIComponent(id)}/otpauth`);
    return res.uri;
  }

  function renderQRInto(svgContainer, data) {
    // qrcode-generator API: qrcode(typeNumber, errorCorrectionLevel)
    // typeNumber=0 means auto-detect smallest size that fits.
    const qr = qrcode(0, 'M');
    qr.addData(data);
    qr.make();
    svgContainer.innerHTML = qr.createSvgTag({ cellSize: 6, margin: 0, scalable: true });
  }

  async function openQR(secret) {
    if (!secret || !secret.id) { toast('Missing secret', 'bad'); return; }
    let uri;
    try { uri = await fetchOtpauthURI(secret.id); }
    catch (e) { toast(t('toast_load_failed', { err: e.message || e }), 'bad'); return; }
    const canvas = $('#qr-canvas');
    renderQRInto(canvas, uri);
    $('#qr-issuer').textContent = secret.issuer + (secret.account ? ' · ' + secret.account : '');
    const uriEl = $('#qr-uri');
    uriEl.textContent = uri;
    uriEl.dataset.uri = uri;
    showScrim(qrScrim);
  }

  // Copy button inside QR dialog
  $('#qr-copy').addEventListener('click', async () => {
    const uri = $('#qr-uri').dataset.uri || '';
    if (!uri) return;
    try {
      await navigator.clipboard.writeText(uri);
      toast(t('qr_copied'), 'good');
    } catch (e) {
      toast(t('toast_copy_failed', { err: e.message || e }), 'bad');
    }
  });
  // Close handlers
  $$('#qr-dialog [data-close]').forEach((b) => b.addEventListener('click', () => hideScrim(qrScrim)));
  // Click outside dialog content
  qrScrim.addEventListener('mousedown', (e) => { if (e.target === qrScrim) hideScrim(qrScrim); });
  // Extend Esc handler to also close the QR dialog (in addition to the existing
  // ones handled by escClose). Single keydown listener on document.
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (!qrScrim.hidden && qrScrim.classList.contains('show')) hideScrim(qrScrim);
  });

  // QR button click delegation (handles both already-rendered and future rows)
  secretsUl.addEventListener('click', (e) => {
    const btn = e.target.closest && e.target.closest('.qr-btn');
    if (!btn) return;
    const id = btn.dataset.id;
    const s = state.secrets.find((x) => x.id === id);
    if (s) openQR(s);
  });

  /* -------- Generate a random TOTP secret (client-side) --------
   * Uses crypto.getRandomValues for CSPRNG. base32 alphabet matches
   * Go's base32.StdEncoding: A-Z + 2-7, no padding. Test vector:
   *   encode([0x31,0x32,...,0x39,0x30]) (ASCII "12345678901234567890")
   *     = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  (32 chars, RFC 4648)
   * which matches internal/core/totp/totp_test.go:10 and totp.go:85.
   */
  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function base32Encode(bytes) {
    let bits = 0, value = 0, out = '';
    for (let i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        out += B32[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) out += B32[(value << (5 - bits)) & 31];
    return out;
  }

  function generateSecret(bytes) {
    const buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    return base32Encode(buf);
  }

  function generateTOTP({ algo = 'SHA1', bytes = 20 } = {}) {
    return { secret: generateSecret(bytes), algorithm: algo, digits: 6, period: 30 };
  }

  // Generate button: fill the secret input with a fresh key.
  // Algorithm + length come from the Advanced <details> selects.
  $('#gen-btn').addEventListener('click', () => {
    const algo = ($('#gen-algo')?.value) || 'SHA1';
    const bytes = Number(($('#gen-bytes')?.value) || 20);
    const { secret } = generateTOTP({ algo, bytes });
    $('#secret').value = secret;
    $('#secret').focus();
    $('#secret').select();
  });

  // Self-test: RFC 4648 §10 test vector for base32. If the alphabet or bit
  // shifting drifts, this catches it at load time before the user does.
  // "12345678901234567890" (20 bytes) -> "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
  (function selfTest() {
    const ascii = new TextEncoder().encode('12345678901234567890');
    const got = base32Encode(ascii);
    const want = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    if (got !== want) console.error('base32 self-test FAILED: got', got, 'want', want);
  })();
});