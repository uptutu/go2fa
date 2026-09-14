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
    no_match_title: 'No matches',
    no_match_body: 'Nothing matches “{q}”. Try a different keyword, or clear the search.',
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
    theme_aria: 'Theme',
    theme_pop_aria: 'Choose theme',
    detail_account: 'Account',
    detail_algo: 'Algorithm',
    detail_digits: 'Digits',
    detail_period: 'Period',
    detail_code_aria: 'Copy current code, {digits} digits',
    detail_notes: 'Notes',
    qr_show: 'Show QR',
    refresh_now: 'Refresh',
    unlock_title: 'Vault locked',
    unlock_body: 'Enter your master password to unlock the vault.',
    unlock_password_label: 'Master password',
    unlock_submit: 'Unlock',
    unlock_err: 'Unlock failed — wrong password?',
    unlock_action: 'Unlock',
    mode_btn_set: 'Set password',
    mode_btn_disable: 'Disable password',
    mode_set_title: 'Set a master password',
    mode_set_body: 'A master password protects your vault on this machine and on backups. Anyone who gets the file also needs the password to read it.',
    mode_disable_title: 'Disable master password',
    mode_disable_body: 'This switches the vault to machine-bound encryption. Anyone with file-system access to this machine can decrypt it without a password.',
    mode_pw_label: 'New password (8+ characters)',
    mode_pw2_label: 'Confirm password',
    mode_show_password: 'Show password',
    mode_pw_mismatch: 'Passwords do not match',
    mode_pw_short: 'Password must be at least 8 characters and not blank',
    mode_pw_whitespace: 'Password cannot be only whitespace',
    mode_current_pw_label: 'Current password',
    mode_current_pw_required: 'Enter your current password to disable password protection',
    mode_pw_wrong: 'Current password is incorrect',
    mode_confirm_required: 'Please check the confirmation box to continue',
    mode_confirm_disable: 'I understand anyone with disk access on this machine can decrypt the vault',
    mode_confirm_set: 'I will remember this password — there is no way to recover it',
    mode_going: 'Switching…',
    mode_done: 'Mode updated',
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
    theme_aria: '主题',
    theme_pop_aria: '选择主题',
    detail_account: '账号',
    detail_algo: '算法',
    detail_digits: '位数',
    detail_period: '周期',
    detail_code_aria: '复制当前验证码,共 {digits} 位',
    detail_notes: '备注',
    qr_show: '显示二维码',
    refresh_now: '立即刷新',
    no_match_title: '无匹配结果',
    no_match_body: '没有匹配 “{q}” 的条目。换个关键词试试,或清空搜索框。',
    unlock_title: '金库已锁定',
    unlock_body: '输入主密码以解锁金库。',
    unlock_password_label: '主密码',
    unlock_submit: '解锁',
    unlock_err: '解锁失败——密码错误?',
    unlock_action: '解锁',
    mode_btn_set: '设置密码',
    mode_btn_disable: '关闭密码保护',
    mode_set_title: '设置主密码',
    mode_set_body: '主密码可在本机与备份文件之外再加一层保护。拿到文件的人也需要密码才能解密。',
    mode_disable_title: '关闭主密码',
    mode_disable_body: '此操作将金库切换为本机绑定加密。任何能访问本机文件系统的人都可在没有密码的情况下解密。',
    mode_pw_label: '新密码(至少 8 位)',
    mode_pw2_label: '确认密码',
    mode_show_password: '显示密码',
    mode_pw_mismatch: '两次密码不一致',
    mode_pw_short: '密码至少 8 位且不能全是空格',
    mode_pw_whitespace: '密码不能全是空白字符',
    mode_current_pw_label: '当前密码',
    mode_current_pw_required: '请输入当前密码以关闭密码保护',
    mode_pw_wrong: '当前密码不正确',
    mode_confirm_required: '请先勾选确认框再继续',
    mode_confirm_disable: '我理解:任何可访问本机磁盘的人都能解密金库',
    mode_confirm_set: '我会记牢这个密码——无法找回',
    mode_going: '切换中…',
    mode_done: '模式已更新',
  },
};

// Language is resolved in the inline <script> in index.html (so the very
// first paint is already in the right language, with no EN→ZH flicker).
// By the time this file runs, <html data-lang> already holds the chosen
// value — read it from there instead of trusting localStorage, which the
// GUI's webview wipes between launches.
let lang0 = document.documentElement.dataset.lang || 'en';

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

/* -------- Vault unlock (idle auto-lock / manual lock) --------
 * The server locks the vault after 15 idle minutes. Status polling
 * notices (unlocked:false) and we prompt here. For no-password vaults
 * the password field is hidden — a bare POST re-derives the machine key.
 */
let unlockPending = false;

async function postUnlock(password) {
  const headers = { 'Content-Type': 'application/json' };
  if (authToken) headers['X-Auth-Token'] = authToken;
  const res = await fetch('/api/unlock', { method: 'POST', headers, body: JSON.stringify({ password }) });
  if (res.ok) return true;
  let msg = '';
  try { msg = (await res.text()) || ''; } catch (_) { /* ignore */ }
  throw new Error(msg || `HTTP ${res.status}`);
}

function promptForUnlock() {
  return new Promise((resolve) => {
    const scrim = $('#unlock');
    const input = $('#unlock-pass');
    $('#unlock-err').textContent = '';
    input.value = '';
    showScrim(scrim);
    setTimeout(() => input.focus(), 50);
    const cleanup = (val) => {
      hideScrim(scrim);
      $$('[data-unlock]', scrim).forEach((b) => { b.onclick = null; });
      input.onkeydown = null;
      resolve(val);
    };
    $$('[data-unlock]', scrim).forEach((b) => {
      b.onclick = async () => {
        if (b.dataset.unlock !== 'yes') return cleanup(false);
        try {
          await postUnlock(input.value);
          cleanup(true);
        } catch (e) {
          $('#unlock-err').textContent = t('unlock_err');
        }
      };
    });
    input.onkeydown = (e) => {
      if (e.key === 'Enter') { e.preventDefault(); $('[data-unlock="yes"]', scrim).click(); }
    };
  });
}

async function ensureUnlocked() {
  if (unlockPending) return;
  unlockPending = true;
  try {
    // No-password vaults unlock by re-deriving the machine key on the
    // server — nothing for the user to type, so skip the dialog entirely
    // instead of showing a password prompt with a hidden field.
    if (state.status && state.status.mode === 'no-password') {
      await postUnlock('');
      await refreshAll();
      return;
    }
    const ok = await promptForUnlock(false);
    if (ok) {
      await refreshAll();
    } else {
      state.secrets = [];
      renderGroups();
      renderSecrets();
    }
  } finally {
    unlockPending = false;
  }
}

/* -------- Mode switch (password ↔ no-password) --------
 * Both directions re-encrypt every row under a fresh KEK. The UI does
 * its own password validation so the server stays a thin shell; the
 * server enforces ≥8 chars and surfaces the resulting mode. Success:
 * reload status (mode pill + button label update) + toast. Failure: keep
 * the dialog open and show the error inline.
 */
const modeScrim = $('#mode-dialog');

// Pure label-setter for the open mode dialog. Called on every language
// switch so the title / body / labels / confirm-button text track the
// active language in real time. Reads the target mode off
// modeScrim.dataset.targetMode (set at open time) and never touches
// inputs or the confirm checkbox — preserves whatever the user typed.
function setModeDialogLabels() {
  const wantPassword = modeScrim.dataset.targetMode === 'password';
  $('#mode-title').textContent = wantPassword ? t('mode_set_title') : t('mode_disable_title');
  $('#mode-body').textContent = wantPassword ? t('mode_set_body') : t('mode_disable_body');
  $('#mode-pw-label').textContent = t('mode_pw_label');
  $('#mode-pw2-label').textContent = t('mode_pw2_label');
  $('#mode-confirm-label').textContent = wantPassword ? t('mode_confirm_set') : t('mode_confirm_disable');
  $('#mode-current-pw-label').textContent = t('mode_current_pw_label');
  $('#mode-go').textContent = wantPassword ? t('mode_set_title') : t('mode_disable_title');
}

function openModeDialog() {
  if (!state.status || !state.status.unlocked) {
    // Defence in depth: button is only shown when unlocked, but if the
    // vault just auto-locked, the call would 401 on the server anyway.
    ensureUnlocked();
    return;
  }
  const wantPassword = state.status.mode !== 'password';
  const fromPassword = state.status.mode === 'password';
  modeScrim.dataset.targetMode = wantPassword ? 'password' : 'no-password';
  $('#mode-pw-fields').hidden = !wantPassword;
  $('#mode-current-pw-field').hidden = !(fromPassword && !wantPassword);
  $('#mode-pw').value = '';
  $('#mode-pw2').value = '';
  $('#mode-current-pw').value = '';
  $('#mode-confirm').checked = false;
  // Gate the submit button on the destructive confirmation checkbox.
  // The server still re-checks, but the disabled state stops an
  // accidental click from triggering a destructive rekey.
  $('#mode-go').disabled = true;
  // Reset show-password toggle and restore masked inputs each open.
  const showPw = $('#mode-show');
  if (showPw) {
    showPw.checked = false;
    $('#mode-pw').type = 'password';
    $('#mode-pw2').type = 'password';
  }
  $('#mode-err').textContent = '';
  setModeDialogLabels();
  showScrim(modeScrim);
  // Focus the first relevant field so Enter / Tab flow sensibly.
  let focusEl = $('#mode-confirm');
  if (wantPassword) focusEl = $('#mode-pw');
  else if (fromPassword) focusEl = $('#mode-current-pw');
  setTimeout(() => focusEl.focus(), 50);
}

async function submitModeSwitch() {
  const target = modeScrim.dataset.targetMode;
  const errEl = $('#mode-err');
  errEl.textContent = '';
  if (!$('#mode-confirm').checked) {
    errEl.textContent = t('mode_confirm_required');
    return;
  }
  let password = '';
  let currentPassword = '';
  const fromPassword = state.status && state.status.mode === 'password';
  if (target === 'password') {
    const pw = $('#mode-pw').value;
    const pw2 = $('#mode-pw2').value;
    // Whitespace check: pure-whitespace passes len() < 8 in some cases
    // ("        " is 8 chars) but produces a KEK with no real entropy.
    // Mirror the server's rule so we never let one reach the wire.
    if (pw.trim() === '' || pw.length < 8) {
      errEl.textContent = pw.trim() === '' && pw.length >= 8
        ? t('mode_pw_whitespace')
        : t('mode_pw_short');
      return;
    }
    if (pw !== pw2) { errEl.textContent = t('mode_pw_mismatch'); return; }
    password = pw;
  } else if (fromPassword) {
    // Disabling password: prove the requester already had access by
    // re-entering the current password. Server verifies this against
    // the in-memory KEK before rekeying — the UI gate is for UX, the
    // server gate is the real boundary.
    currentPassword = $('#mode-current-pw').value;
    if (currentPassword === '') {
      errEl.textContent = t('mode_current_pw_required');
      return;
    }
  }
  const go = $('#mode-go');
  go.disabled = true;
  const prev = go.textContent;
  go.textContent = t('mode_going');
  try {
    // Send both fields: the server enforces confirm == password on the
    // wire so a buggy/hostile client can't rekey the vault with a value
    // the user never saw confirmed. current_password is only meaningful
    // for password → no-password; server ignores it otherwise.
    const body = JSON.stringify({ mode: target, password, confirm: password, current_password: currentPassword });
    const headers = { 'Content-Type': 'application/json' };
    if (authToken) headers['X-Auth-Token'] = authToken;
    const res = await fetch('/api/mode', { method: 'POST', headers, body });
    if (!res.ok) {
      // Structured error: try JSON first (i18n code + English fallback),
      // then plain text. JSON keeps the error in the active language
      // even when the request comes from a non-UI client.
      let msg = '';
      try {
        const ct = res.headers.get('content-type') || '';
        if (ct.includes('application/json')) {
          const data = await res.json();
          if (data && data.code) msg = t(data.code) || data.message || '';
          if (!msg && data && data.message) msg = data.message;
        } else {
          msg = (await res.text()) || '';
        }
      } catch (_) { /* ignore */ }
      errEl.textContent = msg || `HTTP ${res.status}`;
      return;
    }
    hideScrim(modeScrim);
    toast(t('mode_done'), 'good');
    // Mode changed on disk + in-memory KEK; reload everything so the
    // status pill, button label, and secret list all reflect it.
    await refreshAll();
  } catch (e) {
    errEl.textContent = (e && e.message) || String(e);
  } finally {
    go.disabled = false;
    go.textContent = prev;
  }
}

/* -------- Utilities -------- */

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

/* -------- Fuzzy search --------
 * Greedy left-to-right match. Returns null if not all query chars matched
 * in order, or { score, indices } where indices point into the original
 * (unescaped) target string. Scoring rewards: first-char (+10), word-start
 * after separator (+8), camelCase boundary (+4), consecutive run (+6+);
 * penalises skipped chars (-1 each). Tight matches get a length bonus;
 * exact substring matches get a small flat bonus.
 */
function fuzzyMatch(query, target) {
  if (!query) return { score: 0, indices: [] };
  const q = String(query).toLowerCase();
  const t = String(target || '').toLowerCase();
  const qlen = q.length, tlen = t.length;
  if (tlen === 0 || qlen === 0) return null;
  let qi = 0, ti = 0;
  const indices = [];
  let score = 0;
  let run = 0;
  while (qi < qlen && ti < tlen) {
    if (q[qi] === t[ti]) {
      indices.push(ti);
      let s = 1;
      if (ti === 0) s += 10;
      else if (/[\s_\-./@:]/.test(t[ti - 1])) s += 8;
      else if (/[a-z]/.test(t[ti - 1]) && /[A-Z0-9]/.test(t[ti])) s += 4;
      if (run > 0) s += 6 + Math.min(run, 4);
      score += s;
      run++;
      qi++;
    } else {
      score -= 1;
      run = 0;
    }
    ti++;
  }
  if (qi < qlen) return null;
  score += Math.max(0, 25 - tlen);
  if (t.includes(q)) score += 5;
  if (indices[0] === 0) score += 3;
  return { score, indices };
}

// Wrap matched indices (in the raw text) with <mark>. Indices stay aligned
// with the unescaped input by escaping each run separately — <mark> tags
// themselves are never escaped, so they always parse.
function highlight(text, indices) {
  if (!indices || !indices.length) return escapeHtml(text || '');
  const set = new Set(indices);
  const t = String(text || '');
  let out = '', buf = '', inMark = false;
  for (let i = 0; i < t.length; i++) {
    const matched = set.has(i);
    if (matched !== inMark) {
      out += escapeHtml(buf);
      buf = '';
      out += matched ? '<mark>' : '</mark>';
      inMark = matched;
    }
    buf += t[i];
  }
  out += escapeHtml(buf);
  if (inMark) out += '</mark>';
  return out;
}

// Score a secret against the query across issuer / account / group / notes.
// Each field contributes a weighted partial; best-field hit anchors the row.
// Returns null when no field matched.
function scoreSecret(q, s) {
  const fields = [
    { text: s.issuer || '', w: 3 },
    { text: s.account || '', w: 2 },
    { text: s.group_name || '', w: 1 },
    { text: s.notes || '', w: 1 },
  ];
  let total = 0, any = false;
  for (const f of fields) {
    const m = fuzzyMatch(q, f.text);
    if (m) { total += m.score * f.w; any = true; }
  }
  return any ? total : null;
}

/* -------- Theme picker --------
 * Token-driven: picking a theme just rewrites data-theme on <html>; all
 * component styles read from CSS variables, so nothing else changes.
 *
 * Persistence is server-side (PUT /api/preferences) because the GUI's
 * webview process gets no stable localStorage across `2fa gui` launches
 * — glaze doesn't configure a user-data-dir. localStorage still caches
 * the value for instant read-back and survives across page reloads in
 * the same webview session; the server is the source of truth.
 * The server also injects the saved theme into index.html before first
 * paint, so there is no aurora→obsidian flash on startup.
 */
const THEMES = ['aurora', 'obsidian', 'dusk', 'paper', 'ember', 'mono'];
const THEME_LABELS = {
  aurora: 'Aurora', obsidian: 'Obsidian', dusk: 'Dusk',
  paper: 'Paper', ember: 'Ember', mono: 'Mono',
};
const themeRoot = document.documentElement;
const themeBtn = $('#theme-btn');
const themePop = $('#theme-pop');
const themeCurrent = $('#theme-current');

function applyTheme(id, { persist = true } = {}) {
  if (!THEMES.includes(id)) id = 'aurora';
  themeRoot.setAttribute('data-theme', id);
  if (persist) {
    // localStorage is a write-through cache for snappy reloads within
    // the same webview session; the server PUT is the durable copy.
    try { localStorage.setItem('go2fa.theme', id); } catch (_) { /* private mode */ }
    fetch('/api/preferences', { method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ theme: id }) }).catch(() => { /* network blip: next load retries */ });
  }
  if (themeCurrent) themeCurrent.textContent = THEME_LABELS[id];
  $$('.theme-card').forEach((c) =>
    c.setAttribute('aria-pressed', String(c.dataset.theme === id)));
}

applyTheme(themeRoot.getAttribute('data-theme') || 'aurora', { persist: false });

if (themeBtn && themePop) {
  themeBtn.addEventListener('click', () => {
    const open = !themePop.hidden;
    themePop.hidden = open;
    themeBtn.setAttribute('aria-expanded', String(!open));
  });
  document.addEventListener('click', (e) => {
    if (themePop.hidden) return;
    if (e.target.closest('#theme-pop, #theme-btn')) return;
    themePop.hidden = true;
    themeBtn.setAttribute('aria-expanded', 'false');
  });
  themePop.addEventListener('click', (e) => {
    const c = e.target.closest('.theme-card');
    if (!c) return;
    applyTheme(c.dataset.theme);
    themePop.hidden = true;
    themeBtn.setAttribute('aria-expanded', 'false');
    themeBtn.focus();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !themePop.hidden) {
      themePop.hidden = true;
      themeBtn.setAttribute('aria-expanded', 'false');
      themeBtn.focus();
    }
  });
}

function fmtAlgo(a) {
  return ({ SHA1: t('alg_sha1'), SHA256: t('alg_sha256'), SHA512: t('alg_sha512') })[a] || a || '';
}

function visibleSecrets() {
  const q = state.filter.q.trim();
  const group = state.filter.group;
  const passes = (s) => {
    if (group === 'unassigned') return s.group_id === 0;
    if (typeof group === 'number' && group > 0) return s.group_id === group;
    return true;
  };
  const filtered = state.secrets.filter(passes);
  if (!q) return filtered;
  // Fuzzy rank: best match first. Pre-grouping keeps the score field-keyed
  // (cheap to recompute per row; total cost stays O(rows * fields)).
  const scored = [];
  for (const s of filtered) {
    const score = scoreSecret(q, s);
    if (score != null) scored.push({ s, score });
  }
  scored.sort((a, b) => b.score - a.score
    || a.s.issuer.localeCompare(b.s.issuer)
    || (a.s.account || '').localeCompare(b.s.account || ''));
  return scored.map((x) => x.s);
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

  // Mode-switch button: visible only when unlocked; label flips based on
  // current mode (button OFFERS the opposite action).
  const modeBtn = $('#mode-btn');
  if (modeBtn) {
    modeBtn.hidden = !s.unlocked;
    $('#mode-btn-label', modeBtn).textContent =
      s.mode === 'password' ? t('mode_btn_disable') : t('mode_btn_set');
  }
  // Re-entry into the unlock dialog. The dialog can be dismissed via
  // Cancel, leaving the user on an empty main view with no way back —
  // show this button whenever the vault is locked so they can re-open
  // it. There is no server-side manual-lock endpoint, so the button
  // never means "lock" in the current build.
  const lockBtn = $('#lock-btn');
  if (lockBtn) lockBtn.hidden = !!s.unlocked;
}

async function loadStatus() {
  try {
    state.status = await api('/api/status');
  } catch (e) {
    state.status = { error: /** @type any */ (e).message || String(e) };
  }
  renderStatus();
  if (state.status && state.status.unlocked === false) ensureUnlocked();
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

const RING_LEN = 2 * Math.PI * 16;

function codeFmt(s) {
  const digits = String(s.digits || 6);
  return digits === s.code.length ? s.code : (s.code + ' '.repeat(digits)).slice(0, digits);
}

// Patch only the countdown visuals of an existing row — no rebuild, so
// hover / focus / selection on the row are never interrupted.
function updateRowCountdown(li, s) {
  li.classList.toggle('expired', s.remaining <= 0);
  li.classList.toggle('expiring', s.remaining > 0 && s.remaining <= 5);
  const num = $('.num', li);
  if (num && num.textContent !== String(s.remaining)) num.textContent = String(s.remaining);
  const prog = $('.progress', li);
  if (prog) {
    prog.setAttribute('stroke-dashoffset',
      (RING_LEN * (1 - Math.max(0, s.remaining) / s.period)).toFixed(2));
  }
  // Keep the expanded detail panel's timer in the same tick — no separate timer.
  const detSec = li.querySelector('.detail .sec');
  if (detSec && detSec.textContent !== String(s.remaining)) detSec.textContent = String(s.remaining);
}

function updateRow(li, s) {
  const codeBtn = $('.code', li);
  const fmt = codeFmt(s);
  if (!codeBtn.classList.contains('copied') && codeBtn.textContent !== fmt) {
    codeBtn.textContent = fmt;
  }
  const aria = t('code_aria', { digits: String(s.digits || 6), issuer: s.issuer });
  if (codeBtn.getAttribute('aria-label') !== aria) codeBtn.setAttribute('aria-label', aria);
  const q = state.filter.q.trim();
  const mIssuer = q ? fuzzyMatch(q, s.issuer) : null;
  const mAccount = q ? fuzzyMatch(q, s.account || '') : null;
  const mGroup = q ? fuzzyMatch(q, s.group_name || '') : null;
  const mNotes = q ? fuzzyMatch(q, s.notes || '') : null;
  const groupTag = s.group_id > 0 && s.group_name
    ? `<span class="tag">${mGroup ? highlight(s.group_name, mGroup.indices) : escapeHtml(s.group_name)}</span>` : '';
  const issuerHtml = `${mIssuer ? highlight(s.issuer || t('no_issuer'), mIssuer.indices) : escapeHtml(s.issuer || t('no_issuer'))}${groupTag}`;
  const issuerEl = $('.issuer', li);
  if (issuerEl.innerHTML !== issuerHtml) issuerEl.innerHTML = issuerHtml;
  const accountHtml = (mAccount ? highlight(s.account || '', mAccount.indices) : escapeHtml(s.account || ''))
    + (s.notes ? (mAccount ? ' · ' : ' · ') + (mNotes ? highlight(s.notes, mNotes.indices) : escapeHtml(s.notes)) : '');
  const accountEl = $('.account', li);
  if (accountEl.innerHTML !== accountHtml) accountEl.innerHTML = accountHtml;
  const cb = $('.pick-cb', li);
  const on = state.selected.has(s.id);
  if (cb.checked !== on) cb.checked = on;
  updateRowCountdown(li, s);
  fillDetail(li, s);
}

// Fill the inline detail panel from the same `s` the row uses — no extra
// request, so the panel can never disagree with the row about the code.
// Fields with no data are hidden wholesale (label included).
function fillDetail(li, s) {
  const det = $('.detail', li);
  if (!det) return;

  // Detail-panel labels and action buttons are baked into the row
  // template by createRow. renderSecrets is diff-based, so on a
  // language switch existing rows would otherwise keep the labels in
  // the old language. Re-apply translations on every fill — cheap,
  // and keeps detail-panel text in sync with the row data after a
  // language change.
  const accLabel = $('.detail-field-account .label', det);
  if (accLabel) accLabel.textContent = t('detail_account');
  const metaLabels = $$('.meta-row > div .label', det);
  if (metaLabels[0]) metaLabels[0].textContent = t('detail_algo');
  if (metaLabels[1]) metaLabels[1].textContent = t('detail_digits');
  if (metaLabels[2]) metaLabels[2].textContent = t('detail_period');
  const notesLabel = $('.detail-field-notes .label', det);
  if (notesLabel) notesLabel.textContent = t('detail_notes');
  const dCopy = $('.d-copy', det);
  if (dCopy) dCopy.textContent = t('copy');
  const dQr = $('.d-qr', det);
  if (dQr) dQr.textContent = t('qr_show');
  const dRefresh = $('.d-refresh', det);
  if (dRefresh) dRefresh.textContent = t('refresh_now');

  const q = state.filter.q.trim();
  const mAccount = q ? fuzzyMatch(q, s.account || '') : null;
  const mNotes = q ? fuzzyMatch(q, s.notes || '') : null;

  const accField = $('.detail-field-account', det);
  if (s.account && s.account.trim()) {
    accField.hidden = false;
    const el = $('.account-big', accField);
    const html = mAccount ? highlight(s.account, mAccount.indices) : escapeHtml(s.account);
    if (el.innerHTML !== html) el.innerHTML = html;
  } else {
    accField.hidden = true;
  }

  const metaValues = $$('.meta-row > div .value', det);
  metaValues[0].textContent = fmtAlgo(s.algorithm);
  metaValues[1].textContent = String(s.digits);
  metaValues[2].textContent = s.period + 's';

  const codeText = $('.detail-code .code-text', det);
  const fmt = codeFmt(s);
  if (codeText.textContent !== fmt) codeText.textContent = fmt;
  $('.detail-code', det).setAttribute('aria-label',
    t('detail_code_aria', { digits: String(s.digits || 6) }));

  const notesField = $('.detail-field-notes', det);
  if (s.notes && s.notes.trim()) {
    notesField.hidden = false;
    const el = $('.detail-notes', notesField);
    const html = mNotes ? highlight(s.notes, mNotes.indices) : escapeHtml(s.notes);
    if (el.innerHTML !== html) el.innerHTML = html;
  } else {
    notesField.hidden = true;
  }
}

function createRow(s) {
  const li = document.createElement('li');
  li.className = 'secret';
  li.dataset.id = s.id;
  li.tabIndex = 0;
  li.setAttribute('role', 'button');
  li.setAttribute('aria-expanded', 'false');
  if (s.remaining <= 0) li.classList.add('expired');
  else if (s.remaining <= 5) li.classList.add('expiring');

    const q = state.filter.q.trim();
    const mIssuer = q ? fuzzyMatch(q, s.issuer) : null;
    const mAccount = q ? fuzzyMatch(q, s.account || '') : null;
    const mGroup = q ? fuzzyMatch(q, s.group_name || '') : null;
    const mNotes = q ? fuzzyMatch(q, s.notes || '') : null;
    const groupTag = s.group_id > 0 && s.group_name
      ? `<span class="tag">${mGroup ? highlight(s.group_name, mGroup.indices) : escapeHtml(s.group_name)}</span>` : '';
    const issuerHtml = `${mIssuer ? highlight(s.issuer || t('no_issuer'), mIssuer.indices) : escapeHtml(s.issuer || t('no_issuer'))}${groupTag}`;
    const accountHtml = (mAccount ? highlight(s.account || '', mAccount.indices) : escapeHtml(s.account || ''))
      + (s.notes ? ' · ' + (mNotes ? highlight(s.notes, mNotes.indices) : escapeHtml(s.notes)) : '');
    const fmt = codeFmt(s);
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
                  stroke-dashoffset="${(RING_LEN * (1 - Math.max(0, s.remaining) / s.period)).toFixed(2)}"/>
        </svg>
        <span class="num">${Math.max(0, s.remaining)}</span>
      </div>
      <div class="who">
        <div class="issuer">${issuerHtml}</div>
        <div class="account">${accountHtml}</div>
      </div>
      <div class="code-wrap">
        <button class="code" type="button" title="${escapeHtml(t('copy_title_attr'))}" aria-label="${escapeHtml(t('code_aria', { digits: String(s.digits || 6), issuer: s.issuer }))}">${escapeHtml(fmt)}</button>
      </div>
      <div class="row-actions">
        <button class="icon-btn qr-btn" type="button" data-id="${escapeHtml(s.id)}" aria-label="${escapeHtml(t('qr_aria', { issuer: s.issuer }))}" title="${escapeHtml(t('qr_title'))}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3z"/><path d="M20 14v3"/><path d="M14 20h3"/><path d="M20 20h1"/></svg>
        </button>
        <button class="icon-btn edit" type="button" aria-label="${escapeHtml(t('edit_aria', { issuer: s.issuer }))}" title="${escapeHtml(t('edit_title_attr'))}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 1 1 3 3L7 19l-4 1 1-4Z"/></svg>
        </button>
      </div>
      <div class="detail">
        <div class="detail-inner">
          <div class="detail-grid">
            <div class="detail-field-account" ${s.account && s.account.trim() ? '' : 'hidden'}>
              <div class="label">${escapeHtml(t('detail_account'))}</div>
              <div class="account-big" title="${escapeHtml(t('copy_title_attr'))}">${escapeHtml(s.account || '')}</div>
            </div>
            <div class="meta-row">
              <div><span class="label">${escapeHtml(t('detail_algo'))}</span><span class="value">${escapeHtml(fmtAlgo(s.algorithm))}</span></div>
              <div><span class="label">${escapeHtml(t('detail_digits'))}</span><span class="value">${s.digits}</span></div>
              <div><span class="label">${escapeHtml(t('detail_period'))}</span><span class="value">${s.period}s</span></div>
            </div>
            <div class="detail-code-row">
              <div class="detail-code" tabindex="0" role="button" aria-label="${escapeHtml(t('detail_code_aria', { digits: String(s.digits || 6) }))}"><span class="code-text">${escapeHtml(fmt)}</span></div>
              <span class="timer"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg><span class="sec">${Math.max(0, s.remaining)}</span>s</span>
              <div class="detail-actions">
                <button class="btn d-copy" type="button">${escapeHtml(t('copy'))}</button>
                <button class="btn d-qr qr-btn" type="button" data-id="${escapeHtml(s.id)}">${escapeHtml(t('qr_show'))}</button>
                <button class="btn d-refresh" type="button">${escapeHtml(t('refresh_now'))}</button>
              </div>
            </div>
            <div class="detail-field-notes" ${s.notes && s.notes.trim() ? '' : 'hidden'}>
              <div class="label">${escapeHtml(t('detail_notes'))}</div>
              <div class="detail-notes" title="${escapeHtml(t('copy_title_attr'))}">${escapeHtml(s.notes || '')}</div>
            </div>
          </div>
        </div>
      </div>`;

    const codeBtn = $('.code', li);
    codeBtn.onclick = () => copyCode(s.id, codeBtn);
    $('.edit', li).onclick = () => openEdit(s);
    $('.pick-cb', li).onchange = (e) => {
      const on = /** @type {HTMLInputElement} */ (e.target).checked;
      if (on) state.selected.add(s.id); else state.selected.delete(s.id);
      updateSelectionUI();
    };
  // Detail panel: copy (big code or button), refresh via the normal diff-refresh
  // (race-free, same data source as the row). QR reuses the existing .qr-btn
  // delegation, so no wiring needed here.
  $('.detail-code', li).addEventListener('click', () => copyDetailCode(li, s.id));
  $('.d-copy', li).addEventListener('click', () => copyDetailCode(li, s.id));
  $('.d-refresh', li).addEventListener('click', () => { refreshSecrets(); });
  // Account / Notes are click-to-copy — selecting them by drag is fiddly.
  $('.account-big', li).addEventListener('click', (e) => {
    const txt = e.currentTarget.textContent.trim();
    if (txt) copyText(txt);
  });
  $('.detail-notes', li).addEventListener('click', (e) => {
    const txt = e.currentTarget.textContent.trim();
    if (txt) copyText(txt);
  });
  li.addEventListener('keydown', (e) => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target === li) {
      e.preventDefault();
      if (!document.body.classList.contains('selecting')) toggleExpand(s.id);
    }
  });
  updateRowCountdown(li, s);
  secretsUl.appendChild(li);
  return li;
}

// Diff-render: reuse existing rows by id, create/remove only what changed.
// Rebuilding the list every second (the old behavior) destroyed the node
// under the cursor each tick, which is what broke hover/click mid-refresh.
function renderSecrets() {
  const list = visibleSecrets();
  const hasData = state.secrets.length > 0;
  const noMatch = hasData && list.length === 0 && state.filter.q.trim() !== '';
  const trulyEmpty = !hasData; // no data at all → onboarding; filtered-empty keeps the existing copy
  emptyEl.hidden = !trulyEmpty && !noMatch;
  if (noMatch) {
    const titleEl = emptyEl.querySelector('h3');
    const bodyEl = emptyEl.querySelector('p');
    if (titleEl) titleEl.textContent = t('no_match_title');
    if (bodyEl) bodyEl.textContent = t('no_match_body', { q: state.filter.q.trim() });
  } else if (trulyEmpty) {
    // restore onboarding copy so toggling between no-data and no-match flips cleanly
    const titleEl = emptyEl.querySelector('h3');
    const bodyEl = emptyEl.querySelector('p');
    if (titleEl) titleEl.textContent = t('empty_title');
    if (bodyEl) bodyEl.textContent = t('empty_body');
  }
  secretsUl.hidden = list.length === 0;

  const wanted = new Set(list.map((s) => s.id));
  for (const li of $$('li.secret', secretsUl)) {
    if (!wanted.has(li.dataset.id)) li.remove();
  }
  const byId = new Map($$('li.secret', secretsUl).map((li) => [li.dataset.id, li]));
  for (const s of list) {
    const existing = byId.get(s.id);
    if (existing) updateRow(existing, s);
    else createRow(s);
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

async function copyCode(id, btn) {
  // If the code just rotated and the fresh fetch hasn't landed yet, the
  // button still shows last period's code — fetch first so we copy the
  // current one, not the expired one.
  const cur = state.secrets.find((x) => x.id === id);
  if (cur && cur.remaining <= 0) await refreshSecrets();
  // Copy the code that's CURRENTLY on the button, not whatever
  // `state.secrets` happens to hold: while `refreshSecrets()` is in
  // flight after `tickCountdown` detects a rotation, `state.secrets`
  // lags by up to one TOTP rotation. The button text is updated by
  // `updateRow` on every refresh, so `.textContent` is always the latest
  // displayed code.
  const code = btn.textContent.trim();
  if (!code || code === t('copied')) return;
  try {
    await navigator.clipboard.writeText(code);
    const previous = code;
    btn.classList.add('copied');
    btn.textContent = t('copied');
    // server-side touch (last_used) — fire and forget
    try { await api(`/api/code?id=${encodeURIComponent(id)}`); } catch (_) { /* ignore */ }
    toast(t('toast_copied'), 'good');
    setTimeout(() => {
      // Only clear the "Copied!" label. Let `updateRow` keep driving
      // the displayed code on the next tick — it always reads from
      // the fresh `state.secrets`, so we never restore a stale value.
      // If the code rotated during the Copied! window, skip the restore:
      // `updateRow` writes the fresh code as soon as the fetch lands.
      btn.classList.remove('copied');
      const fresh = state.secrets.find((x) => x.id === id);
      if (fresh && fresh.remaining > 0) btn.textContent = codeFmt(fresh);
      else if (!fresh) btn.textContent = previous; // fallback if the row was removed
    }, 900);
  } catch (e) {
    toast(t('toast_copy_failed', { err: e.message }), 'bad');
  }
}

// Copy plain text (account / notes) with the standard toast feedback.
function copyText(text) {
  navigator.clipboard.writeText(text).then(
    () => toast(t('toast_copied'), 'good'),
    (e) => toast(t('toast_copy_failed', { err: e.message }), 'bad'),
  );
}

/* -------- Inline detail expansion --------
 * One expanded row at a time. Closing: same row again, click elsewhere is a
 * no-op (only one open), ESC, or opening another row. Selection mode and
 * sub-controls (.pick / .row-actions / .code / .detail) never expand.
 */
let expandedId = null;

function toggleExpand(id) {
  expandedId = expandedId === id ? null : id;
  $$('.secret', secretsUl).forEach((r) => {
    const open = r.dataset.id === expandedId;
    r.classList.toggle('expanded', open);
    r.setAttribute('aria-expanded', String(open));
  });
}

// Delegated whole-row toggle. Attach once; the diff-render keeps rows alive.
secretsUl.addEventListener('click', (e) => {
  const row = e.target.closest('.secret');
  if (!row) return;
  if (e.target.closest('.pick, .row-actions, .code, .detail')) return;
  if (document.body.classList.contains('selecting')) return;
  toggleExpand(row.dataset.id);
});

document.addEventListener('keydown', (e) => {
  // Don't collapse a row while a modal is open — ESC belongs to the modal.
  if (e.key === 'Escape' && expandedId && !$('.scrim.show') && themePop.hidden) toggleExpand(expandedId);
});

// Copy from the detail panel: same race-free pattern as copyCode (fetch first
// if the code just rotated), but flashes .detail-code instead of the row button
// so the panel's span structure is never overwritten.
async function copyDetailCode(li, id) {
  const cur = state.secrets.find((x) => x.id === id);
  if (cur && cur.remaining <= 0) await refreshSecrets();
  const code = ($('.detail-code .code-text', li)?.textContent || '').trim();
  if (!code) return;
  try {
    await navigator.clipboard.writeText(code);
    const el = $('.detail-code', li);
    el.classList.add('copied');
    // server-side touch (last_used) — fire and forget
    try { api(`/api/code?id=${encodeURIComponent(id)}`); } catch (_) { /* ignore */ }
    toast(t('toast_copied'), 'good');
    setTimeout(() => el.classList.remove('copied'), 900);
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
    // While locked the unlock prompt is already showing; don't stack toasts.
    if (!(state.status && state.status.unlocked === false)) {
      toast(t('toast_load_failed', { err: /** @type any */ (e).message || String(e) }), 'bad');
    }
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
      // Mirror the theme flow: localStorage is a write-through cache for
      // snappy reloads within the same webview session, the server PUT is
      // the durable copy that survives `2fa gui` restarts.
      try { localStorage.setItem('2fa.lang', lang0); } catch (_) {}
      fetch('/api/preferences', { method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ theme: themeRoot.getAttribute('data-theme'), lang: lang0 }) })
        .catch(() => { /* network blip: next load retries from server */ });
      applyI18n();
      // Re-render dynamic content so any cached text refreshes.
      // renderStatus also rewrites #mode-btn-label (Set/Disable password)
      // which is mode-dependent — not picked up by data-i18n scanning.
      renderStatus();
      renderGroups();
      renderGroupSelects();
      renderSecrets();
      // If the Set Password dialog is open, re-translate its title / body /
      // labels / confirm-button. Inputs and the confirm checkbox stay as the
      // user left them.
      if (!modeScrim.hidden) setModeDialogLabels();
    });
  });

  $('#add-btn').addEventListener('click', () => openAdd(''));
  $('#scan-btn').addEventListener('click', startScan);
  $('#new-group-btn').addEventListener('click', createGroup);
  // Mode switch — opens dialog, posts to /api/mode, reloads on success.
  $('#mode-btn').addEventListener('click', openModeDialog);
  $$('#mode-dialog [data-mode]').forEach((b) => {
    b.addEventListener('click', () => {
      if (b.dataset.mode !== 'yes') { hideScrim(modeScrim); return; }
      submitModeSwitch();
    });
  });
  // Enter inside password fields triggers submit.
  ['#mode-pw', '#mode-pw2'].forEach((sel) => {
    $(sel).addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); submitModeSwitch(); }
    });
  });
  // Show / hide master password while typing it. Only flips input type;
  // value is preserved so the user keeps what they typed across toggles.
  const showPw = $('#mode-show');
  if (showPw) {
    showPw.addEventListener('change', (e) => {
      const t = e.target.checked ? 'text' : 'password';
      $('#mode-pw').type = t;
      $('#mode-pw2').type = t;
    });
  }
  // Submit button stays disabled until the user explicitly confirms.
  // Same gate for both directions (set / disable) — the rekey is
  // irreversible either way.
  $('#mode-confirm').addEventListener('change', (e) => {
    $('#mode-go').disabled = !e.target.checked;
  });
  // Re-open the unlock dialog from the top bar when the vault is locked.
  // renderStatus() controls visibility — the button only shows up when
  // !state.status.unlocked. No server-side manual-lock endpoint exists,
  // so the button never means "lock"; it only means "unlock".
  const lockBtn = $('#lock-btn');
  if (lockBtn) {
    lockBtn.addEventListener('click', () => { ensureUnlocked(); });
  }

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

  /* -------- Countdown --------
   * The server sends each code with its `remaining` seconds. Ticking the
   * countdown locally patches only the number + ring of existing rows —
   * no DOM rebuild — so hover / focus / selection are never interrupted.
   * We only re-fetch when a code rotates (remaining hits 0) or on a slow
   * background resync; renderSecrets() is diff-based, so even those
   * refreshes update rows in place.
   */
  const tickCountdown = () => {
    let rotated = false;
    for (const s of state.secrets) {
      s.remaining -= 1;
      if (s.remaining <= 0) rotated = true;
    }
    for (const li of $$('li.secret', secretsUl)) {
      const s = state.secrets.find((x) => x.id === li.dataset.id);
      if (s) updateRowCountdown(li, s);
    }
    if (rotated) refreshSecrets();
  };
  const scheduleTick = () => {
    // Align to the wall clock so we stay in step with the server's period.
    setTimeout(() => { tickCountdown(); scheduleTick(); }, 1000 - (Date.now() % 1000) + 15);
  };
  scheduleTick();
  setInterval(refreshSecrets, 60000); // background resync (diff-rendered, hover-safe)
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

  // Self-test: fuzzy search + highlight. Catches regressions where the
  // scoring drift demotes obvious matches or highlight injection escapes
  // out of <mark>. Cheap: 5 vectors, runs once at load.
  (function fuzzySelfTest() {
    const cases = [
      // [query, target, expected_first_index, must_contain_indices...]
      ['aws',    'amazon web services',      0,  [0, 7, 11]],
      ['git',   'GitHub',                   0,  [0, 1, 2]],
      ['amzn',  'amazon-work',              null, [0, 1, 3, 5]], // q not contiguous, must still match
      ['xyz',   'amazon',                   null, null],         // no match
      ['',      'anything',                 null, []],            // empty query → score 0
    ];
    let ok = true;
    for (const [q, tgt, firstIdx, idxs] of cases) {
      const m = fuzzyMatch(q, tgt);
      if (q === '') {
        if (!m || m.score !== 0 || m.indices.length !== 0) {
          console.error('fuzzy self-test FAILED (empty q):', m); ok = false;
        }
        continue;
      }
      if (idxs === null) {
        if (m !== null) { console.error('fuzzy self-test FAILED (expected null):', q, tgt, m); ok = false; }
        continue;
      }
      if (!m) { console.error('fuzzy self-test FAILED (no match):', q, tgt); ok = false; continue; }
      if (m.indices[0] !== firstIdx) {
        console.error('fuzzy self-test FAILED (first idx):', q, tgt, 'got', m.indices[0], 'want', firstIdx); ok = false;
      }
      for (const want of idxs) {
        if (!m.indices.includes(want)) {
          console.error('fuzzy self-test FAILED (missing idx):', q, tgt, 'want', want, 'got', m.indices); ok = false;
        }
      }
      // Highlight should escape hostile input and never produce unescaped < or >.
      const html = highlight('<script>', m.indices);
      if (html.includes('<script>')) {
        console.error('highlight self-test FAILED (XSS):', html); ok = false;
      }
    }
    if (ok) console.log('fuzzy self-test ok');
  })();
});