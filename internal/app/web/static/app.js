// 2fa Web UI — vanilla JS, no framework. Talks to /api/* on the same origin.

const $ = (s) => document.querySelector(s);

let cached = [];

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function refresh() {
  cached = await api('/api/secrets');
  render();
}

function render() {
  const ul = $('#secrets');
  ul.innerHTML = '';
  for (const s of cached) {
    const li = document.createElement('li');
    const left = document.createElement('div');
    left.innerHTML = `<div class="issuer">${escapeHtml(s.issuer)}</div>
                      <div class="account">${escapeHtml(s.account || '')}</div>`;
    const bar = document.createElement('div');
    bar.className = 'bar';
    bar.style.setProperty('--pct', `${(s.remaining / s.period) * 100}%`);
    const code = document.createElement('div');
    code.className = 'code';
    code.textContent = s.code;
    code.title = 'click to copy';
    code.onclick = async () => {
      await navigator.clipboard.writeText(s.code);
      code.style.background = '#4ade80';
      setTimeout(() => (code.style.background = ''), 400);
      api(`/api/code?id=${s.id}`);
    };
    li.appendChild(left);
    li.appendChild(bar);
    li.appendChild(code);
    ul.appendChild(li);
  }
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

async function addViaUri() {
  const uri = $('#uri').value.trim();
  if (!uri) return;
  try {
    await api('/api/secrets', { method: 'POST', body: JSON.stringify({ uri }) });
    $('#uri').value = '';
    refresh();
  } catch (e) {
    alert('add failed: ' + e.message);
  }
}

async function addManual() {
  const issuer = $('#manual-issuer').value.trim();
  const account = $('#manual-account').value.trim();
  const secret = $('#manual-secret').value.trim();
  if (!issuer || !secret) {
    alert('issuer and secret are required');
    return;
  }
  try {
    await api('/api/secrets', {
      method: 'POST',
      body: JSON.stringify({ issuer, account, secret, algorithm: 'SHA1', digits: 6, period: 30 }),
    });
    $('#manual-issuer').value = '';
    $('#manual-account').value = '';
    $('#manual-secret').value = '';
    refresh();
  } catch (e) {
    alert('add failed: ' + e.message);
  }
}

let stream = null;
async function scanQR() {
  const qr = $('#qr');
  qr.classList.toggle('show');
  if (!qr.classList.contains('show')) {
    if (stream) { stream.getTracks().forEach((t) => t.stop()); stream = null; }
    return;
  }
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    const v = document.getElementById('video');
    v.srcObject = stream;
    tick();
  } catch (e) {
    alert('camera: ' + e.message);
  }
}

function tick() {
  if (!stream) return;
  const v = document.getElementById('video');
  const canvas = document.getElementById('canvas');
  if (v.readyState === v.HAVE_ENOUGH_DATA) {
    canvas.width = v.videoWidth;
    canvas.height = v.videoHeight;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(v, 0, 0, canvas.width, canvas.height);
    const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(img.data, img.width, img.height);
    if (code && code.data.startsWith('otpauth://')) {
      $('#uri').value = code.data;
      if (stream) { stream.getTracks().forEach((t) => t.stop()); stream = null; }
      $('#qr').classList.remove('show');
      addViaUri();
      return;
    }
  }
  requestAnimationFrame(tick);
}

async function init() {
  try {
    const st = await api('/api/status');
    $('#status').textContent =
      `${st.unlocked ? '🔓 unlocked' : '🔒 locked'} · ${st.mode} · ${st.addr}`;
  } catch (e) {
    $('#status').textContent = 'error: ' + e.message;
  }
  await refresh();
  setInterval(refresh, 1000);
}

document.getElementById('add-uri-btn').onclick = addViaUri;
document.getElementById('add-manual-btn').onclick = addManual;
document.getElementById('scan-btn').onclick = scanQR;

init();