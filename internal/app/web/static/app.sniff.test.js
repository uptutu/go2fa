// Smoke test for sniffFormat — mirrors the Go TestSniff* cases in
// internal/core/importexport/importexport_test.go. Run with: node app.sniff.test.js
// We inline the function (instead of importing app.js, which is browser-only)
// so this stays a pure check of the detection rules.

async function sniffFormat(buf) {
  if (buf.length >= 4 && buf[0] === 0x32 && buf[1] === 0x46 && buf[2] === 0x41 && buf[3] === 0x01) {
    return { id: '2fa', needsPassword: true };
  }
  let probe = null;
  try { probe = JSON.parse(new TextDecoder().decode(buf)); } catch { /* not JSON */ }
  if (probe && typeof probe === 'object') {
    if ('version' in probe && 'db' in probe) {
      return { id: 'aegis-enc', needsPassword: true };
    }
    if ('entries' in probe) {
      return { id: 'aegis-plain', needsPassword: false };
    }
  }
  const head = new TextDecoder().decode(buf.subarray(0, Math.min(buf.length, 256))).trimStart();
  if (head.startsWith('otpauth://')) {
    return { id: 'otpauth', needsPassword: false };
  }
  return { id: 'unknown', needsPassword: false };
}

const cases = [
  // .2fa magic → encrypted
  { name: '2fa magic', buf: Uint8Array.of(0x32, 0x46, 0x41, 0x01, 0, 0), expect: { id: '2fa', needsPassword: true } },
  // Aegis plaintext (entries[]) → no password
  { name: 'aegis plaintext', buf: new TextEncoder().encode(JSON.stringify({ version: 1, entries: [] })), expect: { id: 'aegis-plain', needsPassword: false } },
  // Aegis encrypted (version+db) → password required (matches Go TestAPIImportRejectsEncryptedWithoutPassword)
  { name: 'aegis encrypted', buf: new TextEncoder().encode(JSON.stringify({ version: 1, header: { slots: [] }, db: '' })), expect: { id: 'aegis-enc', needsPassword: true } },
  // otpauth URI list → no password
  { name: 'otpauth', buf: new TextEncoder().encode('otpauth://totp/Acme?secret=ABC\notpauth://hotp/X?secret=DEF\n'), expect: { id: 'otpauth', needsPassword: false } },
  // Unknown junk → no password, server will reject
  { name: 'unknown', buf: new TextEncoder().encode('hello world'), expect: { id: 'unknown', needsPassword: false } },
];

let failed = 0;
for (const c of cases) {
  const got = await sniffFormat(c.buf);
  const ok = got.id === c.expect.id && got.needsPassword === c.expect.needsPassword;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${c.name.padEnd(20)} got=${JSON.stringify(got)}`);
  if (!ok) failed++;
}
process.exit(failed === 0 ? 0 : 1);
