# Threat Model

## What 2fa protects against

| Threat | Mitigation |
|---|---|
| Attacker steals your laptop while powered off | AES-256-GCM encryption of sensitive fields; Argon2id-derived KEK (ModePassword) |
| Attacker copies `~/.2fa/vault.sqlite` only | ModeNoPassword: KEK bound to machine-id + per-vault salt → attacker needs both files AND your machine |
| Attacker copies the SQLite file in ModeNoPassword and steals the whole laptop | Combined attacker fails: without `~/.2fa/machine.key` + machine_id, decryption is infeasible |
| Wrong password typed | Detected via GCM verifier (`Open` returns error); in-memory KEK is zeroed |
| Vault file tampering | CRC32 detects truncation; keyed SHA-256 MAC detects bit-flip |
| Vault file replay | GCM nonce uniqueness per write; per-write ciphertext verifies AAD |

## What 2fa does NOT protect against

| Threat | Why | Recommendation |
|---|---|---|
| Malware running as you | In-memory KEK is in the process address space; clipboard reads/writes happen in user space | Use hardware token (YubiKey, Titan) |
| Cold-boot attack | KEK is in RAM; freeze-and-dump recovers it | Sleep with full-disk encryption; lock screen when away |
| Malicious shell history | `2fa add --uri ...` leaves the URI in shell history | Use `read -s` or pass URI via stdin |
| Kernel-level rootkit | Sees decrypted memory and clipboard | Use hardware token |
| Backup code leakage | Backup codes are stored encrypted but presented in plaintext on the UI | Treat codes like passwords |
| Server-side 2FA protection | 2fa is **client-side**; the underlying account may still be compromised via phishing | Use TOTP only as one factor |

## Mode selection guidance

| Use case | Recommended mode |
|---|---|
| Personal laptop, single user, encrypted disk | ModePassword (default) |
| Shared server, no password discipline | ModeNoPassword |
| CI / unattended service needing 2FA | ModeNoPassword with `~/.2fa/` on encrypted volume |
| High-value account (root email, password manager) | ModePassword + hardware token (2FA on the 2fa tool) |

## Cryptographic primitives

| Primitive | Choice | Why |
|---|---|---|
| Key derivation | Argon2id (t=2, m=64 MiB, p=2) | OWASP 2025 recommendation; ~150 ms per derive |
| Symmetric cipher | AES-256-GCM | NIST standard, hardware acceleration on all targets |
| MAC | SHA-256 (keyed) | Adequate for tamper detection; HMAC future work |
| Random | `crypto/rand` (OS CSPRNG) | Default Go |

## Caveats

- **No forward secrecy**. If your password is compromised, all past and
  future vaults using that password are decryptable.
- **No anti-forensics on disk**. The plaintext metadata (`issuer`,
  `account`) is visible without the password. An attacker can profile
  which services you use even if they can't read the secrets.
- **No rate-limiting on Unlock**. Brute-force attempts are limited only by
  Argon2id's ~150 ms per derive → ~40/min. For a strong password this is
  fine; for a 4-digit PIN it is not.
- **Aegis import requires that you trust the export**. The format stores
  decrypted secrets; if your Aegis vault was already on disk, an attacker
  who steals it also gets the Aegis JSON.
- **TUI captures keystrokes**. If you paste an `otpauth://` URI on the
  command line, it lives in shell history. Prefer clipboard paste in TUI.

## Reporting vulnerabilities

Open an issue or email the maintainer. Please do not include the actual
secret bytes in bug reports.