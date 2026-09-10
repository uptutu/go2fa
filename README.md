# 2fa — Cross-platform TOTP Manager

<p align="center"><img src="assets/logo-wordmark.svg" alt="go2fa" width="360"></p>

A single-binary, encrypted TOTP vault with three front-ends — interactive
TUI, Web UI, and Desktop GUI — all sharing the same Go core.

* Module: [`github.com/uptutu/go2fa`](https://github.com/uptutu/go2fa)
* License: MIT
* Go: 1.27+

```
$ 2fa init                  # initialize vault at ~/.2fa/
$ 2fa add --uri "otpauth://totp/GitHub:me?secret=..."
$ 2fa list                  # show all codes with remaining seconds
$ 2fa copy GitHub           # print code, copy to clipboard
$ 2fa tui                   # interactive terminal UI
$ 2fa web                   # browser-based UI
$ 2fa gui                   # same web UI, opens desktop browser
$ 2fa export --format aegis --out backup.json
$ 2fa export --format .2fa --out backup.2fa    # password-encrypted
$ 2fa import backup.json
```

---

## Features

- **Encrypted at rest** — Argon2id key derivation + AES-256-GCM row-level
  encryption of every sensitive field (secret, notes, backup codes).
  Plaintext fields (issuer, account, group) stay indexable so SQL can sort
  and filter.
- **Two vault modes**
  - `password` (recommended): Argon2id KEK from your master password.
  - `no-password`: machine-bound KEK derived from `/etc/machine-id`
    (Linux), `IOPlatformUUID` (macOS), or `MachineGuid` (Windows),
    persisted to a `0600` file. Convenience for local dev / kiosk —
    **not safe** if an attacker can read your disk and copy the machine id.
- **Three front-ends, one binary**
  - `2fa tui` — bubbletea TUI (alt-screen, vim keys, filter, groups).
  - `2fa web` — embedded HTTP server + browser SPA, with `X-No-Password`
    bypass for local dev.
  - `2fa gui` — same UI, opens the default browser (alias for `web`).
- **Standard interop**
  - Export: `.2fa` (our encrypted JSON), Aegis JSON, `otpauth://` URI list.
  - Import: auto-detects format from file content (`.2fa` / Aegis /
    encrypted Aegis / `otpauth://` URIs).
- **Camera QR scan** in the Web UI via `getUserMedia` + jsQR
  (`make vendor-jsqr` fetches the vendored library).
- **Clipboard auto-copy** — `pbcopy` / `wl-copy` / `xclip` / `xsel` / `clip`,
  no-op if none is installed.
- **Groups** with custom hex colors; secrets without a group show under
  `Unassigned`.
- **Backup codes** — per-secret encrypted list (e.g. one-time recovery codes).
- **Web auth modes**
  - `127.0.0.1` listen: no auth required (loopback-only).
  - Non-loopback (`--listen 0.0.0.0:8080`): requires an `X-Auth-Token`
    header (random token printed to stderr at startup).
  - `--no-password` vault + `X-No-Password: true` header: bypass for
    local dev only.

---

## Install

### Pre-built binaries

Download from the
[Releases page](https://github.com/uptutu/go2fa/releases/latest)
(Linux / macOS / Windows, amd64 + arm64):

```sh
# Linux / macOS
curl -L https://github.com/uptutu/go2fa/releases/latest/download/2fa_$(uname -s | tr A-Z a-z)_amd64.tar.gz -o 2fa.tar.gz
tar xzf 2fa.tar.gz 2fa && sudo mv 2fa /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest https://github.com/uptutu/go2fa/releases/latest/download/2fa_windows_amd64.tar.gz -OutFile 2fa.tar.gz
```

### From source

```sh
go install github.com/uptutu/go2fa@latest
```

The same binary includes all three front-ends.

---

## Quickstart

```sh
2fa init                     # prompts: password (recommended) or machine-bound
2fa add --uri "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
2fa tui                      # or `2fa web` / `2fa gui`
```

### TUI keys

| Key              | Action                                   |
| ---------------- | ---------------------------------------- |
| `j` / `k`, arrows | Move selection                         |
| `/`              | Filter (type to narrow, `Esc` to clear)  |
| `g`              | Cycle group filter                       |
| `Enter`          | Copy current code (★ marks for 30 s)     |
| `d`              | Delete (with confirm)                    |
| `q`              | Quit                                     |

### Web / GUI

Open the printed URL in your browser. The UI shows live TOTP codes with
seconds-remaining bars. From the sidebar you can add, edit, group, delete,
and bulk-export selected secrets (checkbox multi-select).

---

## Command reference

```text
2fa init                                  Initialize a new vault
2fa unlock                                Prompt for password and unlock
2fa list                                  List all secrets with current codes
2fa add [<issuer> <account> <b32secret>]  Add a secret (positional args)
   --uri <otpauth-uri>                    …or pass an otpauth:// URI
   --group <name>                         Add into an existing group
2fa copy <issuer> [account]               Print code + copy to clipboard
2fa delete <uuid>                         Delete a secret by UUID
2fa edit <uuid>                           Edit fields (only set flags take effect)
   --issuer / --account / --notes / --backup
   --algorithm SHA1|SHA256|SHA512
   --digits 4..10  --period 5..120
   --group <name>  --secret <base32>
2fa group add <name> [--color #hex]
2fa group list
2fa group rename <id> <newname>
2fa group delete <id>
2fa export --format <.2fa|aegis|otpauth> --out <file|-> [--password <pw>]
2fa import <file|-> [--password <pw>]
2fa tui                                   Launch interactive TUI
2fa web [--listen <addr>] [--token <t>]   Launch embedded web server
2fa gui                                   Launch desktop GUI (native window)

Global flags:
  --no-password    Initialize a no-password (machine-bound) vault
  --listen <addr>  Address for `web` (default 127.0.0.1:<random>)
  --token <tok>    Auth token for non-loopback --listen (random if omitted)
```

---

## Vault location

Default: `~/.2fa/` (overridable via env if your build sets one).

Layout:

```
~/.2fa/
  vault.db           SQLite database (plaintext metadata + encrypted blobs)
  master.kek         KEK material for `--no-password` mode (0600)
```

- `vault.db` schema lives in `internal/core/vault/`.
- `master.kek` only exists when the vault was initialized with
  `--no-password`; password-mode vaults derive the KEK on demand.

---

## Threat model

See [THREAT_MODEL.md](./THREAT_MODEL.md).

The short version:

- ✅ 2fa protects against **disk theft** and **casual attackers**: the
  vault is useless without either the master password *or* the machine-id
  + `master.kek` file (no-password mode).
- ❌ 2fa does **not** protect against malicious code running as your user,
  kernel rootkits, or hardware attackers. If you need that, use a hardware
  token (YubiKey, Titan, etc.).

**Web LAN exposure**: `--listen 0.0.0.0:8080` is plaintext HTTP. Any host
on the LAN can sniff the auth token and your TOTP codes. Put a TLS
terminator (caddy / nginx / stunnel) in front, or bind to a trusted
interface only.

---

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md).

Three layers:

- `internal/core/` — vault store (SQLite + Argon2id + AES-GCM), TOTP
  generator, otpauth URI parser, import/export.
- `internal/tui/` — bubbletea program (Bubbles textinput / viewport /
  key.Binding / help).
- `internal/app/web/` — `net/http` server + `embed.FS` static SPA.

The same `*vault.Vault` is shared across all three front-ends.

---

## Build from source

```sh
make build           # ./2fa binary (includes 2fa gui native window)
make test            # go test ./...
make test-race       # go test -race ./...
make vet             # go vet ./...
make vendor-jsqr     # download jsQR.js for camera scan
make release         # goreleaser (linux / macOS / windows tarballs)
make clean           # remove ./2fa + dist/
```

### Cross-compile (without goreleaser)

```sh
GOOS=linux   GOARCH=amd64   go build -trimpath -o dist/2fa-linux-amd64   .
GOOS=linux   GOARCH=arm64   go build -trimpath -o dist/2fa-linux-arm64   .
GOOS=darwin  GOARCH=amd64   go build -trimpath -o dist/2fa-darwin-amd64  .
GOOS=darwin  GOARCH=arm64   go build -trimpath -o dist/2fa-darwin-arm64  .
GOOS=windows GOARCH=amd64   go build -trimpath -o dist/2fa-windows.exe    .
```

The binary is fully static (`CGO_ENABLED=0` by goreleaser); no libc
dependency.

---

## Platform notes

### Linux

`2fa tui` and `2fa web` need nothing extra. `2fa gui` (native window)
loads `libwebkit2gtk-4.1` at runtime via glaze — no build tag, no
compile-time dependency.

```sh
# Debian / Ubuntu
sudo apt install libwebkit2gtk-4.1-dev   # only for 2fa gui

# Arch
sudo pacman -S webkit2gtk-4.1            # only for 2fa gui
```

The native window uses the system default icon for now; the
`assets/icon.svg` is only exposed to the Web UI as `/favicon.svg` so
browser tabs match the brand.

### macOS

Zero dependencies. Codesign is recommended but optional for personal use
(users can right-click → Open the first time).

### Windows

Zero dependencies. WebView2 (pre-installed on Win10+, auto-update).

---

## Releases

Tagged semver tags (`v0.1.0`, …) are pushed to **both** remotes:

- `origin` → internal GitLab
- `uptutu` → public GitHub: <https://github.com/uptutu/go2fa/releases>

goreleaser builds 6 tarballs per tag (linux/darwin/windows × amd64/arm64)
and creates the GitHub Release with an auto-generated changelog. See
`.goreleaser.yaml` for the exact pipeline.

---

## License

MIT. See [LICENSE](./LICENSE).
