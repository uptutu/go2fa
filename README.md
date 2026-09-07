# 2fa — Cross-platform TOTP Manager

A single-binary, encrypted TOTP vault with three front-ends: TUI, Desktop
GUI, and Web UI — all sharing the same Go core.

```
$ 2fa init                  # initialize vault at ~/.2fa/
$ 2fa add --uri "otpauth://totp/GitHub:me?secret=..."
$ 2fa list                  # show all codes
$ 2fa copy GitHub           # print code, copy to clipboard
$ 2fa tui                   # interactive terminal UI
$ 2fa web                   # browser-based UI
$ 2fa gui                   # desktop GUI (browser-based for v1)
$ 2fa export --format aegis --out backup.json
$ 2fa export --format .2fa --out backup.2fa    # password-encrypted
$ 2fa import backup.json
```

## Features

- **Encrypted at rest** — Argon2id key derivation + AES-256-GCM row-level
  encryption of all sensitive fields (secret, notes, backup codes). Plaintext
  fields (issuer, account, group) remain indexable so SQL can sort/filter.
- **Two modes** — password-protected (recommended) or machine-bound (no
  password; KEK derived from /etc/machine-id and persisted to a 0600 file).
- **Three front-ends, one binary** — bubbletea TUI, browser-based Web UI,
  Desktop GUI. Switch with `2fa tui` / `2fa web` / `2fa gui`.
- **Standard interop** — import/export `.2fa` (our encrypted format),
  Aegis JSON (open-source standard), and `otpauth://` URI lists.
- **Camera QR scan** in the Web/Desktop UI via `getUserMedia` + jsQR
  (vendored separately; see `make vendor-jsqr`).
- **Clipboard auto-copy** via `pbcopy`/`wl-copy`/`xclip`/`xsel`/`clip`.
- **Groups** with custom colors; "Unassigned" gets a default highlight.
- **Backup codes** — per-secret encrypted list (e.g. one-time recovery codes).
- **Local Web UI by default**, `--listen 0.0.0.0:8080 --token <random>` for
  LAN access with mandatory auth token.

## Install

### Pre-built binaries

Download from the Releases page (Linux/macOS/Windows, amd64+arm64):

```sh
# Linux/macOS
curl -L https://github.com/<org>/2fa/releases/latest/download/2fa-$(uname -s | tr A-Z a-z)-amd64 -o 2fa
chmod +x 2fa && sudo mv 2fa /usr/local/bin/
```

### From source

```sh
go install github.com/<org>/2fa/cmd/2fa@latest
```

Requires Go 1.27+.

## Quickstart

```sh
2fa init                     # answer the prompts (password recommended)
2fa add --uri "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
2fa tui
```

In the TUI:
- `j/k` or arrows: move
- `/`: filter (then type, Esc to clear)
- `g`: cycle group
- `Enter`: copy current code (★ marks recently copied for 30 s)
- `d`: delete
- `q`: quit

## Threat model

See [THREAT_MODEL.md](./THREAT_MODEL.md).

The short version: 2fa protects against disk theft and casual attackers.
It does **not** protect against malicious code running as your user, kernel
rootkits, or hardware attackers. If you need that, use a hardware token
(YubiKey, Titan) instead of TOTP.

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md).

## Build from source

```sh
make build           # ./2fa binary
make test            # all tests
make lint            # go vet + gofmt
make vendor-jsqr     # download jsQR.js for camera scan
make release         # goreleaser (linux/macOS/windows tarballs)
```

### Cross-compile

```sh
# Linux from macOS
GOOS=linux GOARCH=amd64 go build -o dist/2fa-linux ./cmd/2fa

# Windows from Linux
GOOS=windows GOARCH=amd64 go build -o dist/2fa.exe ./cmd/2fa

# Native WebView GUI (Linux needs webkit2gtk-4.1-dev, macOS/Windows zero-deps)
go build -tags=webview -o 2fa-gui ./cmd/2fa
```

## Platform notes

### Linux

```sh
# Required for native webview build (-tags=webview)
sudo apt install libwebkit2gtk-4.1-dev
# Arch
sudo pacman -S webkit2gtk-4.1
```

### macOS

Zero dependencies. Codesign is recommended but optional for personal use
(users can right-click → Open the first time).

### Windows

Zero dependencies. Uses WebView2 (pre-installed on Win10+; auto-update).

## License

MIT. See [LICENSE](./LICENSE).