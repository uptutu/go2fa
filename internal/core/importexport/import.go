// Package importexport handles import and export of vault contents in three
// formats:
//
//   - .2fa       binary container, password-encrypted (crypto.SealExport / OpenExport)
//   - Aegis JSON plaintext backup format (encrypted or unencrypted JSON)
//   - otpauth:// URI list (one URI per line)
//
// The Sniff function inspects a file/blob and returns the appropriate
// parser. Plaintext JSON with no "version" or "db" field is treated as
// unencrypted Aegis export. Encrypted JSON Aegis exports have a top-level
// "version" and "header"/"db" structure; we detect that and decrypt with
// a passphrase.
//
// Aegis spec reference:
//   https://github.com/beemdevelopment/Aegis/blob/master/docs/backup.md
package importexport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"2fa/internal/core/crypto"
	"2fa/internal/core/otpauth"
	"2fa/internal/core/totp"
	"2fa/internal/core/vault"
)

// Format describes the detected source format.
type Format int

const (
	FormatUnknown Format = iota
	Format2FA             // our own binary container
	FormatAegisPlain      // unencrypted Aegis JSON
	FormatAegisEncrypted  // password-encrypted Aegis JSON
	FormatOtpauth         // newline-separated otpauth:// URIs
)

// Sniff detects the format from raw bytes (already read into memory).
func Sniff(buf []byte) Format {
	if len(buf) == 0 {
		return FormatUnknown
	}
	if len(buf) >= 4 && [4]byte{buf[0], buf[1], buf[2], buf[3]} == crypto.Magic {
		return Format2FA
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(buf, &probe); err == nil {
		if _, hasVersion := probe["version"]; hasVersion {
			if _, hasDB := probe["db"]; hasDB {
				return FormatAegisEncrypted
			}
		}
		if _, hasEntries := probe["entries"]; hasEntries {
			return FormatAegisPlain
		}
	}
	if bytes.HasPrefix(bytes.TrimSpace(buf), []byte("otpauth://")) {
		return FormatOtpauth
	}
	return FormatUnknown
}

// DetectFile reads the file (or stdin if path == "-") and returns its format.
func DetectFile(path string) (Format, []byte, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return FormatUnknown, nil, err
	}
	return Sniff(data), data, nil
}

// ImportResult holds the secrets and groups parsed from any source.
type ImportResult struct {
	Groups  []vault.Group
	Secrets []vault.Secret
}

// Import imports data from buf using the supplied password (only used for
// Format2FA / FormatAegisEncrypted). Returns the parsed result.
func Import(buf []byte, password string) (ImportResult, error) {
	switch Sniff(buf) {
	case Format2FA:
		return import2FA(buf, password)
	case FormatAegisPlain:
		return importAegisPlain(buf)
	case FormatAegisEncrypted:
		return importAegisEncrypted(buf, password)
	case FormatOtpauth:
		return importOtpauth(buf)
	}
	return ImportResult{}, errors.New("importexport: unrecognized format")
}

// import2FA decrypts our own export container; the plaintext is an Aegis
// JSON payload (so the inner plaintext schema is shared).
func import2FA(buf []byte, password string) (ImportResult, error) {
	plain, err := crypto.OpenExport(password, buf)
	if err != nil {
		return ImportResult{}, err
	}
	return importAegisPlain(plain)
}

// AegisPlain mirrors Aegis's unencrypted JSON backup schema.
type AegisPlain struct {
	Version int          `json:"version"`
	Entries []AegisEntry `json:"entries"`
	Groups  []AegisGroup `json:"groups"`
}

// AegisGroup is Aegis's group record.
type AegisGroup struct {
	UUID   string `json:"uuid"`
	Name   string `json:"name"`
	Parent string `json:"parent,omitempty"`
}

// AegisEntry is one TOTP secret. We only model the fields we use.
type AegisEntry struct {
	Type   string `json:"type"`
	UUID   string `json:"uuid"`
	Name   string `json:"name"`
	Issuer string `json:"issuer"`
	Group  string `json:"group"`
	Info   struct {
		Secret string `json:"secret"`
		Algo   string `json:"algo"`
		Digits int    `json:"digits"`
		Period int    `json:"period"`
	} `json:"info"`
	Note string `json:"note"`
}

func importAegisPlain(buf []byte) (ImportResult, error) {
	var p AegisPlain
	if err := json.Unmarshal(buf, &p); err != nil {
		return ImportResult{}, fmt.Errorf("importexport: aegis json: %w", err)
	}
	var out ImportResult
	for _, ge := range p.Groups {
		out.Groups = append(out.Groups, vault.Group{Name: ge.Name})
	}
	for _, e := range p.Entries {
		sec, err := aegisEntryToSecret(e)
		if err != nil {
			return ImportResult{}, fmt.Errorf("entry %s: %w", e.Name, err)
		}
		sec.Notes = []byte(e.Note)
		out.Secrets = append(out.Secrets, sec)
	}
	return out, nil
}

// AegisEncrypted: top-level version + header + db (base64).
type AegisEncrypted struct {
	Version int             `json:"version"`
	Header  json.RawMessage `json:"header"`
	DB      string          `json:"db"` // base64
}

// AegisEncryptedHeader holds the slots for KDF params.
type AegisEncryptedHeader struct {
	Slots []AegisSlot `json:"slots"`
}

// AegisSlot is one password slot in Aegis's KDF.
type AegisSlot struct {
	UUID     string `json:"uuid"`
	Type     int    `json:"type"`
	N        int    `json:"n"`
	R        int    `json:"r"`
	P        int    `json:"p"`
	Salt     string `json:"salt"`   // base64
	Secret   string `json:"secret"` // base64, encrypted key
	KeyParams struct {
		Nonce string `json:"nonce"`
		Tag   string `json:"tag"`
	} `json:"key_params"`
}

func importAegisEncrypted(buf []byte, password string) (ImportResult, error) {
	var p AegisEncrypted
	if err := json.Unmarshal(buf, &p); err != nil {
		return ImportResult{}, fmt.Errorf("importexport: aegis enc: %w", err)
	}
	var h AegisEncryptedHeader
	if err := json.Unmarshal(p.Header, &h); err != nil {
		return ImportResult{}, fmt.Errorf("aegis header: %w", err)
	}
	if len(h.Slots) == 0 {
		return ImportResult{}, errors.New("aegis enc: no KDF slots")
	}
	slot := h.Slots[0]
	if slot.Type != 2 {
		return ImportResult{}, fmt.Errorf("aegis KDF type %d not supported (need Argon2id=2)", slot.Type)
	}
	plain, err := decryptAegisSlot(slot, password, p.DB)
	if err != nil {
		return ImportResult{}, err
	}
	return importAegisPlain(plain)
}

// decryptAegisSlot derives KEK from password, decrypts the slot's encrypted
// key (the actual DB encryption key), then decrypts the DB payload.
func decryptAegisSlot(slot AegisSlot, password, dbB64 string) ([]byte, error) {
	salt, err := decodeB64(slot.Salt)
	if err != nil {
		return nil, fmt.Errorf("aegis salt: %w", err)
	}
	slotSecret, err := decodeB64(slot.Secret)
	if err != nil {
		return nil, err
	}
	kek := argon2idKey(password, salt, uint32(slot.N), uint32(slot.R), uint8(slot.P), 32)
	// AAD per Aegis spec is the slot's UUID.
	dbKey, err := gcmDecrypt(kek, slotSecret, []byte(slot.UUID))
	if err != nil {
		return nil, fmt.Errorf("aegis: wrong password or corrupted slot: %w", err)
	}
	db, err := decodeB64(dbB64)
	if err != nil {
		return nil, err
	}
	return gcmDecrypt(dbKey, db, []byte("aegis encrypted db"))
}

func importOtpauth(buf []byte) (ImportResult, error) {
	var out ImportResult
	for i, line := range strings.Split(string(buf), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := otpauth.Parse(line)
		if err != nil {
			return ImportResult{}, fmt.Errorf("line %d: %w", i+1, err)
		}
		out.Secrets = append(out.Secrets, vault.Secret{
			Issuer:    u.Issuer,
			Account:   u.Account,
			SecretRaw: u.Secret,
			Algorithm: u.Algorithm,
			Digits:    u.Digits,
			Period:    u.Period,
		})
	}
	return out, nil
}

func aegisEntryToSecret(e AegisEntry) (vault.Secret, error) {
	if e.Type != "totp" {
		return vault.Secret{}, fmt.Errorf("unsupported type %q", e.Type)
	}
	algo, err := parseAlgoName(e.Info.Algo)
	if err != nil {
		return vault.Secret{}, err
	}
	secret, err := decodeAegisSecret(e.Info.Secret)
	if err != nil {
		return vault.Secret{}, fmt.Errorf("secret: %w", err)
	}
	digits := e.Info.Digits
	if digits == 0 {
		digits = 6
	}
	period := e.Info.Period
	if period == 0 {
		period = 30
	}
	return vault.Secret{
		Issuer:    e.Issuer,
		Account:   e.Name,
		SecretRaw: secret,
		Algorithm: algo,
		Digits:    digits,
		Period:    period,
	}, nil
}

func parseAlgoName(s string) (totp.Algo, error) {
	switch strings.ToUpper(s) {
	case "SHA1":
		return totp.SHA1, nil
	case "SHA256":
		return totp.SHA256, nil
	case "SHA512":
		return totp.SHA512, nil
	}
	return 0, fmt.Errorf("unknown algorithm %q", s)
}