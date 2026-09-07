// Package vault provides the encrypted SQLite-backed TOTP vault.
//
// Layered as:
//   model.go    — domain types (Group, Secret, plain/in-memory only)
//   store.go    — SQLite I/O + row-level encryption wrappers
//   vault.go    — Open/Unlock/Lock, KEK derivation, in-memory cache, migrations
package vault

import (
	"time"

	"github.com/google/uuid"

	"2fa/internal/core/totp"
)

// VaultMode reflects whether a password is required.
type VaultMode int

const (
	// ModeNoPassword uses a machine-bound KEK (no user password).
	// Suitable for low-risk personal devices; protects against pure
	// database-file theft but not against local privilege escalation.
	ModeNoPassword VaultMode = iota
	// ModePassword uses Argon2id(password, salt) as the KEK.
	ModePassword
)

// Group is a single-level folder for secrets. ID 0 means "Unassigned".
type Group struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Color     string    `json:"color"`     // hex like "#7c3aed"; empty means default
	SortOrder int       `json:"sort_order"`
	CreatedAt time.Time `json:"created_at"`
}

// Secret is the in-memory representation. SecretRaw, Notes, BackupCodes
// stay as []byte (already decrypted) for the duration the vault is open;
// they are zeroed on Lock().
type Secret struct {
	ID          uuid.UUID
	GroupID     int64 // 0 = unassigned
	Issuer      string
	Account     string
	SecretRaw   totp.Secret // base32-decoded; sensitive
	Algorithm   totp.Algo
	Digits      int
	Period      int
	Notes       []byte // sensitive (free-form)
	BackupCodes []byte // sensitive (JSON array or newline-joined)
	LastUsedAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Meta describes the vault-level state stored in ~/.2fa/vault.json (small,
// unencrypted metadata — only the KEK salt + mode, never the KEK itself).
type Meta struct {
	Mode          VaultMode
	KDFSalt       []byte // 16 bytes; for both password & machine-key modes
	ArgonTime     uint32
	ArgonMemory   uint32
	ArgonThreads  uint8
	Verifier      []byte // GCM-sealed "OK" under KEK, used to detect wrong pw
	VerifierNonce []byte
	CreatedAt     time.Time
	UpdatedAt     time.Time
	SchemaVersion int
}