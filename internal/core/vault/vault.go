package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"2fa/internal/core/crypto"
)

// DirName is the folder under $HOME where vault files live.
const DirName = ".2fa"

// DefaultDir returns the user's 2fa directory, creating it if missing.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, DirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// DatabasePath is the canonical SQLite file.
func DatabasePath() (string, error) {
	d, err := DefaultDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "vault.sqlite"), nil
}

// Vault wraps Store with high-level lifecycle (Init / Unlock / Lock).
// One Vault = one process; multiple vaults are not supported.
type Vault struct {
	*Store
	dir string
}

// Open opens the default vault database under ~/.2fa/vault.sqlite. If the
// file is brand-new, returns a Vault in a "blank" state — caller must
// call Init or UnlockWithPassword/UnlockMachineKey. Existing metadata is
// read but the KEK is NOT derived — caller must supply one.
func Open(ctx context.Context) (*Vault, error) {
	dir, err := DefaultDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "vault.sqlite")
	st, err := OpenStore(ctx, path, nil)
	if err != nil {
		return nil, err
	}
	return &Vault{Store: st, dir: dir}, nil
}

// Exists reports whether a vault database file is on disk.
func Exists() (bool, error) {
	path, err := DatabasePath()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Init initializes a brand-new vault with the chosen mode.
// ModeNoPassword derives KEK from host identity (or persisted machine.key).
// ModePassword derives KEK from password + fresh Argon2id salt.
func (v *Vault) Init(ctx context.Context, mode VaultMode, password string) error {
	m, err := v.LoadMeta(ctx)
	if err != nil {
		return err
	}
	if m.SchemaVersion != 0 {
		return errors.New("vault: already initialized")
	}
	m = Meta{
		Mode:          mode,
		KDFSalt:       crypto.RandomBytes(crypto.SaltLen),
		ArgonTime:     crypto.ArgonTime,
		ArgonMemory:   crypto.ArgonMemory,
		ArgonThreads:  crypto.ArgonThreads,
		SchemaVersion: currentSchemaVersion,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	var kek []byte
	switch mode {
	case ModePassword:
		if password == "" {
			return errors.New("vault: password mode requires non-empty password")
		}
		kek = crypto.DeriveKey(password, m.KDFSalt)
	case ModeNoPassword:
		kek, err = crypto.MachineKey(m.KDFSalt)
		if err != nil {
			// Fallback: persist a fresh random key on disk so the vault can
			// still open on hosts that have no /etc/machine-id (containers).
			kek, err = crypto.PersistMachineKey(v.dir)
			if err != nil {
				return fmt.Errorf("vault: no host identity and no machine.key: %w", err)
			}
		}
	default:
		return errors.New("vault: unknown mode")
	}
	ver, n, err := SealVerifier(kek)
	if err != nil {
		return err
	}
	m.Verifier = ver
	m.VerifierNonce = n
	if err := v.SaveMeta(ctx, m); err != nil {
		return err
	}
	v.Store.kek = kek
	return nil
}

// UnlockWithPassword derives the KEK from a password and verifies it.
func (v *Vault) UnlockWithPassword(ctx context.Context, password string) error {
	m, err := v.LoadMeta(ctx)
	if err != nil {
		return err
	}
	if m.SchemaVersion == 0 {
		return errors.New("vault: not initialized")
	}
	if m.Mode != ModePassword {
		return errors.New("vault: this vault is not password-protected")
	}
	kek := crypto.DeriveKey(password, m.KDFSalt)
	v.Store.kek = kek
	if err := v.VerifyKEK(ctx); err != nil {
		v.Store.Lock()
		return fmt.Errorf("vault: wrong password: %w", err)
	}
	return nil
}

// UnlockMachineKey derives the KEK from the host identity and verifies it.
func (v *Vault) UnlockMachineKey(ctx context.Context) error {
	m, err := v.LoadMeta(ctx)
	if err != nil {
		return err
	}
	if m.SchemaVersion == 0 {
		return errors.New("vault: not initialized")
	}
	if m.Mode != ModeNoPassword {
		return errors.New("vault: this vault requires a password")
	}
	kek, err := crypto.MachineKey(m.KDFSalt)
	if err != nil || kek == nil {
		kek, err = crypto.LoadMachineKey(v.dir)
		if err != nil || kek == nil {
			return errors.New("vault: machine key unavailable")
		}
	}
	v.Store.kek = kek
	if err := v.VerifyKEK(ctx); err != nil {
		v.Store.Lock()
		return err
	}
	return nil
}

// SetPassword transitions an unlocked vault from no-password to password
// mode. Re-encrypts every row under the new KEK.
//
// Implementation note (ponytail): we re-create from the in-memory cache
// rather than streaming re-encryption. Bounded by # of secrets which is
// typically small (<1000). Caller should export first if concerned.
func (v *Vault) SetPassword(ctx context.Context, newPassword string) error {
	if !v.IsUnlocked() {
		return errors.New("vault: locked")
	}
	if newPassword == "" {
		return errors.New("vault: password cannot be empty")
	}
	if err := v.reInitWith(ctx, ModePassword, newPassword); err != nil {
		return err
	}
	return nil
}

// DisablePassword transitions a vault from password mode to no-password.
// WARNING: weakens the vault to machine-bound only.
func (v *Vault) DisablePassword(ctx context.Context) error {
	if !v.IsUnlocked() {
		return errors.New("vault: locked")
	}
	return v.reInitWith(ctx, ModeNoPassword, "")
}

// reInitWith wipes and rebuilds the vault under a fresh KEK (different
// mode). Used by SetPassword and DisablePassword.
func (v *Vault) reInitWith(ctx context.Context, mode VaultMode, password string) error {
	secrets, err := v.ListSecrets(ctx)
	if err != nil {
		return err
	}
	groups, err := v.ListGroups(ctx)
	if err != nil {
		return err
	}
	for _, stmt := range []string{
		`DELETE FROM secrets`,
		`DELETE FROM groups`,
		`DELETE FROM kv_meta`,
	} {
		if _, err := v.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if err := v.Init(ctx, mode, password); err != nil {
		return err
	}
	idMap := make(map[int64]int64, len(groups))
	for _, g := range groups {
		g.ID = 0
		newID, err := v.CreateGroup(ctx, g)
		if err != nil {
			return err
		}
		idMap[g.ID] = newID
	}
	for i := range secrets {
		if newID, ok := idMap[secrets[i].GroupID]; ok {
			secrets[i].GroupID = newID
		}
	}
	for _, s := range secrets {
		if err := v.UpsertSecret(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// NewForTesting wraps an existing Store with a Vault (used by tests in
// other packages). Production code should call Open.
func NewForTesting(s *Store, dir string) *Vault { return &Vault{Store: s, dir: dir} }