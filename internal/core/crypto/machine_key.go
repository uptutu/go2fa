package crypto

import (
	"crypto/sha256"
	"os"
	"path/filepath"
)

// MachineKeyFile is the on-disk filename for the persistent machine key.
// Kept under ~/.2fa/ with 0600 perms; protects no-password vaults against
// a pure database-file theft (attacker would also need this file).
const MachineKeyFile = "machine.key"

// MachineKey derives a deterministic 32-byte key from the host identifier
// + a per-vault random salt. The salt is stored alongside the database so
// the same machine always produces the same KEK for the same vault.
//
// The host identifier is /etc/machine-id on Linux, IOPlatformUUID on macOS,
// and HKLM\...\MachineGuid on Windows (via a small OS-specific helper).
func MachineKey(vaultSalt []byte) ([]byte, error) {
	id, err := hostID()
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(id))
	h.Write([]byte{0})
	h.Write(vaultSalt)
	return h.Sum(nil), nil
}

// PersistMachineKey writes a 32-byte random key to <dir>/<MachineKeyFile>
// with 0600 perms. Used as a fallback when /etc/machine-id is unavailable
// (containers without it).
func PersistMachineKey(dir string) ([]byte, error) {
	k := RandomBytes(ArgonKeyLen)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, MachineKeyFile)
	if err := os.WriteFile(path, k, 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// LoadMachineKey reads the persisted machine key (if any).
// Returns (nil, nil) if the file does not exist.
func LoadMachineKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, MachineKeyFile)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(b) != ArgonKeyLen {
		return nil, nil // corrupt; treat as missing
	}
	return b, nil
}