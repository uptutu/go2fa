// Package crypto provides Argon2id-based key derivation and AES-256-GCM
// authenticated encryption for the 2fa vault.
//
// Design notes (ponytail):
//   - KEK derived from password + per-vault random salt via Argon2id.
//   - No-password vaults derive KEK from a per-machine key (host-bound),
//     see internal/core/vault for the machine key flow.
//   - Every ciphertext is authenticated (GCM tag), so tampering fails fast.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Tunable Argon2id parameters. Defaults match the OWASP 2025 password-storage
// cheat-sheet for interactive (<=1s) authentication on a modern workstation.
const (
	ArgonTime    = 2
	ArgonMemory  = 64 * 1024 // 64 MiB
	ArgonThreads = 2
	ArgonKeyLen  = 32 // AES-256
	SaltLen      = 16
	NonceLen     = 12 // GCM standard nonce
)

// DeriveKey derives a 32-byte key from password+salt using Argon2id.
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLen)
}

// Seal encrypts plaintext with AES-256-GCM and returns nonce||ciphertext.
// Output layout: [12B nonce][N ciphertext+16B tag]. We prepend the nonce
// explicitly because cipher.gcm.Seal only outputs plaintext+tag.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != ArgonKeyLen {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", ArgonKeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	return append(nonce, sealed...), nil
}

// Open is the inverse of Seal.
func Open(key, sealed, aad []byte) ([]byte, error) {
	if len(key) != ArgonKeyLen {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", ArgonKeyLen, len(key))
	}
	if len(sealed) < NonceLen {
		return nil, errors.New("crypto: ciphertext too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := sealed[:gcm.NonceSize()]
	ct := sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, aad)
}

// RandomBytes returns n cryptographically random bytes (panics on RNG failure).
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(fmt.Errorf("crypto: RNG failure: %w", err))
	}
	return b
}

// ConstEq is a constant-time byte slice comparison.
func ConstEq(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}