package importexport

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// decodeAegisSecret handles base64, base32, and hex encodings — Aegis users
// frequently paste secrets in any of these forms. We try each in order.
func decodeAegisSecret(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty secret")
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) > 0 {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) > 0 {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) > 0 {
		return b, nil
	}
	if b, err := decodeBase32(s); err == nil && len(b) > 0 {
		return b, nil
	}
	return nil, fmt.Errorf("unrecognized secret encoding")
}

func decodeBase32(s string) ([]byte, error) {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	return base32.StdEncoding.DecodeString(s)
}

// decodeB64 handles both standard and raw standard base64.
func decodeB64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// argon2idKey derives a key using Argon2id with the supplied parameters.
// Aegis uses (N, r, p) where N = memory KiB, r = iterations, p = lanes.
func argon2idKey(password string, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)
}

// gcmDecrypt decrypts Aegis-format ciphertext: [nonce 12][ct+tag 16]
func gcmDecrypt(key, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < 12+16 {
		return nil, fmt.Errorf("aegis: ciphertext too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, sealed[:12], sealed[12:], aad)
}