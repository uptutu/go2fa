// Package totp implements RFC 6238 (TOTP) and RFC 4226 (HOTP) for SHA1/256/512.
// Self-contained; avoids pulling in pquerna/otp which is no longer maintained.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"strings"
	"time"
)

// Algo is the HMAC algorithm family used inside TOTP.
type Algo int

const (
	SHA1 Algo = iota
	SHA256
	SHA512
)

// ParseAlgo maps the canonical name to Algo. SHA1 is the legacy default.
func ParseAlgo(s string) (Algo, error) {
	switch strings.ToUpper(s) {
	case "", "SHA1":
		return SHA1, nil
	case "SHA256":
		return SHA256, nil
	case "SHA512":
		return SHA512, nil
	default:
		return 0, fmt.Errorf("totp: unknown algorithm %q", s)
	}
}

func (a Algo) String() string {
	switch a {
	case SHA1:
		return "SHA1"
	case SHA256:
		return "SHA256"
	case SHA512:
		return "SHA512"
	}
	return "?"
}

func (a Algo) hash() hash.Hash {
	switch a {
	case SHA1:
		return sha1.New()
	case SHA256:
		return sha256.New()
	case SHA512:
		return sha512.New()
	}
	return sha1.New()
}

// Secret is a decoded base32 TOTP seed.
type Secret []byte

// DecodeSecret accepts base32 (with or without padding) per RFC 4648.
func DecodeSecret(s string) (Secret, error) {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	b, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("totp: bad base32: %w", err)
	}
	return b, nil
}

// EncodeSecret is the inverse of DecodeSecret (uppercase, no padding).
func EncodeSecret(b Secret) string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
}

// Generate computes a TOTP code at time t. Standard params: digits=6, period=30.
func Generate(secret Secret, a Algo, digits, period int, t time.Time) (code string, remaining int, err error) {
	if digits <= 0 || digits > 10 {
		return "", 0, fmt.Errorf("totp: digits out of range: %d", digits)
	}
	if period <= 0 {
		return "", 0, fmt.Errorf("totp: period must be positive: %d", period)
	}
	if len(secret) == 0 {
		return "", 0, errors.New("totp: empty secret")
	}
	counter := uint64(t.Unix()) / uint64(period)
	code, err = hotp(secret, a, digits, counter)
	if err != nil {
		return "", 0, err
	}
	remaining = period - int(t.Unix()%int64(period))
	return code, remaining, nil
}

// hotp = RFC 4226 truncated HMAC-SHA1/256/512 dynamic truncation.
func hotp(secret Secret, a Algo, digits int, counter uint64) (string, error) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(a.hash, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0F
	if int(offset)+4 > len(sum) {
		return "", errors.New("totp: truncated index out of range")
	}
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7FFFFFFF
	mod := uint32(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, truncated%mod), nil
}