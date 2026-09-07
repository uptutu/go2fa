package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/crc32"
)

// Magic identifies the .2fa export container. v1 = 0x32464101 ('2FA' + \x01).
// Bumping MagicVersion requires keeping the old reader code path.
var Magic = [4]byte{'2', 'F', 'A', 0x01}

// Container layout (binary, big-endian except where noted):
//
//   [4]  Magic           "2FA\x01"
//   [1]  Version         1
//   [1]  KDF ID          1 = Argon2id
//   [4]  Argon2 time     uint32
//   [4]  Argon2 memory   uint32 (MiB)
//   [1]  Argon2 threads  uint8
//   [16] KDF salt        (Argon2id salt)
//   [16] MAC salt        (separate salt for HMAC key)
//   [12] Nonce           (GCM nonce)
//   [4]  Ciphertext len  uint32
//   [N]  Ciphertext      (GCM seal of plaintext)
//   [4]  CRC32 of all preceding bytes (little-endian)
//   [32] SHA-256 keyed MAC of all preceding bytes (tamper check)
//
// AAD for GCM = header bytes from Magic up to (but not including) Nonce.
const (
	FormatVersion = 1
	KDFArgon2id   = 1
	// aadLen = bytes covered by AAD: magic..macSalt = 47.
	aadLen = 4 + 1 + 1 + 4 + 4 + 1 + 16 + 16
	// headerLen = aadLen + nonce(12) + ct_len(4) = 63.
	headerLen = aadLen + 12 + 4
)

// ExportHeader describes the KDF parameters recovered from a file.
type ExportHeader struct {
	Version      uint8
	KDF          uint8
	ArgonTime    uint32
	ArgonMemory  uint32
	ArgonThreads uint8
	KDFSalt      []byte
	MACSalt      []byte
	Nonce        []byte
}

// ParseHeader extracts the header without decrypting; returns the ciphertext.
func ParseHeader(buf []byte) (h ExportHeader, ciphertext []byte, err error) {
	if len(buf) < headerLen+4 {
		return h, nil, errors.New("crypto/format: file too short for header")
	}
	if [4]byte{buf[0], buf[1], buf[2], buf[3]} != Magic {
		return h, nil, errors.New("crypto/format: bad magic")
	}
	if buf[4] != FormatVersion {
		return h, nil, fmt.Errorf("crypto/format: unsupported version %d", buf[4])
	}
	h.Version = buf[4]
	h.KDF = buf[5]
	h.ArgonTime = readBE32(buf[6:10])
	h.ArgonMemory = readBE32(buf[10:14])
	h.ArgonThreads = buf[14]
	h.KDFSalt = buf[15:31]
	h.MACSalt = buf[31:47]
	h.Nonce = buf[47:59]
	ctLen := readBE32(buf[59:63])
	if uint32(len(buf)) < uint32(headerLen)+ctLen+4+32 {
		return h, nil, errors.New("crypto/format: truncated ciphertext")
	}
	ct := buf[63 : 63+int(ctLen)]
	crc := readLE32(buf[headerLen+int(ctLen) : headerLen+int(ctLen)+4])
	if crc32.ChecksumIEEE(buf[:headerLen+int(ctLen)]) != crc {
		return h, nil, errors.New("crypto/format: CRC mismatch (file corrupted)")
	}
	return h, append([]byte(nil), ct...), nil
}

// SealExport produces a full .2fa container from plaintext using a password.
// The nonce used by Seal is extracted from its output and written into the
// header so OpenExport can recover it.
func SealExport(password string, plaintext []byte) ([]byte, error) {
	kdfSalt := RandomBytes(SaltLen)
	macSalt := RandomBytes(SaltLen)
	key := DeriveKey(password, kdfSalt)
	macKey := DeriveKey(password+"\x00mac", macSalt)

	// Build header up to (but excluding) the nonce so we can use it as AAD
	// without including the nonce itself in the AAD input.
	hdr := make([]byte, 0, headerLen+16+32)
	hdr = append(hdr, Magic[:]...)
	hdr = append(hdr, FormatVersion, KDFArgon2id)
	hdr = appendUint32BE(hdr, uint32(ArgonTime))
	hdr = appendUint32BE(hdr, uint32(ArgonMemory))
	hdr = append(hdr, ArgonThreads)
	hdr = append(hdr, kdfSalt...)
	hdr = append(hdr, macSalt...)

	// Seal with aad = current hdr (no nonce yet).
	aad := append([]byte(nil), hdr...)
	sealed, err := Seal(key, plaintext, aad)
	if err != nil {
		return nil, err
	}
	// Extract the nonce Seal generated and append it to hdr.
	hdr = append(hdr, sealed[:NonceLen]...)
	ct := sealed[NonceLen:]
	hdr = appendUint32BE(hdr, uint32(len(ct)))
	hdr = append(hdr, ct...)
	hdr = appendUint32LE(hdr, crc32.ChecksumIEEE(hdr))
	hdr = append(hdr, macOf(macKey, hdr)...)
	return hdr, nil
}

// OpenExport is the inverse of SealExport.
func OpenExport(password string, buf []byte) ([]byte, error) {
	if uint32(len(buf)) < uint32(headerLen)+4+32 {
		return nil, errors.New("crypto/format: file too short")
	}
	h, ct, err := ParseHeader(buf)
	if err != nil {
		return nil, err
	}
	macKey := DeriveKey(password+"\x00mac", h.MACSalt)
	want := macOf(macKey, buf[:len(buf)-32])
	if !ConstEq(want, buf[len(buf)-32:]) {
		return nil, errors.New("crypto/format: HMAC mismatch (wrong password or tampered)")
	}
	key := DeriveKey(password, h.KDFSalt)
	// AAD = header bytes excluding the ciphertext length prefix AND nonce.
	// Layout: magic(4)+version(1)+kdf(1)+time(4)+mem(4)+threads(1)+kdfSalt(16)+macSalt(16) = 47.
	aad := buf[:47]
	full := append(append([]byte(nil), h.Nonce...), ct...)
	return Open(key, full, aad)
}

// macOf = SHA-256(key || msg). 32-byte output. Simple "keyed hash"; not
// FIPS HMAC but adequate for tamper detection (any attacker without the
// password-derived macKey cannot forge a valid MAC).
func macOf(key, msg []byte) []byte {
	h := sha256.New()
	h.Write(key)
	h.Write(msg)
	return h.Sum(nil)
}

func appendUint32BE(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendUint32LE(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func readBE32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func readLE32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}