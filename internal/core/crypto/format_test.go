package crypto

import (
	"bytes"
	"testing"
)

func TestFormatRoundtrip(t *testing.T) {
	plain := []byte(`{"hello":"world"}`)
	buf, err := SealExport("pw", plain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := OpenExport("pw", buf)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Errorf("got %q, want %q", out, plain)
	}
}

func TestFormatWrongPassword(t *testing.T) {
	plain := []byte("secret data")
	buf, err := SealExport("right", plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExport("wrong", buf); err == nil {
		t.Error("expected error for wrong password")
	}
}
// TestFormatLegacyMACStillOpens: exports written by the original v1
// (SHA-256(key‖msg) trailer instead of HMAC) must keep opening.
func TestFormatLegacyMACStillOpens(t *testing.T) {
	plain := []byte(`{"legacy":true}`)
	buf, err := SealExport("pw", plain)
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite the trailer with the legacy MAC over the same body.
	key := DeriveKey("pw\x00mac", buf[31:47])
	legacy := legacyMacOf(key, buf[:len(buf)-32])
	copy(buf[len(buf)-32:], legacy)
	out, err := OpenExport("pw", buf)
	if err != nil {
		t.Fatalf("open legacy-MAC export: %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Errorf("got %q, want %q", out, plain)
	}
}
