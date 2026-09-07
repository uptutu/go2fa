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