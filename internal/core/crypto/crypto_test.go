package crypto

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundtrip(t *testing.T) {
	key := RandomBytes(ArgonKeyLen)
	plain := []byte("hello world")
	sealed, err := Seal(key, plain, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sealed len: %d", len(sealed))
	got, err := Open(key, sealed, []byte("aad"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("got %q, want %q", got, plain)
	}
}

func TestSealWrongAAD(t *testing.T) {
	key := RandomBytes(ArgonKeyLen)
	sealed, _ := Seal(key, []byte("x"), []byte("right"))
	if _, err := Open(key, sealed, []byte("wrong")); err == nil {
		t.Error("expected AAD mismatch error")
	}
}