package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B test vectors:
// secret = "12345678901234567890" (ASCII) -> base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
var rfc6238Cases = []struct {
	time   int64
	digits int
	want   string
}{
	{59, 8, "94287082"},
	{59, 6, "287082"},
	{1111111109, 8, "07081804"},
	{1111111109, 6, "081804"},
	{1111111111, 8, "14050471"},
	{1111111111, 6, "050471"},
	{1234567890, 8, "89005924"},
	{1234567890, 6, "005924"},
	{2000000000, 8, "69279037"},
	{2000000000, 6, "279037"},
}

func TestGenerateRFC6238Vectors(t *testing.T) {
	secret, err := DecodeSecret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	for _, c := range rfc6238Cases {
		got, _, err := Generate(secret, SHA1, c.digits, 30, time.Unix(c.time, 0))
		if err != nil {
			t.Errorf("t=%d: %v", c.time, err)
			continue
		}
		if got != c.want {
			t.Errorf("t=%d digits=%d: got %s, want %s", c.time, c.digits, got, c.want)
		}
	}
}

func TestBase32Roundtrip(t *testing.T) {
	in := "JBSWY3DPEHPK3PXP"
	secret, err := DecodeSecret(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	out := EncodeSecret(secret)
	if !strings.EqualFold(strings.TrimRight(out, "="), in) {
		t.Errorf("roundtrip mismatch: %s vs %s", out, in)
	}
}

func TestRemaining(t *testing.T) {
	secret, _ := DecodeSecret("JBSWY3DPEHPK3PXP")
	// 59s into a 30s period: 59 % 30 = 29, remaining = 30 - 29 = 1.
	_, rem, err := Generate(secret, SHA1, 6, 30, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if rem != 1 {
		t.Errorf("remaining: got %d, want 1", rem)
	}
}