package otpauth

import (
	"strings"
	"testing"

	"2fa/internal/core/totp"
)

func TestParseBasic(t *testing.T) {
	in := "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30"
	u, err := Parse(in)
	if err != nil {
		t.Fatal(err)
	}
	if u.Issuer != "GitHub" {
		t.Errorf("issuer: %q", u.Issuer)
	}
	if u.Account != "alice@example.com" {
		t.Errorf("account: %q", u.Account)
	}
	if u.Algorithm != totp.SHA1 {
		t.Errorf("algo: %v", u.Algorithm)
	}
	if u.Digits != 6 || u.Period != 30 {
		t.Errorf("digits/period: %d/%d", u.Digits, u.Period)
	}
}

func TestParseIssuerInLabel(t *testing.T) {
	in := "otpauth://totp/AcmeCorp:bob?secret=JBSWY3DPEHPK3PXP"
	u, err := Parse(in)
	if err != nil {
		t.Fatal(err)
	}
	if u.Issuer != "AcmeCorp" {
		t.Errorf("issuer: %q", u.Issuer)
	}
	if u.Account != "bob" {
		t.Errorf("account: %q", u.Account)
	}
}

func TestParsePercentEncoded(t *testing.T) {
	in := "otpauth://totp/My%20Issuer:user%40example.com?secret=JBSWY3DPEHPK3PXP"
	u, err := Parse(in)
	if err != nil {
		t.Fatal(err)
	}
	if u.Issuer != "My Issuer" {
		t.Errorf("issuer decoded: %q", u.Issuer)
	}
	if u.Account != "user@example.com" {
		t.Errorf("account decoded: %q", u.Account)
	}
}

func TestParseMissingSecret(t *testing.T) {
	if _, err := Parse("otpauth://totp/GitHub:a"); err == nil {
		t.Error("expected error for missing secret")
	}
}

func TestParseBadScheme(t *testing.T) {
	if _, err := Parse("https://example.com/secret"); err == nil {
		t.Error("expected error for wrong scheme")
	}
}

func TestStringRoundtrip(t *testing.T) {
	in := URI{
		Type: TOTP, Issuer: "Acme Co",
		Secret: []byte("JBSWY3DPEHPK3PXP"),
		Algorithm: totp.SHA1, Digits: 6, Period: 30,
		Account: "alice",
	}
	s := in.String()
	if !strings.HasPrefix(s, "otpauth://totp/") {
		t.Errorf("bad prefix: %s", s)
	}
	out, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	if out.Issuer != in.Issuer || out.Account != in.Account {
		t.Errorf("roundtrip mismatch: %+v", out)
	}
}