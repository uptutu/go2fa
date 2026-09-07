package importexport

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uptutu/go2fa/internal/core/crypto"
	"github.com/uptutu/go2fa/internal/core/otpauth"
	"github.com/uptutu/go2fa/internal/core/totp"
	"github.com/uptutu/go2fa/internal/core/vault"
)

func newVault(t *testing.T) *vault.Vault {
	t.Helper()
	dir := t.TempDir()
	st, err := vault.OpenStore(context.Background(), filepath.Join(dir, "vault.sqlite"), nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	v := vault.NewForTesting(st, dir)
	if err := v.Init(context.Background(), vault.ModeNoPassword, ""); err != nil {
		t.Fatalf("init: %v", err)
	}
	return v
}

func TestSniff2FA(t *testing.T) {
	buf, err := crypto.SealExport("test", []byte(`{"version":1,"entries":[],"groups":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if Sniff(buf) != Format2FA {
		t.Errorf("sniff: got %d, want Format2FA", Sniff(buf))
	}
}

func TestSniffOtpauth(t *testing.T) {
	line := otpauth.URI{
		Type:      otpauth.TOTP,
		Issuer:    "Acme",
		Account:   "alice@example.com",
		Secret:    []byte("JBSWY3DPEHPK3PXP"),
		Algorithm: totp.SHA1,
		Digits:    6,
		Period:    30,
	}.String()
	if Sniff([]byte(line)) != FormatOtpauth {
		t.Errorf("sniff: not otpauth")
	}
}

func TestSniffAegisPlain(t *testing.T) {
	j := `{"version":1,"entries":[{"type":"totp","uuid":"x","name":"alice","issuer":"acme","group":"","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30}}],"groups":[]}`
	if Sniff([]byte(j)) != FormatAegisPlain {
		t.Errorf("sniff: not aegis plain, got %d", Sniff([]byte(j)))
	}
}

func TestOtpauthRoundtrip(t *testing.T) {
	in := otpauth.URI{
		Type:      otpauth.TOTP,
		Issuer:    "GitHub",
		Account:   "me@example.com",
		Secret:    []byte("JBSWY3DPEHPK3PXP"),
		Algorithm: totp.SHA1,
		Digits:    6,
		Period:    30,
	}
	s := in.String()
	out, err := otpauth.Parse(s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.Issuer != "GitHub" || out.Account != "me@example.com" {
		t.Errorf("roundtrip: %+v", out)
	}
}

func TestExportImportRoundtripOtpauth(t *testing.T) {
	v := newVault(t)
	ctx := context.Background()
	if err := v.UpsertSecret(ctx, vault.Secret{
		Issuer: "GitHub", Account: "me", SecretRaw: []byte("JBSWY3DPEHPK3PXP"),
		Algorithm: totp.SHA1, Digits: 6, Period: 30,
	}); err != nil {
		t.Fatal(err)
	}
	blob, err := ExportVault(v, "otpauth", "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Import(blob, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Secrets) != 1 {
		t.Fatalf("got %d", len(res.Secrets))
	}
	if res.Secrets[0].Issuer != "GitHub" {
		t.Errorf("issuer: %q", res.Secrets[0].Issuer)
	}
}

func TestExportImportRoundtrip2FA(t *testing.T) {
	v := newVault(t)
	ctx := context.Background()
	if err := v.UpsertSecret(ctx, vault.Secret{
		Issuer: "GH", Account: "u", SecretRaw: []byte("JBSWY3DPEHPK3PXP"),
		Algorithm: totp.SHA1, Digits: 6, Period: 30,
	}); err != nil {
		t.Fatal(err)
	}
	blob, err := ExportVault(v, ".2fa", "secret123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(blob[:4]), "2FA") {
		t.Errorf("missing magic")
	}
	res, err := Import(blob, "secret123")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(res.Secrets) != 1 || res.Secrets[0].Issuer != "GH" {
		t.Errorf("roundtrip lost data: %+v", res)
	}
}