package importexport

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/uptutu/go2fa/internal/core/crypto"
	"github.com/uptutu/go2fa/internal/core/otpauth"
	"github.com/uptutu/go2fa/internal/core/vault"
)

// ExportVault writes all secrets and groups in the chosen format.
//
//   format = ".2fa"    → password-encrypted binary container
//   format = "aegis"   → Aegis-compatible plaintext JSON
//   format = "otpauth" → newline-separated otpauth:// URIs
func ExportVault(v *vault.Vault, format, password string) ([]byte, error) {
	ctx := context.Background()
	all, err := v.ListSecrets(ctx)
	if err != nil {
		return nil, err
	}
	groups, err := v.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	switch format {
	case ".2fa":
		return export2FA(all, groups, password)
	case "aegis":
		return exportAegis(all, groups), nil
	case "otpauth":
		return exportOtpauth(all), nil
	default:
		return nil, fmt.Errorf("importexport: unknown export format %q", format)
	}
}

func ExportSecrets2FA(secrets []vault.Secret, groups []vault.Group, password string) ([]byte, error) {
	return export2FA(secrets, groups, password)
}

func ExportSecretsAegis(secrets []vault.Secret, groups []vault.Group) ([]byte, error) {
	return exportAegis(secrets, groups), nil
}

func ExportSecretsOtpauth(secrets []vault.Secret) ([]byte, error) {
	return exportOtpauth(secrets), nil
}

func export2FA(secrets []vault.Secret, groups []vault.Group, password string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("export .2fa requires --password")
	}
	plain, err := json.Marshal(struct {
		Version int          `json:"version"`
		Entries []AegisEntry `json:"entries"`
		Groups  []AegisGroup `json:"groups"`
	}{
		Version: 1,
		Entries: secretsToAegis(secrets),
		Groups:  groupsToAegis(groups),
	})
	if err != nil {
		return nil, err
	}
	return crypto.SealExport(password, plain)
}

func exportAegis(secrets []vault.Secret, groups []vault.Group) []byte {
	out := struct {
		Version int          `json:"version"`
		Entries []AegisEntry `json:"entries"`
		Groups  []AegisGroup `json:"groups"`
	}{
		Version: 1,
		Entries: secretsToAegis(secrets),
		Groups:  groupsToAegis(groups),
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return b
}

func exportOtpauth(secrets []vault.Secret) []byte {
	var out []byte
	for _, s := range secrets {
		u := otpauth.URI{
			Type:      otpauth.TOTP,
			Issuer:    s.Issuer,
			Account:   s.Account,
			Secret:    s.SecretRaw,
			Algorithm: s.Algorithm,
			Digits:    s.Digits,
			Period:    s.Period,
		}
		out = append(out, []byte(u.String()+"\n")...)
	}
	return out
}

func secretsToAegis(in []vault.Secret) []AegisEntry {
	out := make([]AegisEntry, 0, len(in))
	for _, s := range in {
		e := AegisEntry{
			Type:   "totp",
			UUID:   s.ID.String(),
			Name:   s.Account,
			Issuer: s.Issuer,
		}
		// Write secret as base32 (Aegis' canonical form).
		e.Info.Secret = encodeBase32(s.SecretRaw)
		e.Info.Algo = s.Algorithm.String()
		e.Info.Digits = s.Digits
		e.Info.Period = s.Period
		e.Note = string(s.Notes)
		out = append(out, e)
	}
	return out
}

func groupsToAegis(in []vault.Group) []AegisGroup {
	out := make([]AegisGroup, 0, len(in))
	for i, g := range in {
		out = append(out, AegisGroup{
			UUID: fmt.Sprintf("g-%d-%d", g.ID, i),
			Name: g.Name,
		})
	}
	return out
}

// WriteFile writes b to path or stdout if path is "-".
func WriteFile(path string, b []byte, perm os.FileMode) error {
	if path == "-" {
		_, err := os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(path, b, perm)
}

// encodeBase32 wraps base32 without padding — the form Aegis canonicalizes.
func encodeBase32(b []byte) string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
}