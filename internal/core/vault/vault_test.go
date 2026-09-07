package vault

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"2fa/internal/core/totp"
)

func TestListSecretsCorruptUUID(t *testing.T) {
	v := newTestVault(t, ModePassword, "pw")
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	// Inject a row with a non-UUID id (simulates tampered DB or migration glitch).
	if _, err := v.db.ExecContext(ctx,
		`INSERT INTO secrets(id, issuer, account, secret_enc, secret_nonce, algorithm, digits, period, created_at, updated_at)
		 VALUES('not-a-uuid', 'x', '', '', '', 'SHA1', 6, 30, ?, ?)`,
		now, now); err != nil {
		t.Fatal(err)
	}
	// Must NOT panic; must surface as an error.
	if _, err := v.ListSecrets(ctx); err == nil {
		t.Fatal("expected error from corrupt row")
	}
}

func newTestVault(t *testing.T, mode VaultMode, password string) *Vault {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.sqlite")
	st, err := OpenStore(context.Background(), dbPath, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	v := &Vault{Store: st, dir: dir}
	if err := v.Init(context.Background(), mode, password); err != nil {
		t.Fatalf("init: %v", err)
	}
	return v
}

func TestVaultRoundtripPassword(t *testing.T) {
	v := newTestVault(t, ModePassword, "correct-horse-battery-staple")
	ctx := context.Background()

	gid, err := v.CreateGroup(ctx, Group{Name: "Work", Color: "#7c3aed"})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	sec := Secret{
		GroupID:   gid,
		Issuer:    "GitHub",
		Account:   "alex@example.com",
		SecretRaw: []byte("JBSWY3DPEHPK3PXP"),
		Algorithm: totp.SHA1,
		Digits:    6,
		Period:    30,
		Notes:     []byte("work account"),
	}
	if err := v.UpsertSecret(ctx, sec); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	v.Lock()
	if err := v.UnlockWithPassword(ctx, "correct-horse-battery-staple"); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	all, err := v.ListSecrets(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("want 1 secret, got %d", len(all))
	}
	got := all[0]
	if got.Issuer != "GitHub" || got.Account != "alex@example.com" {
		t.Errorf("metadata mismatch: %+v", got)
	}
	if string(got.SecretRaw) != "JBSWY3DPEHPK3PXP" {
		t.Errorf("secret_raw: got %q", string(got.SecretRaw))
	}
	if string(got.Notes) != "work account" {
		t.Errorf("notes: got %q", string(got.Notes))
	}
}

func TestWrongPasswordRejected(t *testing.T) {
	v := newTestVault(t, ModePassword, "right")
	ctx := context.Background()
	v.Lock()
	err := v.UnlockWithPassword(ctx, "wrong")
	if err == nil {
		t.Fatal("expected wrong-password rejection")
	}
	if !strings.Contains(err.Error(), "wrong password") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestSecretCRUD(t *testing.T) {
	v := newTestVault(t, ModeNoPassword, "")
	ctx := context.Background()

	s := Secret{Issuer: "Test", Account: "u", SecretRaw: []byte("AAAA"), Algorithm: totp.SHA1}
	if err := v.UpsertSecret(ctx, s); err != nil {
		t.Fatal(err)
	}
	all, _ := v.ListSecrets(ctx)
	if len(all) != 1 {
		t.Fatalf("list after add: %d", len(all))
	}
	id := all[0].ID
	if id == uuid.Nil {
		t.Fatal("expected generated UUID")
	}

	all[0].Issuer = "Renamed"
	if err := v.UpsertSecret(ctx, all[0]); err != nil {
		t.Fatal(err)
	}
	got, err := v.GetSecret(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != "Renamed" {
		t.Errorf("update failed: %q", got.Issuer)
	}

	if err := v.TouchLastUsed(ctx, id); err != nil {
		t.Fatal(err)
	}
	got, _ = v.GetSecret(ctx, id)
	if got.LastUsedAt == nil {
		t.Error("last_used_at should be set after touch")
	}

	if err := v.DeleteSecret(ctx, id); err != nil {
		t.Fatal(err)
	}
	if n, _ := v.TotalSecretCount(ctx); n != 0 {
		t.Errorf("after delete: %d secrets", n)
	}
}

func TestSetPasswordReencrypts(t *testing.T) {
	v := newTestVault(t, ModeNoPassword, "")
	ctx := context.Background()
	if err := v.UpsertSecret(ctx, Secret{Issuer: "A", SecretRaw: []byte("BBBB"), Algorithm: totp.SHA1}); err != nil {
		t.Fatal(err)
	}
	if err := v.SetPassword(ctx, "newpass"); err != nil {
		t.Fatal(err)
	}
	m, _ := v.LoadMeta(ctx)
	if m.Mode != ModePassword {
		t.Errorf("mode: got %d, want ModePassword", m.Mode)
	}
	v.Lock()
	if err := v.UnlockWithPassword(ctx, "newpass"); err != nil {
		t.Fatalf("unlock after set: %v", err)
	}
	all, _ := v.ListSecrets(ctx)
	if len(all) != 1 || all[0].Issuer != "A" {
		t.Errorf("data lost after re-encryption: %+v", all)
	}
}