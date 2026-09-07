package tui

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"2fa/internal/core/totp"
	"2fa/internal/core/vault"
)

func newTestModel(t *testing.T) *Model {
	t.Helper()
	dir := t.TempDir()
	st, err := vault.OpenStore(context.Background(), filepath.Join(dir, "vault.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	v := vault.NewForTesting(st, dir)
	if err := v.Init(context.Background(), vault.ModeNoPassword, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := v.CreateGroup(context.Background(), vault.Group{Name: "Work"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.CreateGroup(context.Background(), vault.Group{Name: "Personal"}); err != nil {
		t.Fatal(err)
	}
	if err := v.UpsertSecret(context.Background(), vault.Secret{
		Issuer: "GitHub", Account: "work@x", SecretRaw: []byte("JBSWY3DPEHPK3PXP"),
		Algorithm: totp.SHA1, Digits: 6, Period: 30,
	}); err != nil {
		t.Fatal(err)
	}
	if err := v.UpsertSecret(context.Background(), vault.Secret{
		Issuer: "GitLab", Account: "personal@x", SecretRaw: []byte("JBSWY3DPEHPK3PXP"),
		Algorithm: totp.SHA1, Digits: 6, Period: 30,
	}); err != nil {
		t.Fatal(err)
	}
	if err := v.UpsertSecret(context.Background(), vault.Secret{
		Issuer: "Discord", Account: "x", SecretRaw: []byte("JBSWY3DPEHPK3PXP"),
		Algorithm: totp.SHA1, Digits: 6, Period: 30,
	}); err != nil {
		t.Fatal(err)
	}
	m, err := New(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func key(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

// findGroup returns the ID of the group with the given name, or 0.
func findGroup(m *Model, name string) int64 {
	for _, g := range m.groups {
		if g.Name == name {
			return g.ID
		}
	}
	return 0
}

func TestTUIGroupCycle(t *testing.T) {
	m := newTestModel(t)
	// m.groups is sorted by (sort_order, name) per the store; "Personal" < "Work" alphabetically.
	// Slots: 0=All, 1=Unassigned, 2=groups[0], 3=groups[1], ...
	if m.group != -1 {
		t.Fatalf("initial group: %d, want -1", m.group)
	}
	m.onKey(key("g"))
	if m.group != 0 {
		t.Errorf("after first g: %d, want 0 (Unassigned)", m.group)
	}
	m.onKey(key("g"))
	if m.group != m.groups[0].ID {
		t.Errorf("after second g: %d, want first group %d (%s)", m.group, m.groups[0].ID, m.groups[0].Name)
	}
	m.onKey(key("g"))
	if m.group != m.groups[1].ID {
		t.Errorf("after third g: %d, want second group %d (%s)", m.group, m.groups[1].ID, m.groups[1].Name)
	}
	m.onKey(key("g"))
	if m.group != -1 {
		t.Errorf("after fourth g (wrap): %d, want -1 (All)", m.group)
	}
}

func TestTUIAddMode(t *testing.T) {
	m := newTestModel(t)
	m.onKey(key("a"))
	if !m.addMode {
		t.Fatal("addMode not entered")
	}
	for _, c := range "otpauth://totp/Acme:me@example.com?secret=JBSWY3DPEHPK3PXP" {
		m.onKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{c}})
	}
	if !strings.HasPrefix(m.addInput, "otpauth://") {
		t.Errorf("addInput not captured: %q", m.addInput)
	}
	m.onKey(key("enter"))
	if m.addMode {
		t.Error("addMode not exited on enter")
	}
	if !strings.Contains(m.status, "added") {
		t.Errorf("status: %q", m.status)
	}
	all, _ := m.v.ListSecrets(context.Background())
	if len(all) != 4 {
		t.Errorf("want 4 secrets, got %d", len(all))
	}
}

func TestTUIAddCancel(t *testing.T) {
	m := newTestModel(t)
	m.onKey(key("a"))
	m.onKey(key("o"))
	m.onKey(key("esc"))
	if m.addMode {
		t.Error("addMode not exited on esc")
	}
	if m.addInput != "" {
		t.Errorf("addInput not cleared: %q", m.addInput)
	}
}

func TestTUIViewShowsGroups(t *testing.T) {
	m := newTestModel(t)
	view := m.View()
	for _, want := range []string{"All", "Unassigned", "Work", "Personal"} {
		if !strings.Contains(view, want) {
			t.Errorf("view missing %q", want)
		}
	}
	for _, want := range []string{"GitHub", "GitLab", "Discord"} {
		if !strings.Contains(view, want) {
			t.Errorf("view missing secret %q", want)
		}
	}
}