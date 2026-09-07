package main

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/uptutu/go2fa/internal/core/vault"
	"github.com/uptutu/go2fa/internal/tui"
)

// runTUI opens the vault and launches the bubbletea program.
func runTUI() error {
	ctx := context.Background()
	v, err := openVault(ctx)
	if err != nil {
		return err
	}
	defer v.Close()
	m, err := tui.New(ctx, v)
	if err != nil {
		return fmt.Errorf("tui init: %w", err)
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	return err
}

// keep vault import alive even if we switch the helper above.
var _ = vault.ModePassword
