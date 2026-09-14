package main

import (
	"github.com/uptutu/go2fa/internal/app/gui"
	"github.com/uptutu/go2fa/internal/core/vault"
)

func init() {
	guiRunner = func(v *vault.Vault) error { return gui.Run(v) }
}
