// Package gui wraps the embedded web server in a native desktop window via
// glaze (which dlopens the platform WebView at runtime — no cgo, no
// pkg-config). The HTTP API and SPA are reused unchanged; the window is
// just a browser shell pointed at 127.0.0.1:<random>.
//
// Runtime requirements:
//   - Linux:   webkit2gtk-4.1 (Arch) / libwebkit2gtk-4.1-dev (Debian)
//   - macOS:   WebKit.framework (system)
//   - Windows: WebView2 runtime (pre-installed on Win10 1903+)
package gui

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	glaze "github.com/crgimenes/glaze"

	webapp "github.com/uptutu/go2fa/internal/app/web"
	"github.com/uptutu/go2fa/internal/core/vault"
)

// Run starts the embedded HTTP server on a random loopback port, opens a
// native window pointing at it, and blocks until the window is closed or
// the process receives SIGINT/SIGTERM.
func Run(v *vault.Vault) error {
	srv, err := webapp.New("127.0.0.1:0", v, "")
	if err != nil {
		return err
	}
	bound, err := srv.Start(context.Background())
	if err != nil {
		return err
	}
	defer srv.Stop()

	url := "http://" + bound
	fmt.Fprintln(os.Stderr, "2fa gui ready at", url)

	w, err := glaze.New(false)
	if err != nil {
		return fmt.Errorf("open window: %w (is webkit2gtk-4.1 installed?)", err)
	}
	defer w.Destroy()
	w.SetTitle("go2fa")
	w.SetSize(1024, 720, glaze.HintNone)
	w.Navigate(url)

	// Close the window cleanly on Ctrl+C; otherwise w.Run() blocks and
	// the deferred srv.Stop never runs.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		w.Terminate()
	}()

	w.Run()
	return nil
}
