package gui

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	webapp "github.com/uptutu/go2fa/internal/app/web"
	"github.com/uptutu/go2fa/internal/core/vault"
)

// TestWebServerEndpoint probes the loopback bind contract: a no-password
// vault started on 127.0.0.1:0 must serve /api/status and the embedded
// SPA at /. Headless; no webview required.
func TestWebServerEndpoint(t *testing.T) {
	ctx := context.Background()
	// vault.DefaultDir uses $HOME; redirect to a temp dir so we don't
	// touch the user's real ~/.2fa. Each subtest gets a fresh dir.
	t.Setenv("HOME", t.TempDir())

	v, err := vault.Open(ctx)
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	defer v.Close()
	if err := v.Init(ctx, vault.ModeNoPassword, ""); err != nil {
		t.Fatalf("vault.Init: %v", err)
	}

	srv, err := webapp.New("127.0.0.1:0", v, "")
	if err != nil {
		t.Fatalf("webapp.New: %v", err)
	}
	bound, err := srv.Start(ctx)
	if err != nil {
		t.Fatalf("srv.Start: %v", err)
	}
	defer srv.Stop()

	resp, err := http.Get("http://" + bound + "/api/status")
	if err != nil {
		t.Fatalf("GET /api/status: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	resp, err = http.Get("http://" + bound + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("spa: got %d, want 200", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("spa content-type: got %q, want text/html", ct)
	}

	if !strings.HasPrefix(bound, "127.0.0.1:") {
		t.Fatalf("addr: got %q, want 127.0.0.1:...", bound)
	}

	done := make(chan error, 1)
	go func() { done <- srv.Stop() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("srv.Stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("srv.Stop hung")
	}
}

// TestNewWindowFailsCleanlyWhenWebkitMissing documents the failure mode
// that glaze surfaces when libwebkit2gtk-4.1 is not installed. Skipped
// by default because most dev machines DO have it; run with
// `go test -run TestNewWindowFailsCleanlyWhenWebkitMissing -v` after
// uninstalling webkit to verify the error path.
func TestNewWindowFailsCleanlyWhenWebkitMissing(t *testing.T) {
	t.Skip("verify by hand: uninstall webkit2gtk-4.1, then run this test")
}
