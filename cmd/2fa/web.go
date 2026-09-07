package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"

	webapp "2fa/internal/app/web"
	"2fa/internal/core/vault"
)

var cmdWeb = &cobra.Command{
	Use:   "web",
	Short: "Launch the embedded web UI in your default browser",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := openVault(context.Background())
		if err != nil {
			return err
		}
		defer v.Close()
		return launchWeb(v, false)
	},
}

var cmdGUI = &cobra.Command{
	Use:   "gui",
	Short: "Launch the desktop GUI (browser-based for v1)",
	RunE: func(cmd *cobra.Command, args []string) error {
		// v1 uses the same web UI in a browser tab. A CGO webview build is
		// documented in README under "Native Window".
		v, err := openVault(context.Background())
		if err != nil {
			return err
		}
		defer v.Close()
		fmt.Fprintln(os.Stderr, "gui: launching in default browser; rebuild with -tags=webview for native window")
		return launchWeb(v, true)
	},
}

// launchWeb starts the HTTP server, points the browser at it, and blocks
// until SIGINT / SIGTERM. Without blocking, the main goroutine would exit
// as soon as openBrowser returns, killing the server goroutine.
func launchWeb(v *vault.Vault, _ bool) error {
	addr := flagListen
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	token := flagToken
	host, _, _ := net.SplitHostPort(addr)
	nonLoopback := host != "" && host != "127.0.0.1" && host != "localhost" && host != "::1"
	if nonLoopback && token == "" {
		token = webapp.NewAuthToken()
	}
	srv, err := webapp.New(addr, v, token)
	if err != nil {
		return err
	}
	bound, err := srv.Start(context.Background())
	if err != nil {
		return err
	}
	url := "http://" + bound
	fmt.Fprintln(os.Stderr, "2fa web ready at", url)
	if nonLoopback {
		// Token printed separately, not embedded in the URL: avoids the
		// token landing in browser history, bookmarks, shared screenshots,
		// and HTTP access logs of any reverse proxy.
		fmt.Fprintln(os.Stderr, "Auth token (paste into the login prompt, or send as X-Auth-Token header):")
		fmt.Fprintln(os.Stderr, "  ", token)
	}
	if err := openBrowser(url); err != nil {
		fmt.Fprintln(os.Stderr, "could not open browser automatically:", err)
		fmt.Fprintln(os.Stderr, "open this URL in your browser:", url)
	}
	// Block until Ctrl+C / SIGTERM. Without this, the program exits as
	// soon as openBrowser returns, taking the server goroutine down with
	// it — the user sees "ready" then nothing happens.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Fprintln(os.Stderr, "shutting down...")
	return srv.Stop()
}

// openBrowser launches the user's default browser. We intentionally do NOT
// call cmd.Wait() — the browser is a long-lived child process and waiting
// would block our signal handler.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}