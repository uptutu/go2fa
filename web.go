package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/uptutu/go2fa/internal/app/gui/install"
	webapp "github.com/uptutu/go2fa/internal/app/web"
	"github.com/uptutu/go2fa/internal/core/vault"
)

// guiRunner is set by gui_tagged.go to launch a native window.
var guiRunner func(*vault.Vault) error

var cmdWeb = &cobra.Command{
	Use:   "web",
	Short: "Launch the embedded web UI in your default browser",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := openVault(context.Background())
		if err != nil {
			return err
		}
		defer v.Close()
		return launchWeb(v)
	},
}

var cmdGUI = &cobra.Command{
	Use:   "gui",
	Short: "Launch the desktop GUI (native window)",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := openOrInitVault(context.Background())
		if err != nil {
			return err
		}
		defer v.Close()
		// Deliberately do NOT unlock here. When launched from a desktop
		// shortcut the launching terminal is detached — prompting there
		// would silently drop the input. Leave the vault locked; the
		// SPA's #unlock scrim calls /api/unlock to derive the KEK from
		// whatever the user types in the window. No-password vaults
		// hit the server's UnlockMachineKey branch through the same path.
		return guiRunner(v)
	},
}

var cmdGUIInstall = &cobra.Command{
	Use:   "install",
	Short: "Install a desktop shortcut for the go2fa GUI on this OS",
	Long: "Detects the current OS and writes a launcher shortcut (Linux: .desktop, " +
		"macOS: .app bundle, Windows: .lnk) that invokes `2fa gui`. " +
		"If the vault does not yet exist it is initialised in password mode: " +
		"use --password for unattended scripts, or omit it to be prompted " +
		"(the password then never lands in shell history). " +
		"The shortcut itself does not embed the password; on launch the GUI prompts for " +
		"unlock when the vault is password-protected.",
	RunE: func(cmd *cobra.Command, args []string) error {
		pw, _ := cmd.Flags().GetString("password")
		ctx := context.Background()

		// Init the vault in password mode if missing. --password is for
		// unattended install scripts; interactively we prompt so the password
		// never lands in shell history / ps.
		exists, err := vault.Exists()
		if err != nil {
			return err
		}
		if !exists {
			if pw == "" {
				pw = promptPassword("Set master password: ")
				if pw2 := promptPassword("Confirm: "); pw != pw2 {
					return errors.New("passwords do not match")
				}
			}
			if pw == "" {
				return errors.New("a password is required to initialise the vault (use --password for scripts)")
			}
			v, err := vault.Open(ctx)
			if err != nil {
				return err
			}
			if err := v.Init(ctx, vault.ModePassword, pw); err != nil {
				_ = v.Close()
				return fmt.Errorf("init vault: %w", err)
			}
			if err := v.Close(); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "vault initialised in password mode")
		}

		// The vault lives independently of the shortcut — install must be
		// idempotent: re-running refreshes the shortcut without re-init.
		res, err := install.Install()
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "installed shortcut:", res.ShortcutPath)
		if res.IconPath != "" {
			fmt.Fprintln(os.Stderr, "icon:               ", res.IconPath)
		}
		if res.FellBack {
			fmt.Fprintln(os.Stderr, "note: no ~/Desktop found; shortcut is in XDG applications dir (use app launcher / rofi / dmenu)")
		}
		return nil
	},
}

func init() {
	cmdGUIInstall.Flags().String("password", "", "if the vault does not exist, initialise it in password mode with this password")
}

// launchWeb starts the HTTP server, points the browser at it, and blocks
// until SIGINT / SIGTERM. Without blocking, the main goroutine would exit
// as soon as openBrowser returns, killing the server goroutine.
func launchWeb(v *vault.Vault) error {
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
		fmt.Fprintln(os.Stderr, "⚠ traffic is PLAINTEXT HTTP — any host on the LAN can sniff the token")
		fmt.Fprintln(os.Stderr, "  and TOTP codes. Put a TLS terminator (caddy/nginx/stunnel) in front,")
		fmt.Fprintln(os.Stderr, "  or bind to a trusted interface only.")
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
