// Package install creates a desktop shortcut for the go2fa GUI on the
// current OS. It is intentionally tiny: each platform writes one
// well-known file format (.desktop, .app bundle, .lnk) and reuses the
// shipped assets/icon.svg as the program logo.
//
// The shortcut always launches `<binary> gui` with no extra arguments.
// Password unlock happens via the GUI's own prompt — embedding --password
// in the shortcut would put a plaintext master password in a file the
// user (or an attacker with file access) can read.
package install

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

//go:embed icon.svg
var iconSVG []byte

// AppName is what the shortcut launches and what it is labelled as.
const AppName = "go2fa"

// Result describes what install wrote.
type Result struct {
	ShortcutPath string // path of the created shortcut file
	IconPath     string // path the shortcut points its icon at
	FellBack     bool   // true if no ~/Desktop existed and we wrote to XDG instead
}

// Install writes a desktop shortcut for the current OS that launches
// `2fa gui` (the running binary, resolved via os.Executable with a
// $PATH fallback so `go run` invocations still produce a stable path).
// If the OS is unsupported, returns an error.
func Install() (*Result, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate self: %w", err)
	}
	// When go run ./... invokes us, $0 is the temp build; resolve to a
	// stable "2fa" so the shortcut survives a `go install`.
	launch := exe
	if filepath.Base(exe) == "go-build" || filepath.Base(exe) == "" {
		if path, err := exec.LookPath("2fa"); err == nil {
			launch = path
		}
	}

	switch runtime.GOOS {
	case "linux":
		return installLinux(launch)
	case "darwin":
		return installMac(launch)
	case "windows":
		return installWindows(launch)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// --- linux -----------------------------------------------------------------

func installLinux(launch string) (*Result, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	iconDir := filepath.Join(home, ".local", "share", "icons")
	if err := os.MkdirAll(iconDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir icons: %w", err)
	}
	iconPath := filepath.Join(iconDir, AppName+".svg")
	if err := os.WriteFile(iconPath, iconSVG, 0o644); err != nil {
		return nil, fmt.Errorf("write icon: %w", err)
	}

	desktopDir := filepath.Join(home, "Desktop")
	fellBack := false
	if _, err := os.Stat(desktopDir); os.IsNotExist(err) {
		// XDG fallback for systems without ~/Desktop (server, minimal DE,
		// tiling WMs without xdg-user-dirs). The shortcut still shows up
		// in most app launchers (rofi, GNOME apps, KDE menu) but is NOT
		// visible as an icon on a Desktop folder that doesn't exist.
		desktopDir = filepath.Join(home, ".local", "share", "applications")
		if err := os.MkdirAll(desktopDir, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir applications: %w", err)
		}
		fellBack = true
	}

	// Per the Desktop Entry spec, the Exec line is parsed by the launcher
	// (gio/kde), not a shell. Double-quotes delimit fields and are stripped;
	// single-quotes are taken literally. We only need one field (the
	// subcommand), so no quoting is required.
	body := fmt.Sprintf(`[Desktop Entry]
Version=1.0
Type=Application
Name=go2fa
Comment=Encrypted TOTP authenticator
Exec=%s gui
Icon=%s
Terminal=false
Categories=Utility;Security;
StartupNotify=true
`, launch, iconPath)

	shortcutPath := filepath.Join(desktopDir, AppName+".desktop")
	if err := os.WriteFile(shortcutPath, []byte(body), 0o755); err != nil {
		return nil, fmt.Errorf("write desktop entry: %w", err)
	}
	return &Result{ShortcutPath: shortcutPath, IconPath: iconPath, FellBack: fellBack}, nil
}

// --- macOS -----------------------------------------------------------------

func installMac(launch string) (*Result, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	appDir := filepath.Join(home, "Applications", AppName+".app")
	if err := os.MkdirAll(filepath.Join(appDir, "Contents", "MacOS"), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir app bundle: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(appDir, "Contents", "Resources"), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir app bundle: %w", err)
	}

	iconPath := filepath.Join(appDir, "Contents", "Resources", AppName+".svg")
	if err := os.WriteFile(iconPath, iconSVG, 0o644); err != nil {
		return nil, fmt.Errorf("write icon: %w", err)
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key><string>%s</string>
	<key>CFBundleDisplayName</key><string>%s</string>
	<key>CFBundleExecutable</key><string>%s</string>
	<key>CFBundleIdentifier</key><string>com.uptutu.%s</string>
	<key>CFBundleVersion</key><string>1.0</string>
	<key>CFBundleShortVersionString</key><string>1.0</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleIconFile</key><string>%s</string>
</dict>
</plist>
`, AppName, AppName, AppName, AppName, AppName)

	plistPath := filepath.Join(appDir, "Contents", "Info.plist")
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return nil, fmt.Errorf("write Info.plist: %w", err)
	}

	// launcher script: a real CFBundleExecutable that re-invokes the
	// installed binary. macOS will run it directly when the .app is
	// double-clicked.
	script := fmt.Sprintf("#!/bin/sh\nexec %s gui\n", launch)
	scriptPath := filepath.Join(appDir, "Contents", "MacOS", AppName)
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		return nil, fmt.Errorf("write launcher: %w", err)
	}

	return &Result{ShortcutPath: appDir, IconPath: iconPath}, nil
}

// --- windows ---------------------------------------------------------------

func installWindows(launch string) (*Result, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	desktop := filepath.Join(home, "Desktop")
	if _, err := os.Stat(desktop); os.IsNotExist(err) {
		// Fall back to Start Menu Programs.
		appData := os.Getenv("APPDATA")
		if appData == "" {
			return nil, errors.New("cannot locate Desktop or APPDATA")
		}
		desktop = filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs")
	}
	if err := os.MkdirAll(desktop, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir shortcut dir: %w", err)
	}

	// .lnk generation via PowerShell (always present on Win10+). We do not
	// pull a Windows-only Go dep just to write a shortcut file.
	iconPath := ""
	shortcutPath := filepath.Join(desktop, AppName+".lnk")
	ps := fmt.Sprintf(`$ws = New-Object -ComObject WScript.Shell
$s = $ws.CreateShortcut('%s')
$s.TargetPath = '%s'
$s.Arguments = 'gui'
$s.WorkingDirectory = '%s'
$s.WindowStyle = 1
$s.Description = 'Encrypted TOTP authenticator'
$s.Save
`, shortcutPath, launch, filepath.Dir(launch))

	cmd := exec.CommandContext(context.Background(), "powershell", "-NoProfile", "-Command", ps)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("create .lnk via powershell: %w (is PowerShell available?)", err)
	}
	return &Result{ShortcutPath: shortcutPath, IconPath: iconPath}, nil
}
