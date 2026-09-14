// Package clipboard writes text to the system clipboard and auto-clears
// it after a delay, restoring the previous content when possible —
// same behaviour as `pass -c`. Without the auto-clear a copied TOTP code
// lingers in the clipboard indefinitely, readable by any app the user
// pastes into afterwards.
package clipboard

import (
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ClearAfter is how long a copied code stays on the clipboard.
const ClearAfter = 45 * time.Second

// Write copies s to the clipboard and schedules an auto-clear: after
// ClearAfter, if the clipboard still holds s, the content that was on the
// clipboard before the write is restored (or the clipboard is emptied).
func Write(s string) {
	prev, prevOK := read()
	if !writeNow(s) {
		return
	}
	go func() {
		time.Sleep(ClearAfter)
		cur, ok := read()
		if !ok || cur != s {
			return // user copied something else; leave it alone
		}
		if prevOK {
			_ = writeNow(prev)
		} else {
			_ = writeNow("")
		}
	}()
}

func writeNow(s string) bool {
	cmd := command()
	if cmd == nil {
		return false
	}
	cmd.Stdin = strings.NewReader(s)
	return cmd.Run() == nil
}

func read() (string, bool) {
	switch runtime.GOOS {
	case "darwin":
		b, err := exec.Command("pbpaste").Output()
		return string(b), err == nil
	case "windows":
		b, err := exec.Command("powershell", "-noprofile", "-command", "Get-Clipboard").Output()
		return strings.TrimRight(string(b), "\r\n"), err == nil
	}
	for _, c := range []struct {
		bin  string
		args []string
	}{
		{"wl-paste", nil},
		{"xclip", []string{"-selection", "clipboard", "-o"}},
		{"xsel", []string{"--clipboard", "--output"}},
	} {
		if _, err := exec.LookPath(c.bin); err != nil {
			continue
		}
		b, err := exec.Command(c.bin, c.args...).Output()
		if err != nil {
			continue
		}
		return string(b), true
	}
	return "", false
}

func command() *exec.Cmd {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("pbcopy")
	case "windows":
		return exec.Command("clip")
	}
	for _, bin := range []string{"wl-copy", "xclip", "xsel"} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		switch bin {
		case "wl-copy":
			return exec.Command("wl-copy")
		case "xclip":
			return exec.Command("xclip", "-selection", "clipboard")
		default:
			return exec.Command("xsel", "--clipboard", "--input")
		}
	}
	return nil
}
