//go:build unix && !linux

package crypto

import (
	"os/exec"
	"strings"
)

// hostID returns the macOS IOPlatformUUID via `ioreg`. Falls back to
// hostname as a weak last resort. (Other Unixes — BSDs — would inherit
// this file by build tag, but we only test on macOS/Linux/Windows.)
func hostID() (string, error) {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "IOPlatformUUID") {
				parts := strings.Split(line, "=")
				if len(parts) == 2 {
					return strings.Trim(strings.TrimSpace(parts[1]), `"`), nil
				}
			}
		}
	}
	// Last resort: hostname.
	out2, err2 := exec.Command("hostname").Output()
	if err2 != nil {
		return "", err2
	}
	return strings.TrimSpace(string(out2)), nil
}