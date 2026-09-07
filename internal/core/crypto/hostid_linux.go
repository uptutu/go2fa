//go:build linux

package crypto

import (
	"os"
	"strings"
)

// hostID returns Linux's /etc/machine-id (or /var/lib/dbus/machine-id fallback).
// systemd guarantees /etc/machine-id exists on all modern distros; we try
// the dbus path for older systems and minimal containers.
func hostID() (string, error) {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		b, err := os.ReadFile(path)
		if err == nil {
			id := strings.TrimSpace(string(b))
			if id != "" {
				return id, nil
			}
		}
	}
	// Last resort: hostname (weak identity).
	name, err := os.Hostname()
	if err != nil {
		return "", err
	}
	return name, nil
}