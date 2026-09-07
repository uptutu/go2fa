//go:build windows

package crypto

import (
	"golang.org/x/sys/windows/registry"
)

// hostID reads the Windows MachineGuid from the registry. This value is
// stable per OS install, and (unlike hostname) doesn't change on rename.
func hostID() (string, error) {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.READ|registry.WOW64_64KEY,
	)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", err
	}
	return v, nil
}