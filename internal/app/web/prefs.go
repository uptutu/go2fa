package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// preferencesFile is the basename of the JSON file storing UI prefs (theme).
// Lives next to vault.sqlite so backups / "reset vault" naturally cover it.
const preferencesFile = "preferences.json"

// Preferences are UI-facing knobs that should survive across webview /
// browser launches. Per-vault means per-user: when the user wipes the
// vault they keep their theme, which is the sane default.
type Preferences struct {
	Theme string `json:"theme"`
}

// prefStore is a tiny guarded cache around the on-disk preferences file.
// Reads are common (one per page load via the injected script + a GET);
// writes only on theme change, so a mutex is plenty.
type prefStore struct {
	path string
	mu   sync.Mutex
}

// load returns the persisted preferences, falling back to defaults when
// the file is missing or unparseable. A corrupt file is treated as
// "no prefs" — the user can pick a theme again, the next PUT overwrites.
func (p *prefStore) load() (Preferences, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, err := os.ReadFile(p.path)
	if errors.Is(err, fs.ErrNotExist) {
		return Preferences{Theme: "aurora"}, nil
	}
	if err != nil {
		return Preferences{}, err
	}
	var prefs Preferences
	if err := json.Unmarshal(b, &prefs); err != nil {
		// Corrupt file: rather than fail closed (user sees broken UI), log
		// and return defaults. Next successful PUT will rewrite the file.
		return Preferences{Theme: "aurora"}, nil
	}
	if prefs.Theme == "" {
		prefs.Theme = "aurora"
	}
	return prefs, nil
}

// save writes atomically: write to a tmp file in the same directory, then
// rename. Avoids a partial write leaving an empty / corrupt preferences
// file if the process dies mid-write.
func (p *prefStore) save(prefs Preferences) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, err := json.Marshal(prefs)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".preferences-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		// Cleanup if rename didn't happen.
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, p.path); err != nil {
		return fmt.Errorf("prefs: rename: %w", err)
	}
	return nil
}
