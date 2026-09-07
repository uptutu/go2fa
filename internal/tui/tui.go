// Package tui implements the bubbletea-based terminal UI.
//
// Layout (three columns):
//   ┌──────────┬──────────────────┬──────────────────┐
//   │ GROUPS   │ SECRETS          │ DETAIL (TOTP)    │
//   │ ──────── │ ──────────────── │ ──────────────── │
//   │ All      │ GitHub     alex  │  GitHub          │
//   │ Work     │ GitLab     bob   │   123 456        │
//   │   ► g   │ Discord    ...   │   ▓▓▓▓▓░░ 18s    │
//   └──────────┴──────────────────┴──────────────────┘
//
// Keys:
//
//   /         search filter
//   j/k  ↑/↓  move selection (in active column)
//   tab       cycle column
//   enter     copy current code to clipboard
//   a         add (paste otpauth URI)
//   d         delete
//   q         quit
package tui

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"2fa/internal/core/otpauth"
	"2fa/internal/core/totp"
	"2fa/internal/core/vault"
)

type tickMsg time.Time

// Model is the bubbletea model.
type Model struct {
	ctx      context.Context
	v        *vault.Vault
	groups   []vault.Group
	secrets  []vault.Secret
	filtered []int // indices into secrets after filter
	filter   string
	group    int64 // -1 = all, 0 = unassigned, >0 = group id
	col      int   // 0 groups, 1 secrets, 2 detail
	row      int
	status   string
	copied   bool
	copiedAt time.Time
	// recently copied IDs float to the top for 30s
	promoted map[string]time.Time
	// addInput, when non-nil, is the buffer for an in-progress "a" entry.
	addInput string
	addMode  bool
	quitting bool
}

// New creates a Model rooted at v. Caller must have already unlocked v.
func New(ctx context.Context, v *vault.Vault) (*Model, error) {
	m := &Model{ctx: ctx, v: v, col: 1, group: -1, promoted: map[string]time.Time{}}
	if err := m.reload(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Model) reload() error {
	g, err := m.v.ListGroups(m.ctx)
	if err != nil {
		return err
	}
	s, err := m.v.ListSecrets(m.ctx)
	if err != nil {
		return err
	}
	m.groups = g
	m.secrets = s
	m.recomputeFilter()
	return nil
}

func (m *Model) recomputeFilter() {
	now := time.Now()
	// Drop expired promotions.
	for id, t := range m.promoted {
		if now.Sub(t) > 30*time.Second {
			delete(m.promoted, id)
		}
	}
	promoted := []vault.Secret{}
	normal := []vault.Secret{}
	for _, s := range m.secrets {
		if _, ok := m.promoted[s.ID.String()]; ok {
			promoted = append(promoted, s)
		} else {
			normal = append(normal, s)
		}
	}
	combined := append(promoted, normal...)
	m.filtered = m.filtered[:0]
	for i, s := range combined {
		if m.group >= 0 && s.GroupID != m.group {
			continue
		}
		if m.filter != "" {
			q := strings.ToLower(m.filter)
			if !strings.Contains(strings.ToLower(s.Issuer), q) &&
				!strings.Contains(strings.ToLower(s.Account), q) {
				continue
			}
		}
		m.filtered = append(m.filtered, i)
	}
	if m.row >= len(m.filtered) {
		m.row = len(m.filtered) - 1
	}
	if m.row < 0 {
		m.row = 0
	}
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *Model) Init() tea.Cmd { return tick() }

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tickMsg:
		_ = time.Time(msg)
		m.recomputeFilter()
		if m.copied && time.Since(m.copiedAt) > 2*time.Second {
			m.copied = false
		}
		return m, tick()
	case tea.KeyMsg:
		return m.onKey(msg)
	}
	return m, nil
}

func (m *Model) onKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Add-input mode: capture printable + backspace + enter/esc.
	if m.addMode {
		switch k.String() {
		case "esc":
			m.addMode = false
			m.addInput = ""
			m.status = "add cancelled"
		case "enter":
			uri := strings.TrimSpace(m.addInput)
			m.addMode = false
			m.addInput = ""
			if uri == "" {
				m.status = "add: empty input"
				return m, nil
			}
			u, err := otpauth.Parse(uri)
			if err != nil {
				m.status = "bad URI: " + err.Error()
				return m, nil
			}
			if err := m.v.UpsertSecret(m.ctx, vault.Secret{
				Issuer: u.Issuer, Account: u.Account, SecretRaw: u.Secret,
				Algorithm: u.Algorithm, Digits: u.Digits, Period: u.Period,
			}); err != nil {
				m.status = "add: " + err.Error()
				return m, nil
			}
			m.reload()
			m.status = "added " + u.Issuer
		case "backspace":
			if len(m.addInput) > 0 {
				m.addInput = m.addInput[:len(m.addInput)-1]
			}
		default:
			if len(k.String()) == 1 {
				m.addInput += k.String()
			}
		}
		return m, nil
	}

	// Filter input mode: capture every printable key into the filter buffer.
	if m.filter != "" && k.String() != "esc" && k.String() != "enter" && len(k.String()) == 1 {
		m.filter += k.String()
		m.recomputeFilter()
		return m, nil
	}
	if m.filter != "" && k.String() == "backspace" {
		if len(m.filter) > 0 {
			m.filter = m.filter[:len(m.filter)-1]
		}
		m.recomputeFilter()
		return m, nil
	}
	switch k.String() {
	case "ctrl+c", "q":
		m.quitting = true
		return m, tea.Quit
	case "esc":
		m.filter = ""
		m.recomputeFilter()
	case "tab":
		m.col = (m.col + 1) % 3
	case "/":
		m.col = 1
		m.filter = ""
		m.recomputeFilter()
	case "j", "down":
		if m.col == 0 && m.row < len(m.groups)+1 { // +1 for "Unassigned" row
			m.row++
		} else if m.row < len(m.filtered)-1 {
			m.row++
		}
	case "k", "up":
		if m.row > 0 {
			m.row--
		}
	case "g":
		// cycle: All(-1) → Unassigned(0) → group1 → ... → back to All.
		// Slots = 2 + len(groups).
		totalSlots := 2 + len(m.groups)
		cur := 0
		if m.group == -1 {
			cur = 0
		} else if m.group == 0 {
			cur = 1
		} else {
			cur = 2
			for i, gg := range m.groups {
				if gg.ID == m.group {
					cur = 2 + i
				}
			}
		}
		next := (cur + 1) % totalSlots
		switch {
		case next == 0:
			m.group = -1
		case next == 1:
			m.group = 0
		default:
			m.group = m.groups[next-2].ID
		}
		m.row = 0
		m.recomputeFilter()
	case "enter":
		if s, ok := m.currentSecret(); ok {
			return m, m.copyCmd(s)
		}
	case "a":
		m.addMode = true
		m.addInput = ""
		m.status = "paste otpauth URI then Enter (Esc to cancel)"
	case "d":
		if s, ok := m.currentSecret(); ok {
			if err := m.v.DeleteSecret(m.ctx, s.ID); err != nil {
				m.status = "delete: " + err.Error()
				return m, nil
			}
			m.reload()
			m.status = "deleted"
		}
	}
	return m, nil
}

func (m *Model) currentSecret() (vault.Secret, bool) {
	if len(m.filtered) == 0 || m.row < 0 || m.row >= len(m.filtered) {
		return vault.Secret{}, false
	}
	return m.secrets[m.filtered[m.row]], true
}

func (m *Model) copyCmd(s vault.Secret) tea.Cmd {
	return func() tea.Msg {
		code, _, err := totp.Generate(s.SecretRaw, s.Algorithm, s.Digits, s.Period, time.Now())
		if err != nil {
			return struct{}{}
		}
		m.promoted[s.ID.String()] = time.Now()
		clipboardWrite(code)
		_ = m.v.TouchLastUsed(m.ctx, s.ID)
		return tickMsg(time.Now())
	}
}

func (m *Model) View() string {
	if m.quitting {
		return ""
	}
	const colGroupW = 16
	const colListW = 36
	colDetailW := 50

	var gsb strings.Builder
	gsb.WriteString("Groups\n------\n")
	// Layout: row 0 = All, row 1 = Unassigned, row 2..2+len(groups)-1 = groups
	allCount := len(m.secrets)
	unassignedCount := 0
	for _, s := range m.secrets {
		if s.GroupID == 0 {
			unassignedCount++
		}
	}
	if m.group < 0 {
		prefix := "  "
		if m.col == 0 && m.row == 0 {
			prefix = "> "
		}
		fmt.Fprintf(&gsb, "%sAll (%d)\n", prefix, allCount)
	} else {
		fmt.Fprintf(&gsb, "  All (%d)\n", allCount)
	}
	{
		prefix := "  "
		if m.col == 0 && m.row == 1 {
			prefix = "> "
		}
		marker := " "
		if m.group == 0 {
			marker = "*"
		}
		fmt.Fprintf(&gsb, "%s%s Unassigned (%d)\n", prefix, marker, unassignedCount)
	}
	for i, g := range m.groups {
		count := 0
		for _, s := range m.secrets {
			if s.GroupID == g.ID {
				count++
			}
		}
		prefix := "  "
		if m.col == 0 && m.row == i+2 {
			prefix = "> "
		}
		marker := " "
		if g.ID == m.group {
			marker = "*"
		}
		fmt.Fprintf(&gsb, "%s%s %s (%d)\n", prefix, marker, truncate(g.Name, colGroupW-7), count)
	}

	var lsb strings.Builder
	lsb.WriteString("Secrets")
	if m.filter != "" {
		fmt.Fprintf(&lsb, " [%s]", m.filter)
	}
	lsb.WriteString("\n------\n")
	for i, idx := range m.filtered {
		s := m.secrets[idx]
		prefix := "  "
		if m.col == 1 && m.row == i {
			prefix = "> "
		}
		promo := "  "
		if _, ok := m.promoted[s.ID.String()]; ok {
			promo = "★ "
		}
		fmt.Fprintf(&lsb, "%s%s%-*s  %s\n", prefix, promo, colListW/2-4,
			truncate(s.Issuer, colListW/2-4),
			truncate(s.Account, colListW/2-4))
	}

	var dsb strings.Builder
	dsb.WriteString("Detail\n------\n")
	if s, ok := m.currentSecret(); ok {
		code, rem, err := totp.Generate(s.SecretRaw, s.Algorithm, s.Digits, s.Period, time.Now())
		if err == nil {
			fmt.Fprintf(&dsb, "%s\n", s.Issuer)
			if s.Account != "" {
				fmt.Fprintf(&dsb, "  %s\n", s.Account)
			}
			dsb.WriteString("\n  ")
			dsb.WriteString(code)
			dsb.WriteString("\n\n  ")
			dsb.WriteString(renderProgress(rem, s.Period))
			fmt.Fprintf(&dsb, " %ds\n", rem)
		}
	} else {
		dsb.WriteString("(no selection)\n")
	}

	status := m.status
	if m.copied {
		status = "Copied!"
	}
	if m.addMode {
		status = "› " + m.addInput + "█"
	}
	if status != "" {
		dsb.WriteString("\n" + status + "\n")
	}

	lines := splitLines(gsb.String())
	llines := splitLines(lsb.String())
	dl := splitLines(dsb.String())
	height := max3(len(lines), len(llines), len(dl))
	var out strings.Builder
	for i := 0; i < height; i++ {
		fmt.Fprintf(&out, "%s │ %s │ %s\n",
			pad(getAt(lines, i), colGroupW),
			pad(getAt(llines, i), colListW),
			truncate(getAt(dl, i), colDetailW))
	}
	if m.addMode {
		out.WriteString("\npaste otpauth URI then Enter (Esc to cancel)\n")
	} else {
		out.WriteString("\n[/] filter  [j/k] move  [enter] copy  [g] group  [a] add  [d] del  [q] quit\n")
	}
	return out.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func renderProgress(remaining, period int) string {
	const width = 16
	if period <= 0 {
		return strings.Repeat("░", width)
	}
	filled := remaining * width / period
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	return strings.Repeat("▓", filled) + strings.Repeat("░", width-filled)
}

func splitLines(s string) []string { return strings.Split(strings.TrimRight(s, "\n"), "\n") }
func getAt(s []string, i int) string {
	if i < 0 || i >= len(s) {
		return ""
	}
	return s[i]
}
func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
func max3(a, b, c int) int {
	m := a
	if b > m {
		m = b
	}
	if c > m {
		m = c
	}
	return m
}

// clipboardWrite shells out to the platform clipboard tool.
func clipboardWrite(s string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "windows":
		cmd = exec.Command("clip")
	default:
		for _, bin := range []string{"wl-copy", "xclip", "xsel"} {
			if _, err := exec.LookPath(bin); err == nil {
				switch bin {
				case "wl-copy":
					cmd = exec.Command("wl-copy")
				case "xclip":
					cmd = exec.Command("xclip", "-selection", "clipboard")
				default:
					cmd = exec.Command("xsel", "--clipboard", "--input")
				}
				break
			}
		}
	}
	if cmd == nil {
		return
	}
	cmd.Stdin = strings.NewReader(s)
	_ = cmd.Run()
}

// quiet unused import linter if otpauth is removed later.
var _ = otpauth.Parse