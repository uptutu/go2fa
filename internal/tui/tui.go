// Package tui implements the bubbletea-based terminal UI.
//
// Layout (three columns):
//
//	┌──────────┬──────────────────┬──────────────────┐
//	│ GROUPS   │ SECRETS          │ DETAIL (TOTP)    │
//	│ ──────── │ ──────────────── │ ──────────────── │
//	│ All      │ GitHub     alex  │  GitHub          │
//	│ Work     │ GitLab     bob   │   123 456        │
//	│   ► g   │ Discord    ...   │   ▓▓▓▓▓░░ 18s    │
//	└──────────┴──────────────────┴──────────────────┘
//
// Keys (focus starts on Secrets so Enter copies the first row immediately):
//
//	1..9     jump to Nth row + auto-copy (1 keystroke total)
//	j/k  ↑/↓  move selection in active column
//	tab/shift-tab  cycle column
//	enter    copy current code to clipboard
//	/        start filter (Esc clears, types immediately)
//	a        add (paste otpauth URI)
//	g        cycle group filter (All → Unassigned → group1 …)
//	D        delete (press D twice — second confirms)
//	?        toggle help
//	q / ctrl+c  quit
//
// UI primitives are bubbles components: textinput for filter / add,
// viewport for the scrollable secrets list, help.Model for the keymap
// footer.
package tui

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/uptutu/go2fa/internal/core/otpauth"
	"github.com/uptutu/go2fa/internal/core/totp"
	"github.com/uptutu/go2fa/internal/core/vault"
)

type tickMsg time.Time

// deleteArmed is the time window during which a second D confirms deletion.
const deleteArmWindow = 2 * time.Second

// secretsPanelMinHeight is the floor for the list viewport on very small
// terminals. The viewport grows with the terminal height otherwise.
const secretsPanelMinHeight = 5

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
	// pending deletion: secret ID + time. Second D within window confirms.
	deleteArmedID string
	deleteArmedAt time.Time
	quitting      bool
	helpVisible   bool
	terminalW     int
	terminalH     int

	// addInput/addMode are kept as plain fields (not just the bubbles
	// textinput) because the public API and tests assert on them: callers
	// and TestTUIAddMode/TestTUIAddCancel read m.addMode and m.addInput
	// directly. The addField textinput mirrors addInput into its Edit
	// buffer while addMode is true.
	//
	// Two-step manual add: when addStep == 0 the user types a URI (or
	// anything that isn't "otpauth://..." — that's auto-detected on enter).
	// If it isn't a URI, the model advances to addStep == 1 (name) and then
	// addStep == 2 (secret). Enter on each step moves forward; Esc cancels
	// the whole flow.
	addMode      bool
	addInput     string
	addStep      int // 0 = URI buffer, 1 = name, 2 = secret
	addName      string
	addNameField textinput.Model
	addSecret    string
	addSecretFld textinput.Model
	filterInput  textinput.Model
	addField     textinput.Model
	listViewport viewport.Model
	helpModel    help.Model
	keys         keymap
}

// keymap groups every keyboard binding exposed in the help footer.
// Folding the bindings into one place replaces the long switch ladder
// in onKey and keeps the help line auto-generated.
type keymap struct {
	Copy      key.Binding
	Jump      key.Binding // 1..9; help shows the spec without enumerating each digit
	Down      key.Binding
	Up        key.Binding
	Bottom    key.Binding
	PageDown  key.Binding
	PageUp    key.Binding
	NextCol   key.Binding
	PrevCol   key.Binding
	Filter    key.Binding
	Add       key.Binding
	Group     key.Binding
	Delete    key.Binding
	Help      key.Binding
	Quit      key.Binding
	CancelEsc key.Binding
}

// ShortHelp implements help.KeyMap — only the essentials, kept short.
func (k keymap) ShortHelp() []key.Binding {
	return []key.Binding{k.Copy, k.Jump, k.Filter, k.Add, k.Delete, k.Help, k.Quit}
}

// FullHelp implements help.KeyMap — every binding, grouped by column.
func (k keymap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Copy, k.Down, k.Up, k.Bottom, k.PageDown, k.PageUp},
		{k.NextCol, k.PrevCol, k.Filter, k.Add, k.Group, k.Delete, k.CancelEsc},
		{k.Help, k.Quit, k.Jump},
	}
}

// New creates a Model rooted at v. Caller must have already unlocked v.
func New(ctx context.Context, v *vault.Vault) (*Model, error) {
	fi := textinput.New()
	fi.Placeholder = "filter…"
	fi.Prompt = "/ "
	fi.CharLimit = 64
	fi.Blur() // filter starts inactive; "/" focuses it.

	ai := textinput.New()
	ai.Placeholder = "otpauth:// URI  (or press enter on empty to add manually)"
	ai.Prompt = "› "
	ai.CharLimit = 512
	ai.Blur()

	ni := textinput.New()
	ni.Placeholder = "name (e.g. GitHub)"
	ni.Prompt = "name: "
	ni.CharLimit = 64
	ni.Blur()

	si := textinput.New()
	si.Placeholder = "base32 secret"
	si.Prompt = "secret: "
	si.CharLimit = 128
	si.EchoCharacter = '•'
	si.EchoMode = textinput.EchoPassword
	si.Blur()

	vp := viewport.New(0, secretsPanelMinHeight)
	vp.SetContent("")

	m := &Model{
		ctx:          ctx,
		v:            v,
		col:          1, // start focused on Secrets so Enter copies the first row
		group:        -1,
		promoted:     map[string]time.Time{},
		helpVisible:  true,
		filterInput:  fi,
		addField:     ai,
		addNameField: ni,
		addSecretFld: si,
		listViewport: vp,
		helpModel:    help.New(),
		keys:         defaultKeymap(),
	}
	if err := m.reload(); err != nil {
		return nil, err
	}
	return m, nil
}

func defaultKeymap() keymap {
	return keymap{
		Copy:      key.NewBinding(key.WithKeys("enter"), key.WithHelp("↵", "copy")),
		Jump:      key.NewBinding(key.WithKeys("1..9"), key.WithHelp("1-9", "jump+copy")),
		Down:      key.NewBinding(key.WithKeys("j", "down"), key.WithHelp("j/↓", "down")),
		Up:        key.NewBinding(key.WithKeys("k", "up"), key.WithHelp("k/↑", "up")),
		Bottom:    key.NewBinding(key.WithKeys("G"), key.WithHelp("G", "bottom of list")),
		PageDown:  key.NewBinding(key.WithKeys("pgdown", " ", "f"), key.WithHelp("␣/f", "page down")),
		PageUp:    key.NewBinding(key.WithKeys("pgup", "b"), key.WithHelp("b", "page up")),
		NextCol:   key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "next col")),
		PrevCol:   key.NewBinding(key.WithKeys("shift+tab"), key.WithHelp("⇧tab", "prev col")),
		Filter:    key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
		Add:       key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "add URI")),
		Group:     key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "cycle group")),
		Delete:    key.NewBinding(key.WithKeys("D"), key.WithHelp("D", "delete (×2)")),
		Help:      key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		Quit:      key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
		CancelEsc: key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "cancel")),
	}
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
	case tea.WindowSizeMsg:
		m.terminalW = msg.Width
		m.terminalH = msg.Height
		// Reserve: header (~3) + status (~2) + padding (~3) = ~8 rows.
		vh := msg.Height - 8
		if vh < secretsPanelMinHeight {
			vh = secretsPanelMinHeight
		}
		m.listViewport.Height = vh
		return m, nil
	case tickMsg:
		_ = time.Time(msg)
		// Expire stale delete-arm window.
		if m.deleteArmedID != "" && time.Since(m.deleteArmedAt) > deleteArmWindow {
			m.deleteArmedID = ""
			m.status = "delete cancelled"
		}
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
	// Add-input mode: append printable keys into m.addInput and mirror to
	// addField for rendering. Submit/cancel handled inline.
	if m.addMode {
		// Step 1: name (manual add flow).
		if m.addStep == 1 {
			switch k.String() {
			case "esc":
				m.cancelAdd()
				return m, nil
			case "enter":
				name := strings.TrimSpace(m.addName)
				if name == "" {
					m.status = "name cannot be empty"
					return m, nil
				}
				m.addStep = 2
				m.addSecret = ""
				m.addSecretFld.SetValue("")
				m.addNameField.Blur()
				m.addSecretFld.Focus()
				m.status = "enter base32 secret for " + name + " (Esc cancel)"
				return m, nil
			}
			var cmd tea.Cmd
			m.addNameField, cmd = m.addNameField.Update(k)
			m.addName = m.addNameField.Value()
			return m, cmd
		}
		// Step 2: secret (manual add flow) — submits the row.
		if m.addStep == 2 {
			switch k.String() {
			case "esc":
				m.cancelAdd()
				return m, nil
			case "enter":
				secret := strings.TrimSpace(m.addSecret)
				if secret == "" {
					m.status = "secret cannot be empty"
					return m, nil
				}
				decoded, err := totp.DecodeSecret(secret)
				if err != nil {
					m.status = "bad base32: " + err.Error()
					return m, nil
				}
				if err := m.v.UpsertSecret(m.ctx, vault.Secret{
					Issuer: m.addName, Account: "", SecretRaw: decoded,
					Algorithm: totp.SHA1, Digits: 6, Period: 30,
				}); err != nil {
					m.status = "add: " + err.Error()
					return m, nil
				}
				name := m.addName
				m.cancelAdd()
				m.reload()
				m.status = "added " + stripCtl(name) + " — clear scrollback (typed secret)"
				return m, nil
			}
			var cmd tea.Cmd
			m.addSecretFld, cmd = m.addSecretFld.Update(k)
			m.addSecret = m.addSecretFld.Value()
			return m, cmd
		}
		// Step 0: URI buffer.
		switch k.String() {
		case "esc":
			m.cancelAdd()
			return m, nil
		case "enter":
			uri := strings.TrimSpace(m.addInput)
			if uri == "" {
				// Empty enter jumps to the manual-add flow: name → secret.
				m.addStep = 1
				m.addField.Blur()
				m.addNameField.SetValue("")
				m.addNameField.Focus()
				m.status = "add: enter name (Esc cancel)"
				return m, nil
			}
			if !strings.HasPrefix(uri, "otpauth://") {
				m.status = "not an otpauth:// URI; press Esc and try again, or paste a URI"
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
			m.cancelAdd()
			m.reload()
			m.status = "added " + stripCtl(u.Issuer) + " — clear scrollback (URI contains the secret)"
			return m, nil
		case "backspace":
			if len(m.addInput) > 0 {
				m.addInput = m.addInput[:len(m.addInput)-1]
				m.addField.SetValue(m.addInput)
			}
			return m, nil
		default:
			s := stripCtl(k.String())
			if s != "" {
				m.addInput += s
				m.addField.SetValue(m.addInput)
			}
			return m, nil
		}
	}

	// Filter-input mode: textinput owns editing; commit on enter, cancel on esc.
	if m.filterInput.Focused() {
		switch k.String() {
		case "esc":
			m.filterInput.Blur()
			m.filterInput.SetValue("")
			m.filter = ""
			m.recomputeFilter()
			return m, nil
		case "enter":
			m.filter = m.filterInput.Value()
			m.filterInput.Blur()
			m.recomputeFilter()
			return m, nil
		}
		var cmd tea.Cmd
		prev := m.filterInput.Value()
		m.filterInput, cmd = m.filterInput.Update(k)
		if cur := m.filterInput.Value(); cur != prev {
			m.filter = cur
			m.recomputeFilter()
		}
		return m, cmd
	}

	// Universal shortcuts that don't depend on column.
	switch k.String() {
	case "ctrl+c", "q":
		m.quitting = true
		return m, tea.Quit
	case "?":
		m.helpVisible = !m.helpVisible
		return m, nil
	case "esc":
		m.deleteArmedID = ""
		m.status = ""
	case "tab":
		m.col = (m.col + 1) % 3
		return m, nil
	case "shift+tab":
		m.col = (m.col + 2) % 3
		return m, nil
	case "/":
		m.col = 1
		m.filterInput.SetValue("")
		m.filter = ""
		m.filterInput.Focus()
		m.recomputeFilter()
		return m, nil
	case "a":
		m.addMode = true
		m.addStep = 0
		m.addInput = ""
		m.addName = ""
		m.addSecret = ""
		m.addField.SetValue("")
		m.addNameField.SetValue("")
		m.addSecretFld.SetValue("")
		m.addField.Focus()
		m.status = "paste otpauth URI → Enter  ·  empty Enter → add manually"
		return m, nil
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
		return m, nil
	}

	// Column-aware shortcuts.
	switch m.col {
	case 0:
		switch k.String() {
		case "j", "down":
			if m.row < len(m.groups)+1 { // +1 for "Unassigned" row
				m.row++
			}
		case "k", "up":
			if m.row > 0 {
				m.row--
			}
		case "enter":
			m.applyGroupFromRow()
		}
	case 1, 2:
		switch k.String() {
		case "j", "down":
			if m.row < len(m.filtered)-1 {
				m.row++
			}
		case "k", "up":
			if m.row > 0 {
				m.row--
			}
		case "G":
			if len(m.filtered) > 0 {
				m.row = len(m.filtered) - 1
			}
		case "pgdown", " ", "f":
			m.row += m.listViewport.Height
			if m.row >= len(m.filtered) {
				m.row = len(m.filtered) - 1
			}
			if m.row < 0 {
				m.row = 0
			}
		case "pgup", "b":
			m.row -= m.listViewport.Height
			if m.row < 0 {
				m.row = 0
			}
		case "enter":
			if s, ok := m.currentSecret(); ok {
				return m, m.copyCmd(s)
			}
		case "D":
			return m.handleDelete()
		}

		// 1..9 fast select + auto-copy on the secrets column.
		if m.col == 1 {
			if r, ok := digitRow(k.String()); ok {
				if r > 0 && r <= len(m.filtered) {
					m.row = r - 1
					if s, ok := m.currentSecret(); ok {
						return m, m.copyCmd(s)
					}
				}
				return m, nil
			}
		}
	}
	return m, nil
}

// digitRow returns (1-indexed row, true) for the keys "1".."9".
func digitRow(s string) (int, bool) {
	if len(s) != 1 || s[0] < '1' || s[0] > '9' {
		return 0, false
	}
	return int(s[0] - '0'), true
}

// cancelAdd tears down all add-flow state in one place so every exit
// (success, validation error, user Esc) ends the same way.
func (m *Model) cancelAdd() {
	m.addMode = false
	m.addStep = 0
	m.addInput = ""
	m.addName = ""
	m.addSecret = ""
	m.addField.SetValue("")
	m.addField.Blur()
	m.addNameField.SetValue("")
	m.addNameField.Blur()
	m.addSecretFld.SetValue("")
	m.addSecretFld.Blur()
	m.status = "add cancelled"
}

// handleDelete implements the two-press D confirmation. A first press arms
// the deletion (status hints) and the same key within the window confirms.
func (m *Model) handleDelete() (tea.Model, tea.Cmd) {
	s, ok := m.currentSecret()
	if !ok {
		m.status = "delete: no selection"
		return m, nil
	}
	id := s.ID.String()
	if m.deleteArmedID == id && time.Since(m.deleteArmedAt) <= deleteArmWindow {
		if err := m.v.DeleteSecret(m.ctx, s.ID); err != nil {
			m.status = "delete: " + err.Error()
			m.deleteArmedID = ""
			return m, nil
		}
		m.deleteArmedID = ""
		m.reload()
		m.status = "deleted " + stripCtl(s.Issuer)
		return m, nil
	}
	m.deleteArmedID = id
	m.deleteArmedAt = time.Now()
	m.status = "press D again within 2s to delete " + stripCtl(s.Issuer)
	return m, nil
}

// applyGroupFromRow applies the group corresponding to the selected group row.
func (m *Model) applyGroupFromRow() {
	switch m.row {
	case 0:
		m.group = -1
	case 1:
		m.group = 0
	default:
		idx := m.row - 2
		if idx >= 0 && idx < len(m.groups) {
			m.group = m.groups[idx].ID
		}
	}
	m.row = 0
	m.recomputeFilter()
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

// listContent renders the Secrets pane as a fixed-height, prefixed
// string suitable for viewport.SetContent. The active row gets ">"
// and promoted (recently copied) rows get a star prefix.
func (m *Model) listContent(width int) string {
	if len(m.filtered) == 0 {
		return "  (no secrets)"
	}
	var b strings.Builder
	col := width / 2
	if col < 8 {
		col = 8
	}
	for i, idx := range m.filtered {
		s := m.secrets[idx]
		prefix := "  "
		if m.col == 1 && i == m.row {
			prefix = "> "
		}
		promo := "  "
		if _, ok := m.promoted[s.ID.String()]; ok {
			promo = "★ "
		}
		fmt.Fprintf(&b, "%s%s%-*s  %s\n", prefix, promo, col-4,
			truncate(stripCtl(s.Issuer), col-4),
			truncate(stripCtl(s.Account), col-4))
	}
	return b.String()
}

// groupsContent renders the Groups pane as a fixed-height string.
func (m *Model) groupsContent(width int) string {
	if width <= 0 {
		return ""
	}
	var b strings.Builder
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
		fmt.Fprintf(&b, "%sAll (%d)\n", prefix, allCount)
	} else {
		fmt.Fprintf(&b, "  All (%d)\n", allCount)
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
		fmt.Fprintf(&b, "%s%s Unassigned (%d)\n", prefix, marker, unassignedCount)
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
		fmt.Fprintf(&b, "%s%s %s (%d)\n", prefix, marker, truncate(g.Name, width-7), count)
	}
	return b.String()
}

// detailContent renders the Detail pane as a fixed-height string.
func (m *Model) detailContent(width int) string {
	var b strings.Builder
	b.WriteString("Detail\n")
	b.WriteString(strings.Repeat("-", width) + "\n")
	if s, ok := m.currentSecret(); ok {
		code, rem, err := totp.Generate(s.SecretRaw, s.Algorithm, s.Digits, s.Period, time.Now())
		if err == nil {
			fmt.Fprintf(&b, "%s\n", stripCtl(s.Issuer))
			if s.Account != "" {
				fmt.Fprintf(&b, "  %s\n", stripCtl(s.Account))
			}
			b.WriteString("\n  ")
			b.WriteString(code)
			b.WriteString("\n\n  ")
			b.WriteString(renderProgress(rem, s.Period))
			fmt.Fprintf(&b, " %ds\n", rem)
		}
	} else {
		b.WriteString("(no selection)\n")
	}
	return b.String()
}

// headerLine is the top label row that sits above each pane.
func (m *Model) headerLine(listW, detailW int) (list, detail string) {
	var lb strings.Builder
	lb.WriteString("Secrets")
	if m.filter != "" {
		lb.WriteString(" [")
		lb.WriteString(m.filter)
		lb.WriteString("]")
	}
	if len(m.filtered) > m.listViewport.Height && m.listViewport.Height > 0 {
		fmt.Fprintf(&lb, " (%d/%d)", m.row+1, len(m.filtered))
	}
	lb.WriteString("\n")
	lb.WriteString(strings.Repeat("-", listW))
	lb.WriteString("\n")
	list = lb.String()

	var dtb strings.Builder
	dtb.WriteString("Detail\n")
	dtb.WriteString(strings.Repeat("-", detailW))
	dtb.WriteString("\n")
	detail = dtb.String()
	return list, detail
}

func (m *Model) View() string {
	if m.quitting {
		return ""
	}
	// Pick column widths from terminal width; fall back to a width that
	// comfortably fits the 3-column layout.
	tw := m.terminalW
	if tw < 100 {
		tw = 120
	}
	colGroupW := 16
	colListW := 36
	colDetailW := tw - colGroupW - colListW - 6 // 6 = " │ " * 2
	if colDetailW < 24 {
		colDetailW = 24
	}
	if tw-colGroupW-colListW-6 < 24 {
		// Narrow terminal: collapse the groups column to a 2-column view.
		colGroupW = 0
		colListW = 28
		colDetailW = tw - colListW - 3
		if colDetailW < 20 {
			colDetailW = 20
		}
	}

	// Render each pane at its declared size. The viewport in the secrets
	// pane handles its own scroll position; we only adjust YOffset so the
	// current row stays visible.
	m.ensureViewportPosition()
	m.listViewport.Width = colListW
	listContent := m.listContent(colListW)
	m.listViewport.SetContent(listContent)
	listView := m.listViewport.View()
	// Re-prepend the header so the viewport only owns the rows below it.
	listHead, detailHead := m.headerLine(colListW, colDetailW)
	listRendered := listHead + indentLines(listView, "  ")

	detailRendered := detailHead + indentLines(m.detailContent(colDetailW), "  ")

	// Side-by-side composition with fixed column padding.
	var out strings.Builder
	if colGroupW > 0 {
		groupsRendered := m.renderColumn(m.groupsContent(colGroupW), m.listViewport.Height+2, colGroupW)
		fmt.Fprintf(&out, "%s │ %s │ %s\n",
			groupsRendered,
			padRight(listRendered, colListW),
			truncateLines(detailRendered, colDetailW))
	} else {
		fmt.Fprintf(&out, "%s │ %s\n",
			padRight(listRendered, colListW),
			truncateLines(detailRendered, colDetailW))
	}

	// Status / add-mode bar.
	if m.addMode {
		switch m.addStep {
		case 1:
			out.WriteString("\n" + m.addNameField.View() + "\n")
		case 2:
			out.WriteString("\n" + m.addSecretFld.View() + "\n")
		default:
			out.WriteString("\n" + m.addField.View() + "\n")
		}
	} else {
		status := m.status
		if m.copied {
			status = "✓ Copied!  (auto-clears in 2s)"
		}
		if status == "" {
			status = "ready — [↵ copy] [1-9 jump+copy] [/ filter] [a add] [g group] [D del] [? help] [q quit]"
		}
		out.WriteString("\n" + status + "\n")
	}

	// Filter input line — shown when focused, hidden when empty + blurred.
	if m.filterInput.Focused() {
		out.WriteString(m.filterInput.View() + "\n")
	} else if m.filter != "" {
		out.WriteString("/ " + m.filter + "\n")
	}

	if m.helpVisible {
		out.WriteString(m.helpModel.ShortHelpView(m.keys.ShortHelp()) + "\n")
		out.WriteString(m.helpModel.FullHelpView(m.keys.FullHelp()) + "\n")
	}
	return out.String()
}

// ensureViewportPosition advances the list viewport so the active row is
// in the visible window. Mirrors the previous ensureRowVisible behaviour
// but defers the scroll math to the viewport's own bounds.
func (m *Model) ensureViewportPosition() {
	if m.listViewport.Height <= 0 {
		return
	}
	if m.row < m.listViewport.YOffset {
		m.listViewport.SetYOffset(m.row)
	}
	if m.row >= m.listViewport.YOffset+m.listViewport.Height {
		m.listViewport.SetYOffset(m.row - m.listViewport.Height + 1)
	}
}

// renderColumn pads a string to width and clips to height rows by either
// appending blank rows (when short) or truncating from the top.
func (m *Model) renderColumn(content string, height, width int) string {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	for len(lines) < height {
		lines = append(lines, "")
	}
	if len(lines) > height {
		// Bottom-align so a long list still shows the tail.
		lines = lines[len(lines)-height:]
	}
	var b strings.Builder
	for _, l := range lines {
		fmt.Fprintf(&b, "%s\n", padRight(l, width))
	}
	return strings.TrimRight(b.String(), "\n")
}

// indentLines left-pads every line of s with pad.
func indentLines(s, pad string) string {
	if pad == "" {
		return s
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}

// truncateLines shortens each line of s to at most width bytes (rune-safe).
func truncateLines(s string, width int) string {
	if width <= 0 {
		return ""
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = truncate(l, width)
	}
	return strings.Join(lines, "\n")
}

// padRight returns s padded with spaces to width (no truncation).
func padRight(s string, width int) string {
	if width <= 0 {
		return s
	}
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

// stripCtl removes ANSI/VT escape sequences and other non-printable control
// chars from s. Used on user-controlled strings (issuer, account, notes,
// pasted URI) before they reach the terminal renderer, so escape sequences
// from a malicious or compromised vault row can't rewrite the terminal.
//
// Implements a small subset of ECMA-48:
//   - ESC [ params final-byte      (CSI)
//   - ESC ] body BEL | ESC \\      (OSC)
//   - ESC + single intermediate char (other Fe escape)
//
// Tab (0x09), newline, carriage return, form feed, backspace, and BEL are
// kept as harmless layout/control bytes; every other C0 control and DEL is
// dropped.
func stripCtl(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	const (
		sNorm = iota
		sEsc   // saw ESC, waiting for introducer
		sCSI   // inside CSI: skip until final byte (0x40..0x7E)
		sOSC   // inside OSC: skip until BEL or ST (ESC \)
		sOST   // inside OSC, just saw ESC; next char is '\' = ST end
	)
	state := sNorm
	for _, r := range s {
		switch state {
		case sNorm:
			switch r {
			case 0x1B:
				state = sEsc
			case 0x07, 0x08, 0x09, 0x0A, 0x0C, 0x0D:
				b.WriteRune(r)
			default:
				if r < 0x20 || r == 0x7F {
					// drop other C0 controls and DEL
					continue
				}
				b.WriteRune(r)
			}
		case sEsc:
			switch r {
			case '[':
				state = sCSI
			case ']':
				state = sOSC
			default:
				// single-char Fe escape (e.g., ESC =, ESC c). Drop both.
				state = sNorm
			}
		case sCSI:
			if r >= 0x40 && r <= 0x7E {
				state = sNorm
			}
		case sOSC:
			switch r {
			case 0x07:
				state = sNorm
			case 0x1B:
				state = sOST
			}
		case sOST:
			// Either ST (ESC \) ends the OSC, or it's still OSC body.
			if r == '\\' {
				state = sNorm
			} else {
				state = sOSC
				// re-process current rune in OSC state
				switch r {
				case 0x07:
					state = sNorm
				case 0x1B:
					state = sOST
				}
			}
		}
	}
	return b.String()
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
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