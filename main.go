// Command 2fa is the entry point for the 2fa TOTP manager.
//
// Subcommands:
//
//   init         initialize a vault (prompts for password unless --no-password)
//   unlock       prompt for password and load KEK into the running process
//   lock         zero the in-memory KEK
//   list         list secrets
//   add          add a secret (URI or interactive)
//   copy         print current TOTP code to stdout and clipboard if available
//   delete       delete a secret
//   edit         edit a secret's metadata
//   group        manage groups
//   export       export the vault (encrypted .2fa, or plain aegis/otpauth)
//   import       import from .2fa / Aegis JSON / otpauth URI list
//   tui          launch the bubbletea TUI
//   web          launch the embedded web UI
//
// All subcommands auto-prompt for password if the vault is locked.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/uptutu/go2fa/internal/core/importexport"
	"github.com/uptutu/go2fa/internal/core/otpauth"
	"github.com/uptutu/go2fa/internal/core/totp"
	"github.com/uptutu/go2fa/internal/core/vault"
)

var (
	flagNoPassword bool
	flagListen     string
	flagToken      string
)

func main() {
	root := &cobra.Command{
		Use:           "2fa",
		Short:         "Cross-platform TOTP manager with encrypted vault",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolVar(&flagNoPassword, "no-password", false, "initialize a no-password (machine-bound) vault")
	root.PersistentFlags().StringVar(&flagListen, "listen", "", "address for web subcommand (default 127.0.0.1:random)")
	root.PersistentFlags().StringVar(&flagToken, "token", "", "auth token for non-loopback --listen")

	root.AddCommand(cmdInit, cmdUnlock, cmdList, cmdAdd, cmdCopy,
		cmdDelete, cmdEdit, cmdGroup, cmdExport, cmdImport, cmdTUI, cmdWeb, cmdGUI)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// openVault returns an opened, unlocked vault. Handles init-on-first-run.
func openVault(ctx context.Context) (*vault.Vault, error) {
	exists, err := vault.Exists()
	if err != nil {
		return nil, err
	}
	v, err := vault.Open(ctx)
	if err != nil {
		return nil, err
	}
	if !exists {
		fmt.Fprintln(os.Stderr, "No vault found at", vaultDir(), "— initializing.")
		mode := vault.ModePassword
		pw := ""
		if flagNoPassword || yesNo("Use machine-bound encryption (no master password)?") {
			mode = vault.ModeNoPassword
		} else {
			pw = promptPassword("Set master password: ")
			pw2 := promptPassword("Confirm: ")
			if pw != pw2 {
				return nil, errors.New("passwords do not match")
			}
		}
		if err := v.Init(ctx, mode, pw); err != nil {
			return nil, err
		}
		return v, nil
	}
	if v.IsUnlocked() {
		return v, nil
	}
	m, err := v.LoadMeta(ctx)
	if err != nil {
		return nil, err
	}
	if m.Mode == vault.ModePassword {
		for attempts := 0; attempts < 3; attempts++ {
			pw := promptPassword("Master password: ")
			if err := v.UnlockWithPassword(ctx, pw); err == nil {
				return v, nil
			}
			fmt.Fprintln(os.Stderr, "wrong password")
		}
		return nil, errors.New("too many wrong attempts")
	}
	if err := v.UnlockMachineKey(ctx); err != nil {
		return nil, fmt.Errorf("unlock machine key: %w", err)
	}
	return v, nil
}

func vaultDir() string {
	d, _ := vault.DefaultDir()
	return d
}

func promptPassword(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return ""
		}
		return string(b)
	}
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		return sc.Text()
	}
	return ""
}

func yesNo(q string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", q)
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		s := sc.Text()
		return s == "y" || s == "Y"
	}
	return false
}

// copyToClipboard writes s to the system clipboard using platform commands.
func copyToClipboard(s string) {
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
	cmd.Stdin = &stringReadCloser{s: s}
	_ = cmd.Run()
}

type stringReadCloser struct {
	s string
	o int
}

func (r *stringReadCloser) Read(p []byte) (int, error) {
	if r.o >= len(r.s) {
		return 0, os.ErrClosed
	}
	n := copy(p, r.s[r.o:])
	r.o += n
	return n, nil
}
func (r *stringReadCloser) Close() error { return nil }

// --- commands ---

var cmdInit = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := openVault(context.Background())
		if err == nil {
			v.Close()
		}
		return err
	},
}

var cmdUnlock = &cobra.Command{
	Use:   "unlock",
	Short: "Prompt for password and unlock",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := openVault(context.Background())
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "unlocked")
		return nil
	},
}

var cmdList = &cobra.Command{
	Use:   "list",
	Short: "List all secrets with current TOTP codes",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		v, err := openVault(ctx)
		if err != nil {
			return err
		}
		defer v.Close()
		groups, _ := v.ListGroups(ctx)
		gname := map[int64]string{}
		for _, g := range groups {
			gname[g.ID] = g.Name
		}
		secrets, err := v.ListSecrets(ctx)
		if err != nil {
			return err
		}
		now := time.Now()
		fmt.Fprintf(os.Stdout, "%-24s  %-16s  %-10s  %-12s  %-12s  %s\n",
			"ISSUER", "ACCOUNT", "CODE", "EXPIRES", "LAST_USED", "GROUP")
		for _, s := range secrets {
			code, rem, err := totp.Generate(s.SecretRaw, s.Algorithm, s.Digits, s.Period, now)
			if err != nil {
				code = "ERR"
			}
			lastUsed := "—"
			if s.LastUsedAt != nil {
				lastUsed = formatRelative(now, *s.LastUsedAt)
			}
			group := gname[s.GroupID]
			if group == "" {
				group = "Unassigned"
			}
			fmt.Fprintf(os.Stdout, "%-24s  %-16s  %s(%2ds)  %-12s  %-12s  %s\n",
				truncate(s.Issuer, 24), truncate(s.Account, 16),
				code, rem,
				fmt.Sprintf("%ds", rem),
				lastUsed,
				group)
		}
		return nil
	},
}

// formatRelative returns "just now", "5m ago", "3h ago", "2d ago".
func formatRelative(now, past time.Time) string {
	d := now.Sub(past)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

var cmdAdd = &cobra.Command{
	Use:   "add <issuer> <account> <base32-secret> | add --uri <otpauth-uri>",
	Short: "Add a secret",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		v, err := openVault(ctx)
		if err != nil {
			return err
		}
		defer v.Close()
		uri, _ := cmd.Flags().GetString("uri")
		var sec vault.Secret
		if uri != "" {
			u, err := otpauth.Parse(uri)
			if err != nil {
				return err
			}
			sec = vault.Secret{
				Issuer: u.Issuer, Account: u.Account, SecretRaw: u.Secret,
				Algorithm: u.Algorithm, Digits: u.Digits, Period: u.Period,
			}
		} else if len(args) >= 3 {
			raw, err := totp.DecodeSecret(args[2])
			if err != nil {
				return err
			}
			sec = vault.Secret{
				Issuer: args[0], Account: args[1], SecretRaw: raw,
				Algorithm: totp.SHA1, Digits: 6, Period: 30,
			}
		} else {
			return errors.New("usage: 2fa add <issuer> <account> <base32-secret>  or  --uri <otpauth-uri>")
		}
		if gname, _ := cmd.Flags().GetString("group"); gname != "" {
			found := false
			for _, g := range mustGroups(v, ctx) {
				if g.Name == gname {
					sec.GroupID = g.ID
					found = true
				}
			}
			if !found {
				return fmt.Errorf("group %q not found (use `2fa group add` first)", gname)
			}
		}
		if err := v.UpsertSecret(ctx, sec); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "added:", sec.Issuer, sec.Account)
		return nil
	},
}

func init() {
	cmdAdd.Flags().String("uri", "", "otpauth:// URI")
	cmdAdd.Flags().String("group", "", "group name")
}

var cmdCopy = &cobra.Command{
	Use:   "copy <issuer> [account] [--uuid]",
	Short: "Print current TOTP and copy to clipboard if possible",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		v, err := openVault(ctx)
		if err != nil {
			return err
		}
		defer v.Close()
		if len(args) < 1 {
			return errors.New("usage: 2fa copy <issuer> [account]  or  --uuid <uuid>")
		}
		all, err := v.ListSecrets(ctx)
		if err != nil {
			return err
		}
		var picks []vault.Secret
		for _, s := range all {
			if s.Issuer == args[0] {
				if len(args) > 1 && s.Account != args[1] {
					continue
				}
				picks = append(picks, s)
			}
		}
		if len(picks) == 0 {
			return fmt.Errorf("no secret matches issuer=%q account=%q", args[0], argOr(args, 1, ""))
		}
		if len(picks) > 1 {
			lines := []string{fmt.Sprintf("multiple matches for issuer=%q; pick an account:", args[0])}
			for _, p := range picks {
				lines = append(lines, fmt.Sprintf("  %s  %s", p.ID, p.Account))
			}
			return errors.New(strings.Join(lines, "\n"))
		}
		s := picks[0]
		code, rem, err := totp.Generate(s.SecretRaw, s.Algorithm, s.Digits, s.Period, time.Now())
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, code)
		copyToClipboard(code)
		_ = v.TouchLastUsed(ctx, s.ID)
		if rem <= 5 {
			fmt.Fprintf(os.Stderr, "(code expires in %ds)\n", rem)
		}
		return nil
	},
}

func argOr(args []string, idx int, def string) string {
	if idx < len(args) {
		return args[idx]
	}
	return def
}

var cmdDelete = &cobra.Command{
	Use:   "delete <uuid>",
	Short: "Delete a secret by UUID",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("usage: 2fa delete <uuid>")
		}
		id, err := uuid.Parse(args[0])
		if err != nil {
			return err
		}
		v, err := openVault(context.Background())
		if err != nil {
			return err
		}
		defer v.Close()
		return v.DeleteSecret(context.Background(), id)
	},
}

var cmdEdit = &cobra.Command{
	Use:   "edit <uuid>",
	Short: "Edit a secret's fields. Pass --issuer/--account/--notes/--backup/--algorithm/--digits/--period/--group to set, omit to keep current.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("usage: 2fa edit <uuid> [--issuer ...] [--account ...] [--notes ...] [--backup ...] [--algorithm SHA1|SHA256|SHA512] [--digits N] [--period N] [--group <name>] [--secret <base32>]")
		}
		id, err := uuid.Parse(args[0])
		if err != nil {
			return fmt.Errorf("bad uuid: %w", err)
		}
		ctx := context.Background()
		v, err := openVault(ctx)
		if err != nil {
			return err
		}
		defer v.Close()
		sec, err := v.GetSecret(ctx, id)
		if err != nil {
			return err
		}
		// Update fields that were explicitly set.
		changed := false
		if s, _ := cmd.Flags().GetString("issuer"); cmd.Flags().Changed("issuer") {
			sec.Issuer = s
			changed = true
		}
		if s, _ := cmd.Flags().GetString("account"); cmd.Flags().Changed("account") {
			sec.Account = s
			changed = true
		}
		if s, _ := cmd.Flags().GetString("notes"); cmd.Flags().Changed("notes") {
			sec.Notes = []byte(s)
			changed = true
		}
		if s, _ := cmd.Flags().GetString("backup"); cmd.Flags().Changed("backup") {
			sec.BackupCodes = []byte(s)
			changed = true
		}
		if s, _ := cmd.Flags().GetString("algorithm"); cmd.Flags().Changed("algorithm") {
			a, err := totp.ParseAlgo(s)
			if err != nil {
				return err
			}
			sec.Algorithm = a
			changed = true
		}
		if n, _ := cmd.Flags().GetInt("digits"); cmd.Flags().Changed("digits") {
			if n < 4 || n > 10 {
				return errors.New("digits must be 4..10")
			}
			sec.Digits = n
			changed = true
		}
		if n, _ := cmd.Flags().GetInt("period"); cmd.Flags().Changed("period") {
			if n < 5 || n > 120 {
				return errors.New("period must be 5..120")
			}
			sec.Period = n
			changed = true
		}
		if g, _ := cmd.Flags().GetString("group"); cmd.Flags().Changed("group") {
			var gid int64
			for _, gg := range mustGroups(v, ctx) {
				if gg.Name == g {
					gid = gg.ID
				}
			}
			if gid == 0 && g != "" && g != "Unassigned" {
				return fmt.Errorf("group %q not found (use `2fa group add` first)", g)
			}
			sec.GroupID = gid
			changed = true
		}
		if s, _ := cmd.Flags().GetString("secret"); cmd.Flags().Changed("secret") {
			raw, err := totp.DecodeSecret(s)
			if err != nil {
				return err
			}
			sec.SecretRaw = raw
			changed = true
		}
		if !changed {
			return errors.New("no --field flags given; nothing to update")
		}
		if err := v.UpsertSecret(ctx, sec); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "updated:", sec.Issuer, sec.Account)
		return nil
	},
}

func init() {
	cmdEdit.Flags().String("issuer", "", "set issuer")
	cmdEdit.Flags().String("account", "", "set account label")
	cmdEdit.Flags().String("notes", "", "set notes (replaces existing)")
	cmdEdit.Flags().String("backup", "", "set backup codes, newline-separated")
	cmdEdit.Flags().String("algorithm", "", "SHA1 | SHA256 | SHA512")
	cmdEdit.Flags().Int("digits", 0, "code length (4..10)")
	cmdEdit.Flags().Int("period", 0, "code period in seconds (5..120)")
	cmdEdit.Flags().String("group", "", "move to group (by name)")
	cmdEdit.Flags().String("secret", "", "replace base32 secret (use with care)")
}

var cmdGroup = &cobra.Command{
	Use:   "group <add|list|rename|delete> [args]",
	Short: "Manage groups",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("usage: 2fa group add|list|rename|delete ...")
		}
		v, err := openVault(context.Background())
		if err != nil {
			return err
		}
		defer v.Close()
		ctx := context.Background()
		switch args[0] {
		case "list":
			groups, _ := v.ListGroups(ctx)
			for _, g := range groups {
				fmt.Fprintf(os.Stdout, "%d  %s  %s\n", g.ID, g.Name, g.Color)
			}
		case "add":
			if len(args) < 2 {
				return errors.New("usage: 2fa group add <name> [--color #hex]")
			}
			color, _ := cmd.Flags().GetString("color")
			id, err := v.CreateGroup(ctx, vault.Group{Name: args[1], Color: color})
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, "created id", id)
		case "rename":
			if len(args) < 3 {
				return errors.New("usage: 2fa group rename <id> <newname>")
			}
			var id int64
			fmt.Sscanf(args[1], "%d", &id)
			if err := v.RenameGroup(ctx, id, args[2], ""); err != nil {
				return err
			}
		case "delete":
			if len(args) < 2 {
				return errors.New("usage: 2fa group delete <id>")
			}
			var id int64
			fmt.Sscanf(args[1], "%d", &id)
			if err := v.DeleteGroup(ctx, id); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown subcommand %q", args[0])
		}
		return nil
	},
}

func init() {
	cmdGroup.Flags().String("color", "", "hex color like #7c3aed")
}

var cmdExport = &cobra.Command{
	Use:   "export --format <.2fa|aegis|otpauth> --out <file|->",
	Short: "Export the vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		format, _ := cmd.Flags().GetString("format")
		out, _ := cmd.Flags().GetString("out")
		password, _ := cmd.Flags().GetString("password")
		if format == "" {
			format = "aegis"
		}
		if out == "" {
			out = "-"
		}
		if format == ".2fa" && password == "" {
			password = promptPassword("Encryption password: ")
		}
		v, err := openVault(context.Background())
		if err != nil {
			return err
		}
		defer v.Close()
		data, err := importexport.ExportVault(v, format, password)
		if err != nil {
			return err
		}
		return importexport.WriteFile(out, data, 0o600)
	},
}

func init() {
	cmdExport.Flags().String("format", "aegis", "export format: .2fa | aegis | otpauth")
	cmdExport.Flags().String("out", "-", "output file or - for stdout")
	cmdExport.Flags().String("password", "", "encryption password (prompted if .2fa)")
}

var cmdImport = &cobra.Command{
	Use:   "import <file|->",
	Short: "Import from .2fa / Aegis JSON / otpauth URI list",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("usage: 2fa import <file|->")
		}
		format, buf, err := importexport.DetectFile(args[0])
		if err != nil {
			return err
		}
		password, _ := cmd.Flags().GetString("password")
		if format == importexport.Format2FA || format == importexport.FormatAegisEncrypted {
			if password == "" {
				password = promptPassword("File password: ")
			}
		}
		res, err := importexport.Import(buf, password)
		if err != nil {
			return err
		}
		v, err := openVault(context.Background())
		if err != nil {
			return err
		}
		defer v.Close()
		ctx := context.Background()
		gid := map[string]int64{}
		existingGroups, _ := v.ListGroups(ctx)
		for _, g := range existingGroups {
			gid[g.Name] = g.ID
		}
		for _, g := range res.Groups {
			if _, ok := gid[g.Name]; ok {
				continue
			}
			newID, err := v.CreateGroup(ctx, g)
			if err != nil {
				return err
			}
			gid[g.Name] = newID
		}
		for _, s := range res.Secrets {
			if err := v.UpsertSecret(ctx, s); err != nil {
				return err
			}
		}
		fmt.Fprintf(os.Stdout, "imported %d secrets, %d groups\n", len(res.Secrets), len(res.Groups))
		return nil
	},
}

func init() {
	cmdImport.Flags().String("password", "", "file password")
}

var cmdTUI = &cobra.Command{
	Use:   "tui",
	Short: "Launch the interactive TUI",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTUI()
	},
}

func mustGroups(v *vault.Vault, ctx context.Context) []vault.Group {
	gs, _ := v.ListGroups(ctx)
	return gs
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}