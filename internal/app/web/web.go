// Package web implements the Web UI / Desktop shell. A single binary serves
// both `2fa web` (browser) and `2fa gui` (native window via webview_go).
package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/uptutu/go2fa/internal/core/importexport"
	"github.com/uptutu/go2fa/internal/core/otpauth"
	"github.com/uptutu/go2fa/internal/core/totp"
	"github.com/uptutu/go2fa/internal/core/vault"
)

// Server wraps the HTTP API.
type Server struct {
	v            *vault.Vault
	mux          *http.ServeMux
	addr         string
	srv          *http.Server
	listener     net.Listener
	token        string       // required for non-loopback binds
	lastActivity atomic.Int64 // unix seconds of the last gated request
	prefs        prefStore    // UI prefs (theme) persisted next to the vault
}

// idleLockAfter locks the vault when the API has seen no request for this
// long. The KEK otherwise lives in memory for the whole web/gui session.
const idleLockAfter = 15 * time.Minute

// New constructs a server bound to addr.
func New(addr string, v *vault.Vault, token string) (*Server, error) {
	// Sidecar files (preferences.json) live next to vault.sqlite so a
	// "wipe the vault" operation naturally cleans them up too. Falling
	// back to vault.DefaultDir keeps the API usable even when v was
	// constructed via Open without a separate vault directory.
	dir := v.Dir()
	if dir == "" {
		var err error
		dir, err = vault.DefaultDir()
		if err != nil {
			return nil, err
		}
	}
	s := &Server{
		v:        v,
		addr:     addr,
		token:    token,
		mux:      http.NewServeMux(),
		prefs:    prefStore{path: filepath.Join(dir, preferencesFile)},
	}
	s.lastActivity.Store(time.Now().Unix())
	s.routes()
	return s, nil
}

// Start binds a listener and serves in a goroutine. Returns the bound addr.
func (s *Server) Start(ctx context.Context) (string, error) {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return "", err
	}
	s.listener = ln
	s.srv = &http.Server{Handler: s.mux, ReadHeaderTimeout: 5 * time.Second}
	go s.idleLockLoop()
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("web: %v", err)
		}
	}()
	return ln.Addr().String(), nil
}

// Stop shuts the server down.
func (s *Server) Stop() error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(context.Background())
}

// Addr returns the bound address.
func (s *Server) Addr() string {
	if s.listener == nil {
		return s.addr
	}
	return s.listener.Addr().String()
}

// Loopback reports whether the bound address is loopback.
func (s *Server) Loopback() bool {
	host, _, _ := net.SplitHostPort(s.Addr())
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	return ip.IsLoopback()
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/status", s.handleStatus)
	s.mux.HandleFunc("/api/unlock", s.handleUnlock)
	s.mux.HandleFunc("/api/groups", s.handleGroups)
	s.mux.HandleFunc("/api/groups/", s.handleGroupItem)
	s.mux.HandleFunc("/api/secrets", s.handleSecrets)
	s.mux.HandleFunc("/api/secrets/", s.handleSecretItem)
	s.mux.HandleFunc("/api/code", s.handleCode)
	s.mux.HandleFunc("/api/parse-otpauth", s.handleParseOtpauth)
	s.mux.HandleFunc("/api/export", s.handleExport)
	s.mux.HandleFunc("/api/mode", s.handleMode)
	s.mux.HandleFunc("/api/preferences", s.handlePreferences)
	// Catch-all: intercept index.html to inject the saved theme so first
	// paint is correct (no FOUC, no flash of default theme). Everything
	// else falls through to the static file server.
	s.mux.HandleFunc("/", s.serveRoot)
}

// authOK enforces the auth-token policy:
//
//   - token == ""      : loopback allowed, non-loopback denied.
//   - token != ""      : require matching X-Auth-Token header on every
//     request, loopback or not. Query-string tokens are
//     rejected to avoid leaking the token into browser
//     history, bookmarks, and HTTP access logs.
//
// Token comparison uses crypto/subtle.ConstantTimeCompare so a remote
// attacker cannot mount a timing attack against the header value.
func (s *Server) authOK(r *http.Request) bool {
	if s.token == "" {
		return s.Loopback()
	}
	tok := r.Header.Get("X-Auth-Token")
	return subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) == 1
}

// originOK defends against CSRF on non-loopback binds: any state-changing
// request whose Origin header points at a different host is rejected.
// Loopback binds are exempt (single-user). Requests with no Origin (e.g.
// curl) are allowed through; auth+token still gates them.
func (s *Server) originOK(r *http.Request) bool {
	if s.Loopback() {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	bindHost, _, _ := net.SplitHostPort(s.Addr())
	if bindHost == "" {
		bindHost = s.Addr()
	}
	originHost := u.Hostname()
	return strings.EqualFold(originHost, bindHost)
}

// gate is the single entry point for handler-level access checks: auth +
// CSRF/origin. Returns true if the request may proceed; otherwise writes
// the appropriate error response and returns false.
func (s *Server) gate(r *http.Request, w http.ResponseWriter) bool {
	s.lastActivity.Store(time.Now().Unix())
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.originOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// idleLockLoop locks the vault after idleLockAfter of API silence.
func (s *Server) idleLockLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		if s.v.IsUnlocked() &&
			time.Since(time.Unix(s.lastActivity.Load(), 0)) > idleLockAfter {
			log.Printf("web: idle for %s — locking vault", idleLockAfter)
			s.v.Lock()
		}
	}
}

// writeForbidden short-circuits a CSRF / origin mismatch.
func (s *Server) writeForbidden(w http.ResponseWriter) {
	http.Error(w, "forbidden", http.StatusForbidden)
}

func (s *Server) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeErr(w http.ResponseWriter, code int, msg string) {
	http.Error(w, msg, code)
}

// apiError is the structured error body returned by writeAPIError. The
// `code` field is an i18n key (matching the `dict` keys in app.js) so
// non-English clients can translate the message client-side; `message`
// is the English fallback for clients that don't know the code.
//
// Endpoints that need bilingual error rendering should use this helper
// instead of writeErr / http.Error. The Content-Type stays JSON so the
// frontend can distinguish by content-type sniffing.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (s *Server) writeAPIError(w http.ResponseWriter, code int, i18nKey, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(apiError{Code: i18nKey, Message: msg})
}

// internalErr logs the underlying error and returns a generic 500 to the
// caller. Use this for server-side failures (decryption, DB, crypto) so
// internal state and file paths do not leak through HTTP responses.
// A locked vault is not an internal error: 423 lets the frontend show the
// unlock prompt instead of a generic failure.
func (s *Server) internalErr(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, vault.ErrLocked) {
		http.Error(w, "vault locked", http.StatusLocked)
		return
	}
	log.Printf("web: %s %s: %v", r.Method, r.URL.Path, err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// readBounded caps the request body at max bytes to bound memory use from
// authenticated POST/PATCH callers. After reading, check the error with
// decodeErr / errors.As(&maxErr) to return 413 instead of 400.
func readBounded(r *http.Request, w http.ResponseWriter, max int64) {
	r.Body = http.MaxBytesReader(w, r.Body, max)
}

// decodeErr classifies json.Read errors and writes the right status.
func (s *Server) decodeErr(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

// notFoundOrInternalErr returns true if err was a clean "not found" (404);
// otherwise it logs err and writes a generic 500, returning false.
func (s *Server) notFoundOrInternalErr(w http.ResponseWriter, r *http.Request, err error, notFoundMsg string) bool {
	if errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "no rows") {
		s.writeErr(w, http.StatusNotFound, notFoundMsg)
		return true
	}
	s.internalErr(w, r, err)
	return false
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !s.gate(r, w) {

		return
	}
	m, _ := s.v.LoadMeta(r.Context())
	out := map[string]any{
		"unlocked":   s.v.IsUnlocked(),
		"loopback":   s.Loopback(),
		"addr":       s.Addr(),
		"mode":       "password",
		"created_at": m.CreatedAt,
	}
	if m.Mode == vault.ModeNoPassword {
		out["mode"] = "no-password"
	}
	s.writeJSON(w, out)
}

// handleUnlock unlocks a locked vault (idle auto-lock, or `2fa lock`).
// Password mode needs the master password; no-password mode re-derives
// the machine key.
func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if !s.gate(r, w) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.v.IsUnlocked() {
		s.writeJSON(w, map[string]bool{"ok": true})
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	readBounded(r, w, 16*1024)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.decodeErr(w, err)
		return
	}
	m, err := s.v.LoadMeta(r.Context())
	if err != nil {
		s.internalErr(w, r, err)
		return
	}
	if m.Mode == vault.ModeNoPassword {
		err = s.v.UnlockMachineKey(r.Context())
	} else {
		err = s.v.UnlockWithPassword(r.Context(), in.Password)
	}
	if err != nil {
		http.Error(w, "unlock failed", http.StatusUnauthorized)
		return
	}
	s.lastActivity.Store(time.Now().Unix())
	s.writeJSON(w, map[string]bool{"ok": true})
}

type secretJSON struct {
	ID        string `json:"id"`
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
	Code      string `json:"code"`
	Remaining int    `json:"remaining"`
	GroupID   int64  `json:"group_id"`
	GroupName string `json:"group_name"`
	Notes     string `json:"notes,omitempty"`
	HasBackup bool   `json:"has_backup"`
}

func (s *Server) currentCode(sec vault.Secret) (string, int) {
	code, rem, _ := totp.Generate(sec.SecretRaw, sec.Algorithm, sec.Digits, sec.Period, time.Now())
	return code, rem
}

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	if !s.gate(r, w) {

		return
	}
	switch r.Method {
	case http.MethodGet:
		groups, _ := s.v.ListGroups(r.Context())
		gname := map[int64]string{}
		for _, g := range groups {
			gname[g.ID] = g.Name
		}
		secrets, err := s.v.ListSecrets(r.Context())
		if err != nil {
			s.internalErr(w, r, err)
			return
		}
		out := make([]secretJSON, 0, len(secrets))
		for _, sec := range secrets {
			code, rem := s.currentCode(sec)
			out = append(out, secretJSON{
				ID: sec.ID.String(), Issuer: sec.Issuer, Account: sec.Account,
				Algorithm: sec.Algorithm.String(), Digits: sec.Digits, Period: sec.Period,
				Code: code, Remaining: rem,
				GroupID: sec.GroupID, GroupName: gname[sec.GroupID],
				Notes:     string(sec.Notes),
				HasBackup: len(sec.BackupCodes) > 0,
			})
		}
		s.writeJSON(w, out)
	case http.MethodPost:
		var in struct {
			URI       string `json:"uri"`
			Issuer    string `json:"issuer"`
			Account   string `json:"account"`
			Secret    string `json:"secret"`
			Algorithm string `json:"algorithm"`
			Digits    int    `json:"digits"`
			Period    int    `json:"period"`
			GroupID   int64  `json:"group_id"`
		}
		readBounded(r, w, 64*1024)
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			s.decodeErr(w, err)
			return
		}
		var sec vault.Secret
		if in.URI != "" {
			u, err := otpauth.Parse(in.URI)
			if err != nil {
				s.writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
			sec = vault.Secret{
				Issuer: u.Issuer, Account: u.Account, SecretRaw: u.Secret,
				Algorithm: u.Algorithm, Digits: u.Digits, Period: u.Period,
				GroupID: in.GroupID,
			}
		} else {
			raw, err := totp.DecodeSecret(in.Secret)
			if err != nil {
				s.writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
			a, _ := totp.ParseAlgo(in.Algorithm)
			if in.Digits == 0 {
				in.Digits = 6
			}
			if in.Period == 0 {
				in.Period = 30
			}
			sec = vault.Secret{
				Issuer: in.Issuer, Account: in.Account, SecretRaw: raw,
				Algorithm: a, Digits: in.Digits, Period: in.Period,
				GroupID: in.GroupID,
			}
		}
		if err := s.v.UpsertSecret(r.Context(), sec); err != nil {
			s.internalErr(w, r, err)
			return
		}
		s.writeJSON(w, map[string]string{"id": sec.ID.String()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSecretItem(w http.ResponseWriter, r *http.Request) {
	if !s.gate(r, w) {

		return
	}
	// Sub-resource: /api/secrets/{id}/otpauth — render canonical otpauth:// URI for QR.
	if strings.HasSuffix(r.URL.Path, "/otpauth") {
		s.handleSecretOtpauth(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/secrets/")
	if id == "" {
		s.writeErr(w, http.StatusBadRequest, "missing id")
		return
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	switch r.Method {
	case http.MethodGet:
		sec, err := s.v.GetSecret(r.Context(), uid)
		if err != nil {
			s.notFoundOrInternalErr(w, r, err, "not found")
			return
		}
		groups, _ := s.v.ListGroups(r.Context())
		gname := ""
		for _, g := range groups {
			if g.ID == sec.GroupID {
				gname = g.Name
			}
		}
		code, rem := s.currentCode(sec)
		s.writeJSON(w, secretJSON{
			ID: sec.ID.String(), Issuer: sec.Issuer, Account: sec.Account,
			Algorithm: sec.Algorithm.String(), Digits: sec.Digits, Period: sec.Period,
			Code: code, Remaining: rem,
			GroupID: sec.GroupID, GroupName: gname,
			Notes:     string(sec.Notes),
			HasBackup: len(sec.BackupCodes) > 0,
		})
	case http.MethodPatch:
		readBounded(r, w, 64*1024)
		sec, err := s.v.GetSecret(r.Context(), uid)
		if err != nil {
			s.notFoundOrInternalErr(w, r, err, "not found")
			return
		}
		var patch map[string]any
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			s.decodeErr(w, err)
			return
		}
		if v, ok := patch["issuer"].(string); ok {
			sec.Issuer = v
		}
		if v, ok := patch["account"].(string); ok {
			sec.Account = v
		}
		if v, ok := patch["notes"].(string); ok {
			sec.Notes = []byte(v)
		}
		if v, ok := patch["backup"].(string); ok {
			sec.BackupCodes = []byte(v)
		}
		if v, ok := patch["algorithm"].(string); ok {
			a, err := totp.ParseAlgo(v)
			if err != nil {
				s.writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
			sec.Algorithm = a
		}
		if v, ok := patch["digits"].(float64); ok {
			if int(v) < 4 || int(v) > 10 {
				s.writeErr(w, http.StatusBadRequest, "digits must be 4..10")
				return
			}
			sec.Digits = int(v)
		}
		if v, ok := patch["period"].(float64); ok {
			if int(v) < 5 || int(v) > 120 {
				s.writeErr(w, http.StatusBadRequest, "period must be 5..120")
				return
			}
			sec.Period = int(v)
		}
		if v, ok := patch["secret"].(string); ok && v != "" {
			raw, err := totp.DecodeSecret(v)
			if err != nil {
				s.writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
			sec.SecretRaw = raw
		}
		if v, ok := patch["group_id"].(float64); ok {
			sec.GroupID = int64(v)
		}
		if err := s.v.UpsertSecret(r.Context(), sec); err != nil {
			s.internalErr(w, r, err)
			return
		}
		s.writeJSON(w, map[string]bool{"ok": true})
	case http.MethodDelete:
		if err := s.v.DeleteSecret(r.Context(), uid); err != nil {
			s.internalErr(w, r, err)
			return
		}
		s.writeJSON(w, map[string]bool{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSecretOtpauth returns the canonical otpauth:// URI for a single secret.
// Used by the web UI to render a QR code so users can scan it with their phone.
// Gated by the same auth token as the rest of the /api surface. The seed lives
// inside the URI itself; the user already authorized viewing the secret when
// they could see it in the list, so this is the same trust boundary.
func (s *Server) handleSecretOtpauth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/secrets/")
	id = strings.TrimSuffix(id, "/otpauth")
	uid, err := uuid.Parse(id)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	sec, err := s.v.GetSecret(r.Context(), uid)
	if err != nil {
		s.notFoundOrInternalErr(w, r, err, "not found")
		return
	}
	uri := otpauth.URI{
		Type:      otpauth.TOTP,
		Issuer:    sec.Issuer,
		Account:   sec.Account,
		Secret:    sec.SecretRaw,
		Algorithm: sec.Algorithm,
		Digits:    sec.Digits,
		Period:    sec.Period,
	}
	s.writeJSON(w, map[string]string{"uri": uri.String()})
}

func (s *Server) handleCode(w http.ResponseWriter, r *http.Request) {
	if !s.gate(r, w) {

		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		s.writeErr(w, http.StatusBadRequest, "id required")
		return
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	sec, err := s.v.GetSecret(r.Context(), uid)
	if err != nil {
		s.notFoundOrInternalErr(w, r, err, "not found")
		return
	}
	code, rem := s.currentCode(sec)
	_ = s.v.TouchLastUsed(r.Context(), uid)
	s.writeJSON(w, map[string]any{"code": code, "remaining": rem})
}

func (s *Server) handleParseOtpauth(w http.ResponseWriter, r *http.Request) {
	if !s.gate(r, w) {

		return
	}
	readBounded(r, w, 64*1024)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		s.writeErr(w, http.StatusBadRequest, "read body")
		return
	}
	u, err := otpauth.Parse(string(body))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, u)
}

// handleExport returns a partial or full vault export.
//
// Request body: {"format":".2fa"|"aegis"|"otpauth", "ids":[uuid,...]?, "password":string?}
//   - ids omitted/empty → export all secrets (current scope filter is applied client-side first)
//   - format=".2fa" requires password
//
// Response: raw bytes (Content-Type set per format, Content-Disposition: attachment).
// ponytail: scope-gate on ids is done in the handler below; backend never trusts
// the client to filter secrets out of the vault.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if !s.gate(r, w) {

		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Format   string   `json:"format"`
		IDs      []string `json:"ids"`
		Password string   `json:"password"`
	}
	readBounded(r, w, 64*1024)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.decodeErr(w, err)
		return
	}
	switch in.Format {
	case ".2fa", "aegis", "otpauth":
	default:
		s.writeErr(w, http.StatusBadRequest, "format must be .2fa|aegis|otpauth")
		return
	}
	all, err := s.v.ListSecrets(r.Context())
	if err != nil {
		s.internalErr(w, r, err)
		return
	}
	groups, _ := s.v.ListGroups(r.Context())
	picked := all
	if len(in.IDs) > 0 {
		want := make(map[uuid.UUID]struct{}, len(in.IDs))
		for _, id := range in.IDs {
			u, err := uuid.Parse(id)
			if err != nil {
				s.writeErr(w, http.StatusBadRequest, "bad id: "+id)
				return
			}
			want[u] = struct{}{}
		}
		picked = picked[:0]
		for _, sec := range all {
			if _, ok := want[sec.ID]; ok {
				picked = append(picked, sec)
			}
		}
		if len(picked) == 0 {
			s.writeErr(w, http.StatusBadRequest, "no matching secrets")
			return
		}
		// Scope groups to the ones actually used by picked, so the exported
		// .2fa / aegis file doesn't carry orphan group names.
		used := make(map[int64]struct{}, len(picked))
		for _, sec := range picked {
			used[sec.GroupID] = struct{}{}
		}
		filtered := groups[:0]
		for _, g := range groups {
			if _, ok := used[g.ID]; ok {
				filtered = append(filtered, g)
			}
		}
		groups = filtered
	}
	var data []byte
	switch in.Format {
	case ".2fa":
		data, err = importexport.ExportSecrets2FA(picked, groups, in.Password)
	case "aegis":
		data, err = importexport.ExportSecretsAegis(picked, groups)
	case "otpauth":
		data, err = importexport.ExportSecretsOtpauth(picked)
	}
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ct := "application/octet-stream"
	ext := in.Format
	if in.Format == "aegis" {
		ct = "application/json"
		ext = "aegis.json"
	} else if in.Format == "otpauth" {
		ct = "text/plain; charset=utf-8"
		ext = "otpauth.txt"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", `attachment; filename="export-`+ext+`"`)
	_, _ = w.Write(data)
}

// handleMode switches the vault between password and no-password mode.
// Backed by Vault.SetPassword / DisablePassword, which re-encrypt every
// row under the new KEK. The vault must be unlocked — Lock() zeroing the
// KEK would leave us unable to decrypt the rows we're about to re-write.
// Both directions are destructive in different ways:
//
//   - password → no-password: weakens the vault to machine-bound only.
//   - no-password → password: caller is responsible for remembering the
//     password; recovery is impossible without an exported backup.
//
// The 8-char minimum on the new password is a UX floor, not a crypto
// claim: Argon2id derives the KEK regardless, but anything shorter is
// essentially "no password" anyway and gets in the way of clear warning
// copy in the UI ("set a password" should mean something).
//
// Validation runs server-side too, not just in the UI: the API must
// reject a pure-whitespace password (otherwise "        " would pass
// the byte-length check and produce a KEK with no real entropy), and
// the two password fields must match on the wire (otherwise a buggy or
// hostile client could rekey the vault with a value the user never saw
// in the confirmation box).
func (s *Server) handleMode(w http.ResponseWriter, r *http.Request) {
	if !s.gate(r, w) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.v.IsUnlocked() {
		http.Error(w, "vault locked", http.StatusUnauthorized)
		return
	}
	var in struct {
		Mode     string `json:"mode"`
		Password string `json:"password"`
		Confirm  string `json:"confirm"`
	}
	readBounded(r, w, 16*1024)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.decodeErr(w, err)
		return
	}
	ctx := r.Context()
	switch in.Mode {
	case "password":
		// TrimSpace: reject pure-whitespace input. Trim then check length
		// would lose legit "  password  " typing, so check TrimSpace
		// being empty OR raw length < 8.
		if strings.TrimSpace(in.Password) == "" || len(in.Password) < 8 {
			s.writeAPIError(w, http.StatusBadRequest, "mode_pw_short",
				"password must be at least 8 characters and not blank")
			return
		}
		if in.Password != in.Confirm {
			s.writeAPIError(w, http.StatusBadRequest, "mode_pw_mismatch",
				"passwords do not match")
			return
		}
		if err := s.v.SetPassword(ctx, in.Password); err != nil {
			s.internalErr(w, r, err)
			return
		}
	case "no-password":
		if err := s.v.DisablePassword(ctx); err != nil {
			s.internalErr(w, r, err)
			return
		}
	default:
		s.writeAPIError(w, http.StatusBadRequest, "mode_invalid",
			"mode must be 'password' or 'no-password'")
		return
	}
	m, _ := s.v.LoadMeta(ctx)
	out := "password"
	if m.Mode == vault.ModeNoPassword {
		out = "no-password"
	}
	s.writeJSON(w, map[string]any{"ok": true, "mode": out})
}

// handlePreferences is the server-authoritative UI prefs store. Theme
// lives here (not just localStorage) so the choice survives across
// `2fa gui` launches — the underlying webview gets no persistent
// localStorage without a configured user-data-dir that glaze does not set.
// Non-loopback binds still pass through auth + origin checks via gate().
func (s *Server) handlePreferences(w http.ResponseWriter, r *http.Request) {
	if !s.gate(r, w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		prefs, err := s.prefs.load()
		if err != nil {
			s.internalErr(w, r, err)
			return
		}
		s.writeJSON(w, prefs)
	case http.MethodPut:
		readBounded(r, w, 4*1024)
		var in Preferences
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			s.decodeErr(w, err)
			return
		}
		// Whitelist theme values: keep the API from accepting arbitrary
		// strings that the client then injects into a style attribute.
		switch in.Theme {
		case "aurora", "obsidian", "dusk", "paper", "ember", "mono":
		default:
			s.writeErr(w, http.StatusBadRequest, "unknown theme")
			return
		}
		if err := s.prefs.save(in); err != nil {
			s.internalErr(w, r, err)
			return
		}
		s.writeJSON(w, in)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// serveRoot handles the catch-all: serves the embedded static assets, but
// intercepts index.html to inject the saved theme. The injected script
// runs BEFORE first paint, so the user sees the correct theme even on
// the very first frame — no aurora→obsidian flash.
func (s *Server) serveRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/" || r.URL.Path == "/index.html" {
		s.serveIndex(w, r)
		return
	}
	http.FileServer(http.FS(staticFS)).ServeHTTP(w, r)
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	body, err := fs.ReadFile(staticFS, "index.html")
	if err != nil {
		s.internalErr(w, r, err)
		return
	}
	prefs, err := s.prefs.load()
	if err != nil {
		// Non-fatal: if prefs fail to load, serve default theme rather
		// than breaking the whole UI. Log so it's not silently lost.
		log.Printf("web: load prefs: %v", err)
		prefs.Theme = "aurora"
	}
	// Inject before the existing theme-detection script. The inline
	// script in index.html reads window.__initialTheme first.
	inject := fmt.Sprintf(`<script>window.__initialTheme=%q;</script>`, prefs.Theme)
	body = bytes.Replace(body, []byte("<script>"), []byte(inject+"<script>"), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	if !s.gate(r, w) {

		return
	}
	switch r.Method {
	case http.MethodGet:
		gs, _ := s.v.ListGroups(r.Context())
		s.writeJSON(w, gs)
	case http.MethodPost:
		var in struct {
			Name  string `json:"name"`
			Color string `json:"color"`
		}
		readBounded(r, w, 16*1024)
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			s.decodeErr(w, err)
			return
		}
		if in.Name == "" {
			s.writeErr(w, http.StatusBadRequest, "name required")
			return
		}
		id, err := s.v.CreateGroup(r.Context(), vault.Group{Name: in.Name, Color: in.Color})
		if err != nil {
			s.internalErr(w, r, err)
			return
		}
		s.writeJSON(w, map[string]any{"id": id})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGroupItem handles PATCH and DELETE on /api/groups/{id}.
func (s *Server) handleGroupItem(w http.ResponseWriter, r *http.Request) {
	if !s.gate(r, w) {

		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/groups/")
	var id int64
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil || id <= 0 {
		s.writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var patch struct {
			Name  string `json:"name"`
			Color string `json:"color"`
		}
		readBounded(r, w, 16*1024)
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			s.decodeErr(w, err)
			return
		}
		if err := s.v.RenameGroup(r.Context(), id, patch.Name, patch.Color); err != nil {
			s.internalErr(w, r, err)
			return
		}
		s.writeJSON(w, map[string]bool{"ok": true})
	case http.MethodDelete:
		if err := s.v.DeleteGroup(r.Context(), id); err != nil {
			s.internalErr(w, r, err)
			return
		}
		s.writeJSON(w, map[string]bool{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// NewAuthToken generates a 128-bit hex token for non-loopback access.
func NewAuthToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// keep fmt import alive for future use
var _ = fmt.Sprintf
