// Package web implements the Web UI / Desktop shell. A single binary serves
// both `2fa web` (browser) and `2fa gui` (native window via webview_go).
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/uptutu/go2fa/internal/core/importexport"
	"github.com/uptutu/go2fa/internal/core/otpauth"
	"github.com/uptutu/go2fa/internal/core/totp"
	"github.com/uptutu/go2fa/internal/core/vault"
)

// Server wraps the HTTP API.
type Server struct {
	v        *vault.Vault
	mux      *http.ServeMux
	addr     string
	srv      *http.Server
	listener net.Listener
	token    string // required for non-loopback binds
}

// New constructs a server bound to addr.
func New(addr string, v *vault.Vault, token string) (*Server, error) {
	s := &Server{v: v, addr: addr, token: token, mux: http.NewServeMux()}
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
	s.mux.HandleFunc("/api/groups", s.handleGroups)
	s.mux.HandleFunc("/api/groups/", s.handleGroupItem)
	s.mux.HandleFunc("/api/secrets", s.handleSecrets)
	s.mux.HandleFunc("/api/secrets/", s.handleSecretItem)
	s.mux.HandleFunc("/api/code", s.handleCode)
	s.mux.HandleFunc("/api/parse-otpauth", s.handleParseOtpauth)
	s.mux.HandleFunc("/api/export", s.handleExport)
	s.mux.Handle("/", http.FileServer(http.FS(staticFS)))
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

// internalErr logs the underlying error and returns a generic 500 to the
// caller. Use this for server-side failures (decryption, DB, crypto) so
// internal state and file paths do not leak through HTTP responses.
func (s *Server) internalErr(w http.ResponseWriter, r *http.Request, err error) {
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
	if in.Format == "aegis" {
		ct = "application/json"
	} else if in.Format == "otpauth" {
		ct = "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", `attachment; filename="export-`+in.Format+`"`)
	_, _ = w.Write(data)
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
