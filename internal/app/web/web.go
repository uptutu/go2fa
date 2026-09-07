// Package web implements the Web UI / Desktop shell. A single binary serves
// both `2fa web` (browser) and `2fa gui` (native window via webview_go).
package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"2fa/internal/core/otpauth"
	"2fa/internal/core/totp"
	"2fa/internal/core/vault"
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
	s.mux.Handle("/", http.FileServer(http.FS(staticFS)))
}

func (s *Server) authOK(r *http.Request) bool {
	if s.Loopback() {
		return true
	}
	if s.token == "" {
		return false
	}
	tok := r.Header.Get("X-Auth-Token")
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	return tok == s.token
}

func (s *Server) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeErr(w http.ResponseWriter, code int, msg string) {
	http.Error(w, msg, code)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		s.writeErr(w, http.StatusUnauthorized, "unauthorized")
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
	if !s.authOK(r) {
		s.writeErr(w, http.StatusUnauthorized, "unauthorized")
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
			s.writeErr(w, http.StatusInternalServerError, err.Error())
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
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			s.writeErr(w, http.StatusBadRequest, err.Error())
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
			s.writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeJSON(w, map[string]string{"id": sec.ID.String()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSecretItem(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		s.writeErr(w, http.StatusUnauthorized, "unauthorized")
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
			s.writeErr(w, http.StatusNotFound, err.Error())
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
		sec, err := s.v.GetSecret(r.Context(), uid)
		if err != nil {
			s.writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		var patch map[string]any
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			s.writeErr(w, http.StatusBadRequest, err.Error())
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
			s.writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeJSON(w, map[string]bool{"ok": true})
	case http.MethodDelete:
		if err := s.v.DeleteSecret(r.Context(), uid); err != nil {
			s.writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeJSON(w, map[string]bool{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCode(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		s.writeErr(w, http.StatusUnauthorized, "unauthorized")
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
		s.writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	code, rem := s.currentCode(sec)
	_ = s.v.TouchLastUsed(r.Context(), uid)
	s.writeJSON(w, map[string]any{"code": code, "remaining": rem})
}

func (s *Server) handleParseOtpauth(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		s.writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	body, _ := io.ReadAll(r.Body)
	u, err := otpauth.Parse(string(body))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, u)
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		s.writeErr(w, http.StatusUnauthorized, "unauthorized")
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
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			s.writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if in.Name == "" {
			s.writeErr(w, http.StatusBadRequest, "name required")
			return
		}
		id, err := s.v.CreateGroup(r.Context(), vault.Group{Name: in.Name, Color: in.Color})
		if err != nil {
			s.writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeJSON(w, map[string]any{"id": id})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGroupItem handles PATCH and DELETE on /api/groups/{id}.
func (s *Server) handleGroupItem(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		s.writeErr(w, http.StatusUnauthorized, "unauthorized")
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
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			s.writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.v.RenameGroup(r.Context(), id, patch.Name, patch.Color); err != nil {
			s.writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeJSON(w, map[string]bool{"ok": true})
	case http.MethodDelete:
		if err := s.v.DeleteGroup(r.Context(), id); err != nil {
			s.writeErr(w, http.StatusInternalServerError, err.Error())
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