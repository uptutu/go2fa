package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/uptutu/go2fa/internal/core/otpauth"
	"github.com/uptutu/go2fa/internal/core/totp"
	"github.com/uptutu/go2fa/internal/core/vault"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	st, err := vault.OpenStore(context.Background(), filepath.Join(dir, "vault.sqlite"), nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	v := vault.NewForTesting(st, dir)
	if err := v.Init(context.Background(), vault.ModeNoPassword, ""); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv, err := New("127.0.0.1:0", v, "")
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if _, err := srv.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(); _ = v.Close() })
	return srv
}

func TestAPIStatus(t *testing.T) {
	srv := newTestServer(t)
	res, err := http.Get("http://" + srv.Addr() + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	if body["unlocked"] != true {
		t.Errorf("expected unlocked=true, got %v", body["unlocked"])
	}
}

func TestAPISecretsRoundtrip(t *testing.T) {
	srv := newTestServer(t)
	uri := "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30"
	res, err := http.Post("http://"+srv.Addr()+"/api/secrets", "application/json",
		bytes.NewBufferString(`{"uri":"`+uri+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("POST status %d: %s", res.StatusCode, b)
	}
	res.Body.Close()

	res, err = http.Get("http://" + srv.Addr() + "/api/secrets")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var list []secretJSON
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("want 1, got %d", len(list))
	}
	if list[0].Issuer != "GitHub" {
		t.Errorf("issuer: %s", list[0].Issuer)
	}
	if len(list[0].Code) != 6 {
		t.Errorf("code length: %s", list[0].Code)
	}
	// Confirm the code matches what totp.Generate produces directly.
	raw, _ := totp.DecodeSecret("JBSWY3DPEHPK3PXP")
	want, _, _ := totp.Generate(raw, totp.SHA1, 6, 30, time.Now())
	if list[0].Code != want {
		t.Errorf("server code %s != totp code %s (timing drift ok)", list[0].Code, want)
	}
}

func TestAPIDeleteSecret(t *testing.T) {
	srv := newTestServer(t)
	uri := "otpauth://totp/Test:a?secret=AAAA&algorithm=SHA1&digits=6&period=30"
	http.Post("http://"+srv.Addr()+"/api/secrets", "application/json",
		bytes.NewBufferString(`{"uri":"`+uri+`"}`))

	res, _ := http.Get("http://" + srv.Addr() + "/api/secrets")
	var list []secretJSON
	json.NewDecoder(res.Body).Decode(&list)
	res.Body.Close()
	if len(list) != 1 {
		t.Fatalf("setup: want 1 secret, got %d", len(list))
	}
	id := list[0].ID

	req, _ := http.NewRequest("DELETE", "http://"+srv.Addr()+"/api/secrets/"+id, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Errorf("delete: %d", res.StatusCode)
	}
	res.Body.Close()

	res, _ = http.Get("http://" + srv.Addr() + "/api/secrets")
	json.NewDecoder(res.Body).Decode(&list)
	res.Body.Close()
	if len(list) != 0 {
		t.Errorf("after delete: %d", len(list))
	}
}

func TestAPIGroups(t *testing.T) {
	srv := newTestServer(t)
	res, err := http.Post("http://"+srv.Addr()+"/api/groups", "application/json",
		bytes.NewBufferString(`{"name":"Work","color":"#7c3aed"}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Errorf("create: %d", res.StatusCode)
	}
	res.Body.Close()
	res, err = http.Get("http://" + srv.Addr() + "/api/groups")
	if err != nil {
		t.Fatal(err)
	}
	var gs []vault.Group
	json.NewDecoder(res.Body).Decode(&gs)
	res.Body.Close()
	if len(gs) != 1 || gs[0].Name != "Work" {
		t.Errorf("groups: %+v", gs)
	}
}

func TestAPIPostPlainSecret(t *testing.T) {
	srv := newTestServer(t)
	body := `{"issuer":"Manual","account":"a","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1","digits":6,"period":30}`
	res, err := http.Post("http://"+srv.Addr()+"/api/secrets", "application/json",
		bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("status %d: %s", res.StatusCode, b)
	}
	res.Body.Close()
}

func TestAPIRequiresAuthWhenTokenSet(t *testing.T) {
	// When a token is configured, every request (loopback included) must
	// present a matching header. Token comparison is constant-time.
	dir := t.TempDir()
	st, _ := vault.OpenStore(context.Background(), filepath.Join(dir, "vault.sqlite"), nil)
	v := vault.NewForTesting(st, dir)
	v.Init(context.Background(), vault.ModeNoPassword, "")
	srv, _ := New("127.0.0.1:0", v, "secret-token")
	if _, err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	// No header: 401, even on loopback.
	res, _ := http.Get("http://" + srv.Addr() + "/api/status")
	if res.StatusCode != 401 {
		t.Errorf("no token: want 401, got %d", res.StatusCode)
	}
	res.Body.Close()

	// Wrong header: 401.
	req, _ := http.NewRequest("GET", "http://"+srv.Addr()+"/api/status", nil)
	req.Header.Set("X-Auth-Token", "wrong")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 401 {
		t.Errorf("wrong token: want 401, got %d", res.StatusCode)
	}
	res.Body.Close()

	// Correct header: 200.
	req, _ = http.NewRequest("GET", "http://"+srv.Addr()+"/api/status", nil)
	req.Header.Set("X-Auth-Token", "secret-token")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Errorf("correct token: want 200, got %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestAPILoopbackNoTokenAllowed(t *testing.T) {
	// Loopback with NO token configured: still open (default `2fa web` use).
	srv := newTestServer(t)
	res, _ := http.Get("http://" + srv.Addr() + "/api/status")
	if res.StatusCode != 200 {
		t.Errorf("loopback no-token: want 200, got %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestAPIQueryStringTokenRejected(t *testing.T) {
	// Query-string `?token=` is no longer accepted; only the
	// X-Auth-Token header gates non-loopback binds. This avoids the
	// token landing in browser history / bookmarks / proxy logs.
	dir := t.TempDir()
	st, _ := vault.OpenStore(context.Background(), filepath.Join(dir, "vault.sqlite"), nil)
	v := vault.NewForTesting(st, dir)
	v.Init(context.Background(), vault.ModeNoPassword, "")
	srv, _ := New("127.0.0.1:0", v, "secret-token")
	if _, err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	// Query-string token: 401.
	res, _ := http.Get("http://" + srv.Addr() + "/api/status?token=secret-token")
	if res.StatusCode != 401 {
		t.Errorf("?token= should be rejected, got %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestAPIPayloadTooLarge(t *testing.T) {
	srv := newTestServer(t)
	// 70 KiB body exceeds the 64 KiB limit on /api/secrets.
	big := make([]byte, 70*1024)
	for i := range big {
		big[i] = 'A'
	}
	body := `{"issuer":"` + string(big) + `","secret":"JBSWY3DPEHPK3PXP"}`
	res, err := http.Post("http://"+srv.Addr()+"/api/secrets", "application/json",
		bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized POST: want 413, got %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestAPIPatchSecret(t *testing.T) {
	srv := newTestServer(t)
	uri := "otpauth://totp/GitHub:a?secret=JBSWY3DPEHPK3PXP"
	http.Post("http://"+srv.Addr()+"/api/secrets", "application/json",
		bytes.NewBufferString(`{"uri":"`+uri+`"}`))

	// List to get id.
	res, _ := http.Get("http://" + srv.Addr() + "/api/secrets")
	var list []secretJSON
	json.NewDecoder(res.Body).Decode(&list)
	res.Body.Close()
	id := list[0].ID

	// PATCH issuer + notes.
	req, _ := http.NewRequest("PATCH", "http://"+srv.Addr()+"/api/secrets/"+id,
		bytes.NewBufferString(`{"issuer":"GitLab","notes":"work account","digits":8}`))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("PATCH status %d: %s", res.StatusCode, b)
	}
	res.Body.Close()

	// GET single secret to confirm.
	res, _ = http.Get("http://" + srv.Addr() + "/api/secrets/" + id)
	var one secretJSON
	json.NewDecoder(res.Body).Decode(&one)
	res.Body.Close()
	if one.Issuer != "GitLab" {
		t.Errorf("issuer after patch: %q", one.Issuer)
	}
	if one.Notes != "work account" {
		t.Errorf("notes after patch: %q", one.Notes)
	}
	if one.Digits != 8 {
		t.Errorf("digits after patch: %d", one.Digits)
	}
}

func TestAPIPatchSecretValidation(t *testing.T) {
	srv := newTestServer(t)
	uri := "otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP"
	http.Post("http://"+srv.Addr()+"/api/secrets", "application/json",
		bytes.NewBufferString(`{"uri":"`+uri+`"}`))
	res, _ := http.Get("http://" + srv.Addr() + "/api/secrets")
	var list []secretJSON
	json.NewDecoder(res.Body).Decode(&list)
	res.Body.Close()
	id := list[0].ID

	// digits out of range
	req, _ := http.NewRequest("PATCH", "http://"+srv.Addr()+"/api/secrets/"+id,
		bytes.NewBufferString(`{"digits":2}`))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 400 {
		t.Errorf("expected 400 for bad digits, got %d", res.StatusCode)
	}
	res.Body.Close()

	// bad algorithm
	req, _ = http.NewRequest("PATCH", "http://"+srv.Addr()+"/api/secrets/"+id,
		bytes.NewBufferString(`{"algorithm":"MD5"}`))
	req.Header.Set("Content-Type", "application/json")
	res, _ = http.DefaultClient.Do(req)
	if res.StatusCode != 400 {
		t.Errorf("expected 400 for bad algorithm, got %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestAPIDeleteGroup(t *testing.T) {
	srv := newTestServer(t)
	res, _ := http.Post("http://"+srv.Addr()+"/api/groups", "application/json",
		bytes.NewBufferString(`{"name":"Work"}`))
	res.Body.Close()
	res, _ = http.Get("http://" + srv.Addr() + "/api/groups")
	var gs []vault.Group
	json.NewDecoder(res.Body).Decode(&gs)
	res.Body.Close()
	if len(gs) != 1 {
		t.Fatalf("setup: %d groups", len(gs))
	}
	id := gs[0].ID

	req, _ := http.NewRequest("DELETE", fmt.Sprintf("http://%s/api/groups/%d", srv.Addr(), id), nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Errorf("delete: %d", res.StatusCode)
	}
	res.Body.Close()

	res, _ = http.Get("http://" + srv.Addr() + "/api/groups")
	json.NewDecoder(res.Body).Decode(&gs)
	res.Body.Close()
	if len(gs) != 0 {
		t.Errorf("after delete: %d groups", len(gs))
	}
}

func TestAPIPatchGroup(t *testing.T) {
	srv := newTestServer(t)
	res, _ := http.Post("http://"+srv.Addr()+"/api/groups", "application/json",
		bytes.NewBufferString(`{"name":"Work","color":"#aaa"}`))
	res.Body.Close()
	res, _ = http.Get("http://" + srv.Addr() + "/api/groups")
	var gs []vault.Group
	json.NewDecoder(res.Body).Decode(&gs)
	res.Body.Close()
	id := gs[0].ID

	req, _ := http.NewRequest("PATCH", fmt.Sprintf("http://%s/api/groups/%d", srv.Addr(), id),
		bytes.NewBufferString(`{"name":"Job","color":"#7c3aed"}`))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Errorf("patch: %d", res.StatusCode)
	}
	res.Body.Close()

	res, _ = http.Get("http://" + srv.Addr() + "/api/groups")
	json.NewDecoder(res.Body).Decode(&gs)
	res.Body.Close()
	if gs[0].Name != "Job" || gs[0].Color != "#7c3aed" {
		t.Errorf("after patch: %+v", gs[0])
	}
}

func TestAPISecretOtpauth(t *testing.T) {
	srv := newTestServer(t)
	uri := "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30"
	res, err := http.Post("http://"+srv.Addr()+"/api/secrets", "application/json",
		bytes.NewBufferString(`{"uri":"`+uri+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("POST status %d: %s", res.StatusCode, b)
	}
	res.Body.Close()

	// List secrets and pick the real ID (POST returns zero-UUID because
	// Store.UpsertSecret takes Secret by value).
	res, err = http.Get("http://" + srv.Addr() + "/api/secrets")
	if err != nil {
		t.Fatal(err)
	}
	var list []secretJSON
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if len(list) == 0 {
		t.Fatal("no secrets in list")
	}
	id := list[0].ID

	// Fetch the otpauth URI for the new secret
	res, err = http.Get("http://" + srv.Addr() + "/api/secrets/" + id + "/otpauth")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("status %d: %s", res.StatusCode, b)
	}
	var body struct{ URI string }
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.URI == "" {
		t.Fatal("empty uri")
	}
	// Round-trip: parse the emitted URI; should yield a non-empty secret.
	parsed, err := otpauth.Parse(body.URI)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.Secret) == 0 {
		t.Fatal("no secret in re-parsed URI")
	}
}

// TestAPIUnlockFlow: lock the vault and verify the lock surface —
// secrets return 423, unlock with the wrong password is rejected, unlock
// with the right password restores access.
func TestAPIUnlockFlow(t *testing.T) {
	dir := t.TempDir()
	st, err := vault.OpenStore(context.Background(), filepath.Join(dir, "vault.sqlite"), nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	v := vault.NewForTesting(st, dir)
	if err := v.Init(context.Background(), vault.ModePassword, "pw123"); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv, err := New("127.0.0.1:0", v, "")
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if _, err := srv.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(); _ = v.Close() })

	if err := v.UpsertSecret(context.Background(), vault.Secret{Issuer: "A", SecretRaw: []byte("XXXX"), Algorithm: totp.SHA1}); err != nil {
		t.Fatal(err)
	}
	v.Lock()

	res, err := http.Get("http://" + srv.Addr() + "/api/secrets")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusLocked {
		t.Fatalf("locked list: got %d, want 423", res.StatusCode)
	}

	post := func(pw string) int {
		body, _ := json.Marshal(map[string]string{"password": pw})
		res, err := http.Post("http://"+srv.Addr()+"/api/unlock", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if code := post("wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d, want 401", code)
	}
	if code := post("pw123"); code != http.StatusOK {
		t.Fatalf("right password: got %d, want 200", code)
	}

	res, err = http.Get("http://" + srv.Addr() + "/api/secrets")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list after unlock: got %d, want 200", res.StatusCode)
	}
}

// TestAPIUnlockNoPasswordMode: a locked no-password vault unlocks via a
// bare POST (machine key re-derived server-side, no password needed).
func TestAPIUnlockNoPasswordMode(t *testing.T) {
	dir := t.TempDir()
	st, err := vault.OpenStore(context.Background(), filepath.Join(dir, "vault.sqlite"), nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	v := vault.NewForTesting(st, dir)
	if err := v.Init(context.Background(), vault.ModeNoPassword, ""); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv, err := New("127.0.0.1:0", v, "")
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if _, err := srv.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(); _ = v.Close() })
	v.Lock()

	res, err := http.Get("http://" + srv.Addr() + "/api/secrets")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusLocked {
		t.Fatalf("locked list: got %d, want 423", res.StatusCode)
	}

	res, err = http.Post("http://"+srv.Addr()+"/api/unlock", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("unlock: got %d, want 200", res.StatusCode)
	}
}

// TestAPIModeSwitch covers /api/mode: password ↔ no-password transitions,
// including re-encryption of stored secrets, validation errors, and the
// locked-vault guard. Each scenario uses a fresh server so the KEK state
// is independent (reInitWith's atomic backup is exercised per case).
func TestAPIModeSwitch(t *testing.T) {
	post := func(t *testing.T, srv *Server, body string) (*http.Response, []byte) {
		t.Helper()
		res, err := http.Post("http://"+srv.Addr()+"/api/mode", "application/json",
			bytes.NewReader([]byte(body)))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res, b
	}

	t.Run("no-password → password re-encrypts secrets", func(t *testing.T) {
		srv := newTestServer(t) // ModeNoPassword
		uri := "otpauth://totp/GitHub:a?secret=JBSWY3DPEHPK3PXP"
		http.Post("http://"+srv.Addr()+"/api/secrets", "application/json",
			bytes.NewBufferString(`{"uri":"`+uri+`"}`))

		res, body := post(t, srv, `{"mode":"password","password":"newmasterpass"}`)
		if res.StatusCode != 200 {
			t.Fatalf("switch: %d %s", res.StatusCode, body)
		}
		var out map[string]string
		_ = json.Unmarshal(body, &out)
		if out["mode"] != "password" {
			t.Errorf("mode after switch: %q", out["mode"])
		}

		// Status must reflect the new mode.
		res, _ = http.Get("http://" + srv.Addr() + "/api/status")
		var st map[string]any
		json.NewDecoder(res.Body).Decode(&st)
		res.Body.Close()
		if st["mode"] != "password" {
			t.Errorf("status mode: %v", st["mode"])
		}

		// Secret must still decrypt under the new KEK and match by code.
		res, _ = http.Get("http://" + srv.Addr() + "/api/secrets")
		var list []secretJSON
		json.NewDecoder(res.Body).Decode(&list)
		res.Body.Close()
		if len(list) != 1 || list[0].Issuer != "GitHub" {
			t.Fatalf("list after switch: %+v", list)
		}
		raw, _ := totp.DecodeSecret("JBSWY3DPEHPK3PXP")
		want, _, _ := totp.Generate(raw, totp.SHA1, 6, 30, time.Now())
		if list[0].Code != want {
			t.Errorf("code after rekey: %s != %s", list[0].Code, want)
		}

		// Wrong password must fail on a fresh unlock — proves the new KEK
		// actually replaced the old one (not a no-op that left the old
		// verifier intact).
		srv.v.Lock()
		if err := srv.v.UnlockWithPassword(context.Background(), "newmasterpass"); err != nil {
			t.Errorf("unlock with new password: %v", err)
		}
		srv.v.Lock()
		if err := srv.v.UnlockWithPassword(context.Background(), "wrong"); err == nil {
			t.Error("unlock with wrong password should fail")
		}
	})

	t.Run("password → no-password", func(t *testing.T) {
		// Fresh password-mode server.
		dir := t.TempDir()
		st, _ := vault.OpenStore(context.Background(), filepath.Join(dir, "vault.sqlite"), nil)
		v := vault.NewForTesting(st, dir)
		if err := v.Init(context.Background(), vault.ModePassword, "originalpass"); err != nil {
			t.Fatal(err)
		}
		srv, _ := New("127.0.0.1:0", v, "")
		srv.Start(context.Background())
		t.Cleanup(func() { srv.Stop(); v.Close() })

		uri := "otpauth://totp/AWS:a?secret=JBSWY3DPEHPK3PXP"
		http.Post("http://"+srv.Addr()+"/api/secrets", "application/json",
			bytes.NewBufferString(`{"uri":"`+uri+`"}`))

		res, body := post(t, srv, `{"mode":"no-password"}`)
		if res.StatusCode != 200 {
			t.Fatalf("switch: %d %s", res.StatusCode, body)
		}
		var out map[string]string
		_ = json.Unmarshal(body, &out)
		if out["mode"] != "no-password" {
			t.Errorf("mode after switch: %q", out["mode"])
		}

		// Status flips.
		res, _ = http.Get("http://" + srv.Addr() + "/api/status")
		var status map[string]any
		json.NewDecoder(res.Body).Decode(&status)
		res.Body.Close()
		if status["mode"] != "no-password" {
			t.Errorf("status mode: %v", status["mode"])
		}

		// Secret decrypts under the machine key.
		res, _ = http.Get("http://" + srv.Addr() + "/api/secrets")
		var list []secretJSON
		json.NewDecoder(res.Body).Decode(&list)
		res.Body.Close()
		if len(list) != 1 || list[0].Issuer != "AWS" {
			t.Fatalf("list after disable: %+v", list)
		}
	})

	t.Run("password too short", func(t *testing.T) {
		srv := newTestServer(t)
		res, _ := post(t, srv, `{"mode":"password","password":"short"}`)
		if res.StatusCode != 400 {
			t.Errorf("short pw: want 400, got %d", res.StatusCode)
		}
	})

	t.Run("unknown mode", func(t *testing.T) {
		srv := newTestServer(t)
		res, _ := post(t, srv, `{"mode":"biometric"}`)
		if res.StatusCode != 400 {
			t.Errorf("unknown mode: want 400, got %d", res.StatusCode)
		}
	})

	t.Run("locked vault rejected", func(t *testing.T) {
		srv := newTestServer(t)
		srv.v.Lock()
		res, _ := post(t, srv, `{"mode":"password","password":"newmasterpass"}`)
		if res.StatusCode != 401 {
			t.Errorf("locked: want 401, got %d", res.StatusCode)
		}
	})

	t.Run("wrong method", func(t *testing.T) {
		srv := newTestServer(t)
		res, _ := http.Get("http://" + srv.Addr() + "/api/mode")
		if res.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("GET: want 405, got %d", res.StatusCode)
		}
		res.Body.Close()
	})

	t.Run("idempotent switch — no secrets lost across double-toggle", func(t *testing.T) {
		srv := newTestServer(t)
		// Two secrets + a group.
		for _, uri := range []string{
			"otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP",
			"otpauth://totp/B:b?secret=JBSWY3DPEHPK3PXP",
		} {
			http.Post("http://"+srv.Addr()+"/api/secrets", "application/json",
				bytes.NewBufferString(`{"uri":"`+uri+`"}`))
		}
		http.Post("http://"+srv.Addr()+"/api/groups", "application/json",
			bytes.NewBufferString(`{"name":"Work"}`))

		// no-password → password → no-password.
		post(t, srv, `{"mode":"password","password":"newmasterpass"}`)
		post(t, srv, `{"mode":"no-password"}`)

		res, _ := http.Get("http://" + srv.Addr() + "/api/secrets")
		var list []secretJSON
		json.NewDecoder(res.Body).Decode(&list)
		res.Body.Close()
		if len(list) != 2 {
			t.Errorf("secrets lost: %d", len(list))
		}
		// Group must come back too (reInitWith's idMap fix is what makes this hold).
		res, _ = http.Get("http://" + srv.Addr() + "/api/groups")
		var gs []vault.Group
		json.NewDecoder(res.Body).Decode(&gs)
		res.Body.Close()
		if len(gs) != 1 || gs[0].Name != "Work" {
			t.Errorf("groups after round-trip: %+v", gs)
		}
	})
}

// TestAPIPreferences covers GET/PUT /api/preferences: default theme,
// persistence across reads, validation, and the index.html injection that
// is the whole reason this endpoint exists (the GUI's webview has no
// stable localStorage across launches).
func TestAPIPreferences(t *testing.T) {
	t.Run("default theme when no file", func(t *testing.T) {
		srv := newTestServer(t)
		res, _ := http.Get("http://" + srv.Addr() + "/api/preferences")
		if res.StatusCode != 200 {
			t.Fatalf("status: %d", res.StatusCode)
		}
		var prefs struct{ Theme string }
		json.NewDecoder(res.Body).Decode(&prefs)
		res.Body.Close()
		if prefs.Theme != "aurora" {
			t.Errorf("default theme: %q", prefs.Theme)
		}
	})

	t.Run("put then get round-trip", func(t *testing.T) {
		srv := newTestServer(t)
		req, _ := http.NewRequest("PUT", "http://"+srv.Addr()+"/api/preferences",
			bytes.NewBufferString(`{"theme":"obsidian"}`))
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != 200 {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("PUT: %d %s", res.StatusCode, b)
		}
		res.Body.Close()

		res, _ = http.Get("http://" + srv.Addr() + "/api/preferences")
		var prefs struct{ Theme string }
		json.NewDecoder(res.Body).Decode(&prefs)
		res.Body.Close()
		if prefs.Theme != "obsidian" {
			t.Errorf("after PUT: %q", prefs.Theme)
		}
	})

	t.Run("persists across new server", func(t *testing.T) {
		// First server: write a theme.
		srv := newTestServer(t)
		req, _ := http.NewRequest("PUT", "http://"+srv.Addr()+"/api/preferences",
			bytes.NewBufferString(`{"theme":"dusk"}`))
		req.Header.Set("Content-Type", "application/json")
		res, _ := http.DefaultClient.Do(req)
		res.Body.Close()

		// Restart: a fresh server in the SAME dir reads back what we wrote.
		// Pull the prefs path off the first server and open a second one
		// pointing at the same vault dir.
		dir := srv.v.Dir()
		srv.Stop()
		srv.v.Close()

		st, err := vault.OpenStore(context.Background(), filepath.Join(dir, "vault.sqlite"), nil)
		if err != nil {
			t.Fatal(err)
		}
		v := vault.NewForTesting(st, dir)
		srv2, _ := New("127.0.0.1:0", v, "")
		if _, err := srv2.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer srv2.Stop()
		defer v.Close()

		res, _ = http.Get("http://" + srv2.Addr() + "/api/preferences")
		var prefs struct{ Theme string }
		json.NewDecoder(res.Body).Decode(&prefs)
		res.Body.Close()
		if prefs.Theme != "dusk" {
			t.Errorf("after restart: %q (want dusk)", prefs.Theme)
		}
	})

	t.Run("unknown theme rejected", func(t *testing.T) {
		srv := newTestServer(t)
		req, _ := http.NewRequest("PUT", "http://"+srv.Addr()+"/api/preferences",
			bytes.NewBufferString(`{"theme":"<script>alert(1)</script>"}`))
		req.Header.Set("Content-Type", "application/json")
		res, _ := http.DefaultClient.Do(req)
		if res.StatusCode != 400 {
			t.Errorf("bad theme: want 400, got %d", res.StatusCode)
		}
		res.Body.Close()
	})

	t.Run("index.html injects saved theme", func(t *testing.T) {
		srv := newTestServer(t)
		req, _ := http.NewRequest("PUT", "http://"+srv.Addr()+"/api/preferences",
			bytes.NewBufferString(`{"theme":"ember"}`))
		req.Header.Set("Content-Type", "application/json")
		res, _ := http.DefaultClient.Do(req)
		res.Body.Close()

		res, _ = http.Get("http://" + srv.Addr() + "/")
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if !bytes.Contains(body, []byte(`window.__initialTheme="ember"`)) {
			t.Errorf("index.html missing theme injection; head was:\n%s",
				body[:min(len(body), 600)])
		}
	})

	t.Run("index.html falls back to aurora when no prefs", func(t *testing.T) {
		srv := newTestServer(t)
		res, _ := http.Get("http://" + srv.Addr() + "/")
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if !bytes.Contains(body, []byte(`window.__initialTheme="aurora"`)) {
			t.Errorf("default inject missing:\n%s", body[:min(len(body), 600)])
		}
	})
}

func min(a, b int) int { if a < b { return a }; return b }
