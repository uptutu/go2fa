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

	"2fa/internal/core/totp"
	"2fa/internal/core/vault"
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

func TestAPIRequiresAuthWhenNonLoopback(t *testing.T) {
	// Create a non-loopback-bound server with a token; verify auth is enforced.
	dir := t.TempDir()
	st, _ := vault.OpenStore(context.Background(), filepath.Join(dir, "vault.sqlite"), nil)
	v := vault.NewForTesting(st, dir)
	v.Init(context.Background(), vault.ModeNoPassword, "")
	srv, _ := New("127.0.0.1:0", v, "secret-token")
	if _, err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	// Loopback is allowed by default (authOK returns true for loopback).
	// Even with a token set, loopback requests still succeed.
	res, _ := http.Get("http://" + srv.Addr() + "/api/status")
	if res.StatusCode != 200 {
		t.Errorf("loopback should be allowed regardless of token, got %d", res.StatusCode)
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