package vault

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite" // pure-Go sqlite driver

	"github.com/uptutu/go2fa/internal/core/crypto"
	"github.com/uptutu/go2fa/internal/core/totp"
)

// schema is the single source of truth for the on-disk layout.
// Bump schemaVersion in Meta when adding migrations.
const schema = `
CREATE TABLE IF NOT EXISTS groups (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT    NOT NULL UNIQUE,
  color       TEXT    NOT NULL DEFAULT '',
  sort_order  INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets (
  id           TEXT    PRIMARY KEY,
  group_id     INTEGER NOT NULL DEFAULT 0,
  issuer       TEXT    NOT NULL,
  account      TEXT    NOT NULL DEFAULT '',
  secret_enc   TEXT    NOT NULL,
  secret_nonce TEXT    NOT NULL,
  algorithm    TEXT    NOT NULL DEFAULT 'SHA1',
  digits       INTEGER NOT NULL DEFAULT 6,
  period       INTEGER NOT NULL DEFAULT 30,
  notes_enc    TEXT,
  notes_nonce  TEXT,
  backup_enc   TEXT,
  backup_nonce TEXT,
  last_used_at TEXT,
  created_at   TEXT    NOT NULL,
  updated_at   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_secrets_group ON secrets(group_id);
CREATE INDEX IF NOT EXISTS idx_secrets_issuer ON secrets(issuer COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS kv_meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
`

const currentSchemaVersion = 1

// Store wraps the *sql.DB with row-level encryption helpers. It holds the
// KEK in memory while the vault is unlocked; Lock() must zero it.
type Store struct {
	db  *sql.DB
	kek []byte // 32 bytes; nil when locked
}

// OpenStore opens (or creates) the SQLite database at path and runs
// migrations. Pass kek=nil to leave the store locked (for inspection).
func OpenStore(ctx context.Context, path string, kek []byte) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("vault: open %s: %w", path, err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("vault: schema: %w", err)
	}
	return &Store{db: db, kek: kek}, nil
}

// Close releases the DB handle and zeroes the KEK.
func (s *Store) Close() error {
	for i := range s.kek {
		s.kek[i] = 0
	}
	s.kek = nil
	return s.db.Close()
}

// Lock zeroes the in-memory KEK without closing the DB.
func (s *Store) Lock() {
	for i := range s.kek {
		s.kek[i] = 0
	}
	s.kek = nil
}

// IsUnlocked reports whether the KEK is loaded.
func (s *Store) IsUnlocked() bool { return s.kek != nil }

// LoadMeta reads the vault metadata (mode, salt, argon params, verifier).
func (s *Store) LoadMeta(ctx context.Context) (Meta, error) {
	var m Meta
	row := s.db.QueryRowContext(ctx, `SELECT v FROM kv_meta WHERE k='meta'`)
	var blob string
	err := row.Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return m, nil // brand-new vault
	}
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal([]byte(blob), &m); err != nil {
		return m, err
	}
	return m, nil
}

// SaveMeta upserts the vault metadata.
func (s *Store) SaveMeta(ctx context.Context, m Meta) error {
	m.UpdatedAt = time.Now().UTC()
	blob, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO kv_meta(k, v) VALUES('meta', ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`,
		string(blob))
	return err
}

// VerifyKEK checks the stored verifier against the in-memory KEK.
func (s *Store) VerifyKEK(ctx context.Context) error {
	if !s.IsUnlocked() {
		return errors.New("vault: locked")
	}
	m, err := s.LoadMeta(ctx)
	if err != nil {
		return err
	}
	if len(m.Verifier) == 0 || len(m.VerifierNonce) == 0 {
		return errors.New("vault: no verifier set")
	}
	sealed := append(append([]byte(nil), m.VerifierNonce...), m.Verifier...)
	plain, err := crypto.Open(s.kek, sealed, nil)
	if err != nil {
		return err
	}
	if string(plain) != "OK" {
		return errors.New("vault: verifier mismatch")
	}
	return nil
}

// SealVerifier produces a verifier for the given KEK.
func SealVerifier(kek []byte) (cipher, nonce []byte, err error) {
	c, err := crypto.Seal(kek, []byte("OK"), nil)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, crypto.NonceLen)
	copy(nonce, c[:crypto.NonceLen])
	cipher = make([]byte, len(c)-crypto.NonceLen)
	copy(cipher, c[crypto.NonceLen:])
	return cipher, nonce, nil
}

// --- Groups ---

func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, color, sort_order, created_at FROM groups ORDER BY sort_order, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		var created string
		if err := rows.Scan(&g.ID, &g.Name, &g.Color, &g.SortOrder, &created); err != nil {
			return nil, err
		}
		g.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) CreateGroup(ctx context.Context, g Group) (int64, error) {
	if g.CreatedAt.IsZero() {
		g.CreatedAt = time.Now().UTC()
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO groups(name, color, sort_order, created_at) VALUES(?, ?, ?, ?)`,
		g.Name, g.Color, g.SortOrder, g.CreatedAt.Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) RenameGroup(ctx context.Context, id int64, name, color string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE groups SET name=?, color=? WHERE id=?`, name, color, id)
	return err
}

func (s *Store) DeleteGroup(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM groups WHERE id=?`, id)
	return err
}

// --- Secrets ---

// ListSecrets returns all secrets with their sensitive fields decrypted.
func (s *Store) ListSecrets(ctx context.Context) ([]Secret, error) {
	if !s.IsUnlocked() {
		return nil, errors.New("vault: locked")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, group_id, issuer, account, secret_enc, secret_nonce, algorithm,
		       digits, period, notes_enc, notes_nonce, backup_enc, backup_nonce,
		       last_used_at, created_at, updated_at
		FROM secrets ORDER BY issuer COLLATE NOCASE, account COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Secret
	for rows.Next() {
		var sec Secret
		var idStr, algo string
		var secEnc, secN, notesEnc, notesN, backupEnc, backupN sql.NullString
		var lastUsed, created, updated sql.NullString
		if err := rows.Scan(&idStr, &sec.GroupID, &sec.Issuer, &sec.Account,
			&secEnc, &secN, &algo, &sec.Digits, &sec.Period,
			&notesEnc, &notesN, &backupEnc, &backupN,
			&lastUsed, &created, &updated); err != nil {
			return nil, err
		}
		sec.ID, err = uuid.Parse(idStr)
		if err != nil {
			return nil, fmt.Errorf("vault: corrupt row id %q: %w", idStr, err)
		}
		if sec.SecretRaw, err = openNullable(s.kek, secEnc.String, secN.String); err != nil {
			return nil, fmt.Errorf("decrypt secret %s: %w", sec.ID, err)
		}
		if sec.Notes, err = openNullable(s.kek, notesEnc.String, notesN.String); err != nil {
			return nil, err
		}
		if sec.BackupCodes, err = openNullable(s.kek, backupEnc.String, backupN.String); err != nil {
			return nil, err
		}
		sec.Algorithm, err = totp.ParseAlgo(algo)
		if err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			t, _ := time.Parse(time.RFC3339, lastUsed.String)
			sec.LastUsedAt = &t
		}
		sec.CreatedAt, _ = time.Parse(time.RFC3339, created.String)
		sec.UpdatedAt, _ = time.Parse(time.RFC3339, updated.String)
		out = append(out, sec)
	}
	return out, rows.Err()
}

// GetSecret fetches a single secret by UUID, decrypted.
func (s *Store) GetSecret(ctx context.Context, id uuid.UUID) (Secret, error) {
	if !s.IsUnlocked() {
		return Secret{}, errors.New("vault: locked")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, group_id, issuer, account, secret_enc, secret_nonce, algorithm,
		       digits, period, notes_enc, notes_nonce, backup_enc, backup_nonce,
		       last_used_at, created_at, updated_at
		FROM secrets WHERE id = ?`, id.String())
	var sec Secret
	var idStr, algo string
	var secEnc, secN, notesEnc, notesN, backupEnc, backupN sql.NullString
	var lastUsed, created, updated sql.NullString
	if err := row.Scan(&idStr, &sec.GroupID, &sec.Issuer, &sec.Account,
		&secEnc, &secN, &algo, &sec.Digits, &sec.Period,
		&notesEnc, &notesN, &backupEnc, &backupN,
		&lastUsed, &created, &updated); err != nil {
		return sec, err
	}
	var err error
	sec.ID, err = uuid.Parse(idStr)
	if err != nil {
		return sec, fmt.Errorf("vault: corrupt row id %q: %w", idStr, err)
	}
	if sec.SecretRaw, err = openNullable(s.kek, secEnc.String, secN.String); err != nil {
		return sec, err
	}
	if sec.Notes, err = openNullable(s.kek, notesEnc.String, notesN.String); err != nil {
		return sec, err
	}
	if sec.BackupCodes, err = openNullable(s.kek, backupEnc.String, backupN.String); err != nil {
		return sec, err
	}
	sec.Algorithm, _ = totp.ParseAlgo(algo)
	if lastUsed.Valid {
		t, _ := time.Parse(time.RFC3339, lastUsed.String)
		sec.LastUsedAt = &t
	}
	sec.CreatedAt, _ = time.Parse(time.RFC3339, created.String)
	sec.UpdatedAt, _ = time.Parse(time.RFC3339, updated.String)
	return sec, nil
}

// UpsertSecret inserts or updates a secret. Sensitive fields are encrypted.
func (s *Store) UpsertSecret(ctx context.Context, in Secret) error {
	if !s.IsUnlocked() {
		return errors.New("vault: locked")
	}
	if in.ID == uuid.Nil {
		in.ID = uuid.New()
	}
	if in.Algorithm == 0 {
		in.Algorithm = totp.SHA1
	}
	if in.Digits == 0 {
		in.Digits = 6
	}
	if in.Period == 0 {
		in.Period = 30
	}
	now := time.Now().UTC()
	in.UpdatedAt = now
	if in.CreatedAt.IsZero() {
		in.CreatedAt = now
	}
	secEnc, secN, err := sealBytes(s.kek, in.SecretRaw)
	if err != nil {
		return err
	}
	notesEnc, notesN, err := sealNullable(s.kek, in.Notes)
	if err != nil {
		return err
	}
	backupEnc, backupN, err := sealNullable(s.kek, in.BackupCodes)
	if err != nil {
		return err
	}
	var lastUsed sql.NullString
	if in.LastUsedAt != nil {
		lastUsed = sql.NullString{String: in.LastUsedAt.UTC().Format(time.RFC3339), Valid: true}
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO secrets(id, group_id, issuer, account, secret_enc, secret_nonce,
			algorithm, digits, period, notes_enc, notes_nonce, backup_enc, backup_nonce,
			last_used_at, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			group_id=excluded.group_id, issuer=excluded.issuer, account=excluded.account,
			secret_enc=excluded.secret_enc, secret_nonce=excluded.secret_nonce,
			algorithm=excluded.algorithm, digits=excluded.digits, period=excluded.period,
			notes_enc=excluded.notes_enc, notes_nonce=excluded.notes_nonce,
			backup_enc=excluded.backup_enc, backup_nonce=excluded.backup_nonce,
			last_used_at=excluded.last_used_at, updated_at=excluded.updated_at`,
		in.ID.String(), in.GroupID, in.Issuer, in.Account,
		secEnc, secN, in.Algorithm.String(), in.Digits, in.Period,
		notesEnc, notesN, backupEnc, backupN,
		lastUsed, in.CreatedAt.Format(time.RFC3339), in.UpdatedAt.Format(time.RFC3339))
	return err
}

// TouchLastUsed stamps last_used_at = now for a secret.
func (s *Store) TouchLastUsed(ctx context.Context, id uuid.UUID) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx,
		`UPDATE secrets SET last_used_at=? WHERE id=?`, now, id.String())
	return err
}

// DeleteSecret removes a secret by UUID.
func (s *Store) DeleteSecret(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE id=?`, id.String())
	return err
}

// TotalSecretCount returns the number of stored secrets.
func (s *Store) TotalSecretCount(ctx context.Context) (int, error) {
	row := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets`)
	var n int
	err := row.Scan(&n)
	return n, err
}

// --- helpers ---

func sealBytes(kek, plain []byte) (enc, nonce sql.NullString, err error) {
	if len(plain) == 0 {
		return sql.NullString{}, sql.NullString{}, nil
	}
	sealed, err := crypto.Seal(kek, plain, nil)
	if err != nil {
		return sql.NullString{}, sql.NullString{}, err
	}
	nonce = sql.NullString{String: toHex(sealed[:crypto.NonceLen]), Valid: true}
	enc = sql.NullString{String: toHex(sealed[crypto.NonceLen:]), Valid: true}
	return enc, nonce, nil
}

func sealNullable(kek, plain []byte) (enc, nonce sql.NullString, err error) {
	if len(plain) == 0 {
		return sql.NullString{}, sql.NullString{}, nil
	}
	return sealBytes(kek, plain)
}

func openNullable(kek []byte, encHex, nonceHex string) ([]byte, error) {
	if encHex == "" || nonceHex == "" {
		return nil, nil
	}
	nonce, err := fromHex(nonceHex)
	if err != nil {
		return nil, err
	}
	ct, err := fromHex(encHex)
	if err != nil {
		return nil, err
	}
	return crypto.Open(kek, append(nonce, ct...), nil)
}

func toHex(b []byte) string { return strings.ToLower(fmt.Sprintf("%x", b)) }

func fromHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("vault: odd hex length")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var hi, lo byte
		var err error
		if hi, err = unhex(s[2*i]); err != nil {
			return nil, err
		}
		if lo, err = unhex(s[2*i+1]); err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func unhex(c byte) (byte, error) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', nil
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, nil
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("vault: bad hex char %q", c)
}