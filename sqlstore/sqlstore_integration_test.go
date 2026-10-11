//go:build integration

package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	oidcsession "github.com/aidenappl/go-oidc-session"
	_ "github.com/go-sql-driver/mysql"
)

// OIDC_SESSION_TEST_DSN points at a scratch MariaDB database, e.g.
// root:test@tcp(127.0.0.1:3307)/oidc_test?parseTime=True
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("OIDC_SESSION_TEST_DSN")
	if dsn == "" {
		t.Skip("OIDC_SESSION_TEST_DSN not set")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sealer, _ := NewAESGCM(bytes.Repeat([]byte{1}, 32))
	s := &Store{DB: db, Sealer: sealer, SessionsTable: "t_sessions", StatesTable: "t_states"}
	ctx := context.Background()
	for _, tbl := range []string{"t_sessions", "t_states"} {
		if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS "+tbl); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStoreSessionLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	sess := oidcsession.Session{
		ID: "a1", UserID: 42, Provider: "idp", Subject: "sub-1", SID: "sid-1",
		Tokens:    oidcsession.TokenSet{AccessToken: "at", RefreshToken: "rt", IDToken: "idt", Expiry: now.Add(10 * time.Minute)},
		CreatedAt: now, LastSeenAt: now, RefreshedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}

	var raw string
	if err := s.DB.QueryRowContext(ctx, "SELECT refresh_token FROM t_sessions WHERE id='a1'").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw == "rt" {
		t.Fatal("refresh token stored in plaintext")
	}

	got, err := s.GetSession(ctx, "a1")
	if err != nil || got == nil {
		t.Fatalf("GetSession: %v %v", got, err)
	}
	if got.Tokens.RefreshToken != "rt" || got.Tokens.IDToken != "idt" || got.SID != "sid-1" || !got.Tokens.Expiry.Equal(sess.Tokens.Expiry) {
		t.Fatalf("round trip mismatch: %+v", got)
	}

	if err := s.UpdateSessionTokens(ctx, "a1", oidcsession.TokenSet{AccessToken: "at2", RefreshToken: "rt2"}, now); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetSession(ctx, "a1")
	if got.Tokens.RefreshToken != "rt2" || got.Tokens.IDToken != "" || !got.Tokens.Expiry.IsZero() {
		t.Fatalf("after update: %+v", got.Tokens)
	}

	if missing, err := s.GetSession(ctx, "nope"); missing != nil || err != nil {
		t.Fatalf("missing session = %v, %v; want nil, nil", missing, err)
	}

	sess.ID, sess.SID = "a2", "sid-2"
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DeleteSessionsBySID(ctx, "idp", "sid-2"); n != 1 || err != nil {
		t.Fatalf("DeleteSessionsBySID = %d, %v", n, err)
	}
	if n, err := s.DeleteSessionsBySubject(ctx, "idp", "sub-1"); n != 1 || err != nil {
		t.Fatalf("DeleteSessionsBySubject = %d, %v", n, err)
	}
}

func TestStoreStateIsSingleUse(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.SaveState(ctx, "st", []byte(`{"a":1}`), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if data, err := s.ConsumeState(ctx, "st"); err != nil || string(data) != `{"a":1}` {
		t.Fatalf("first consume = %q, %v", data, err)
	}
	if _, err := s.ConsumeState(ctx, "st"); !errors.Is(err, oidcsession.ErrNoState) {
		t.Fatalf("second consume err = %v, want ErrNoState", err)
	}
	if err := s.SaveState(ctx, "old", []byte(`{}`), time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeState(ctx, "old"); !errors.Is(err, oidcsession.ErrNoState) {
		t.Fatalf("expired consume err = %v, want ErrNoState", err)
	}
}
