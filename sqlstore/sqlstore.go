// Package sqlstore is a MariaDB/MySQL SessionStore and StateStore for
// go-oidc-session. Provider tokens are encrypted with a Sealer before they are
// written; session ids are already SHA-256 hashes of the cookie value.
//
// The DSN must carry parseTime=True. Times are stored in UTC.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	sq "github.com/Masterminds/squirrel"
	oidcsession "github.com/aidenappl/go-oidc-session"
)

// Default table names.
const (
	DEFAULT_SESSIONS_TABLE = "oidc_sessions"
	DEFAULT_STATES_TABLE   = "oidc_login_states"
)

// Store implements oidcsession.SessionStore and oidcsession.StateStore.
type Store struct {
	DB     *sql.DB
	Sealer Sealer

	// SessionsTable and StatesTable default to the DEFAULT_* names.
	SessionsTable string
	StatesTable   string

	// Logf receives background-sweep failures. Defaults to log.Printf.
	Logf func(format string, args ...any)
}

// New returns a Store with default table names.
func New(db *sql.DB, sealer Sealer) *Store {
	return &Store{DB: db, Sealer: sealer}
}

func (s *Store) sessions() string {
	if s.SessionsTable != "" {
		return s.SessionsTable
	}
	return DEFAULT_SESSIONS_TABLE
}

func (s *Store) states() string {
	if s.StatesTable != "" {
		return s.StatesTable
	}
	return DEFAULT_STATES_TABLE
}

func (s *Store) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// Schema returns the CREATE TABLE statements for this store's tables, for an
// application's own migration system. Migrate runs them directly.
func (s *Store) Schema() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s.sessions() + ` (
	id            CHAR(64)     NOT NULL,
	user_id       BIGINT       NOT NULL,
	provider      VARCHAR(64)  NOT NULL,
	subject       VARCHAR(255) NOT NULL,
	sid           VARCHAR(255) NULL,
	access_token  TEXT         NOT NULL,
	refresh_token TEXT         NULL,
	id_token      TEXT         NULL,
	token_expiry  DATETIME(6)  NULL,
	created_at    DATETIME(6)  NOT NULL,
	last_seen_at  DATETIME(6)  NOT NULL,
	refreshed_at  DATETIME(6)  NOT NULL,
	expires_at    DATETIME(6)  NOT NULL,
	PRIMARY KEY (id),
	KEY idx_user (user_id),
	KEY idx_subject (provider, subject),
	KEY idx_sid (provider, sid),
	KEY idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS ` + s.states() + ` (
	state      VARCHAR(64) NOT NULL,
	data       TEXT        NOT NULL,
	expires_at DATETIME(6) NOT NULL,
	PRIMARY KEY (state),
	KEY idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}
}

// Migrate creates the tables if they do not exist.
func (s *Store) Migrate(ctx context.Context) error {
	for _, stmt := range s.Schema() {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("sqlstore: migrate: %w", err)
		}
	}
	return nil
}

// PurgeExpired deletes sessions past their absolute expiry and stale login
// states. Run it periodically; sessions the provider ended are deleted as
// they are used, so only abandoned ones accumulate.
func (s *Store) PurgeExpired(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	var total int64
	for _, table := range []string{s.sessions(), s.states()} {
		query, args, err := sq.Delete(table).Where(sq.Lt{"expires_at": now}).ToSql()
		if err != nil {
			return total, err
		}
		res, err := s.DB.ExecContext(ctx, query, args...)
		if err != nil {
			return total, fmt.Errorf("sqlstore: purge %s: %w", table, err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// ─── StateStore ─────────────────────────────────────────────────────────────

func (s *Store) SaveState(ctx context.Context, state string, data []byte, expiresAt time.Time) error {
	query, args, err := sq.Insert(s.states()).
		Columns("state", "data", "expires_at").
		Values(state, string(data), expiresAt.UTC()).ToSql()
	if err != nil {
		return err
	}
	if _, err := s.DB.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("sqlstore: save state: %w", err)
	}
	return nil
}

// ConsumeState reads and deletes a state in one transaction, so two callbacks
// racing on one state cannot both succeed.
func (s *Store) ConsumeState(ctx context.Context, state string) ([]byte, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: consume state: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query, args, err := sq.Select("data").From(s.states()).
		Where(sq.Eq{"state": state}).
		Where(sq.Gt{"expires_at": time.Now().UTC()}).
		Suffix("FOR UPDATE").ToSql()
	if err != nil {
		return nil, err
	}
	var data string
	if err := tx.QueryRowContext(ctx, query, args...).Scan(&data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, oidcsession.ErrNoState
		}
		return nil, fmt.Errorf("sqlstore: consume state: %w", err)
	}

	query, args, err = sq.Delete(s.states()).Where(sq.Eq{"state": state}).ToSql()
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return nil, fmt.Errorf("sqlstore: consume state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("sqlstore: consume state: %w", err)
	}
	return []byte(data), nil
}

// ─── SessionStore ───────────────────────────────────────────────────────────

var sessionColumns = []string{
	"id", "user_id", "provider", "subject", "sid",
	"access_token", "refresh_token", "id_token", "token_expiry",
	"created_at", "last_seen_at", "refreshed_at", "expires_at",
}

type sealedTokens struct {
	access, refresh, id string
}

func (s *Store) seal(t oidcsession.TokenSet) (sealedTokens, error) {
	if s.Sealer == nil {
		return sealedTokens{}, errors.New("sqlstore: no Sealer configured; refusing to store tokens in plaintext")
	}
	var out sealedTokens
	var err error
	if out.access, err = s.Sealer.Seal(t.AccessToken); err != nil {
		return out, err
	}
	if out.refresh, err = s.Sealer.Seal(t.RefreshToken); err != nil {
		return out, err
	}
	if out.id, err = s.Sealer.Seal(t.IDToken); err != nil {
		return out, err
	}
	return out, nil
}

func nullable(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func (s *Store) CreateSession(ctx context.Context, sess oidcsession.Session) error {
	tok, err := s.seal(sess.Tokens)
	if err != nil {
		return err
	}
	query, args, err := sq.Insert(s.sessions()).Columns(sessionColumns...).Values(
		sess.ID, sess.UserID, sess.Provider, sess.Subject, nullable(sess.SID),
		tok.access, nullable(tok.refresh), nullable(tok.id), nullTime(sess.Tokens.Expiry),
		sess.CreatedAt.UTC(), sess.LastSeenAt.UTC(), sess.RefreshedAt.UTC(), sess.ExpiresAt.UTC(),
	).ToSql()
	if err != nil {
		return err
	}
	if _, err := s.DB.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("sqlstore: create session: %w", err)
	}
	go s.sweep()
	return nil
}

// sweep opportunistically purges expired rows after a login.
func (s *Store) sweep() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := s.PurgeExpired(ctx); err != nil {
		s.logf("sqlstore: purge expired: %v", err)
	}
}

func (s *Store) GetSession(ctx context.Context, id string) (*oidcsession.Session, error) {
	query, args, err := sq.Select(sessionColumns...).From(s.sessions()).Where(sq.Eq{"id": id}).ToSql()
	if err != nil {
		return nil, err
	}
	var (
		sess                oidcsession.Session
		sid, refresh, idTok *string
		access              string
		expiry              *time.Time
	)
	err = s.DB.QueryRowContext(ctx, query, args...).Scan(
		&sess.ID, &sess.UserID, &sess.Provider, &sess.Subject, &sid,
		&access, &refresh, &idTok, &expiry,
		&sess.CreatedAt, &sess.LastSeenAt, &sess.RefreshedAt, &sess.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlstore: get session: %w", err)
	}
	if s.Sealer == nil {
		return nil, errors.New("sqlstore: no Sealer configured")
	}
	if sid != nil {
		sess.SID = *sid
	}
	if expiry != nil {
		sess.Tokens.Expiry = *expiry
	}
	if sess.Tokens.AccessToken, err = s.Sealer.Open(access); err != nil {
		return nil, err
	}
	if refresh != nil {
		if sess.Tokens.RefreshToken, err = s.Sealer.Open(*refresh); err != nil {
			return nil, err
		}
	}
	if idTok != nil {
		if sess.Tokens.IDToken, err = s.Sealer.Open(*idTok); err != nil {
			return nil, err
		}
	}
	return &sess, nil
}

func (s *Store) UpdateSessionTokens(ctx context.Context, id string, t oidcsession.TokenSet, refreshedAt time.Time) error {
	tok, err := s.seal(t)
	if err != nil {
		return err
	}
	query, args, err := sq.Update(s.sessions()).
		Set("access_token", tok.access).
		Set("refresh_token", nullable(tok.refresh)).
		Set("id_token", nullable(tok.id)).
		Set("token_expiry", nullTime(t.Expiry)).
		Set("refreshed_at", refreshedAt.UTC()).
		Where(sq.Eq{"id": id}).ToSql()
	if err != nil {
		return err
	}
	if _, err := s.DB.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("sqlstore: update session tokens: %w", err)
	}
	return nil
}

func (s *Store) TouchSession(ctx context.Context, id string, at time.Time) error {
	query, args, err := sq.Update(s.sessions()).Set("last_seen_at", at.UTC()).Where(sq.Eq{"id": id}).ToSql()
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, query, args...)
	return err
}

func (s *Store) deleteWhere(ctx context.Context, where sq.Eq) (int, error) {
	query, args, err := sq.Delete(s.sessions()).Where(where).ToSql()
	if err != nil {
		return 0, err
	}
	res, err := s.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("sqlstore: delete sessions: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.deleteWhere(ctx, sq.Eq{"id": id})
	return err
}

func (s *Store) DeleteSessionsBySID(ctx context.Context, provider, sid string) (int, error) {
	return s.deleteWhere(ctx, sq.Eq{"provider": provider, "sid": sid})
}

func (s *Store) DeleteSessionsBySubject(ctx context.Context, provider, subject string) (int, error) {
	return s.deleteWhere(ctx, sq.Eq{"provider": provider, "subject": subject})
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID int64) (int, error) {
	return s.deleteWhere(ctx, sq.Eq{"user_id": userID})
}

// Compile-time interface checks.
var (
	_ oidcsession.SessionStore = (*Store)(nil)
	_ oidcsession.StateStore   = (*Store)(nil)
)
