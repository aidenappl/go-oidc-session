package oidctest

import (
	"context"
	"sync"
	"time"

	oidcsession "github.com/aidenappl/go-oidc-session"
)

// MemoryStateStore is an in-memory StateStore for tests.
//
// ⚠️ ITS ConsumeState IS GENUINELY ATOMIC, and that is deliberate rather than
// incidental. A test fixture whose consume had the SELECT-then-DELETE race would
// make the single-use test pass for the wrong reason — the race would simply not
// be exercised under a single-goroutine test — and would model the bug the real
// implementations must avoid. Holding the mutex across the read and the delete is
// this store's equivalent of a row lock.
type MemoryStateStore struct {
	mu      sync.Mutex
	records map[string]memoryRecord
}

type memoryRecord struct {
	data      []byte
	expiresAt time.Time
}

// NewMemoryStateStore returns an empty store.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{records: map[string]memoryRecord{}}
}

func (s *MemoryStateStore) SaveState(_ context.Context, state string, data []byte, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[state] = memoryRecord{data: data, expiresAt: expiresAt}
	return nil
}

func (s *MemoryStateStore) ConsumeState(_ context.Context, state string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[state]
	if !ok {
		return nil, oidcsession.ErrNoState
	}
	// Deleted whether or not it turns out to be valid: a record that has been
	// presented once must never be presentable again, expired or not.
	delete(s.records, state)

	if time.Now().After(rec.expiresAt) {
		return nil, oidcsession.ErrNoState
	}
	return rec.data, nil
}

// Count reports how many records remain, so a test can assert consumption.
func (s *MemoryStateStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// MemorySessionStore is an in-memory SessionStore for tests.
type MemorySessionStore struct {
	mu       sync.Mutex
	sessions map[string]oidcsession.Session

	// Refreshes counts UpdateSessionTokens calls.
	Refreshes int
}

// NewMemorySessionStore returns an empty store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: map[string]oidcsession.Session{}}
}

func (s *MemorySessionStore) CreateSession(_ context.Context, sess oidcsession.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
	return nil
}

func (s *MemorySessionStore) GetSession(_ context.Context, id string) (*oidcsession.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, nil
	}
	return &sess, nil
}

func (s *MemorySessionStore) UpdateSessionTokens(_ context.Context, id string, t oidcsession.TokenSet, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil
	}
	sess.Tokens, sess.RefreshedAt = t, at
	s.sessions[id] = sess
	s.Refreshes++
	return nil
}

func (s *MemorySessionStore) TouchSession(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		sess.LastSeenAt = at
		s.sessions[id] = sess
	}
	return nil
}

func (s *MemorySessionStore) DeleteSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

func (s *MemorySessionStore) DeleteSessionsBySID(_ context.Context, provider, sid string) (int, error) {
	return s.deleteWhere(func(x oidcsession.Session) bool { return x.Provider == provider && x.SID == sid }), nil
}

func (s *MemorySessionStore) DeleteSessionsBySubject(_ context.Context, provider, subject string) (int, error) {
	return s.deleteWhere(func(x oidcsession.Session) bool { return x.Provider == provider && x.Subject == subject }), nil
}

func (s *MemorySessionStore) DeleteUserSessions(_ context.Context, userID int64) (int, error) {
	return s.deleteWhere(func(x oidcsession.Session) bool { return x.UserID == userID }), nil
}

func (s *MemorySessionStore) deleteWhere(match func(oidcsession.Session) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, sess := range s.sessions {
		if match(sess) {
			delete(s.sessions, id)
			n++
		}
	}
	return n
}

// Count reports how many sessions are live.
func (s *MemorySessionStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}
