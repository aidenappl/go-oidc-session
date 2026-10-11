package oidcsession_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/aidenappl/go-oidc-session"
	"github.com/aidenappl/go-oidc-session/oidctest"
)

// logoutTargetStub is a SessionStore that records what back-channel logout
// asked it to end.
type logoutTargetStub struct {
	oidcsession.SessionStore // nil: only the two methods below may be called

	mu        sync.Mutex
	bySID     []string
	bySubject []string
	err       error
	ended     int
}

func (s *logoutTargetStub) DeleteSessionsBySID(_ context.Context, _, sid string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	s.bySID = append(s.bySID, sid)
	return s.ended, nil
}

func (s *logoutTargetStub) DeleteSessionsBySubject(_ context.Context, _, sub string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	s.bySubject = append(s.bySubject, sub)
	return s.ended, nil
}

func postLogout(t *testing.T, h http.Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/auth/sso/backchannel-logout",
		strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func newLogoutFixture(t *testing.T, store oidcsession.SessionStore) (*oidctest.FakeIDP, http.Handler, string) {
	t.Helper()
	idp := oidctest.NewFakeIDP(t)
	const clientID = "test-client"

	b := &oidcsession.BackchannelLogout{
		Sessions: store,
		Providers: func(context.Context, string) (*oidcsession.Provider, error) {
			return &oidcsession.Provider{
				Slug:         "idp",
				Kind:         oidcsession.KindOIDC,
				IssuerURL:    idp.Issuer(),
				ClientID:     clientID,
				ClientSecret: "secret",
				RedirectURL:  "https://rp.example/callback",
			}, nil
		},
		Logf: func(string, ...any) {},
	}
	return idp, b.Handler("idp"), clientID
}

// TestBackchannelLogoutRejectsMalformedTokens is the test that matters.
//
// ⚠️ A RECEIVER THAT ACCEPTS A VALID LOGOUT TOKEN HAS PROVEN ALMOST NOTHING.
// This endpoint is reachable without a cookie or a bearer token — its only
// authentication is the signature — so what has to be true is that it REFUSES
// everything else. Each case here is a specific attack.
func TestBackchannelLogoutRejectsMalformedTokens(t *testing.T) {
	cases := []struct {
		name string
		opts oidctest.LogoutTokenOptions
		why  string
	}{
		{
			name: "unsigned",
			opts: oidctest.LogoutTokenOptions{Subject: "u1", Unsigned: true},
			why:  "alg:none. Accepting it lets anyone who can reach this URL log out any user they can name.",
		},
		{
			name: "wrong_audience",
			opts: oidctest.LogoutTokenOptions{Subject: "u1", WrongAudience: "someone-else"},
			why:  "addressed to a different relying party; acting on it means acting on another RP's logout traffic",
		},
		{
			name: "wrong_issuer",
			opts: oidctest.LogoutTokenOptions{Subject: "u1", WrongIssuer: "https://evil.example"},
			why:  "forged issuer",
		},
		{
			name: "expired",
			opts: oidctest.LogoutTokenOptions{Subject: "u1", Expired: true},
			why:  "an expired token is a captured one being replayed",
		},
		{
			name: "no_events_claim",
			opts: oidctest.LogoutTokenOptions{Subject: "u1", OmitEvents: true},
			why:  "without `events` there is nothing identifying this as a logout token rather than some other JWT this issuer signed — an id_token would otherwise qualify",
		},
		{
			name: "carries_a_nonce",
			opts: oidctest.LogoutTokenOptions{Subject: "u1", WithNonce: "n-123"},
			why:  "§2.4 FORBIDS `nonce`. A logout token carrying one can be replayed into the id_token position and accepted as proof the user just authenticated — a sign-out turned into a sign-in",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &logoutTargetStub{ended: 1}
			idp, h, clientID := newLogoutFixture(t, store)

			token, err := idp.MintLogoutToken(clientID, tc.opts)
			if err != nil {
				t.Fatalf("failed to mint: %v", err)
			}

			rr := postLogout(t, h, token)
			if rr.Code == http.StatusOK {
				t.Fatalf("ACCEPTED a logout token that should be refused (%s). %s", tc.name, tc.why)
			}

			store.mu.Lock()
			defer store.mu.Unlock()
			if len(store.bySID) != 0 || len(store.bySubject) != 0 {
				t.Fatalf("a refused token still ended sessions (sid=%v sub=%v). Rejection must "+
					"happen BEFORE anything acts on a claim.", store.bySID, store.bySubject)
			}
		})
	}
}

// TestBackchannelLogoutPrefersSID pins that a session-scoped notification ends
// that session and NOT every session the subject holds.
//
// Getting this backwards turns a targeted revocation into a global sign-out —
// the user is logged out of every device because one session was ended.
func TestBackchannelLogoutPrefersSID(t *testing.T) {
	store := &logoutTargetStub{ended: 1}
	idp, h, clientID := newLogoutFixture(t, store)

	token, err := idp.MintLogoutToken(clientID, oidctest.LogoutTokenOptions{
		Subject: "user-1",
		SID:     "sess-9",
	})
	if err != nil {
		t.Fatal(err)
	}

	if rr := postLogout(t, h, token); rr.Code != http.StatusOK {
		t.Fatalf("valid logout token returned %d: %s", rr.Code, rr.Body.String())
	}

	if len(store.bySID) != 1 || store.bySID[0] != "sess-9" {
		t.Errorf("bySID = %v, want [sess-9]", store.bySID)
	}
	if len(store.bySubject) != 0 {
		t.Errorf("a token naming a session ALSO ended every session for the subject (%v). "+
			"That signs the user out of every other device over one revoked session.", store.bySubject)
	}
}

// TestBackchannelLogoutFallsBackToSubject covers the subject-wide event — an
// administrator revoking a grant, which ends every session that subject holds.
func TestBackchannelLogoutFallsBackToSubject(t *testing.T) {
	store := &logoutTargetStub{ended: 3}
	idp, h, clientID := newLogoutFixture(t, store)

	token, err := idp.MintLogoutToken(clientID, oidctest.LogoutTokenOptions{Subject: "user-1"})
	if err != nil {
		t.Fatal(err)
	}

	if rr := postLogout(t, h, token); rr.Code != http.StatusOK {
		t.Fatalf("returned %d: %s", rr.Code, rr.Body.String())
	}
	if len(store.bySubject) != 1 || store.bySubject[0] != "user-1" {
		t.Errorf("bySubject = %v, want [user-1]", store.bySubject)
	}
}

// TestBackchannelLogoutDuplicateIsSuccess pins that a re-delivered token answers
// 200.
//
// The sender re-sends the IDENTICAL token when it could not record an
// acknowledgement. Answering 4xx would make it retry to exhaustion and then
// report this receiver as broken — for a message that had already been applied.
func TestBackchannelLogoutDuplicateIsSuccess(t *testing.T) {
	store := &logoutTargetStub{ended: 1}
	idp, h, clientID := newLogoutFixture(t, store)

	token, err := idp.MintLogoutToken(clientID, oidctest.LogoutTokenOptions{Subject: "user-1"})
	if err != nil {
		t.Fatal(err)
	}

	for i := range 2 {
		if rr := postLogout(t, h, token); rr.Code != http.StatusOK {
			t.Fatalf("delivery %d returned %d: %s", i+1, rr.Code, rr.Body.String())
		}
	}

	if len(store.bySubject) != 1 {
		t.Errorf("the store was called %d times for a token delivered twice; the replay cache "+
			"should have absorbed the second", len(store.bySubject))
	}
}

// TestBackchannelLogoutRequiresPOST — §2.5 is a form POST. A GET is a probe or a
// misconfiguration and must not be treated as a logout.
func TestBackchannelLogoutRequiresPOST(t *testing.T) {
	store := &logoutTargetStub{}
	_, h, _ := newLogoutFixture(t, store)

	req := httptest.NewRequest(http.MethodGet, "/auth/sso/backchannel-logout", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET returned %d, want 405", rr.Code)
	}
}
