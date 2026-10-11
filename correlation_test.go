package oidcsession_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sync"
	"testing"

	oidcsession "github.com/aidenappl/go-oidc-session"
	"github.com/aidenappl/go-oidc-session/oidctest"
	"golang.org/x/oauth2"
)

const (
	corrRequestID = "0123456789abcdef"
	corrTraceID   = "4bf92f35-77b3-4da6-a3ce-929d0e0e4736"
)

var corrTraceparentRe = regexp.MustCompile(`^00-4bf92f3577b34da6a3ce929d0e0e4736-[0-9a-f]{16}-01$`)

// headerLog records request headers per path.
type headerLog struct {
	mu   sync.Mutex
	seen map[string][]http.Header
}

func (l *headerLog) add(path string, h http.Header) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[string][]http.Header{}
	}
	l.seen[path] = append(l.seen[path], h.Clone())
}

func (l *headerLog) get(path string) []http.Header {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seen[path]
}

// recordingProxy fronts the fake IdP and records what arrives, so assertions
// are on the wire rather than on what the client believes it sent.
func recordingProxy(t *testing.T, idp *oidctest.FakeIDP) (string, *headerLog) {
	t.Helper()
	target, _ := url.Parse(idp.Issuer())
	rp := httputil.NewSingleHostReverseProxy(target)
	log := &headerLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r.URL.Path, r.Header)
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, log
}

// recordingTransport records headers at the client side, as the caller's own
// transport. Used for the OIDC adapter, whose issuer must match the fake IdP's
// URL exactly and so cannot sit behind a proxy.
type recordingTransport struct{ log *headerLog }

func (rt recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.log.add(r.URL.Path, r.Header)
	return http.DefaultTransport.RoundTrip(r)
}

func assertIDs(t *testing.T, path string, h http.Header, want bool) {
	t.Helper()
	rid, tid, tp := h.Get("X-Request-ID"), h.Get("X-Trace-ID"), h.Get("traceparent")
	if !want {
		if rid != "" || tid != "" || tp != "" {
			t.Errorf("%s: correlation headers sent without valid ids: rid=%q tid=%q traceparent=%q", path, rid, tid, tp)
		}
		return
	}
	if rid != corrRequestID {
		t.Errorf("%s: X-Request-ID = %q, want %q", path, rid, corrRequestID)
	}
	if tid != corrTraceID {
		t.Errorf("%s: X-Trace-ID = %q, want %q", path, tid, corrTraceID)
	}
	if !corrTraceparentRe.MatchString(tp) {
		t.Errorf("%s: traceparent = %q", path, tp)
	}
}

type hostKey struct{}

// TestCorrelation_OAuth2Adapter covers the token exchange (x/oauth2) and the
// hand-rolled userinfo call.
func TestCorrelation_OAuth2Adapter(t *testing.T) {
	for _, withIDs := range []bool{true, false} {
		t.Run(map[bool]string{true: "with ids", false: "without ids"}[withIDs], func(t *testing.T) {
			idp := oidctest.NewFakeIDP(t)
			proxyURL, log := recordingProxy(t, idp)
			ctx := context.Background()
			if withIDs {
				ctx = oidcsession.WithCorrelation(ctx, corrRequestID, corrTraceID)
			}

			p := &oidcsession.Provider{
				Slug:         "fake-oauth2",
				Kind:         oidcsession.KindOAuth2,
				AuthorizeURL: idp.Issuer() + "/authorize",
				TokenURL:     proxyURL + "/token",
				UserInfoURL:  proxyURL + "/userinfo",
				ClientID:     testClientID,
				ClientSecret: "test-secret",
				RedirectURL:  "https://rp.test/auth/sso/callback",
			}
			adapter, err := oidcsession.NewAdapter(ctx, p)
			if err != nil {
				t.Fatalf("NewAdapter: %v", err)
			}
			store := oidctest.NewMemoryStateStore()
			state, nonce, verifier, err := oidcsession.GenerateState(ctx, store, p.Slug, "/")
			if err != nil {
				t.Fatalf("GenerateState: %v", err)
			}
			authURL, err := adapter.AuthCodeURL(state, nonce, verifier, oidcsession.AuthOptions{})
			if err != nil {
				t.Fatalf("AuthCodeURL: %v", err)
			}
			code := codeFromAuthorize(t, authURL)

			if _, _, err := adapter.Exchange(ctx, code, verifier, nonce); err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			for _, path := range []string{"/token", "/userinfo"} {
				hs := log.get(path)
				if len(hs) != 1 {
					t.Fatalf("%s calls = %d, want 1", path, len(hs))
				}
				assertIDs(t, path, hs[0], withIDs)
			}
		})
	}
}

// TestCorrelation_OIDCExchange covers the OIDC adapter's exchange and UserInfo,
// both made by x/oauth2 / go-oidc through the oauth2.HTTPClient context value.
// The caller's own client is placed there to prove it is wrapped, not replaced.
func TestCorrelation_OIDCExchange(t *testing.T) {
	for _, withIDs := range []bool{true, false} {
		t.Run(map[bool]string{true: "with ids", false: "without ids"}[withIDs], func(t *testing.T) {
			idp := oidctest.NewFakeIDP(t)
			p := newOIDCProvider(t, idp, func(p *oidcsession.Provider) {
				p.FetchUserInfo = true
				p.UserInfoURL = idp.Issuer() + "/userinfo"
			})

			log := &headerLog{}
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: recordingTransport{log: log}})
			if withIDs {
				ctx = oidcsession.WithCorrelation(ctx, corrRequestID, corrTraceID)
			}

			adapter, err := oidcsession.NewAdapter(context.Background(), p)
			if err != nil {
				t.Fatalf("NewAdapter: %v", err)
			}
			store := oidctest.NewMemoryStateStore()
			state, nonce, verifier, err := oidcsession.GenerateState(ctx, store, p.Slug, "/")
			if err != nil {
				t.Fatalf("GenerateState: %v", err)
			}
			authURL, err := adapter.AuthCodeURL(state, nonce, verifier, oidcsession.AuthOptions{})
			if err != nil {
				t.Fatalf("AuthCodeURL: %v", err)
			}
			code := codeFromAuthorize(t, authURL)

			if _, _, err := adapter.Exchange(ctx, code, verifier, nonce); err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			for _, path := range []string{"/token", "/userinfo"} {
				hs := log.get(path)
				if len(hs) != 1 {
					t.Fatalf("%s calls through the caller's client = %d, want 1", path, len(hs))
				}
				assertIDs(t, path, hs[0], withIDs)
			}
		})
	}
}
