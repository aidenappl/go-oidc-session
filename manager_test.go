package oidcsession_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	oidcsession "github.com/aidenappl/go-oidc-session"
	"github.com/aidenappl/go-oidc-session/oidctest"
)

// fixedUser resolves every identity to user 42, or refuses with err.
type fixedUser struct{ err error }

func (u fixedUser) ResolveUser(context.Context, *oidcsession.Provider, oidcsession.Identity) (int64, error) {
	if u.err != nil {
		return 0, u.err
	}
	return 42, nil
}

func (u fixedUser) LinkIdentity(context.Context, *oidcsession.Provider, int64, oidcsession.Identity) error {
	return u.err
}

// appFixture is a relying party wired to a fake provider, plus a browser.
type appFixture struct {
	idp      *oidctest.FakeIDP
	m        *oidcsession.Manager
	sessions *oidctest.MemorySessionStore
	srv      *httptest.Server
	browser  *http.Client
}

func newApp(t *testing.T, mutate func(*appFixture)) *appFixture {
	t.Helper()
	f := &appFixture{idp: oidctest.NewFakeIDP(t), sessions: oidctest.NewMemorySessionStore()}

	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)

	p := newOIDCProvider(t, f.idp, func(p *oidcsession.Provider) { p.RedirectURL = f.srv.URL + "/callback" })
	f.m = &oidcsession.Manager{
		Providers: func(context.Context, string) (*oidcsession.Provider, error) {
			return p, nil
		},
		DefaultProvider:  "fake",
		States:           oidctest.NewMemoryStateStore(),
		Sessions:         f.sessions,
		Users:            fixedUser{},
		CookieName:       "app_session",
		Insecure:         true,
		DefaultReturnURL: f.srv.URL + "/home",
		LoginPageURL:     f.srv.URL + "/signin",
		Logf:             func(context.Context, string, ...any) {},
	}
	if mutate != nil {
		mutate(f)
	}

	mux.HandleFunc("/login", f.m.LoginHandler)
	mux.HandleFunc("/callback", f.m.CallbackHandler)
	mux.HandleFunc("/home", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/signin", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		_, err := f.m.Authenticate(w, r)
		switch {
		case err == nil:
			w.WriteHeader(http.StatusOK)
		case errors.Is(err, oidcsession.ErrProviderUnavailable):
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	f.browser = &http.Client{Jar: jar}
	return f
}

// visit follows redirects and returns the final URL.
func (f *appFixture) visit(t *testing.T, path string) *url.URL {
	t.Helper()
	res, err := f.browser.Get(f.srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	_ = res.Body.Close()
	return res.Request.URL
}

func (f *appFixture) me(t *testing.T) int {
	t.Helper()
	res, err := f.browser.Get(f.srv.URL + "/me")
	if err != nil {
		t.Fatalf("GET /me: %v", err)
	}
	_ = res.Body.Close()
	return res.StatusCode
}

func TestManager_LoginCreatesSession(t *testing.T) {
	f := newApp(t, nil)
	final := f.visit(t, "/login?return_to=/home/stacks")
	if final.Path != "/home/stacks" {
		t.Fatalf("landed on %s, want /home/stacks", final)
	}
	if got := f.me(t); got != http.StatusOK {
		t.Fatalf("/me = %d after login, want 200", got)
	}
	if f.sessions.Count() != 1 {
		t.Fatalf("%d sessions, want 1", f.sessions.Count())
	}
}

func TestManager_PromptNoneForwardedAndLoginRequired(t *testing.T) {
	f := newApp(t, nil)
	f.idp.NoSession = true

	final := f.visit(t, "/login?prompt=none&return_to=/home/x")
	if got := f.idp.LastAuthorize.Get("prompt"); got != "none" {
		t.Fatalf("prompt sent to provider = %q, want none", got)
	}
	if final.Path != "/signin" || final.Query().Get("error") != "login_required" {
		t.Fatalf("landed on %s, want /signin?error=login_required", final)
	}
	if rt := final.Query().Get("return_to"); rt != f.srv.URL+"/home/x" {
		t.Fatalf("return_to = %q, want it preserved", rt)
	}
	if f.sessions.Count() != 0 {
		t.Fatal("login_required must not create a session")
	}
}

func TestManager_LoginWithLiveSessionSkipsProvider(t *testing.T) {
	f := newApp(t, nil)
	f.visit(t, "/login")
	f.idp.LastAuthorize = nil

	final := f.visit(t, "/login?prompt=none&return_to=/home/y")
	if f.idp.LastAuthorize != nil {
		t.Fatal("a browser with a live session was sent to the provider again")
	}
	if final.Path != "/home/y" {
		t.Fatalf("landed on %s, want /home/y", final)
	}
}

func TestManager_RefreshRotatesAndKeepsSessionAlive(t *testing.T) {
	f := newApp(t, nil)
	// Inside the default one-minute leeway, so every request refreshes.
	f.idp.ExpiresIn = 30
	f.visit(t, "/login")

	for i := 1; i <= 3; i++ {
		if got := f.me(t); got != http.StatusOK {
			t.Fatalf("request %d: /me = %d, want 200", i, got)
		}
		if got := f.idp.RefreshCalls(); got != i {
			t.Fatalf("after request %d: %d refreshes, want %d", i, got, i)
		}
	}
	// Each refresh presented the rotated successor; presenting a spent token
	// would have been refused by the fake's reuse detection.
	if f.sessions.Refreshes != 3 {
		t.Fatalf("%d stored refreshes, want 3", f.sessions.Refreshes)
	}
}

func TestManager_ConcurrentRefreshIsSingleFlight(t *testing.T) {
	f := newApp(t, nil)
	f.idp.ExpiresIn = 30
	f.visit(t, "/login")
	f.idp.RefreshDelay = 200 * time.Millisecond

	var wg sync.WaitGroup
	codes := make(chan int, 10)
	for range 10 {
		wg.Go(func() { codes <- f.me(t) })
	}
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != http.StatusOK {
			t.Fatalf("a concurrent request got %d, want 200", c)
		}
	}
	if got := f.idp.RefreshCalls(); got != 1 {
		t.Fatalf("%d refresh calls for 10 concurrent requests, want 1 — a second would present a spent rotating token", got)
	}
}

func TestManager_RevokedGrantEndsSession(t *testing.T) {
	f := newApp(t, nil)
	f.idp.ExpiresIn = 30
	f.visit(t, "/login")
	f.idp.RevokeAll()

	if got := f.me(t); got != http.StatusUnauthorized {
		t.Fatalf("/me = %d after revocation, want 401", got)
	}
	if f.sessions.Count() != 0 {
		t.Fatal("refused refresh left the session in the store")
	}
}

func TestManager_OutageGraceThenUnavailable(t *testing.T) {
	t.Run("inside grace keeps serving", func(t *testing.T) {
		f := newApp(t, nil)
		f.idp.ExpiresIn = 30
		f.visit(t, "/login")
		f.idp.RefreshStatus = http.StatusInternalServerError
		if got := f.me(t); got != http.StatusOK {
			t.Fatalf("/me = %d during a provider outage inside grace, want 200", got)
		}
	})
	t.Run("past grace is 503 not 401", func(t *testing.T) {
		f := newApp(t, func(f *appFixture) { f.m.OutageGrace = time.Millisecond })
		f.idp.ExpiresIn = 1
		f.visit(t, "/login")
		time.Sleep(1100 * time.Millisecond)
		f.idp.RefreshStatus = http.StatusInternalServerError
		if got := f.me(t); got != http.StatusServiceUnavailable {
			t.Fatalf("/me = %d past grace, want 503", got)
		}
		if f.sessions.Count() != 1 {
			t.Fatal("an outage must not delete the session")
		}
	})
}

func TestManager_ResolverLoginErrorCode(t *testing.T) {
	f := newApp(t, func(f *appFixture) {
		f.m.Users = fixedUser{err: &oidcsession.LoginError{Code: "pending"}}
	})
	final := f.visit(t, "/login")
	if final.Path != "/signin" || final.Query().Get("error") != "pending" {
		t.Fatalf("landed on %s, want /signin?error=pending", final)
	}
}

func TestManager_CallbackRequiresStateCookie(t *testing.T) {
	f := newApp(t, nil)
	// Start a login in one browser, finish it in another: login CSRF.
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := noFollow.Get(f.srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	res, err = noFollow.Get(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	final := f.visit(t, strings.TrimPrefix(res.Header.Get("Location"), f.srv.URL))
	if final.Query().Get("error") != "state_mismatch" {
		t.Fatalf("landed on %s, want error=state_mismatch", final)
	}
	if f.sessions.Count() != 0 {
		t.Fatal("a callback without the state cookie created a session")
	}
}

func TestManager_LogoutUsesEndSessionEndpoint(t *testing.T) {
	f := newApp(t, nil)
	f.visit(t, "/login")

	u, _ := url.Parse(f.srv.URL + "/logout")
	req := httptest.NewRequest(http.MethodPost, u.String(), nil)
	for _, c := range f.browser.Jar.Cookies(u) {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	target, err := url.Parse(f.m.Logout(rr, req))
	if err != nil {
		t.Fatal(err)
	}
	if target.Path != "/logout" || !strings.HasPrefix(target.String(), f.idp.Issuer()) {
		t.Fatalf("logout target %s, want the provider's end_session_endpoint", target)
	}
	q := target.Query()
	if q.Get("id_token_hint") == "" || q.Get("post_logout_redirect_uri") != f.srv.URL+"/signin" || q.Get("client_id") == "" {
		t.Fatalf("logout query %v missing id_token_hint/post_logout_redirect_uri/client_id", q)
	}
	if f.sessions.Count() != 0 {
		t.Fatal("logout left the session in the store")
	}
}

func TestManager_SafeReturnURL(t *testing.T) {
	m := &oidcsession.Manager{
		DefaultReturnURL:     "https://app.example.test/",
		AllowedReturnOrigins: []string{"https://other.example.test"},
	}
	tests := []struct{ in, want string }{
		{"", "https://app.example.test/"},
		{"/stacks/3?x=1", "https://app.example.test/stacks/3?x=1"},
		{"https://app.example.test/a", "https://app.example.test/a"},
		{"https://other.example.test/b", "https://other.example.test/b"},
		{"https://evil.test/", "https://app.example.test/"},
		{"//evil.test/", "https://app.example.test/"},
		{"/\\evil.test/", "https://app.example.test/"},
		{"javascript:alert(1)", "https://app.example.test/"},
		{"https://user@app.example.test/", "https://app.example.test/"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := m.SafeReturnURL(tt.in); got != tt.want {
				t.Errorf("SafeReturnURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
