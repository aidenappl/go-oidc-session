package oidcsession_test

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"

	oidcsession "github.com/aidenappl/go-oidc-session"
	"github.com/aidenappl/go-oidc-session/oidctest"
)

// policyRecorder records every path it carries, then delegates.
type policyRecorder struct {
	mu    sync.Mutex
	paths map[string]int
	block bool
}

func (r *policyRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	if r.paths == nil {
		r.paths = map[string]int{}
	}
	r.paths[req.URL.Path]++
	block := r.block
	r.mu.Unlock()
	if block {
		return nil, errors.New("blocked by policy")
	}
	return http.DefaultTransport.RoundTrip(req)
}

func (r *policyRecorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for p := range r.paths {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Provider.HTTPClient must carry EVERY call to the IdP — discovery, JWKS, the
// token exchange, OIDC UserInfo and introspection — so an application's
// dial-time SSRF guard covers endpoints discovery returned, not just the ones
// an administrator typed.
func TestProviderHTTPClient_CarriesEveryOIDCCall(t *testing.T) {
	idp := oidctest.NewFakeIDP(t)
	rt := &policyRecorder{}
	client := &http.Client{Transport: rt}
	p := newOIDCProvider(t, idp, func(p *oidcsession.Provider) {
		p.HTTPClient = client
		p.FetchUserInfo = true
		p.UserInfoURL = idp.Issuer() + "/userinfo"
	})
	if _, _, err := login(t, idp, p); err != nil {
		t.Fatalf("login: %v", err)
	}
	got := strings.Join(rt.seen(), " ")
	for _, want := range []string{"/.well-known/openid-configuration", "/jwks", "/token", "/userinfo"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s did not go through Provider.HTTPClient (saw %s)", want, got)
		}
	}
}

func TestProviderHTTPClient_CarriesOAuth2Calls(t *testing.T) {
	g := newGitHubLike(t, `{"id": 7, "email": null}`, `[{"email":"a@b.test","primary":true,"verified":true}]`)
	rt := &policyRecorder{}
	p := g.provider(true)
	p.HTTPClient = &http.Client{Transport: rt}
	if _, err := g.exchange(t, p); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	got := strings.Join(rt.seen(), " ")
	for _, want := range []string{"/token", "/user", "/user/emails"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s did not go through Provider.HTTPClient (saw %s)", want, got)
		}
	}
}

// A refusing client really stops the flow: nothing falls back to the package
// default behind the application's back.
func TestProviderHTTPClient_RefusalIsFinal(t *testing.T) {
	idp := oidctest.NewFakeIDP(t)
	p := newOIDCProvider(t, idp, func(p *oidcsession.Provider) {
		p.HTTPClient = &http.Client{Transport: &policyRecorder{block: true}}
	})
	if _, err := oidcsession.NewAdapter(context.Background(), p); err == nil {
		t.Fatal("discovery succeeded although the provider's client refuses every request")
	}

	g := newGitHubLike(t, `{"id": 7}`, `[]`)
	gp := g.provider(false)
	gp.HTTPClient = &http.Client{Transport: &policyRecorder{block: true}}
	a, err := oidcsession.NewAdapter(context.Background(), gp)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Exchange(context.Background(), "code", "verifier", "nonce"); err == nil {
		t.Fatal("exchange succeeded although the provider's client refuses every request")
	}

}
