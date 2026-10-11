package oidcsession_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	oidcsession "github.com/aidenappl/go-oidc-session"
	"github.com/aidenappl/go-oidc-session/oidctest"
)

// githubLike is a minimal GitHub-shaped OAuth2 provider: a token endpoint, a
// `/user` profile with a NUMERIC `id` and no `sub`, and a `/user/emails` list.
type githubLike struct {
	srv         *httptest.Server
	user        string // raw JSON body of /user
	emails      string // raw JSON body of /user/emails
	emailsCalls atomic.Int64
}

func newGitHubLike(t *testing.T, user, emails string) *githubLike {
	t.Helper()
	g := &githubLike{user: user, emails: emails}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gho_test","token_type":"bearer"}`))
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gho_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(g.user))
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		g.emailsCalls.Add(1)
		if r.Header.Get("Authorization") != "Bearer gho_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(g.emails))
	})
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *githubLike) provider(withEmails bool) *oidcsession.Provider {
	p := &oidcsession.Provider{
		Slug:         "github",
		Kind:         oidcsession.KindOAuth2,
		AuthorizeURL: g.srv.URL + "/authorize",
		TokenURL:     g.srv.URL + "/token",
		UserInfoURL:  g.srv.URL + "/user",
		ClientID:     testClientID,
		ClientSecret: "test-secret",
		RedirectURL:  "https://rp.test/auth/sso/callback",
	}
	if withEmails {
		p.EmailsURL = g.srv.URL + "/user/emails"
	}
	return p
}

func (g *githubLike) exchange(t *testing.T, p *oidcsession.Provider) (*oidcsession.Identity, error) {
	t.Helper()
	ctx := context.Background()
	a, err := oidcsession.NewAdapter(ctx, p)
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	id, _, err := a.Exchange(ctx, "code", "verifier", "nonce")
	return id, err
}

// TestOAuth2_NumericSubjectIsExact pins the GitHub-subject defect: a numeric
// `id` decoded as float64 stringified as "1.2345678e+07", and ids beyond 2^53
// lost digits. A subject is an identity key and must round-trip exactly.
func TestOAuth2_NumericSubjectIsExact(t *testing.T) {
	tests := []struct {
		name string
		user string
		want string
	}{
		{"github_id_8_digits", `{"id":12345678,"login":"octo","email":"o@example.test"}`, "12345678"},
		{"large_id", `{"id":98765432101,"login":"octo","email":"o@example.test"}`, "98765432101"},
		{"beyond_float64_precision", `{"id":9007199254740993,"email":"o@example.test"}`, "9007199254740993"},
		{"enveloped_numeric_id", `{"success":true,"data":{"id":12345678,"email":"o@example.test"}}`, "12345678"},
		{"string_sub_preferred_over_id", `{"sub":"abc","id":12345678}`, "abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newGitHubLike(t, tt.user, `[]`)
			id, err := g.exchange(t, g.provider(false))
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if id.Subject != tt.want {
				t.Fatalf("Subject = %q, want %q", id.Subject, tt.want)
			}
		})
	}
}

// TestOAuth2_RawClaimsKeepNumbers checks the re-encoded claim set preserves the
// numeric literal rather than a float rendering.
func TestOAuth2_RawClaimsKeepNumbers(t *testing.T) {
	// Above 2^53: a float64 round trip re-encodes this as 9007199254740992.
	g := newGitHubLike(t, `{"id":9007199254740993}`, `[]`)
	id, err := g.exchange(t, g.provider(false))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(id.RawClaims, &m); err != nil {
		t.Fatalf("RawClaims: %v", err)
	}
	if string(m["id"]) != "9007199254740993" {
		t.Fatalf("RawClaims id = %s, want 9007199254740993", m["id"])
	}
}

// TestOAuth2_EmailsURLFallback covers the GitHub `/user/emails` fallback.
func TestOAuth2_EmailsURLFallback(t *testing.T) {
	tests := []struct {
		name         string
		user         string
		emails       string
		withEmails   bool
		trust        bool
		wantEmail    string
		wantVerified bool
		wantCalls    int64
	}{
		{
			name:         "picks_primary_verified",
			user:         `{"id":1,"email":null}`,
			emails:       `[{"email":"other@example.test","primary":false,"verified":true,"visibility":null},{"email":"main@example.test","primary":true,"verified":true,"visibility":"private"}]`,
			withEmails:   true,
			wantEmail:    "main@example.test",
			wantVerified: true,
			wantCalls:    1,
		},
		{
			name:         "first_verified_when_primary_unverified",
			user:         `{"id":1}`,
			emails:       `[{"email":"main@example.test","primary":true,"verified":false},{"email":"ok@example.test","primary":false,"verified":true}]`,
			withEmails:   true,
			wantEmail:    "ok@example.test",
			wantVerified: true,
			wantCalls:    1,
		},
		{
			name:         "unverified_only_is_not_verified",
			user:         `{"id":1,"email":null}`,
			emails:       `[{"email":"x@example.test","primary":false,"verified":false},{"email":"p@example.test","primary":true,"verified":false}]`,
			withEmails:   true,
			wantEmail:    "p@example.test",
			wantVerified: false,
			wantCalls:    1,
		},
		{
			name:         "trust_does_not_override_unverified_fallback",
			user:         `{"id":1,"email":null}`,
			emails:       `[{"email":"p@example.test","primary":true,"verified":false}]`,
			withEmails:   true,
			trust:        true,
			wantEmail:    "p@example.test",
			wantVerified: false,
			wantCalls:    1,
		},
		{
			name:         "trust_with_verified_fallback",
			user:         `{"id":1}`,
			emails:       `[{"email":"p@example.test","primary":true,"verified":true}]`,
			withEmails:   true,
			trust:        true,
			wantEmail:    "p@example.test",
			wantVerified: true,
			wantCalls:    1,
		},
		{
			name:         "trust_still_applies_to_profile_email",
			user:         `{"id":1,"email":"public@example.test"}`,
			emails:       `[]`,
			withEmails:   true,
			trust:        true,
			wantEmail:    "public@example.test",
			wantVerified: true,
			wantCalls:    0,
		},
		{
			name:         "trust_without_any_email_is_not_verified",
			user:         `{"id":1}`,
			emails:       `[]`,
			withEmails:   false,
			trust:        true,
			wantEmail:    "",
			wantVerified: false,
			wantCalls:    0,
		},
		{
			name:         "not_called_when_email_present",
			user:         `{"id":1,"email":"public@example.test"}`,
			emails:       `[{"email":"main@example.test","primary":true,"verified":true}]`,
			withEmails:   true,
			wantEmail:    "public@example.test",
			wantVerified: false,
			wantCalls:    0,
		},
		{
			name:       "not_called_when_unconfigured",
			user:       `{"id":1,"email":null}`,
			emails:     `[{"email":"main@example.test","primary":true,"verified":true}]`,
			withEmails: false,
			wantCalls:  0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newGitHubLike(t, tt.user, tt.emails)
			p := g.provider(tt.withEmails)
			p.TrustEmailVerified = tt.trust
			id, err := g.exchange(t, p)
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if id.Email != tt.wantEmail {
				t.Errorf("Email = %q, want %q", id.Email, tt.wantEmail)
			}
			if id.EmailVerified != tt.wantVerified {
				t.Errorf("EmailVerified = %v, want %v", id.EmailVerified, tt.wantVerified)
			}
			if got := g.emailsCalls.Load(); got != tt.wantCalls {
				t.Errorf("emails endpoint called %d times, want %d", got, tt.wantCalls)
			}
		})
	}
}

// TestOAuth2_EmailsURLFailureFailsLogin: a failed fallback (typically a missing
// `user:email` scope) must not silently produce an email-less identity.
func TestOAuth2_EmailsURLFailureFailsLogin(t *testing.T) {
	tests := []struct {
		name    string
		emails  string
		path    string
		wantErr string
	}{
		{"status_404", `[]`, "/missing", "status 404"},
		{"malformed_json", `{"message":"not an array"}`, "/user/emails", "not a JSON array"},
		{"truncated_json", `[{"email":`, "/user/emails", "not a JSON array"},
		{"empty_array", `[]`, "/user/emails", "no usable address"},
		{"all_empty_addresses", `[{"email":"","primary":true,"verified":true}]`, "/user/emails", "no usable address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newGitHubLike(t, `{"id":1}`, tt.emails)
			p := g.provider(false)
			p.EmailsURL = g.srv.URL + tt.path
			_, err := g.exchange(t, p)
			if err == nil {
				t.Fatal("Exchange succeeded although the emails fallback yielded nothing usable")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

// TestEmailsURLValidation covers EmailsURL configuration mistakes.
func TestEmailsURLValidation(t *testing.T) {
	base := func() oidcsession.Provider {
		return oidcsession.Provider{Slug: "s", Kind: oidcsession.KindOAuth2, ClientID: "c", RedirectURL: "u", AuthorizeURL: "a", TokenURL: "t", UserInfoURL: "ui"}
	}
	tests := []struct {
		name    string
		mutate  func(*oidcsession.Provider)
		wantErr bool
	}{
		{"absolute_https_ok", func(p *oidcsession.Provider) { p.EmailsURL = "https://api.github.com/user/emails" }, false},
		{"relative_rejected", func(p *oidcsession.Provider) { p.EmailsURL = "/user/emails" }, true},
		{"bad_scheme_rejected", func(p *oidcsession.Provider) { p.EmailsURL = "file:///etc/passwd" }, true},
		{"oidc_rejected", func(p *oidcsession.Provider) {
			p.Kind = oidcsession.KindOIDC
			p.IssuerURL = "https://issuer.test"
			p.EmailsURL = "https://api.github.com/user/emails"
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := base()
			tt.mutate(&p)
			err := p.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestOIDC_NumericClaimIsExact covers the id_token decode path: a numeric
// claim used as the subject must stringify exactly there too. (UserInfo claims
// go through the same decodeClaims helper.)
func TestOIDC_NumericClaimIsExact(t *testing.T) {
	idp := oidctest.NewFakeIDP(t)
	idp.ExtraClaims = map[string]any{"gh_id": int64(98765432101)}
	p := newOIDCProvider(t, idp, func(p *oidcsession.Provider) { p.SubjectClaim = "gh_id" })
	id, _, err := login(t, idp, p)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if id.Subject != "98765432101" {
		t.Fatalf("Subject = %q, want %q", id.Subject, "98765432101")
	}
}

// TestOIDC_UserInfoNumericClaimIsExact covers the OIDC UserInfo decode path: a
// numeric claim present ONLY in UserInfo must survive the merge exactly.
func TestOIDC_UserInfoNumericClaimIsExact(t *testing.T) {
	idp := oidctest.NewFakeIDP(t)
	idp.UserInfoExtraClaims = map[string]any{"gh_id": int64(9007199254740993)}
	p := newOIDCProvider(t, idp, func(p *oidcsession.Provider) {
		p.FetchUserInfo = true
		p.UserInfoURL = idp.Issuer() + "/userinfo"
	})
	id, _, err := login(t, idp, p)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(id.RawClaims, &m); err != nil {
		t.Fatalf("RawClaims: %v", err)
	}
	if string(m["gh_id"]) != "9007199254740993" {
		t.Fatalf("RawClaims gh_id = %s, want 9007199254740993", m["gh_id"])
	}
}
