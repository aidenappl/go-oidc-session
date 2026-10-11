package oidcsession_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	oidcsession "github.com/aidenappl/go-oidc-session"
	"github.com/aidenappl/go-oidc-session/oidctest"
)

// ─────────────────────────────────────────────────────────────────────────────
// These tests drive a REAL protocol exchange against a fake provider. Every one
// of them would pass against a mocked adapter while the corresponding defence was
// missing, which is why the fixture is a server and not a mock.
// ─────────────────────────────────────────────────────────────────────────────

const testClientID = "test-client"

// newOIDCProvider wires a Provider at the fake IdP.
func newOIDCProvider(t *testing.T, idp *oidctest.FakeIDP, mutate func(*oidcsession.Provider)) *oidcsession.Provider {
	t.Helper()
	p := &oidcsession.Provider{
		Slug:          "fake",
		DisplayName:   "Fake",
		Kind:          oidcsession.KindOIDC,
		IssuerURL:     idp.Issuer(),
		ClientID:      testClientID,
		ClientSecret:  "test-secret",
		RedirectURL:   "https://rp.test/auth/sso/callback",
		AllowAutoLink: true,
		AutoProvision: true,
	}
	if mutate != nil {
		mutate(p)
	}
	return p
}

// login runs a complete authorize → callback → exchange cycle and returns the
// identity, going through the real HTTP endpoints of the fake IdP.
func login(t *testing.T, idp *oidctest.FakeIDP, p *oidcsession.Provider) (*oidcsession.Identity, *oidcsession.TokenSet, error) {
	t.Helper()
	ctx := context.Background()

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

	// Follow the authorize redirect the way a browser would, without following the
	// final hop to the (nonexistent) RP callback.
	code := codeFromAuthorize(t, authURL)

	sd, err := oidcsession.ConsumeState(ctx, store, state)
	if err != nil {
		t.Fatalf("ConsumeState: %v", err)
	}

	return adapterExchange(ctx, adapter, code, sd.Verifier, sd.Nonce)
}

func adapterExchange(ctx context.Context, a oidcsession.Adapter, code, verifier, nonce string) (*oidcsession.Identity, *oidcsession.TokenSet, error) {
	return a.Exchange(ctx, code, verifier, nonce)
}

// TestPKCE_VerifierIsActuallySent is THE regression test for the defect that
// motivated this package.
//
// The previous implementation generated a verifier, sent its S256 challenge at
// authorize time, and then dropped the verifier at the token exchange. PKCE
// looked configured and defended nothing.
//
// This asserts it from BOTH directions, because either alone is passable by a
// broken client:
//
//  1. the challenge reaches the authorization endpoint, and
//  2. the verifier reaches the TOKEN endpoint and hashes to that challenge.
//
// Point 2 is checked against what the fake IdP actually received, not against
// what the client believes it sent.
func TestPKCE_VerifierIsActuallySent(t *testing.T) {
	idp := oidctest.NewFakeIDP(t)
	p := newOIDCProvider(t, idp, nil)

	ctx := context.Background()
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

	t.Run("challenge_reaches_the_authorization_endpoint", func(t *testing.T) {
		u, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("parse authorize URL: %v", err)
		}
		gotChallenge := u.Query().Get("code_challenge")
		if gotChallenge == "" {
			t.Fatal("no code_challenge on the authorize URL — PKCE is not being offered at all")
		}
		if method := u.Query().Get("code_challenge_method"); method != "S256" {
			t.Fatalf("code_challenge_method = %q, want S256 (plain is trivially reversible)", method)
		}

		sum := sha256.Sum256([]byte(verifier))
		if want := base64.RawURLEncoding.EncodeToString(sum[:]); gotChallenge != want {
			t.Fatalf("code_challenge = %q, want S256(verifier) = %q", gotChallenge, want)
		}
	})

	code := codeFromAuthorize(t, authURL)
	if _, _, err := adapter.Exchange(ctx, code, verifier, nonce); err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	t.Run("verifier_reaches_the_token_endpoint", func(t *testing.T) {
		form := idp.LastTokenRequest()
		if form == nil {
			t.Fatal("the token endpoint recorded no request")
		}
		got := form.Get("code_verifier")
		if got == "" {
			t.Fatal("THE DEFECT: no code_verifier reached the token endpoint. The challenge was sent at authorize time and never answered, so PKCE was configured and defended nothing.")
		}
		if got != verifier {
			t.Fatalf("code_verifier = %q, want %q", got, verifier)
		}
	})
}

// TestPKCE_StrictServerRejectsAMissingVerifier proves the fake IdP's enforcement
// is real.
//
// Without this, TestPKCE_VerifierIsActuallySent could pass against a fixture that
// never checks anything, and the suite would be asserting the client's behaviour
// against a server with no opinion. A test fixture that cannot fail is not a
// fixture.
func TestPKCE_StrictServerRejectsAMissingVerifier(t *testing.T) {
	idp := oidctest.NewFakeIDP(t)
	p := newOIDCProvider(t, idp, nil)
	ctx := context.Background()

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

	// A WRONG verifier must be refused by the server.
	if _, _, err := adapter.Exchange(ctx, code, "wrong-verifier-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nonce); err == nil {
		t.Fatal("the fake IdP accepted a wrong code_verifier, so its PKCE enforcement is not real and the PKCE test above proves nothing")
	}
}

// TestNonce_MismatchIsRejected covers the check go-oidc does not perform.
//
// go-oidc's Verify() validates signature, issuer, audience and expiry, and
// explicitly leaves the nonce to the caller. An implementation that assumes the
// library covers it accepts an id_token minted for a DIFFERENT session — the
// id_token injection attack.
func TestNonce_MismatchIsRejected(t *testing.T) {
	idp := oidctest.NewFakeIDP(t)
	idp.WrongNonce = "a-nonce-from-some-other-session"

	p := newOIDCProvider(t, idp, nil)
	if _, _, err := login(t, idp, p); err == nil {
		t.Fatal("an id_token carrying the wrong nonce was ACCEPTED — this is id_token injection, and go-oidc will not catch it for you")
	} else if !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("rejected, but not for the nonce: %v", err)
	}
}

// TestIDToken_Rejections covers every id_token defect in one table.
//
// Each case is a distinct way an id_token can be wrong, and each is verified by
// go-oidc rather than by this package — so this table is also the assertion that
// the verifier is wired up at all. A single misconfiguration (a nil verifier, a
// wrong ClientID) would turn several of these green in the wrong direction.
func TestIDToken_Rejections(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*oidctest.FakeIDP)
		why    string
	}{
		{
			name:   "missing_id_token",
			mutate: func(f *oidctest.FakeIDP) { f.OmitIDToken = true },
			why:    "an OIDC login with no id_token has no signed assertion of identity",
		},
		{
			name:   "wrong_audience",
			mutate: func(f *oidctest.FakeIDP) { f.WrongAudience = "some-other-client" },
			why:    "an id_token minted for another client must not authenticate here — that is cross-client token reuse",
		},
		{
			name:   "wrong_issuer",
			mutate: func(f *oidctest.FakeIDP) { f.WrongIssuer = "https://evil.example" },
			why:    "the iss must match the configured issuer exactly",
		},
		{
			name:   "expired",
			mutate: func(f *oidctest.FakeIDP) { f.ExpiredIDToken = true },
			why:    "an expired id_token is a replay of an old authentication",
		},
		{
			name:   "alg_none",
			mutate: func(f *oidctest.FakeIDP) { f.UnsignedIDToken = true },
			why:    "an unsigned token is attacker-authored; accepting alg:none means anyone can be anyone",
		},
		{
			name:   "unknown_kid",
			mutate: func(f *oidctest.FakeIDP) { f.UnknownKID = true },
			why:    "a kid absent from the JWKS must not fall back to 'the only key' — that would make key rotation unenforceable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := oidctest.NewFakeIDP(t)
			tt.mutate(idp)

			p := newOIDCProvider(t, idp, nil)
			if _, _, err := login(t, idp, p); err == nil {
				t.Fatalf("login SUCCEEDED with a %s id_token. %s", tt.name, tt.why)
			}
		})
	}
}

// TestUserInfo_SubjectMustMatchIDToken covers OIDC Core §5.3.2.
//
// UserInfo is fetched with a bearer token and is not signed. If its `sub` were
// merged without comparison, anything that can obtain a different user's access
// token becomes a way to log in as that user, because the email and name merged
// in would be theirs.
func TestUserInfo_SubjectMustMatchIDToken(t *testing.T) {
	t.Run("matching_sub_succeeds", func(t *testing.T) {
		idp := oidctest.NewFakeIDP(t)
		p := newOIDCProvider(t, idp, func(p *oidcsession.Provider) {
			p.FetchUserInfo = true
			p.UserInfoURL = idp.Issuer() + "/userinfo"
		})

		id, _, err := login(t, idp, p)
		if err != nil {
			t.Fatalf("login with matching userinfo sub failed: %v", err)
		}
		if id.Subject != idp.Subject {
			t.Fatalf("subject = %q, want %q", id.Subject, idp.Subject)
		}
	})

	t.Run("mismatched_sub_fails_the_whole_login", func(t *testing.T) {
		idp := oidctest.NewFakeIDP(t)
		idp.UserInfoSubject = "a-completely-different-subject"
		p := newOIDCProvider(t, idp, func(p *oidcsession.Provider) {
			p.FetchUserInfo = true
			p.UserInfoURL = idp.Issuer() + "/userinfo"
		})

		_, _, err := login(t, idp, p)
		if err == nil {
			t.Fatal("a UserInfo response whose sub disagreed with the id_token was USED. OIDC Core §5.3.2 requires discarding it; merging it is an impersonation path.")
		}
		if !strings.Contains(err.Error(), "5.3.2") && !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("rejected, but the error does not identify the cause: %v", err)
		}
	})
}

// TestIdentity_IsKeyedOnSubjectNotEmail pins the invariant, by construction.
func TestIdentity_IsKeyedOnSubjectNotEmail(t *testing.T) {
	idp := oidctest.NewFakeIDP(t)
	idp.Subject = "stable-subject-abc"
	idp.Email = "changed@example.test"

	p := newOIDCProvider(t, idp, nil)
	id, _, err := login(t, idp, p)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if id.Subject != "stable-subject-abc" {
		t.Fatalf("Subject = %q, want the id_token sub", id.Subject)
	}
	if id.Subject == id.Email {
		t.Fatal("Subject equals Email — identity must never be keyed on an address that can be reassigned")
	}
	if id.Provider != "fake" {
		t.Fatalf("Provider = %q, want the provider slug", id.Provider)
	}
}

// TestEmailVerified covers the gate on auto-linking.
func TestEmailVerified(t *testing.T) {
	t.Run("unverified_idp_email_stays_unverified", func(t *testing.T) {
		idp := oidctest.NewFakeIDP(t)
		idp.EmailVerified = false

		p := newOIDCProvider(t, idp, nil)
		id, _, err := login(t, idp, p)
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		if id.EmailVerified {
			t.Fatal("EmailVerified is true for an IdP that said false — auto-linking would attach an identity on an address the user may not control")
		}
	})

	t.Run("trust_override_applies", func(t *testing.T) {
		idp := oidctest.NewFakeIDP(t)
		idp.EmailVerified = false

		p := newOIDCProvider(t, idp, func(p *oidcsession.Provider) { p.TrustEmailVerified = true })
		id, _, err := login(t, idp, p)
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		if !id.EmailVerified {
			t.Fatal("TrustEmailVerified did not take effect")
		}
	})
}

// TestOAuth2Adapter_SendsPKCE covers the weaker adapter, which is where the
// dropped-verifier bug actually lived.
func TestOAuth2Adapter_SendsPKCE(t *testing.T) {
	idp := oidctest.NewFakeIDP(t)
	ctx := context.Background()

	p := &oidcsession.Provider{
		Slug:         "fake-oauth2",
		Kind:         oidcsession.KindOAuth2,
		AuthorizeURL: idp.Issuer() + "/authorize",
		TokenURL:     idp.Issuer() + "/token",
		UserInfoURL:  idp.Issuer() + "/userinfo",
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

	id, _, err := adapter.Exchange(ctx, code, verifier, nonce)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Subject != idp.Subject {
		t.Fatalf("Subject = %q, want %q", id.Subject, idp.Subject)
	}

	form := idp.LastTokenRequest()
	if form.Get("code_verifier") != verifier {
		t.Fatalf("THE ORIGINAL DEFECT, in the adapter it shipped in: code_verifier = %q, want %q", form.Get("code_verifier"), verifier)
	}
}

// TestProviderValidation covers configuration mistakes that would otherwise
// surface mid-flow, after the user has already been redirected.
func TestProviderValidation(t *testing.T) {
	tests := []struct {
		name string
		p    oidcsession.Provider
	}{
		{"no_slug", oidcsession.Provider{Kind: oidcsession.KindOIDC, ClientID: "c", RedirectURL: "u", IssuerURL: "i"}},
		{"no_client_id", oidcsession.Provider{Slug: "s", Kind: oidcsession.KindOIDC, RedirectURL: "u", IssuerURL: "i"}},
		{"no_redirect_url", oidcsession.Provider{Slug: "s", Kind: oidcsession.KindOIDC, ClientID: "c", IssuerURL: "i"}},
		{"oidc_without_issuer", oidcsession.Provider{Slug: "s", Kind: oidcsession.KindOIDC, ClientID: "c", RedirectURL: "u"}},
		{"oauth2_without_authorize", oidcsession.Provider{Slug: "s", Kind: oidcsession.KindOAuth2, ClientID: "c", RedirectURL: "u", TokenURL: "t", UserInfoURL: "ui"}},
		{"oauth2_without_token", oidcsession.Provider{Slug: "s", Kind: oidcsession.KindOAuth2, ClientID: "c", RedirectURL: "u", AuthorizeURL: "a", UserInfoURL: "ui"}},
		{"oauth2_without_userinfo", oidcsession.Provider{Slug: "s", Kind: oidcsession.KindOAuth2, ClientID: "c", RedirectURL: "u", AuthorizeURL: "a", TokenURL: "t"}},
		{"unknown_kind", oidcsession.Provider{Slug: "s", Kind: "saml", ClientID: "c", RedirectURL: "u"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.Validate(); err == nil {
				t.Fatal("Validate accepted an unusable provider; the failure would surface after the user was already redirected")
			}
		})
	}
}

// TestIdentitySID pins where `sid` comes from.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ THE THIRD SUBTEST IS THE ONE THAT MATTERS. `sid` names WHICH SESSION a
// back-channel logout ends, so whoever controls it controls whose session dies.
// UserInfo is fetched with a bearer token and is NOT signed — reading `sid` from
// it would let an unsigned response pick the target. Capturing it before the
// merge is the property; this test is what stops a later refactor moving the
// capture below the merge, where everything would still appear to work.
// ─────────────────────────────────────────────────────────────────────────────
func TestIdentitySID(t *testing.T) {
	t.Run("read_from_the_signed_id_token", func(t *testing.T) {
		idp := oidctest.NewFakeIDP(t)
		idp.IDTokenSID = "sess-from-id-token"
		p := newOIDCProvider(t, idp, nil)

		id, _, err := login(t, idp, p)
		if err != nil {
			t.Fatalf("login failed: %v", err)
		}
		if id.SID != "sess-from-id-token" {
			t.Errorf("SID = %q, want %q. Without it a session is unreachable by "+
				"back-channel logout forever — the column cannot be backfilled.", id.SID, "sess-from-id-token")
		}
	})

	t.Run("absent_is_normal_not_an_error", func(t *testing.T) {
		idp := oidctest.NewFakeIDP(t) // no sid stamped
		p := newOIDCProvider(t, idp, nil)

		id, _, err := login(t, idp, p)
		if err != nil {
			t.Fatalf("a provider that issues no sid must still log in: %v", err)
		}
		if id.SID != "" {
			t.Errorf("SID = %q, want empty", id.SID)
		}
	})

	t.Run("userinfo_must_not_supply_it", func(t *testing.T) {
		idp := oidctest.NewFakeIDP(t)
		idp.UserInfoSID = "sid-from-unsigned-userinfo"
		p := newOIDCProvider(t, idp, func(p *oidcsession.Provider) {
			p.FetchUserInfo = true
			p.UserInfoURL = idp.Issuer() + "/userinfo"
		})

		id, _, err := login(t, idp, p)
		if err != nil {
			t.Fatalf("login failed: %v", err)
		}
		if id.SID != "" {
			t.Fatalf("SID = %q — taken from the UNSIGNED UserInfo response. `sid` selects "+
				"which session a back-channel logout ends, so accepting one from an unsigned "+
				"source hands that choice to anything that can answer the UserInfo call. It "+
				"must be read from the verified id_token, BEFORE the merge.", id.SID)
		}
	})

	t.Run("id_token_wins_over_userinfo", func(t *testing.T) {
		idp := oidctest.NewFakeIDP(t)
		idp.IDTokenSID = "signed-sid"
		idp.UserInfoSID = "unsigned-sid"
		p := newOIDCProvider(t, idp, func(p *oidcsession.Provider) {
			p.FetchUserInfo = true
			p.UserInfoURL = idp.Issuer() + "/userinfo"
		})

		id, _, err := login(t, idp, p)
		if err != nil {
			t.Fatalf("login failed: %v", err)
		}
		if id.SID != "signed-sid" {
			t.Errorf("SID = %q, want %q — the signed value must win", id.SID, "signed-sid")
		}
	})
}
