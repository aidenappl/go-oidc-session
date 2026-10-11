package oidcsession

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// discoveryTimeout bounds an OIDC discovery fetch. Discovery happens on the
// first login through a provider and is then cached, so this is a startup-shaped
// cost, not a per-request one — but it sits on a user-facing path, so it must not
// hang.
const discoveryTimeout = 10 * time.Second

// userInfoTimeout bounds the optional UserInfo call.
const userInfoTimeout = 5 * time.Second

var (
	discoveryMu    sync.Mutex
	discoveryCache = map[string]*oidc.Provider{}
)

// discover performs OIDC discovery once per issuer and caches the result.
//
// The cache is keyed on the issuer URL and never invalidated. That is correct for
// what it holds: endpoint URLs and the JWKS URI, which are part of the issuer's
// stable identity rather than rotating material. The KEYS behind that JWKS URI are
// fetched and re-fetched by go-oidc's own remote key set, which handles rotation —
// so caching this does not pin a retired signing key.
func discover(ctx context.Context, issuer string) (*oidc.Provider, error) {
	discoveryMu.Lock()
	defer discoveryMu.Unlock()

	// Keyed by the client too: go-oidc keeps the discovery context's client for
	// every later JWKS fetch, so a provider discovered under one client must not
	// be served to a caller that configured another (Provider.HTTPClient).
	key := issuer
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && c != nil {
		key = fmt.Sprintf("%s\x00%p", issuer, c)
	}
	if p, ok := discoveryCache[key]; ok {
		return p, nil
	}

	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()

	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("sso: oidc discovery for %q: %w", issuer, err)
	}
	discoveryCache[key] = p
	return p, nil
}

// oidcAdapter drives a compliant OpenID Connect provider.
type oidcAdapter struct {
	provider *Provider
	oidcProv *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

func newOIDCAdapter(ctx context.Context, p *Provider) (Adapter, error) {
	op, err := discover(withProviderClient(ctx, p), p.IssuerURL)
	if err != nil {
		return nil, err
	}

	// The verifier checks the signature against the provider's JWKS, plus `iss`,
	// `aud` (== our client_id) and `exp`.
	//
	// ⚠️ IT DOES NOT CHECK THE NONCE. go-oidc documents this and leaves it to the
	// caller; Exchange below does it. "We use a well-known library" is not a
	// substitute for reading which checks the library actually performs — one of
	// the implementations this package replaced relied on exactly that assumption
	// and verified no nonce at all.
	verifier := op.Verifier(&oidc.Config{ClientID: p.ClientID})

	if p.FetchUserInfo {
		var doc struct {
			UserInfoEndpoint string `json:"userinfo_endpoint"`
		}
		if err := op.Claims(&doc); err != nil || doc.UserInfoEndpoint == "" {
			// Reported rather than silently skipping the fetch, because silently
			// skipping means the sub check silently does not happen.
			return nil, fmt.Errorf("sso: oidc provider %q asks for userinfo but its discovery document publishes no userinfo_endpoint", p.Slug)
		}
	}

	return &oidcAdapter{
		provider: p,
		oidcProv: op,
		verifier: verifier,
		oauth: &oauth2.Config{
			ClientID:     p.ClientID,
			ClientSecret: p.ClientSecret,
			Endpoint:     op.Endpoint(),
			RedirectURL:  p.RedirectURL,
			Scopes:       p.scopeList(),
		},
	}, nil
}

// endSessionSource is implemented by adapters whose provider advertises an
// end_session_endpoint (OIDC RP-Initiated Logout 1.0).
type endSessionSource interface {
	EndSessionEndpoint() string
}

// EndSessionEndpoint returns the discovered end_session_endpoint, or "".
func (a *oidcAdapter) EndSessionEndpoint() string {
	var c struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := a.oidcProv.Claims(&c); err != nil {
		return ""
	}
	return c.EndSession
}

// LogoutVerifier exposes the id_token verifier for back-channel logout.
//
// It satisfies logoutVerifierSource, the narrow interface BackchannelLogout
// type-asserts for. Only KindOIDC implements it — an OAuth2 provider has no
// signed tokens and no JWKS, so there is nothing to verify a logout token
// against, and back-channel logout is genuinely unavailable there rather than
// merely unimplemented.
func (a *oidcAdapter) LogoutVerifier() *oidc.IDTokenVerifier { return a.verifier }

func (a *oidcAdapter) AuthCodeURL(state, nonce, verifier string, opts AuthOptions) (string, error) {
	if state == "" || nonce == "" || verifier == "" {
		// All three come from GenerateState. An empty one means the caller
		// hand-assembled the flow and dropped a defence; refuse rather than build a
		// URL that authenticates without it.
		return "", fmt.Errorf("sso: AuthCodeURL requires state, nonce and verifier")
	}
	return a.oauth.AuthCodeURL(state, append([]oauth2.AuthCodeOption{
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	}, opts.params()...)...), nil
}

// Refresh redeems a refresh token at the discovered token endpoint.
//
// A rotated id_token in the response is verified like any other, minus the
// nonce (OIDC Core §12.2: a refreshed id_token carries none), and kept for
// RP-initiated logout's id_token_hint. One that fails verification is
// dropped rather than failing the refresh: the access and refresh tokens are
// what the session runs on, and they came from the authenticated token
// endpoint.
func (a *oidcAdapter) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
	ctx = withCorrelatingClient(withProviderClient(ctx, a.provider))
	tok, err := refreshWith(ctx, a.oauth, refreshToken)
	if err != nil {
		return nil, err
	}
	ts := tokenSetFrom(tok)
	if raw, _ := tok.Extra("id_token").(string); raw != "" {
		if _, err := a.verifier.Verify(ctx, raw); err == nil {
			ts.IDToken = raw
		}
	}
	return ts, nil
}

func (a *oidcAdapter) Exchange(ctx context.Context, code, verifier, nonce string) (*Identity, *TokenSet, error) {
	if verifier == "" || nonce == "" {
		return nil, nil, fmt.Errorf("sso: Exchange requires the verifier and nonce from the state record")
	}

	// oauth2.VerifierOption sends code_verifier. Without it the S256 challenge we
	// sent at authorize time is unanswered and the exchange fails at any server
	// that enforces PKCE — and silently succeeds at one that does not, which is the
	// failure mode worth fearing.
	// Correlation ids on ctx ride along on the exchange, id_token verification
	// and UserInfo calls below, via the oauth2.HTTPClient context value.
	ctx = withCorrelatingClient(withProviderClient(ctx, a.provider))

	oauthToken, err := a.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, nil, fmt.Errorf("sso: oidc code exchange: %w", err)
	}

	rawID, _ := oauthToken.Extra("id_token").(string)
	if rawID == "" {
		return nil, nil, fmt.Errorf("sso: oidc token response carried no id_token")
	}

	idToken, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, nil, fmt.Errorf("sso: oidc id_token verification failed: %w", err)
	}

	// ── The nonce check go-oidc does not do ──────────────────────────────────
	//
	// This binds the id_token to the authorization request we started. Without it,
	// an id_token obtained in ANY session for this client is accepted in THIS
	// session — the id_token injection attack. The comparison is on the value from
	// the server-side state record, never on anything in the request.
	if idToken.Nonce != nonce {
		return nil, nil, fmt.Errorf("sso: oidc id_token nonce mismatch")
	}

	var rawClaims json.RawMessage
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, nil, fmt.Errorf("sso: oidc claim decode: %w", err)
	}
	claims, err := decodeClaims(rawClaims)
	if err != nil {
		return nil, nil, fmt.Errorf("sso: oidc claim decode: %w", err)
	}

	// Subject comes from the VERIFIED id_token, and the configured claim override
	// is read from that same verified claim set — never from an unverified source.
	subject := claimString(claims, a.provider.SubjectClaim, "sub")
	if subject == "" {
		subject = idToken.Subject
	}
	if subject == "" {
		return nil, nil, fmt.Errorf("sso: oidc identity has no subject")
	}

	// ⚠️ CAPTURED HERE, BEFORE THE USERINFO MERGE, AND THAT ORDERING IS THE
	// SECURITY PROPERTY. UserInfo is fetched with a bearer token and is not
	// signed; reading `sid` after the merge would let an unsigned response name
	// which session a back-channel logout ends. Only the verified id_token may
	// supply it.
	sid := claimString(claims, "", "sid")

	if a.provider.FetchUserInfo {
		uiClaims, err := a.fetchUserInfo(ctx, oauthToken, subject)
		if err != nil {
			return nil, nil, err
		}
		// Merge UserInfo UNDER the id_token: a claim present in both keeps the
		// id_token's value, because that one is signed.
		for k, v := range uiClaims {
			if _, exists := claims[k]; !exists {
				claims[k] = v
			}
		}
	}

	email := claimString(claims, a.provider.EmailClaim, "email")
	emailVerified := a.provider.TrustEmailVerified ||
		claimBool(claims, a.provider.EmailVerifiedClaim, "email_verified")

	raw, err := json.Marshal(claims)
	if err != nil {
		// Claims came out of a JSON document, so this cannot normally fail; not
		// swallowed, because a silently-empty RawClaims would be a confusing thing
		// for an application to debug.
		return nil, nil, fmt.Errorf("sso: re-encode claims: %w", err)
	}

	id := &Identity{
		Provider:      a.provider.Slug,
		Subject:       subject,
		SID:           sid,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          claimPtr(claims, "name"),
		Picture:       claimPtr(claims, "picture"),
		RawClaims:     raw,
	}
	tokens := tokenSetFrom(oauthToken)
	tokens.IDToken = rawID
	return id, tokens, nil
}

// fetchUserInfo calls the UserInfo endpoint and returns its claims.
//
// ─────────────────────────────────────────────────────────────────────────────
// OIDC Core §5.3.2: THE `sub` MUST MATCH, OR THE RESPONSE MUST NOT BE USED.
//
// The specification is unusually blunt about this, and the reason is worth
// stating: the UserInfo response is fetched with a BEARER TOKEN and is not signed.
// If its `sub` were merged without comparison, then any way of getting a
// different user's access token — a mix-up between providers, a confused-deputy
// endpoint, a caching proxy — becomes a way to log in as that user, because the
// email and name merged in would be theirs.
//
// So a mismatch is a hard failure of the whole login, not a skipped merge. There
// is no configuration to relax it.
// ─────────────────────────────────────────────────────────────────────────────
func (a *oidcAdapter) fetchUserInfo(ctx context.Context, tok *oauth2.Token, idTokenSubject string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, userInfoTimeout)
	defer cancel()

	ui, err := a.oidcProv.UserInfo(ctx, oauth2.StaticTokenSource(tok))
	if err != nil {
		return nil, fmt.Errorf("sso: oidc userinfo: %w", err)
	}

	if ui.Subject != idTokenSubject {
		return nil, fmt.Errorf("sso: oidc userinfo sub %q does not match id_token sub %q (OIDC Core §5.3.2 — response discarded)",
			ui.Subject, idTokenSubject)
	}

	var rawClaims json.RawMessage
	if err := ui.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("sso: oidc userinfo claim decode: %w", err)
	}
	claims, err := decodeClaims(rawClaims)
	if err != nil {
		return nil, fmt.Errorf("sso: oidc userinfo claim decode: %w", err)
	}
	return claims, nil
}

// readLimited reads at most n bytes.
//
// Every response body this package parses goes through it. An IdP is a trusted
// party right up until it is a compromised or misconfigured one, and an unbounded
// io.ReadAll on a remote response is a memory-exhaustion primitive handed to
// whoever controls that endpoint.
func readLimited(r io.Reader, n int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, n))
}

// maxResponseBytes bounds an IdP response. Generous for a token or UserInfo
// document — a large id_token with many claims is a few kilobytes.
const maxResponseBytes = 1 << 20 // 1 MiB

// decodeClaims decodes a JSON object into a claim map, keeping numbers as
// json.Number.
//
// ⚠️ PLAIN json.Unmarshal INTO map[string]any IS WRONG FOR CLAIMS. It turns every
// number into a float64, and fmt.Sprint of a float64 uses %v — so GitHub's
// numeric `id` 12345678 became the subject "1.2345678e+07", and ids above 2^53
// lose digits outright. A subject is an identity key; it must round-trip
// exactly. json.Number is the literal text of the number, so it does.
func decodeClaims(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil {
		return nil, err
	}
	if claims == nil {
		// A JSON `null` decodes to a nil map without error; callers index and
		// write into it, so refuse it here.
		return nil, fmt.Errorf("claims are null, not an object")
	}
	return claims, nil
}

// claimString reads a string claim by the configured name, falling back to the
// standard name.
//
// Values are stringified via fmt.Sprint so a numeric `sub` — which some providers
// emit despite the specification requiring a string — is read rather than
// silently dropped. Numbers arrive as json.Number (see decodeClaims), so the
// stringified form is the exact integer text, never a float. "<nil>" is
// filtered because that is what fmt.Sprint produces for a JSON null, and a
// literal "<nil>" subject would be a shared identity for every user whose claim
// was null.
func claimString(claims map[string]any, field, fallback string) string {
	for _, f := range []string{field, fallback} {
		if f == "" {
			continue
		}
		v, ok := claims[f]
		if !ok || v == nil {
			continue
		}
		if s := fmt.Sprint(v); s != "" && s != "<nil>" {
			return s
		}
	}
	return ""
}

// claimBool reads a boolean claim, accepting the string forms some providers send.
func claimBool(claims map[string]any, field, fallback string) bool {
	for _, f := range []string{field, fallback} {
		if f == "" {
			continue
		}
		switch v := claims[f].(type) {
		case bool:
			return v
		case string:
			return v == "true"
		}
	}
	return false
}

func claimPtr(claims map[string]any, field string) *string {
	if v, ok := claims[field]; ok && v != nil {
		if s := fmt.Sprint(v); s != "" && s != "<nil>" {
			return &s
		}
	}
	return nil
}

// httpClient is the client used for the hand-rolled OAuth2 calls. A timeout is
// set explicitly: http.DefaultClient has none, so a hung IdP would hold a request
// goroutine indefinitely.
var httpClient = &http.Client{Timeout: 15 * time.Second}
