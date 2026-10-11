package oidcsession

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// oauth2Adapter drives a plain OAuth2 provider with no OIDC discovery and no
// id_token.
//
// ⚠️ IT IS STRICTLY WEAKER THAN THE OIDC ADAPTER, and the difference is not
// cosmetic. With no id_token there is:
//
//   - no SIGNED assertion of identity — the subject comes from a bearer-token
//     call to a UserInfo endpoint, so anything that can obtain an access token can
//     become that user;
//   - no `nonce` to verify, so no binding between the identity and this
//     authorization request;
//   - no `aud`, so no way to detect a token minted for a different client.
//
// PKCE still applies and is still enforced, which is what keeps a stolen code
// from being redeemable. Prefer KindOIDC whenever the provider supports it, and
// treat this adapter as the compatibility path it is.
type oauth2Adapter struct {
	provider *Provider
	oauth    *oauth2.Config
}

func newOAuth2Adapter(p *Provider) (Adapter, error) {
	return &oauth2Adapter{
		provider: p,
		oauth: &oauth2.Config{
			ClientID:     p.ClientID,
			ClientSecret: p.ClientSecret,
			RedirectURL:  p.RedirectURL,
			Scopes:       p.scopeList(),
			Endpoint: oauth2.Endpoint{
				AuthURL:  p.AuthorizeURL,
				TokenURL: p.TokenURL,
				// Send client credentials in the POST body as well as trying Basic.
				// AuthStyleAutoDetect probes, which costs a wasted round trip on
				// first use and — worse — makes the first login after a restart behave
				// differently from the rest.
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
	}, nil
}

func (a *oauth2Adapter) AuthCodeURL(state, nonce, verifier string, opts AuthOptions) (string, error) {
	if state == "" || verifier == "" {
		return "", fmt.Errorf("sso: AuthCodeURL requires state and verifier")
	}
	// nonce is accepted and unused: there is no id_token to bind it to. It is not
	// sent as a bare query parameter, because a parameter the provider ignores and
	// the client cannot verify is security theatre that a later reader may mistake
	// for a defence.
	return a.oauth.AuthCodeURL(state, append([]oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(verifier),
	}, opts.params()...)...), nil
}

// Refresh redeems a refresh token at the configured token endpoint. Many plain
// OAuth2 providers issue non-expiring access tokens and no refresh token; the
// Manager never calls this for a session without one.
func (a *oauth2Adapter) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
	ctx = withCorrelatingClient(withProviderClient(ctx, a.provider))
	tok, err := refreshWith(ctx, a.oauth, refreshToken)
	if err != nil {
		return nil, err
	}
	return tokenSetFrom(tok), nil
}

func (a *oauth2Adapter) Exchange(ctx context.Context, code, verifier, nonce string) (*Identity, *TokenSet, error) {
	if verifier == "" {
		return nil, nil, fmt.Errorf("sso: Exchange requires the verifier from the state record")
	}

	// ⚠️ THE VERIFIER IS ACTUALLY SENT HERE.
	//
	// This is the defect that motivated extracting this package. The implementation
	// this replaced accepted a `verifier` argument, discarded it, and hand-rolled
	// three token requests in sequence (JSON body, then HTTP Basic, then body
	// credentials) hoping one would be accepted. The result: a PKCE challenge was
	// sent at authorize time and never answered, so the mechanism was configured,
	// visible in logs, and defending nothing — and the sequence of attempts made
	// every login perform a failing request first.
	//
	// One request, the standard library's, with the verifier attached.
	oauthToken, err := a.oauth.Exchange(withCorrelatingClient(withProviderClient(ctx, a.provider)), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, nil, fmt.Errorf("sso: oauth2 code exchange: %w", err)
	}
	if oauthToken.AccessToken == "" {
		return nil, nil, fmt.Errorf("sso: oauth2 token response carried no access_token")
	}

	claims, err := a.userInfo(ctx, oauthToken.AccessToken)
	if err != nil {
		return nil, nil, err
	}

	subject := claimString(claims, a.provider.SubjectClaim, "sub")
	if subject == "" {
		// Some non-OIDC providers name it `id`. Tried as a second fallback rather
		// than being the default, so a provider that sends both is keyed on the
		// standard one.
		subject = claimString(claims, "", "id")
	}
	if subject == "" {
		return nil, nil, fmt.Errorf("sso: oauth2 userinfo has no subject claim (tried %q, \"sub\", \"id\")", a.provider.SubjectClaim)
	}

	email := claimString(claims, a.provider.EmailClaim, "email")
	emailVerified := a.provider.TrustEmailVerified ||
		claimBool(claims, a.provider.EmailVerifiedClaim, "email_verified")

	// Email fallback for providers (GitHub) whose profile endpoint omits a
	// private address. Only consulted when the profile carried no email at all —
	// a provider that does assert one is never second-guessed by a second call.
	if email == "" && a.provider.EmailsURL != "" {
		fbEmail, fbVerified, err := a.fallbackEmail(ctx, oauthToken.AccessToken)
		if err != nil {
			return nil, nil, err
		}
		// The per-address `verified` flag is authoritative for an address that
		// came from the emails endpoint: TrustEmailVerified is a statement about
		// what the provider ASSERTS in its profile, and it asserted nothing here.
		email = fbEmail
		emailVerified = fbVerified
	}
	// A verified flag with no address to attach it to must not reach a resolver.
	emailVerified = emailVerified && email != ""

	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, nil, fmt.Errorf("sso: re-encode claims: %w", err)
	}

	id := &Identity{
		Provider:      a.provider.Slug,
		Subject:       subject,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          claimPtr(claims, "name"),
		Picture:       claimPtr(claims, "picture"),
		RawClaims:     raw,
	}
	tokens := tokenSetFrom(oauthToken)
	return id, tokens, nil
}

// userInfo fetches and unwraps the provider's user profile.
//
// It tolerates one non-standard shape deliberately: a `{success, data:{...}}`
// envelope, which several first-party APIs on this platform return because their
// standard responder wraps everything. Unwrapping it here is what lets those
// services be configured as providers without a bespoke adapter.
//
// It does NOT tolerate an unbounded body, a non-2xx status, or a missing subject.
func (a *oauth2Adapter) userInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, userInfoTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.provider.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("sso: oauth2 userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	applyCorrelation(req)

	resp, err := a.provider.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("sso: oauth2 userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := readLimited(resp.Body, maxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("sso: oauth2 userinfo read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The body is included because an IdP's error message is the fastest route to
		// a misconfiguration — but it is truncated, because it is remote content
		// going into this service's logs.
		return nil, fmt.Errorf("sso: oauth2 userinfo status %d: %s", resp.StatusCode, truncate(string(body), 256))
	}

	// Flat object first — the standard shape. decodeClaims keeps numbers as
	// json.Number, so a numeric `id` stringifies exactly rather than as a float.
	flat, err := decodeClaims(body)
	if err != nil {
		return nil, fmt.Errorf("sso: oauth2 userinfo is not a JSON object: %w", err)
	}

	// Enveloped shape: {"success":true,"data":{...}}. Unwrapped only when `data` is
	// itself an object, so a provider with a legitimate top-level `data` claim of
	// another type is left alone.
	if inner, ok := flat["data"].(map[string]any); ok {
		if _, hasSuccess := flat["success"]; hasSuccess {
			return inner, nil
		}
	}
	return flat, nil
}

// emailEntry is one element of a GitHub-shaped `/user/emails` response.
type emailEntry struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// fallbackEmail fetches Provider.EmailsURL and picks an address from a
// GitHub-shaped list: `[{email, primary, verified, visibility}]`.
//
// Selection order: primary AND verified, then the first verified, then — with
// verified=false — the primary (or first) unverified address. An unverified
// address is still returned because Email is a hint; EmailVerified is what gates
// auto-linking, and it stays false. The returned verified flag is the
// provider's per-address one; TrustEmailVerified does not apply.
//
// A failure here FAILS THE LOGIN rather than continuing without an email: a
// non-200, a malformed body, or a list with no usable address. The usual cause
// is a missing scope (`user:email` on GitHub), and a login that silently
// provisions an email-less user is the harder failure to diagnose.
func (a *oauth2Adapter) fallbackEmail(ctx context.Context, accessToken string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, userInfoTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.provider.EmailsURL, nil)
	if err != nil {
		return "", false, fmt.Errorf("sso: oauth2 emails request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	applyCorrelation(req)

	resp, err := a.provider.client().Do(req)
	if err != nil {
		return "", false, fmt.Errorf("sso: oauth2 emails: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := readLimited(resp.Body, maxResponseBytes)
	if err != nil {
		return "", false, fmt.Errorf("sso: oauth2 emails read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("sso: oauth2 emails status %d: %s", resp.StatusCode, truncate(string(body), 256))
	}

	var entries []emailEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return "", false, fmt.Errorf("sso: oauth2 emails is not a JSON array: %w", err)
	}

	email, verified := pickEmail(entries)
	if email == "" {
		return "", false, fmt.Errorf("sso: oauth2 emails endpoint returned no usable address")
	}
	return email, verified, nil
}

// pickEmail applies fallbackEmail's selection order.
func pickEmail(entries []emailEntry) (string, bool) {
	for _, e := range entries {
		if e.Primary && e.Verified && e.Email != "" {
			return e.Email, true
		}
	}
	for _, e := range entries {
		if e.Verified && e.Email != "" {
			return e.Email, true
		}
	}
	for _, e := range entries {
		if e.Primary && e.Email != "" {
			return e.Email, false
		}
	}
	for _, e := range entries {
		if e.Email != "" {
			return e.Email, false
		}
	}
	return "", false
}

// truncate bounds a string for logging.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
