// Package sso implements the relying-party half of an OAuth2/OpenID Connect
// single sign-on flow, as a library with no opinion about what a user is.
//
// ─────────────────────────────────────────────────────────────────────────────
// WHY THIS EXISTS
//
// Three services on this platform each grew their own copy of an SSO flow, and
// the copies drifted in ways that matter. One generated a PKCE verifier and then
// silently dropped it at the token exchange, which is PKCE that looks
// implemented and defends nothing. One keyed identity on EMAIL rather than on
// (provider, subject), which is an account-takeover primitive the moment an IdP
// lets an address be reassigned. One never checked the `nonce` — go-oidc's
// Verify() deliberately does not check it, so "we use a library" is not
// sufficient. One had no bound on how long it would trust a stale introspection
// result.
//
// Each of those is a subtle, silent defect that a working login does not reveal.
// The fix is not three more code reviews; it is one implementation where the
// defended path is the only path.
//
// ─────────────────────────────────────────────────────────────────────────────
// WHAT THIS PACKAGE DELIBERATELY DOES NOT KNOW
//
// It does not know what a user is, where sessions live, how secrets are stored,
// or what your schema looks like. Three interfaces are the whole contract:
//
//	UserResolver  — identity → your user. You own provisioning and linking.
//	StateStore    — where an in-flight login's state lives, single-use.
//	SessionStore  — where a live SSO session's cached tokens live.
//
// Everything else is a plain struct you fill in. In particular Provider is NOT
// a database row: each application maps its own table (or its config file, or a
// literal) onto it. That is what lets a service with no provider table use this
// at all.
//
// ─────────────────────────────────────────────────────────────────────────────
// THE INVARIANTS. Do not make these configurable.
//
//  1. Identity is (Provider, Subject). NEVER email. Email is a hint used only
//     for the strictly-gated verified-both-sides link.
//  2. PKCE S256 is always generated and always sent.
//  3. `nonce` is always verified on an id_token.
//  4. `state` is single-use, server-side, and never derived from a cookie.
//  5. A UserInfo response whose `sub` differs from the id_token's `sub` is
//     discarded, not merged (OIDC Core §5.3.2).
//
// A caller cannot switch any of these off, because every one of them was found
// missing in a shipped implementation that appeared to work.
package oidcsession

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

// Kind selects which adapter drives a provider.
type Kind string

const (
	// KindOIDC is a compliant OpenID Connect provider, configured by issuer URL
	// alone: endpoints, JWKS and supported algorithms all come from discovery.
	// Any OIDC provider — Google, Okta, Entra, Auth0 — is a config value,
	// not a code change.
	KindOIDC Kind = "oidc"

	// KindOAuth2 is a plain OAuth2 provider with explicitly configured endpoints
	// and a UserInfo URL. It exists for providers that predate OIDC or publish no
	// discovery document.
	//
	// ⚠️ It is strictly weaker and should be a last resort: there is no id_token,
	// so there is no signed assertion of identity, no `nonce` binding, and
	// identity rests entirely on a bearer-token call to a UserInfo endpoint.
	KindOAuth2 Kind = "oauth2"
)

// Provider is one identity provider, fully resolved.
//
// It is a plain struct, not a schema. Applications map their own storage onto it
// — a database row, a config file, or a literal in main() — which is what makes
// this package usable by a service that has no provider table at all.
//
// ClientSecret is the RESOLVED secret, not a reference to one. Resolving it is
// the application's job because every service does it differently (Keyring
// reference, AES-GCM column, plain environment variable), and a library that
// tried to own that would need to know all three.
type Provider struct {
	// Slug is the stable identifier for this provider. It is recorded as the
	// `provider` half of an identity, so ⚠️ CHANGING IT ORPHANS EVERY IDENTITY
	// LINKED THROUGH IT — those users can no longer be found by their identity
	// and will fall through to linking or provisioning on their next login.
	Slug string

	// DisplayName is what a login page shows. Presentation only.
	DisplayName string

	Kind Kind

	// IssuerURL is required for KindOIDC. Discovery runs against
	// {IssuerURL}/.well-known/openid-configuration, and the `iss` of every
	// id_token must match it exactly.
	IssuerURL string

	// AuthorizeURL, TokenURL and UserInfoURL are required for KindOAuth2 and
	// ignored for KindOIDC, where discovery supplies them. Taking them from
	// discovery is not a convenience: an attacker who can make a client use a
	// token endpoint the issuer did not publish has a credential-exfiltration
	// path.
	AuthorizeURL string
	TokenURL     string
	UserInfoURL  string

	ClientID     string
	ClientSecret string

	// Scopes is a space-separated list. Empty means "openid email profile" for
	// KindOIDC.
	Scopes string

	// RedirectURL must match byte-for-byte what is registered with the IdP —
	// OAuth's redirect_uri comparison is exact, with no normalisation of trailing
	// slashes, case or default ports.
	RedirectURL string

	// SubjectClaim, EmailClaim and EmailVerifiedClaim override the claim names
	// read from an id_token or UserInfo response, for providers that use
	// non-standard ones. Empty means the standard name.
	//
	// ⚠️ SubjectClaim is the identity key. Pointing it at a mutable or
	// reassignable claim — an email, a username, a display name — reintroduces
	// exactly the account-takeover this package exists to prevent. If you are
	// tempted to set it, the question to answer first is "can this value ever be
	// reassigned to a different human?"
	SubjectClaim       string
	EmailClaim         string
	EmailVerifiedClaim string

	// TrustEmailVerified treats this provider's asserted email as verified even
	// when it sends no email_verified claim.
	//
	// ⚠️ It is a decision about the PROVIDER, never about a user, and it gates
	// auto-linking. Setting it for a provider that lets people register an
	// address they do not control turns link-on-login into account takeover. Only
	// set it for a provider you operate, or one contractually verifying
	// addresses.
	TrustEmailVerified bool

	// AllowAutoLink permits attaching a new identity to an EXISTING user when
	// both sides have a verified email. See UserResolver for why both.
	AllowAutoLink bool

	// AutoProvision permits creating a new local user for an unrecognised
	// identity. With it off, an unknown identity is refused and an administrator
	// must create the account first.
	AutoProvision bool

	// FetchUserInfo makes KindOIDC call the UserInfo endpoint in addition to
	// reading the id_token.
	//
	// Off by default: an id_token is a signed assertion and is sufficient, while
	// UserInfo is an extra network round trip on every login. Turn it on for
	// providers that keep claims out of the id_token to keep it small.
	//
	// When on, the response's `sub` MUST equal the id_token's `sub` or the whole
	// response is discarded (OIDC Core §5.3.2). That check is not optional and
	// not configurable — see fetchUserInfo.
	FetchUserInfo bool

	// EmailsURL is an optional KindOAuth2 fallback for providers whose UserInfo
	// response omits the email — GitHub's `/user` returns `"email": null` for any
	// user with a private address. When set and UserInfo carried no email, it is
	// fetched with the access token and must return GitHub's `/user/emails`
	// shape: `[{"email","primary","verified","visibility"}]`. The primary verified
	// address wins, then the first verified one; with neither, an unverified
	// address is returned with EmailVerified=false. The per-address `verified`
	// flag is authoritative — TrustEmailVerified does NOT apply to an address
	// obtained this way. The fallback address is set on Identity.Email only;
	// Identity.RawClaims is the UserInfo response and does not include it.
	//
	// For GitHub: "https://api.github.com/user/emails", with the `user:email`
	// scope. A failed fetch — non-200, malformed, or no usable address — fails
	// the login rather than continuing email-less.
	//
	// Rejected on KindOIDC: an OIDC provider asserts email in its claims (use
	// FetchUserInfo), and silently ignoring the field would hide a misconfiguration.
	EmailsURL string

	// HTTPClient, when set, carries EVERY outbound call this package makes to
	// the provider: OIDC discovery, the JWKS fetch, the token exchange, OIDC and
	// OAuth2 UserInfo, the EmailsURL fallback and introspection. nil keeps the
	// package default (a 15s-timeout client) — the previous behaviour.
	//
	// It exists so a multi-tenant application can enforce an SSRF policy at DIAL
	// time (refusing private, loopback, link-local and CGNAT addresses, and
	// refusing redirects) for endpoints an administrator typed in — including
	// the ones discovery returns, which a save-time URL check never sees.
	// FetchIcon is unaffected: it has its own guard.
	//
	// ⚠️ OIDC discovery is cached per (issuer, HTTPClient). Reuse one client
	// value per policy rather than building a new one per request, or the cache
	// never hits.
	HTTPClient *http.Client `json:"-"`
}

// client is the HTTP client for calls to this provider.
func (p *Provider) client() *http.Client {
	if p != nil && p.HTTPClient != nil {
		return p.HTTPClient
	}
	return httpClient
}

// withProviderClient puts the provider's HTTPClient on ctx under
// oauth2.HTTPClient, which is where x/oauth2 (token exchange) and go-oidc
// (discovery, JWKS, UserInfo) look for one. The provider's client wins over
// one already on ctx: it is the policy the application configured for this
// provider. No-op when HTTPClient is nil.
func withProviderClient(ctx context.Context, p *Provider) context.Context {
	if p == nil || p.HTTPClient == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, p.HTTPClient)
}

// Validate reports whether the provider is usable, with an error naming the
// specific field at fault.
//
// It is called by NewAdapter, so a misconfigured provider fails when it is first
// used rather than producing a half-working flow. A provider missing its
// TokenURL, for instance, would otherwise get all the way to a redirect the user
// can complete before failing on the callback — a failure the user sees and the
// operator cannot easily place.
func (p *Provider) Validate() error {
	if p.Slug == "" {
		return fmt.Errorf("sso: provider has no slug")
	}
	if p.ClientID == "" {
		return fmt.Errorf("sso: provider %q has no client_id", p.Slug)
	}
	if p.RedirectURL == "" {
		return fmt.Errorf("sso: provider %q has no redirect_url", p.Slug)
	}

	switch p.Kind {
	case KindOIDC:
		if p.IssuerURL == "" {
			return fmt.Errorf("sso: oidc provider %q has no issuer_url", p.Slug)
		}
		if p.FetchUserInfo && p.UserInfoURL == "" {
			// Discovery supplies it, so this is only reachable if the caller both
			// asked for UserInfo and the discovery document omitted the endpoint.
			// Reported here rather than silently skipping the fetch, because
			// silently skipping means the sub check silently does not happen.
			return fmt.Errorf("sso: oidc provider %q asks for userinfo but no endpoint is known", p.Slug)
		}
		if p.EmailsURL != "" {
			return fmt.Errorf("sso: oidc provider %q sets emails_url, which only applies to kind %q (use FetchUserInfo)", p.Slug, KindOAuth2)
		}
	case KindOAuth2:
		if p.AuthorizeURL == "" {
			return fmt.Errorf("sso: oauth2 provider %q has no authorize_url", p.Slug)
		}
		if p.TokenURL == "" {
			return fmt.Errorf("sso: oauth2 provider %q has no token_url", p.Slug)
		}
		if p.UserInfoURL == "" {
			// For KindOAuth2 there is no id_token, so UserInfo is the ONLY source of
			// identity. Without it there is nothing to log in as.
			return fmt.Errorf("sso: oauth2 provider %q has no userinfo_url, so it cannot establish an identity", p.Slug)
		}
		if p.EmailsURL != "" {
			// It is called with the user's access token, so it must be an absolute
			// http(s) URL — a relative or schemeless value would otherwise fail on
			// the first login, after the user has already been redirected.
			u, err := url.Parse(p.EmailsURL)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return fmt.Errorf("sso: oauth2 provider %q has an invalid emails_url %q (want an absolute http(s) URL)", p.Slug, p.EmailsURL)
			}
		}
	default:
		return fmt.Errorf("sso: provider %q has unknown kind %q (want %q or %q)", p.Slug, p.Kind, KindOIDC, KindOAuth2)
	}
	return nil
}

// scopeList returns the configured scopes, or the OIDC default.
func (p *Provider) scopeList() []string {
	if s := strings.Fields(p.Scopes); len(s) > 0 {
		return s
	}
	if p.Kind == KindOIDC {
		return []string{"openid", "email", "profile"}
	}
	return nil
}
