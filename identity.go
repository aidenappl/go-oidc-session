package oidcsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Identity is the provider-agnostic result of a successful SSO login.
//
// ─────────────────────────────────────────────────────────────────────────────
// (Provider, Subject) IS THE IDENTITY. EMAIL IS NOT, AND NEVER BECOMES IT.
//
// Subject is the IdP's stable, never-reassigned identifier for a human — `sub`
// in OIDC, which Core §2 requires to be locally unique and never reassigned.
// Paired with Provider it is the only correct key for "who is this".
//
// Email is a HINT, used for exactly one thing: the strictly-gated
// verified-both-sides link in UserResolver. Treating it as the identity is the
// classic account-takeover bug, and it does not require a malicious IdP — an
// employee leaves, their address is reassigned to a new hire, and the new hire
// logs into the old one's account. Two of the three implementations this package
// replaced had that bug.
// ─────────────────────────────────────────────────────────────────────────────
type Identity struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`

	// SID is the OIDC session identifier (`sid`) from the id_token, when the
	// provider issues one.
	//
	// ─────────────────────────────────────────────────────────────────────────
	// ⚠️ STORE IT ON THE SESSION EVEN IF YOU HAVE NOT IMPLEMENTED BACK-CHANNEL
	// LOGOUT. It is the only handle by which a session-scoped logout can name
	// this session, and a session persisted without one is unreachable by that
	// mechanism FOREVER — adding the column later reaches only sessions created
	// after it.
	//
	// It is read from the VERIFIED id_token claim set only, and deliberately
	// BEFORE any UserInfo merge: UserInfo is fetched with a bearer token and is
	// not signed, so letting it supply a `sid` would let an unsigned response
	// name which session to end.
	//
	// Empty is normal and is not an error. Plain OAuth2 providers have no
	// id_token at all, and a conforming OIDC provider need not issue `sid`.
	// ─────────────────────────────────────────────────────────────────────────
	SID string `json:"sid,omitempty"`

	Email string `json:"email"`

	// EmailVerified is the IdP's assertion, OR the provider-level
	// TrustEmailVerified override. It gates auto-linking, so an unverified email
	// can never attach an identity to an existing account.
	EmailVerified bool `json:"email_verified"`

	Name    *string `json:"name,omitempty"`
	Picture *string `json:"picture,omitempty"`

	// RawClaims is the full claim set, for an application that wants to store or
	// map something this struct does not model.
	//
	// ⚠️ It is UNVALIDATED beyond the signature check on the id_token that carried
	// it. Do not read an authorization decision out of it without deciding, for
	// that specific claim, whether the IdP is authoritative for it.
	RawClaims json.RawMessage `json:"raw_claims,omitempty"`
}

// TokenSet is the raw IdP token material from a login.
//
// The Manager keeps these server-side for the life of a session (the BFF
// pattern, RFC 10017 §6.1). Refreshing them is how a session proves the
// upstream grant is still alive: a successful refresh extends the session, an
// invalid_grant ends it.
//
// ⚠️ THESE ARE LIVE CREDENTIALS. Store them encrypted, or do not store them.
// SessionStore is defined so that encryption is the application's choice and this
// package never has to hold a key — see its documentation.
type TokenSet struct {
	AccessToken  string
	RefreshToken string

	// IDToken is retained for back-channel logout (which needs a `sid`) and for
	// debugging. It is not required to establish the identity — that already
	// happened during Exchange.
	IDToken string

	// Expiry is when AccessToken expires. Zero means the provider did not say,
	// which the Manager treats as "never needs refreshing" — the session then
	// lives until Manager.MaxLifetime or a back-channel logout.
	Expiry time.Time
}

// AuthOptions are the optional OIDC authorization request parameters a login
// may carry.
type AuthOptions struct {
	// Prompt is the OIDC `prompt` parameter. "none" asks the provider to answer
	// without showing any UI: it either returns a code for the session it
	// already has, or an error such as login_required. "" omits it.
	Prompt string

	// LoginHint is the OIDC `login_hint` parameter. "" omits it.
	LoginHint string
}

// ErrGrantInvalid is returned by Adapter.Refresh when the provider definitively
// refused the refresh token (RFC 6749 §5.2 invalid_grant): expired, revoked or
// rotated away. The session it belongs to is over. Any other Refresh error is
// a failure to get an answer, not a refusal.
var ErrGrantInvalid = errors.New("oidcsession: refresh token refused by the provider (invalid_grant)")

// Adapter turns one provider's OAuth2/OIDC dance into an Identity.
//
// Two implementations exist and there should not be a third: a provider that
// needs bespoke Go code is a provider whose quirks belong behind one of these
// two, or a sign that it is not actually OAuth2.
type Adapter interface {
	// AuthCodeURL builds the authorize URL for a login attempt.
	//
	// All three arguments are mandatory and all three are generated by
	// GenerateState, not by the caller:
	//   state    — anti-CSRF, single-use, validated server-side
	//   nonce    — binds the id_token to this request; verified on return
	//   verifier — the PKCE verifier whose S256 challenge is sent
	//
	// ⚠️ An implementation that accepts `verifier` and does not send a challenge
	// derived from it has implemented nothing. That exact bug shipped in one of
	// the flows this package replaced, and it is why the PKCE round trip is
	// asserted end-to-end in adapter_test.go rather than reviewed.
	AuthCodeURL(state, nonce, verifier string, opts AuthOptions) (string, error)

	// Exchange completes the callback: redeems the code (sending the PKCE
	// verifier), verifies what can be verified — including the nonce — and returns
	// the identity plus the tokens.
	Exchange(ctx context.Context, code, verifier, nonce string) (*Identity, *TokenSet, error)

	// Refresh redeems a refresh token for a new TokenSet. The result's
	// RefreshToken is the one to use next: the successor from a rotating
	// provider, or the same token from one that does not rotate. Returns an
	// error wrapping ErrGrantInvalid when the provider refused the token.
	Refresh(ctx context.Context, refreshToken string) (*TokenSet, error)
}

// NewAdapter validates the provider and returns the adapter for its kind.
func NewAdapter(ctx context.Context, p *Provider) (Adapter, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	switch p.Kind {
	case KindOIDC:
		return newOIDCAdapter(ctx, p)
	case KindOAuth2:
		return newOAuth2Adapter(p)
	default:
		// Unreachable: Validate rejects unknown kinds. Kept so adding a Kind
		// without an adapter fails loudly instead of returning a nil interface.
		return nil, fmt.Errorf("sso: no adapter for kind %q", p.Kind)
	}
}
