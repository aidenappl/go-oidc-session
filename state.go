package oidcsession

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/oauth2"
)

// StateTTL bounds how long an in-flight login may sit between the redirect and
// the callback.
//
// Ten minutes, not one: it has to cover a user who is redirected to their IdP,
// completes a password prompt, an MFA challenge and possibly a consent screen,
// on a phone, on a bad connection. It also has to not be so long that a captured
// state is useful much later — though single use, not the TTL, is what actually
// closes that.
const StateTTL = 10 * time.Minute

// StateData is the server-side record for one in-flight login.
//
// It never reaches the browser. See StateStore for why that matters: the nonce
// and verifier below are exactly the values an attacker would need to substitute.
type StateData struct {
	Provider string `json:"provider"`

	// Nonce binds the id_token to this authorization request. Verified in
	// Exchange, by this package, because go-oidc's Verify() does not.
	Nonce string `json:"nonce"`

	// Verifier is the PKCE code verifier. Its S256 challenge went to the
	// authorization endpoint; this value goes to the token endpoint.
	Verifier string `json:"verifier"`

	// ReturnURL is where to send the browser afterwards.
	//
	// ⚠️ IT MUST ALREADY BE SANITISED BY THE CALLER. This package stores and
	// returns it verbatim and cannot tell a path from an absolute URL to an
	// attacker's host. An unsanitised value here is an open redirect at the end of
	// an authenticated flow, which is a phishing primitive with your domain on it.
	// Accept only a same-site path, or an allowlisted origin.
	ReturnURL string `json:"return_url"`

	ExpiresAt time.Time `json:"expires_at"`

	// LinkUserID, when non-zero, marks this an authenticated account-LINK flow
	// rather than a login: the callback attaches the returned identity to THIS
	// user, skipping resolution entirely, because the active session already
	// proved the step-up.
	LinkUserID int64 `json:"link_user_id,omitempty"`

	// Prompt is the `prompt` the login was started with. A callback that
	// receives login_required for a prompt=none attempt is the expected
	// "no provider session" answer, not a failure.
	Prompt string `json:"prompt,omitempty"`
}

// GenerateState creates a fresh {state, nonce, verifier} for a login, persists
// the record single-use, and returns the three values the authorize URL needs.
//
// ⚠️ ALL THREE ARE GENERATED HERE, TOGETHER, AND NONE IS OPTIONAL. The reason
// this is one function rather than three helpers a caller composes: a caller who
// composes them can forget one, and the forgotten one is invisible — a login with
// no nonce works perfectly until someone replays an id_token, and a login with no
// verifier works perfectly until someone steals a code. Making the flow's entry
// point produce all three means "forgot to send PKCE" is not a reachable state.
func GenerateState(ctx context.Context, store StateStore, provider, returnURL string) (state, nonce, verifier string, err error) {
	return generateState(ctx, store, StateData{Provider: provider, ReturnURL: returnURL})
}

// GenerateLinkState is GenerateState for the authenticated account-linking flow.
func GenerateLinkState(ctx context.Context, store StateStore, provider, returnURL string, linkUserID int64) (state, nonce, verifier string, err error) {
	if linkUserID == 0 {
		// A zero id would silently downgrade a link flow into a login flow, which
		// would resolve or provision instead of linking — the wrong user entirely.
		return "", "", "", fmt.Errorf("sso: GenerateLinkState requires a non-zero user id")
	}
	return generateState(ctx, store, StateData{Provider: provider, ReturnURL: returnURL, LinkUserID: linkUserID})
}

// generateState fills in the nonce, verifier and expiry on sd and persists it.
func generateState(ctx context.Context, store StateStore, sd StateData) (string, string, string, error) {
	if store == nil {
		return "", "", "", fmt.Errorf("sso: no StateStore configured")
	}
	if sd.Provider == "" {
		return "", "", "", fmt.Errorf("sso: GenerateState requires a provider slug")
	}

	state, err := randToken()
	if err != nil {
		return "", "", "", err
	}
	nonce, err := randToken()
	if err != nil {
		return "", "", "", err
	}
	// oauth2.GenerateVerifier produces a 43-character RFC 7636-compliant verifier
	// from crypto/rand. Used rather than hand-rolled so the length and alphabet
	// rules cannot be got subtly wrong.
	verifier := oauth2.GenerateVerifier()

	expiresAt := time.Now().Add(StateTTL)
	sd.Nonce, sd.Verifier, sd.ExpiresAt = nonce, verifier, expiresAt
	payload, err := json.Marshal(sd)
	if err != nil {
		return "", "", "", fmt.Errorf("sso: marshal state: %w", err)
	}

	if err := store.SaveState(ctx, state, payload, expiresAt); err != nil {
		return "", "", "", fmt.Errorf("sso: persist state: %w", err)
	}
	return state, nonce, verifier, nil
}

// ConsumeState validates and single-use consumes a state record.
//
// The atomicity that makes it single-use lives in the StateStore implementation,
// not here — see ConsumeState on that interface. This function adds the checks
// that do not need storage semantics: non-empty, parseable, unexpired.
//
// Every failure returns the SAME error shape. A caller must not be able to learn
// whether a state was unknown, malformed, expired or already used: those
// distinctions tell someone probing with captured values which of their captures
// was real.
func ConsumeState(ctx context.Context, store StateStore, state string) (*StateData, error) {
	if store == nil {
		return nil, fmt.Errorf("sso: no StateStore configured")
	}
	if state == "" {
		return nil, ErrNoState
	}

	raw, err := store.ConsumeState(ctx, state)
	if err != nil {
		// Includes ErrNoState from the store. Wrapped, not replaced, so a caller can
		// still errors.Is it while a storage failure keeps its cause.
		return nil, err
	}

	var sd StateData
	if err := json.Unmarshal(raw, &sd); err != nil {
		// A corrupt record is treated as no record. It has already been consumed by
		// the store, so it cannot be retried.
		return nil, ErrNoState
	}
	if time.Now().After(sd.ExpiresAt) {
		// Belt and braces: the store is also expected to expire records. Checked
		// here too because a store that only expires lazily would otherwise accept
		// an arbitrarily old state.
		return nil, ErrNoState
	}
	return &sd, nil
}

// randToken returns 256 bits of crypto/rand as base64url.
//
// The error is RETURNED, not panicked on. A library that panics takes the calling
// process down; a failing login is the correct blast radius for a randomness
// failure this rare.
func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sso: crypto/rand failed: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
