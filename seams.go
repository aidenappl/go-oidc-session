package oidcsession

import (
	"context"
	"errors"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// THE THREE SEAMS
//
// This package knows how to talk to an identity provider. It knows nothing about
// your users, your sessions, or your storage — and it must not learn, because the
// three services adopting it have three different schemas, and one of them has no
// provider table at all.
//
// Everything application-specific goes through one of these interfaces. If you
// find yourself wanting to add a fourth, check first whether the thing you need
// is genuinely application-specific or whether it is a protocol concern that
// belongs implemented once, in here.
// ─────────────────────────────────────────────────────────────────────────────

// ErrNoState is returned by a StateStore when the state is unknown, already
// consumed, or expired. All three are the same answer to the caller: this login
// cannot proceed.
var ErrNoState = errors.New("sso: unknown, expired or already-consumed state")

// StateStore persists the server-side record of an in-flight login.
//
// ⚠️ WHY THIS IS SERVER-SIDE AND NOT A COOKIE. The record holds the `nonce` and
// the PKCE verifier. If the browser held them, the callback would be validating
// values the client could substitute — and PKCE's entire premise is that the user
// agent is where the code leaks. Keeping them here means the callback compares
// against something the client never possessed.
type StateStore interface {
	// SaveState stores data under state until expiresAt.
	SaveState(ctx context.Context, state string, data []byte, expiresAt time.Time) error

	// ConsumeState atomically returns and deletes the record for state.
	//
	// ⚠️⚠️ ATOMICITY IS THE SECURITY PROPERTY, AND IT IS YOUR IMPLEMENTATION'S JOB.
	// This is the single most important line in this file.
	//
	// "Atomically" means: of N concurrent callers presenting the SAME state,
	// EXACTLY ONE receives the data and the rest receive ErrNoState. A SELECT
	// followed by a DELETE does NOT satisfy this — both callers read the row, both
	// proceed, and an attacker replaying a captured state alongside the real
	// callback is deliberately racing that window.
	//
	// Implement it as a conditional single statement whose affected-row count
	// decides the winner, and let the database's row lock arbitrate:
	//
	//	DELETE FROM sso_state WHERE state = ?   → RowsAffected() == 1 wins
	//
	// reading the payload back in the same statement (RETURNING) or by a read
	// guarded on having won the delete. Every other shape has a race.
	//
	// A record that has expired must return ErrNoState even if it is still
	// present, and should be deleted anyway — a caller must not be able to
	// distinguish "expired" from "never existed", and a store that only deletes on
	// success accumulates dead rows.
	ConsumeState(ctx context.Context, state string) ([]byte, error)
}

// UserResolver maps a verified Identity onto an application user.
//
// ─────────────────────────────────────────────────────────────────────────────
// THIS IS THE SECURITY-CRITICAL SEAM. IMPLEMENT THE ORDER EXACTLY.
//
// This package cannot enforce your provisioning rules, so it documents them
// instead, and the ordering below is load-bearing. It is where the nOAuth and
// pre-account-takeover defences live:
//
//  1. KNOWN IDENTITY — (Provider, Subject) already exists. Load and return its
//     owning user. This is the only identity key; email is never it.
//
//  2. SAFE LINK — no such identity, but the IdP asserts a VERIFIED email that
//     matches an EXISTING user whose OWN email is also verified, AND
//     Provider.AllowAutoLink is set. Only then attach the identity.
//
//     ⚠️ BOTH SIDES MUST BE VERIFIED, and this is not belt-and-braces. The
//     attack it stops: an attacker registers a native account on the victim's
//     address and never verifies it. The victim later signs in through SSO. If
//     linking only required the IDP side to be verified, the victim's SSO login
//     binds onto the attacker's account — and the attacker, who knows the
//     password, now has the victim's session. Requiring the local account to be
//     verified too means the attacker's unverified planted account can never be
//     a link target.
//
//     An existing user with an UNVERIFIED email must be REFUSED, not fallen
//     through to provisioning — provisioning would collide on the unique email
//     and the error would be confusing rather than explanatory.
//
//  3. PROVISION — otherwise, if Provider.AutoProvision is set, create a user and
//     its first identity. Create them ATOMICALLY: a failed identity insert that
//     leaves an orphaned user row produces an account nobody can log into that
//     also blocks re-registration on that address.
//
//     Provision into a PENDING state if your application has one. A user who
//     arrived through SSO has proved they control an IdP account, which is not
//     the same as being authorised to use your service.
//
//  4. REFUSE — provisioning disabled and no match. Return an error.
//
// ─────────────────────────────────────────────────────────────────────────────
type UserResolver interface {
	// ResolveUser returns the local user id for an identity, following the order
	// documented above.
	//
	// A returned error fails the login. That is the correct default: this runs
	// after the IdP has authenticated someone, so "I could not work out who this
	// is" must not become "log them in as somebody".
	ResolveUser(ctx context.Context, p *Provider, id Identity) (localUserID int64, err error)

	// LinkIdentity attaches an identity to a SPECIFIC already-authenticated user,
	// for the account-linking flow (a signed-in user adding a second provider).
	//
	// It bypasses steps 1–4 deliberately: the active session already proved the
	// step-up, so there is nothing to resolve. It must still refuse if the
	// identity is already linked to a DIFFERENT user — otherwise linking becomes a
	// way to move an identity between accounts.
	LinkIdentity(ctx context.Context, p *Provider, userID int64, id Identity) error
}

// SessionStore persists server-side sessions (RFC 10017 §6.1, the BFF pattern).
//
// Sessions are keyed by ID — the SHA-256 of the opaque cookie value, never the
// cookie value itself — so a read of the store does not yield usable cookies,
// and a user may hold any number of concurrent sessions (one per browser).
//
// ⚠️ ENCRYPTION IS YOURS AND IS NOT OPTIONAL. Session.Tokens are live provider
// credentials. Encrypt them at rest; the sqlstore package does so with a Sealer.
type SessionStore interface {
	// CreateSession inserts a new session.
	CreateSession(ctx context.Context, s Session) error

	// GetSession returns the session with this ID, or (nil, nil) when there is
	// none. "No such session" must not be an error.
	GetSession(ctx context.Context, id string) (*Session, error)

	// UpdateSessionTokens replaces the session's tokens after a refresh and
	// records when it happened.
	UpdateSessionTokens(ctx context.Context, id string, tokens TokenSet, refreshedAt time.Time) error

	// TouchSession records activity. Called at most once per Manager.TouchInterval.
	TouchSession(ctx context.Context, id string, at time.Time) error

	// DeleteSession ends one session. Deleting a missing session is not an error.
	DeleteSession(ctx context.Context, id string) error

	// DeleteSessionsBySID ends the sessions created under this provider session
	// id (back-channel logout naming a `sid`). (0, nil) when there are none.
	DeleteSessionsBySID(ctx context.Context, provider, sid string) (int, error)

	// DeleteSessionsBySubject ends every session this provider subject holds
	// (back-channel logout naming only a `sub`). (0, nil) when there are none.
	DeleteSessionsBySubject(ctx context.Context, provider, subject string) (int, error)

	// DeleteUserSessions ends every session a local user holds — for an
	// application-side "sign out everywhere", suspension or deletion.
	DeleteUserSessions(ctx context.Context, userID int64) (int, error)
}

// Session is one signed-in browser.
type Session struct {
	// ID is the SHA-256 (hex) of the cookie value.
	ID string

	// UserID is the application's local user id, from UserResolver.
	UserID int64

	// Provider is the slug of the provider that authenticated this session.
	Provider string

	// Subject is the provider's stable identifier for the user.
	Subject string

	// SID is the provider's session id from the id_token, when it sent one.
	// Back-channel logout targets sessions by it.
	SID string

	Tokens TokenSet

	CreatedAt   time.Time
	LastSeenAt  time.Time
	RefreshedAt time.Time

	// ExpiresAt is the absolute end of the session (Manager.MaxLifetime). The
	// provider normally ends it sooner, by refusing a refresh.
	ExpiresAt time.Time
}
