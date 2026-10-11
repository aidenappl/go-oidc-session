package oidcsession

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// MANAGER — THE BROWSER SIDE OF SSO, BFF-STYLE (RFC 10017 §6.1)
//
// The application's backend is the OIDC client. Provider tokens never reach the
// browser; the browser holds one opaque, HttpOnly session cookie whose SHA-256
// keys a server-side Session row.
//
// The session's lifetime is the PROVIDER'S. Whenever the stored access token is
// about to expire, the next request refreshes it server-side. A successful
// refresh is proof the upstream grant is alive and extends the session; an
// invalid_grant ends it. So a user stays signed in exactly as long as their
// provider session (refresh token) lives, and a revocation at the provider takes
// effect within one access-token lifetime — or immediately, via back-channel
// logout. There is no separate application clock to drift out of step, and no
// introspection checkpoint.
//
// When a session ends, the frontend sends the browser to LoginHandler with
// prompt=none. A user still signed in at the provider comes straight back with a
// new session and never sees a page; only a user the provider has no session
// for lands on LoginPageURL with error=login_required.
// ─────────────────────────────────────────────────────────────────────────────

// Session errors returned by Authenticate.
var (
	// ErrNoSession — no session cookie, or it names no session. Answer 401.
	ErrNoSession = errors.New("oidcsession: no session")

	// ErrSessionEnded — the session existed and is now over: the provider
	// refused the refresh, MaxLifetime passed, or there is nothing left to
	// refresh with. Answer 401; the frontend re-authenticates with prompt=none.
	ErrSessionEnded = errors.New("oidcsession: session ended")

	// ErrProviderUnavailable — the access token has expired, the provider could
	// not be reached to refresh it, and OutageGrace has run out. Answer 503,
	// NOT 401: a 401 would send the browser to re-authenticate against the
	// provider that is already unreachable.
	ErrProviderUnavailable = errors.New("oidcsession: identity provider unavailable")
)

// LoginError is returned by a UserResolver to refuse a login with a code the
// application's login page understands (e.g. "pending", "no_access"). The code
// is passed to LoginPageURL as ?error=<code>. Any other resolver error is
// reported as "login_failed".
type LoginError struct {
	Code string
	Err  error
}

func (e *LoginError) Error() string {
	if e.Err != nil {
		return "oidcsession: login refused (" + e.Code + "): " + e.Err.Error()
	}
	return "oidcsession: login refused (" + e.Code + ")"
}

func (e *LoginError) Unwrap() error { return e.Err }

// Event is a telemetry record. Fields never contain a token or cookie value.
type Event struct {
	// Name is dotted, e.g. "login.succeeded", "session.refresh_refused".
	Name string
	// Warn marks a degraded or failed outcome; everything else is routine.
	Warn   bool
	Fields map[string]any
}

// Manager defaults.
const (
	DEFAULT_COOKIE_NAME    = "session"
	DEFAULT_MAX_LIFETIME   = 30 * 24 * time.Hour
	DEFAULT_REFRESH_LEEWAY = time.Minute
	DEFAULT_OUTAGE_GRACE   = 10 * time.Minute
	DEFAULT_TOUCH_INTERVAL = 5 * time.Minute

	// refreshTimeout bounds one refresh call to the provider.
	refreshTimeout = 10 * time.Second
)

// Manager is one application's SSO session layer. Configure the exported
// fields, then mount LoginHandler, CallbackHandler and BackchannelHandler, and
// call Authenticate from the auth middleware.
type Manager struct {
	// Providers resolves a provider slug to its configuration. Called per
	// login/refresh rather than cached, so a rotated secret applies at once.
	Providers func(ctx context.Context, slug string) (*Provider, error)

	// DefaultProvider is used when a login names no ?provider=.
	DefaultProvider string

	States   StateStore
	Sessions SessionStore
	Users    UserResolver

	// CookieName defaults to "session". Use an app-specific name.
	CookieName string
	// CookiePath defaults to "/".
	CookiePath string
	// CookieDomain is empty for a host-only cookie, which is recommended: the
	// cookie is set by and only ever sent to the API host. The frontend calls
	// that host with credentials, and same-site requests carry a Lax cookie.
	CookieDomain string
	// Insecure drops the Secure attribute. Local HTTP development only.
	Insecure bool

	// MaxLifetime is the absolute cap on a session. Defaults to 30 days. The
	// provider's refresh-token policy normally ends a session first.
	MaxLifetime time.Duration
	// RefreshLeeway refreshes this long before the access token expires.
	// Defaults to 1 minute.
	RefreshLeeway time.Duration
	// OutageGrace is how long past access-token expiry a session keeps working
	// while the provider is unreachable. Defaults to 10 minutes.
	OutageGrace time.Duration
	// TouchInterval throttles LastSeenAt writes. Defaults to 5 minutes.
	TouchInterval time.Duration

	// DefaultReturnURL is where a login lands without a usable return_to.
	// Required, absolute (e.g. "https://lattice.appleby.cloud/").
	DefaultReturnURL string
	// AllowedReturnOrigins are the origins return_to may point at, in addition
	// to DefaultReturnURL's. Anything else is replaced by DefaultReturnURL.
	AllowedReturnOrigins []string
	// LoginPageURL is the application's own sign-in page. Login failures and
	// prompt=none's login_required land here as ?error=<code>&return_to=<url>.
	// Required, absolute.
	LoginPageURL string
	// PostLogoutURL is sent as post_logout_redirect_uri on RP-initiated logout,
	// and is where Logout sends the browser when the provider has no
	// end_session_endpoint. Defaults to LoginPageURL.
	PostLogoutURL string

	// OnLogin runs after a session is created — for audit logging.
	OnLogin func(ctx context.Context, r *http.Request, s *Session, id Identity)
	// OnEvent receives telemetry. Optional.
	OnEvent func(ctx context.Context, e Event)
	// Logf receives diagnostic text. Defaults to log.Printf.
	Logf func(ctx context.Context, format string, args ...any)

	flights     flightGroup
	bcOnce      sync.Once
	backchannel *BackchannelLogout
}

type ctxKey struct{}

// WithSession returns ctx carrying s.
func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, ctxKey{}, s)
}

// SessionFrom returns the session WithSession stored on ctx.
func SessionFrom(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(ctxKey{}).(*Session)
	return s, ok && s != nil
}

// ─── Configuration helpers ──────────────────────────────────────────────────

func (m *Manager) cookieName() string {
	if m.CookieName != "" {
		return m.CookieName
	}
	return DEFAULT_COOKIE_NAME
}

func (m *Manager) stateCookieName() string { return m.cookieName() + "_login" }

func (m *Manager) cookiePath() string {
	if m.CookiePath != "" {
		return m.CookiePath
	}
	return "/"
}

func durationOr(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}

func (m *Manager) emit(ctx context.Context, name string, warn bool, fields map[string]any) {
	if m.OnEvent != nil {
		m.OnEvent(ctx, Event{Name: name, Warn: warn, Fields: fields})
	}
}

func (m *Manager) logf(ctx context.Context, format string, args ...any) {
	if m.Logf != nil {
		m.Logf(ctx, format, args...)
		return
	}
	log.Printf(format, args...)
}

func (m *Manager) setCookie(w http.ResponseWriter, name, value string, expires time.Time, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     m.cookiePath(),
		Domain:   m.CookieDomain,
		Expires:  expires,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   !m.Insecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie expires the session cookie.
func (m *Manager) ClearCookie(w http.ResponseWriter) {
	m.setCookie(w, m.cookieName(), "", time.Unix(0, 0), -1)
}

// hashID is the store key for a cookie value.
func hashID(cookieValue string) string {
	sum := sha256.Sum256([]byte(cookieValue))
	return hex.EncodeToString(sum[:])
}

func (m *Manager) provider(ctx context.Context, slug string) (*Provider, Adapter, error) {
	if m.Providers == nil {
		return nil, nil, fmt.Errorf("oidcsession: no Providers lookup configured")
	}
	p, err := m.Providers(ctx, slug)
	if err != nil {
		return nil, nil, err
	}
	if p == nil {
		return nil, nil, fmt.Errorf("oidcsession: provider %q not found", slug)
	}
	a, err := NewAdapter(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	return p, a, nil
}

// ─── return_to handling ─────────────────────────────────────────────────────

func origin(u *url.URL) string { return strings.ToLower(u.Scheme + "://" + u.Host) }

// SafeReturnURL returns raw if it points at an allowed origin (or is a
// same-origin path relative to DefaultReturnURL), else DefaultReturnURL. It is
// the only thing standing between return_to and an open redirect.
func (m *Manager) SafeReturnURL(raw string) string {
	def := m.DefaultReturnURL
	if raw == "" {
		return def
	}
	base, err := url.Parse(def)
	if err != nil {
		return def
	}
	// A bare path: resolve it against the default origin. "//host" and "/\host"
	// are scheme-relative to a browser and must not be treated as paths.
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") && !strings.HasPrefix(raw, "/\\") {
		ref, err := url.Parse(raw)
		if err != nil {
			return def
		}
		return base.ResolveReference(ref).String()
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return def
	}
	o := origin(u)
	if o == origin(base) {
		return u.String()
	}
	for _, allowed := range m.AllowedReturnOrigins {
		if a, err := url.Parse(allowed); err == nil && o == origin(a) {
			return u.String()
		}
	}
	return def
}

// loginPage redirects to LoginPageURL with an error code and the return URL.
func (m *Manager) loginPage(w http.ResponseWriter, r *http.Request, code, returnTo string) {
	u, err := url.Parse(m.LoginPageURL)
	if err != nil || m.LoginPageURL == "" {
		http.Error(w, "sign-in failed: "+code, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if returnTo != "" {
		q.Set("return_to", returnTo)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ─── Login ──────────────────────────────────────────────────────────────────

// allowedPrompts are the OIDC prompt values a login may forward.
var allowedPrompts = map[string]bool{"": true, "none": true, "login": true, "consent": true, "select_account": true}

// LoginHandler starts a login: GET ?provider=&return_to=&prompt=.
//
// A browser that already holds a live session is sent straight to return_to,
// so a prompt=none bounce can never loop on a session that is fine.
func (m *Manager) LoginHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	returnTo := m.SafeReturnURL(q.Get("return_to"))

	prompt := q.Get("prompt")
	if !allowedPrompts[prompt] {
		prompt = ""
	}

	if prompt != "login" {
		if _, err := m.Authenticate(w, r); err == nil {
			http.Redirect(w, r, returnTo, http.StatusFound)
			return
		}
	}

	slug := q.Get("provider")
	if slug == "" {
		slug = m.DefaultProvider
	}
	_, adapter, err := m.provider(ctx, slug)
	if err != nil {
		m.logf(ctx, "oidcsession: login: provider %q: %v", slug, err)
		m.emit(ctx, "login.failed", true, map[string]any{"provider": slug, "reason": "provider_unavailable"})
		m.loginPage(w, r, "provider_unavailable", returnTo)
		return
	}

	state, nonce, verifier, err := generateState(ctx, m.States, StateData{Provider: slug, ReturnURL: returnTo, Prompt: prompt})
	if err != nil {
		m.logf(ctx, "oidcsession: login: state: %v", err)
		m.emit(ctx, "login.failed", true, map[string]any{"provider": slug, "reason": "state_failed"})
		m.loginPage(w, r, "login_failed", returnTo)
		return
	}
	authURL, err := adapter.AuthCodeURL(state, nonce, verifier, AuthOptions{Prompt: prompt, LoginHint: q.Get("login_hint")})
	if err != nil {
		m.logf(ctx, "oidcsession: login: authorize url: %v", err)
		m.loginPage(w, r, "login_failed", returnTo)
		return
	}

	// Binds the login to this browser: the callback only accepts a state that
	// this cookie also carries, which defeats login CSRF (an attacker cannot
	// make a victim's browser complete the attacker's login).
	m.setCookie(w, m.stateCookieName(), state, time.Now().Add(StateTTL), int(StateTTL.Seconds()))
	m.emit(ctx, "login.started", false, map[string]any{"provider": slug, "prompt": prompt})
	http.Redirect(w, r, authURL, http.StatusFound)
}

// interactionErrors are the OIDC Core §3.1.2.6 errors meaning "the provider
// would need to show the user something" — the expected answer to prompt=none
// for someone without a provider session.
var interactionErrors = map[string]bool{
	"login_required": true, "interaction_required": true,
	"consent_required": true, "account_selection_required": true,
}

// CallbackHandler completes a login at the registered redirect_uri.
func (m *Manager) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	state := q.Get("state")

	cookie, cerr := r.Cookie(m.stateCookieName())
	m.setCookie(w, m.stateCookieName(), "", time.Unix(0, 0), -1)

	sd, err := ConsumeState(ctx, m.States, state)
	if err != nil {
		m.emit(ctx, "login.failed", false, map[string]any{"reason": "state_expired"})
		m.loginPage(w, r, "state_expired", "")
		return
	}
	if cerr != nil || cookie.Value != state {
		m.emit(ctx, "login.failed", true, map[string]any{"provider": sd.Provider, "reason": "state_mismatch"})
		m.loginPage(w, r, "state_mismatch", sd.ReturnURL)
		return
	}

	if perr := q.Get("error"); perr != "" {
		if interactionErrors[perr] {
			// The normal "not signed in at the provider" answer to prompt=none,
			// and only meaningful as such for one. Either way the user must
			// sign in interactively.
			m.emit(ctx, "login.required", false, map[string]any{"provider": sd.Provider, "prompt": sd.Prompt})
			m.loginPage(w, r, "login_required", sd.ReturnURL)
			return
		}
		code := "provider_error"
		if perr == "access_denied" {
			code = "access_denied"
		}
		m.emit(ctx, "login.failed", perr != "access_denied", map[string]any{"provider": sd.Provider, "reason": perr})
		m.loginPage(w, r, code, sd.ReturnURL)
		return
	}

	p, adapter, err := m.provider(ctx, sd.Provider)
	if err != nil {
		m.logf(ctx, "oidcsession: callback: provider %q: %v", sd.Provider, err)
		m.emit(ctx, "login.failed", true, map[string]any{"provider": sd.Provider, "reason": "provider_unavailable"})
		m.loginPage(w, r, "provider_unavailable", sd.ReturnURL)
		return
	}

	identity, tokens, err := adapter.Exchange(ctx, q.Get("code"), sd.Verifier, sd.Nonce)
	if err != nil {
		m.logf(ctx, "oidcsession: callback: exchange via %q: %v", sd.Provider, err)
		m.emit(ctx, "login.failed", true, map[string]any{"provider": sd.Provider, "reason": "exchange_failed"})
		m.loginPage(w, r, "login_failed", sd.ReturnURL)
		return
	}

	var userID int64
	if sd.LinkUserID != 0 {
		err = m.Users.LinkIdentity(ctx, p, sd.LinkUserID, *identity)
		userID = sd.LinkUserID
	} else {
		userID, err = m.Users.ResolveUser(ctx, p, *identity)
	}
	if err != nil {
		code := "login_failed"
		var le *LoginError
		if errors.As(err, &le) && le.Code != "" {
			code = le.Code
		} else {
			m.logf(ctx, "oidcsession: callback: resolve user via %q: %v", sd.Provider, err)
		}
		m.emit(ctx, "login.failed", le == nil, map[string]any{"provider": sd.Provider, "reason": code})
		m.loginPage(w, r, code, sd.ReturnURL)
		return
	}

	sess, err := m.IssueSession(w, r, sd.Provider, userID, *identity, *tokens)
	if err != nil {
		m.logf(ctx, "oidcsession: callback: create session: %v", err)
		m.emit(ctx, "login.failed", true, map[string]any{"provider": sd.Provider, "reason": "session_store_failed"})
		m.loginPage(w, r, "login_failed", sd.ReturnURL)
		return
	}

	if m.OnLogin != nil {
		m.OnLogin(ctx, r, sess, *identity)
	}
	m.emit(ctx, "login.succeeded", false, map[string]any{"provider": sd.Provider, "user_id": userID, "prompt": sd.Prompt})
	http.Redirect(w, r, m.SafeReturnURL(sd.ReturnURL), http.StatusFound)
}

// IssueSession creates a session for a login the application has already
// resolved, and sets the session cookie. CallbackHandler uses it; an
// application that runs its own callback (for example to support account
// linking) calls it after resolving the user, so its sessions get the same
// provider-bound lifetime.
//
// A fresh session id is minted on every login (session fixation), and any
// session this browser already held is ended rather than left orphaned.
func (m *Manager) IssueSession(w http.ResponseWriter, r *http.Request, provider string, userID int64, identity Identity, tokens TokenSet) (*Session, error) {
	ctx := r.Context()
	if old, err := r.Cookie(m.cookieName()); err == nil && old.Value != "" {
		if err := m.Sessions.DeleteSession(ctx, hashID(old.Value)); err != nil {
			m.logf(ctx, "oidcsession: delete previous session: %v", err)
		}
	}

	raw, err := randToken()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	sess := &Session{
		ID:          hashID(raw),
		UserID:      userID,
		Provider:    provider,
		Subject:     identity.Subject,
		SID:         identity.SID,
		Tokens:      tokens,
		CreatedAt:   now,
		LastSeenAt:  now,
		RefreshedAt: now,
		ExpiresAt:   now.Add(durationOr(m.MaxLifetime, DEFAULT_MAX_LIFETIME)),
	}
	if err := m.Sessions.CreateSession(ctx, *sess); err != nil {
		return nil, fmt.Errorf("oidcsession: create session: %w", err)
	}
	m.setCookie(w, m.cookieName(), raw, sess.ExpiresAt, 0)
	return sess, nil
}

// ─── Authenticate ───────────────────────────────────────────────────────────

// Authenticate resolves the request's session, refreshing the provider tokens
// first when they are due. It clears the cookie when the session is gone.
func (m *Manager) Authenticate(w http.ResponseWriter, r *http.Request) (*Session, error) {
	ctx := r.Context()
	c, err := r.Cookie(m.cookieName())
	if err != nil || c.Value == "" {
		return nil, ErrNoSession
	}

	s, err := m.Sessions.GetSession(ctx, hashID(c.Value))
	if err != nil {
		return nil, fmt.Errorf("oidcsession: load session: %w", err)
	}
	if s == nil {
		m.ClearCookie(w)
		return nil, ErrNoSession
	}

	now := time.Now()
	if !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt) {
		m.end(ctx, s, "session.expired")
		m.ClearCookie(w)
		return nil, ErrSessionEnded
	}

	if m.refreshDue(s, now) {
		s, err = m.refresh(ctx, s)
		if err != nil {
			if errors.Is(err, ErrSessionEnded) {
				m.ClearCookie(w)
			}
			return nil, err
		}
	}

	if now.Sub(s.LastSeenAt) >= durationOr(m.TouchInterval, DEFAULT_TOUCH_INTERVAL) {
		if err := m.Sessions.TouchSession(ctx, s.ID, now); err != nil {
			m.logf(ctx, "oidcsession: touch session: %v", err)
		}
		s.LastSeenAt = now
	}
	return s, nil
}

// refreshDue reports whether the access token expires within RefreshLeeway. A
// zero Expiry means the provider gave none: nothing to refresh.
func (m *Manager) refreshDue(s *Session, now time.Time) bool {
	if s.Tokens.Expiry.IsZero() {
		return false
	}
	return now.Add(durationOr(m.RefreshLeeway, DEFAULT_REFRESH_LEEWAY)).After(s.Tokens.Expiry)
}

// end deletes a session and reports why.
func (m *Manager) end(ctx context.Context, s *Session, event string) {
	if err := m.Sessions.DeleteSession(ctx, s.ID); err != nil {
		m.logf(ctx, "oidcsession: delete session: %v", err)
	}
	m.emit(ctx, event, false, map[string]any{"provider": s.Provider, "user_id": s.UserID})
}

// refresh renews s's provider tokens. Concurrent requests for one session share
// a single call — two refreshes racing with one rotating refresh token would
// otherwise present the same token twice, which a provider doing reuse
// detection (RFC 9700 §4.14) treats as theft and answers by revoking the grant.
func (m *Manager) refresh(ctx context.Context, s *Session) (*Session, error) {
	return m.flights.do(s.ID, func() (*Session, error) {
		// Detached from the request's cancellation: the result is shared, and
		// one closed tab must not fail the refresh for every waiter.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
		defer cancel()

		// Re-read: another instance may have refreshed already, in which case
		// the token we hold has been rotated away and must not be presented.
		fresh, err := m.Sessions.GetSession(ctx, s.ID)
		if err != nil {
			return nil, fmt.Errorf("oidcsession: reload session: %w", err)
		}
		if fresh == nil {
			return nil, ErrSessionEnded
		}
		now := time.Now()
		if !m.refreshDue(fresh, now) {
			return fresh, nil
		}

		if fresh.Tokens.RefreshToken == "" {
			if now.Before(fresh.Tokens.Expiry) {
				return fresh, nil
			}
			m.end(ctx, fresh, "session.expired")
			return nil, ErrSessionEnded
		}

		_, adapter, err := m.provider(ctx, fresh.Provider)
		var ts *TokenSet
		if err == nil {
			ts, err = adapter.Refresh(ctx, fresh.Tokens.RefreshToken)
		}
		if err != nil {
			if errors.Is(err, ErrGrantInvalid) {
				m.end(ctx, fresh, "session.refresh_refused")
				return nil, ErrSessionEnded
			}
			// No answer is not a refusal. Keep serving inside the grace window
			// (measured from the token's own expiry, so repeated failures cannot
			// extend it), then fail as unavailable rather than signing out.
			m.logf(ctx, "oidcsession: refresh via %q failed: %v", fresh.Provider, err)
			if now.Before(fresh.Tokens.Expiry.Add(durationOr(m.OutageGrace, DEFAULT_OUTAGE_GRACE))) {
				m.emit(ctx, "session.refresh_unavailable", true, map[string]any{"provider": fresh.Provider, "user_id": fresh.UserID, "grace": true})
				return fresh, nil
			}
			m.emit(ctx, "session.refresh_unavailable", true, map[string]any{"provider": fresh.Provider, "user_id": fresh.UserID, "grace": false})
			return nil, ErrProviderUnavailable
		}

		if ts.IDToken == "" {
			ts.IDToken = fresh.Tokens.IDToken
		}
		if ts.RefreshToken == "" {
			ts.RefreshToken = fresh.Tokens.RefreshToken
		}
		if err := m.Sessions.UpdateSessionTokens(ctx, fresh.ID, *ts, now); err != nil {
			// The provider has already rotated the refresh token; failing to
			// store the successor means the next refresh presents a spent one.
			// Logged loudly — the session will likely end at the next refresh.
			m.logf(ctx, "oidcsession: store refreshed tokens for session of user %d: %v", fresh.UserID, err)
			m.emit(ctx, "session.refresh_store_failed", true, map[string]any{"provider": fresh.Provider, "user_id": fresh.UserID})
		}
		fresh.Tokens, fresh.RefreshedAt = *ts, now
		m.emit(ctx, "session.refreshed", false, map[string]any{"provider": fresh.Provider, "user_id": fresh.UserID})
		return fresh, nil
	})
}

// ─── Logout ─────────────────────────────────────────────────────────────────

// Logout ends the request's session and returns where to send the browser: the
// provider's end_session_endpoint (RP-initiated logout, which also ends the
// provider session and with it — via back-channel logout — every other
// application's), or PostLogoutURL when the provider has none. The caller
// answers in its own response shape; the frontend navigates to the URL.
func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) string {
	ctx := r.Context()
	postLogout := m.PostLogoutURL
	if postLogout == "" {
		postLogout = m.LoginPageURL
	}

	c, err := r.Cookie(m.cookieName())
	m.ClearCookie(w)
	if err != nil || c.Value == "" {
		return postLogout
	}
	s, err := m.Sessions.GetSession(ctx, hashID(c.Value))
	if err != nil || s == nil {
		return postLogout
	}
	m.end(ctx, s, "logout")

	p, adapter, err := m.provider(ctx, s.Provider)
	if err != nil {
		return postLogout
	}
	es, ok := adapter.(endSessionSource)
	if !ok {
		return postLogout
	}
	endpoint := es.EndSessionEndpoint()
	if endpoint == "" {
		return postLogout
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return postLogout
	}
	q := u.Query()
	q.Set("client_id", p.ClientID)
	if s.Tokens.IDToken != "" {
		q.Set("id_token_hint", s.Tokens.IDToken)
	}
	q.Set("post_logout_redirect_uri", postLogout)
	u.RawQuery = q.Encode()
	return u.String()
}

// ─── Back-channel logout ────────────────────────────────────────────────────

// BackchannelHandler returns the OIDC Back-Channel Logout endpoint for one
// provider. Mount it at the backchannel_logout_uri registered with it.
func (m *Manager) BackchannelHandler(providerSlug string) http.Handler {
	m.bcOnce.Do(func() {
		m.backchannel = &BackchannelLogout{
			Sessions:  m.Sessions,
			Providers: m.Providers,
			Logf: func(format string, args ...any) {
				m.logf(context.Background(), format, args...)
			},
		}
	})
	return m.backchannel.Handler(providerSlug)
}

// ─── single-flight ──────────────────────────────────────────────────────────

type flight struct {
	done chan struct{}
	s    *Session
	err  error
}

// flightGroup collapses concurrent refreshes of one session into one call.
type flightGroup struct {
	mu sync.Mutex
	m  map[string]*flight
}

func (g *flightGroup) do(key string, fn func() (*Session, error)) (*Session, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = map[string]*flight{}
	}
	if f, ok := g.m[key]; ok {
		g.mu.Unlock()
		<-f.done
		if f.s == nil {
			return nil, f.err
		}
		cp := *f.s
		return &cp, f.err
	}
	f := &flight{done: make(chan struct{})}
	g.m[key] = f
	g.mu.Unlock()

	f.s, f.err = fn()
	close(f.done)

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	return f.s, f.err
}
