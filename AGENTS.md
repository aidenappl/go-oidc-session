# AGENTS.md — go-oidc-session

> **⚠️ Golden rule — keep this file current:** any change to the `Manager` contract, the
> `SessionStore`/`StateStore`/`UserResolver` interfaces, the `sqlstore` schema or the session
> lifetime model MUST update this file in the same change.
>
> **⚠️ Blast radius:** every internal web app's sign-in runs through this library. Consumers pin a
> tag, so a change is opt-in, but a bad release that services upgrade to breaks sign-in everywhere.

---

## 1. What this repo is

A provider-agnostic Go library that makes a service's API the **OIDC client for its own
browser frontend** — the *Backend for Frontend* pattern of RFC 10017 §6.1. It owns:

- login (`authorization_code` + PKCE S256 + `state` + `nonce`, browser-bound by a state cookie),
  including `prompt=none` silent re-authentication;
- **server-side sessions**: the browser holds one opaque `HttpOnly` cookie; provider tokens never
  leave the server;
- **session lifetime = provider lifetime**: provider tokens are refreshed server-side when due, and
  the session ends when the provider refuses the refresh;
- RP-initiated logout and OIDC Back-Channel Logout 1.0;
- a MariaDB store (`sqlstore`) with AES-256-GCM encryption of tokens at rest.

It does **not** own users, authorization (roles/grants), API tokens or password login — those stay
in each application. It knows nothing about any particular identity provider: any OIDC issuer
(our own IdP, Google, Okta, Entra…) or plain OAuth2 provider is configuration.

## 2. Stack & dependencies

- Go 1.25 · module `github.com/aidenappl/go-oidc-session` · not a service (no `main`, no image)
- `github.com/coreos/go-oidc/v3` — discovery, JWKS, id_token and logout-token verification
- `golang.org/x/oauth2` — code flow, PKCE, refresh grant
- `sqlstore`: `github.com/Masterminds/squirrel`, `database/sql` (caller supplies the MySQL driver)
- `oidctest`: a fake provider and in-memory stores, test-only; `golang-jwt/jwt/v5` mints its tokens

## 3. Project structure

```
manager.go        Manager: LoginHandler, CallbackHandler, IssueSession, Authenticate, Logout, BackchannelHandler
refresh.go        refresh_token grant, invalid_grant → ErrGrantInvalid, AuthOptions params
seams.go          StateStore, UserResolver, SessionStore interfaces and the Session type
identity.go       Identity, TokenSet, AuthOptions, the Adapter interface
oidc.go           OIDC adapter (discovery, id_token + nonce verification, end_session_endpoint)
oauth2.go         plain-OAuth2 adapter (GitHub-style userinfo + emails fallback)
provider.go       Provider configuration and validation
state.go          login state generation / single-use consumption
backchannel.go    OIDC Back-Channel Logout 1.0 receiver
icon.go           provider icon fetching/sanitising for login buttons
correlate.go      forwards request/trace ids on outbound provider calls
correlate/        correlation-id carrier and transport
sqlstore/         MariaDB SessionStore + StateStore, Sealer (AES-256-GCM)
oidctest/         FakeIDP (rotating refresh tokens, reuse detection, prompt=none) + memory stores
```

## 4. Running, building & testing

| Command | What it does |
|---|---|
| `dev build` | `go build ./...` |
| `dev test` | unit tests with `-race` (Manager end-to-end against `oidctest.FakeIDP`) |
| `dev test-integration` | `sqlstore` against a throwaway MariaDB 11.4 in Docker (tmpfs datadir) |
| `dev vet` | `go vet` with and without the `integration` tag |
| `dev check` | fmt + vet + tests |

Integration tests are behind `//go:build integration` and need `OIDC_SESSION_TEST_DSN`
(`parseTime=True` required).

## 5. How code is written here

- No provider names in code or comments. A provider is a `Provider` value.
- Errors that a caller must branch on are sentinels: `ErrNoSession`, `ErrSessionEnded`,
  `ErrProviderUnavailable`, `ErrGrantInvalid`, `ErrNoState`. Resolver refusals use `*LoginError`.
- Telemetry goes through `Manager.OnEvent` (`Event{Name, Warn, Fields}`); fields never carry a token
  or cookie value. Diagnostic text goes through `Logf`.
- Table-driven tests with the standard `testing` package; no testify.

## 6. Domain & architecture

### Request flow

```
browser ──GET /auth/sso/login?prompt=none&return_to=…──▶ API (Manager.LoginHandler)
        ◀─302 provider /authorize (state, nonce, PKCE, prompt)
provider: live session? ──yes──▶ 302 /auth/sso/callback?code=…
                         ──no───▶ 302 /auth/sso/callback?error=login_required
API (CallbackHandler): exchange code → UserResolver → CreateSession → Set-Cookie → 302 return_to
                       login_required → 302 LoginPageURL?error=login_required&return_to=…
every API request: Manager.Authenticate → refresh provider tokens if due → session
```

### Session lifetime

| Event | Result |
|---|---|
| access token within `RefreshLeeway` (1m) of expiry | refresh on the next request (single-flight per session; reloads first so a rotated token is never presented twice) |
| refresh succeeds | tokens replaced; session continues |
| provider answers `invalid_grant` | session deleted → `ErrSessionEnded` (401) |
| provider unreachable | serve until `Tokens.Expiry + OutageGrace` (10m), then `ErrProviderUnavailable` (**503, not 401**) |
| back-channel logout (`sid`, else `sub`) | matching sessions deleted |
| `MaxLifetime` (30d) | session deleted |
| no refresh token and access token expired | session ended; frontend re-authenticates silently |

There is deliberately **no introspection checkpoint**: each refresh is a live confirmation of the
grant, and back-channel logout covers immediate revocation.

### Security properties

- cookie value is 256 random bits; the store keys sessions by its SHA-256
- fresh session id on every login; the browser's previous session is deleted (fixation)
- login bound to the browser by a `<cookie>_login` state cookie (login CSRF)
- `return_to` restricted to `DefaultReturnURL`'s origin and `AllowedReturnOrigins` (open redirect)
- id_token nonce verified; UserInfo `sub` must match; `sid` only from the signed id_token
- for `KindOIDC` every endpoint (UserInfo included) comes from discovery; `UserInfoURL` /
  `AuthorizeURL` / `TokenURL` are ignored. `FetchUserInfo` is checked against the discovered
  `userinfo_endpoint` in `newOIDCAdapter`, not in `Validate` (which runs before discovery —
  v0.1.0 checked it there and broke every OIDC provider that fetched UserInfo)
- tokens AES-256-GCM sealed at rest by `sqlstore`; it refuses to run without a `Sealer`

## 7. Ecosystem & related repos

Consumed by `lattice-api` and `openbucket-api` (full `Manager` handlers), `monitor-core` (its own
login/callback for account linking, then `Manager.IssueSession`; `Authenticate` gates its
`/auth/refresh` so its zone-verified JWTs stay bound to the provider session), and `forta-api`
(adapter + state only, for federating to Google). Replaces the `sso` package of `go-forta`.
`keyring-api` is not migrated yet — it still uses `go-forta` directly.

## 8. Operations

Not deployed. Released by git tag (`vX.Y.Z`); bump `correlate.Version` (sent as the User-Agent) in
the same commit. Consumers upgrade by `go get github.com/aidenappl/go-oidc-session@vX.Y.Z`.

Common failure modes in a consumer:
- every login ends at `state_mismatch` — the API is not on HTTPS while `Insecure` is false, or the
  callback host differs from the login host so the state cookie is not sent
- users bounced to the login page with `login_required` in a loop — the frontend auto-redirects even
  when `?error=` is present; it must not
- `session.refresh_store_failed` events — the DB write after a rotation failed; that session will end
  at its next refresh

## 9. Rules & guardrails

- Never put a token, cookie value or id_token in a log line, event or error string.
- Never answer 401 for `ErrProviderUnavailable`.
- Never call `Adapter.Refresh` outside `Manager.refresh` — the single-flight there is what stops a
  rotating refresh token being presented twice (which a provider treats as theft).
- Never weaken `SafeReturnURL`; add origins via `AllowedReturnOrigins`.
- No provider-specific code paths.

## 10. Verification

```
gofmt -l .                       # must print nothing
go vet ./... && go vet -tags integration ./...
go test -race ./...
dev test-integration             # whenever sqlstore changes
```

## 11. Keeping this file updated

Any change to the public API, the interfaces in `seams.go`, the `sqlstore` schema, the session
lifetime table above, or the security properties must update this file in the same change —
and `README.md` if usage changes.
