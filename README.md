# go-oidc-session

Provider-agnostic OIDC sign-in and server-side sessions for Go APIs that back a browser frontend.

> **appleby.cloud platform** · Go library · `github.com/aidenappl/go-oidc-session`

---

## Overview

Your API becomes the OIDC client (the *Backend for Frontend* pattern, RFC 10017). The browser gets
one opaque `HttpOnly` cookie; provider tokens stay on the server and are refreshed there, so a
session lasts exactly as long as the user's session with the identity provider. When it ends, the
frontend re-authenticates with `prompt=none` — a user still signed in at the provider never sees a
login page.

## Role in the ecosystem

Shared by every internal app's API (lattice, monitor, openbucket, keyring) for single sign-on, and
by the identity provider itself for federating to upstream providers such as Google.

## Tech stack

Go 1.25 · `coreos/go-oidc/v3` · `golang.org/x/oauth2` · MariaDB via `sqlstore` (squirrel)

## Getting started

### Prerequisites

- Go 1.25+
- A MariaDB database (DSN with `parseTime=True`) for `sqlstore`
- A 32-byte session encryption key (base64)
- An OIDC client registered with your provider: redirect URI `https://<api>/auth/sso/callback`,
  back-channel logout URI `https://<api>/auth/sso/backchannel-logout`

### Setup

```go
sealer, _ := sqlstore.NewAESGCMFromBase64(env.SessionKey)
store := sqlstore.New(db.DB, sealer)
_ = store.Migrate(ctx)

sessions := &oidcsession.Manager{
    Providers:        loadProvider, // func(ctx, slug) (*oidcsession.Provider, error)
    DefaultProvider:  "sso",
    States:           store,
    Sessions:         store,
    Users:            userResolver, // your oidcsession.UserResolver
    CookieName:       "myapp_session",
    DefaultReturnURL: "https://myapp.example.com/",
    LoginPageURL:     "https://myapp.example.com/login",
}

r.HandleFunc("/auth/sso/login", sessions.LoginHandler).Methods(http.MethodGet)
r.HandleFunc("/auth/sso/callback", sessions.CallbackHandler).Methods(http.MethodGet)
r.Handle("/auth/sso/backchannel-logout", sessions.BackchannelHandler("sso")).Methods(http.MethodPost)

// in your auth middleware
s, err := sessions.Authenticate(w, r)
switch {
case errors.Is(err, oidcsession.ErrProviderUnavailable): // 503
case err != nil:                                         // 401
}
```

Frontend: on a 401, navigate to `https://<api>/auth/sso/login?prompt=none&return_to=<current url>`.
Show your login page's button only when it was reached with `?error=…`.

## Development

| Command | What it does |
|---|---|
| `dev build` | Build all packages |
| `dev test` | Unit tests with the race detector |
| `dev test-integration` | `sqlstore` tests against MariaDB in Docker |
| `dev vet` | `go vet`, including integration-tagged files |
| `dev check` | fmt + vet + tests |
| `dev tidy` | `go mod tidy` |

## Project structure

```
manager.go   sign-in handlers, Authenticate, refresh, logout (local unless EndProviderSession)
seams.go     StateStore / UserResolver / SessionStore interfaces
oidc.go      OIDC adapter        oauth2.go  plain OAuth2 adapter
sqlstore/    MariaDB store + AES-GCM sealer
oidctest/    fake identity provider + in-memory stores for tests
```

## Deployment

Not deployed — released by git tag and consumed through the Go module proxy.

## Contributing & further reading

- [AGENTS.md](AGENTS.md) — architecture, session lifetime model, guardrails
- RFC 10017 (OAuth 2.0 for Browser-Based Applications), RFC 9700 (OAuth 2.0 Security BCP),
  OIDC Back-Channel Logout 1.0, OIDC RP-Initiated Logout 1.0
- Consumers: `lattice-api`, `monitor-core`, `openbucket-api`, `keyring-api`, `forta-api`
