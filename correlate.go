package oidcsession

import (
	"context"
	"net/http"

	"github.com/aidenappl/go-oidc-session/correlate"
	"golang.org/x/oauth2"
)

// WithCorrelation returns ctx carrying a request id and a trace id that this
// package forwards on its calls to the identity provider — introspection, the
// OAuth2 userinfo call and the authorization-code exchange — as X-Request-ID,
// X-Trace-ID and a W3C traceparent. Ids that are not a UUID or 8-64 hex
// characters are dropped, never forwarded.
//
// Ids are only forwarded to the provider's own endpoints. FetchIcon, which
// talks to an administrator-supplied third-party host, never sends them.
//
// ⚠️ The ids travel on the context, so a caller must pass the REQUEST context
// (r.Context()) into Checkpointer.Check and Adapter.Exchange — a
// context.Background() carries nothing.
func WithCorrelation(ctx context.Context, requestID, traceID string) context.Context {
	return correlate.With(ctx, requestID, traceID)
}

// applyCorrelation stamps the ids carried by req's context onto req.
func applyCorrelation(req *http.Request) {
	rid, tid := correlate.From(req.Context())
	correlate.Apply(req, rid, tid)
}

// withCorrelatingClient returns ctx with an oauth2.HTTPClient whose transport
// stamps correlation ids, so requests x/oauth2 and go-oidc make on ctx's behalf
// (the token exchange, OIDC userinfo) carry them too.
//
// It changes nothing when ctx carries no ids, so an uncorrelated caller keeps
// exactly the client it had before. A client the caller already placed under
// oauth2.HTTPClient is preserved: its transport is wrapped, not replaced.
func withCorrelatingClient(ctx context.Context) context.Context {
	if rid, tid := correlate.From(ctx); rid == "" && tid == "" {
		return ctx
	}
	base, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if base == nil {
		// x/oauth2's own default when ctx carries no client.
		base = http.DefaultClient
	}
	if _, already := base.Transport.(*correlate.Transport); already {
		return ctx
	}
	wrapped := *base
	wrapped.Transport = &correlate.Transport{Base: base.Transport}
	return context.WithValue(ctx, oauth2.HTTPClient, &wrapped)
}
