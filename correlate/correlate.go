// Package correlate carries request/trace correlation ids through a context and
// stamps them onto outbound requests to identity providers.
//
// It exists so every service in the ecosystem can follow one user-visible
// failure from its own logs into the identity provider's, without this module importing
// go-monitor or any other dependency: the ids travel as plain strings.
//
// Only ids that monitor-core itself would accept are ever forwarded. An inbound
// X-Request-ID is caller-supplied, so anything outside that shape is dropped
// rather than relayed to another service's logs.
package correlate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
)

// Version is the go-oidc-session release this code belongs to. It is sent in the
// User-Agent of every outbound request ("go-oidc-session/<Version>") so the provider can
// tell which SDK version a consumer runs. Bump it in the same commit as the
// release notes for a new tag.
const Version = "0.1.0"

// UserAgent is the User-Agent set on outbound requests that do not already
// carry one.
const UserAgent = "go-oidc-session/" + Version

// Header names. X-Request-ID is canonicalised by net/http as "X-Request-Id";
// Get/Set are case-insensitive, so either spelling reads the same value.
const (
	HeaderRequestID   = "X-Request-ID"
	HeaderTraceID     = "X-Trace-ID"
	HeaderTraceparent = "traceparent"
	HeaderUserAgent   = "User-Agent"
)

// correlationIDPattern is go-monitor's correlationIDPattern (ids.go), which is
// itself monitor-core's structs.correlationIDRegex, verbatim: a hyphenated UUID
// or 8-64 hex characters.
const correlationIDPattern = `^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{8,64})$`

var correlationIDRegex = regexp.MustCompile(correlationIDPattern)

// Valid reports whether id is a non-empty correlation id monitor-core accepts.
// Unlike go-monitor's ValidCorrelationID, the empty string is NOT valid here:
// this answers "may this be forwarded", and an empty id never is.
func Valid(id string) bool {
	return id != "" && correlationIDRegex.MatchString(id)
}

type ctxKey struct{}

type ids struct {
	requestID string
	traceID   string
}

// With returns ctx carrying requestID and traceID. Invalid ids are dropped
// here rather than at send time, so From never returns anything Apply would
// refuse. An id that is empty or invalid keeps whatever ctx already held for
// that field.
func With(ctx context.Context, requestID, traceID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	cur, _ := ctx.Value(ctxKey{}).(ids)
	next := cur
	if Valid(requestID) {
		next.requestID = requestID
	}
	if Valid(traceID) {
		next.traceID = traceID
	}
	if next == cur {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, next)
}

// From returns the ids carried by ctx, or empty strings.
func From(ctx context.Context) (requestID, traceID string) {
	if ctx == nil {
		return "", ""
	}
	v, _ := ctx.Value(ctxKey{}).(ids)
	return v.requestID, v.traceID
}

// Apply stamps correlation headers onto an outbound request:
//
//   - X-Request-ID, when requestID is valid;
//   - X-Trace-ID, when traceID is valid;
//   - traceparent (W3C Trace Context), when traceID normalises to 32 hex
//     characters — a hyphenated UUID or a bare 32-hex id — with a fresh random
//     parent id and the sampled flag;
//   - User-Agent "go-oidc-session/<Version>".
//
// A header the caller already set is never overwritten, and an invalid id is
// never forwarded.
func Apply(req *http.Request, requestID, traceID string) {
	if req == nil {
		return
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	setIfAbsent(req.Header, HeaderUserAgent, UserAgent)
	if Valid(requestID) {
		setIfAbsent(req.Header, HeaderRequestID, requestID)
	}
	if Valid(traceID) {
		setIfAbsent(req.Header, HeaderTraceID, traceID)
		if tp := Traceparent(traceID); tp != "" {
			setIfAbsent(req.Header, HeaderTraceparent, tp)
		}
	}
}

func setIfAbsent(h http.Header, key, value string) {
	if h.Get(key) == "" {
		h.Set(key, value)
	}
}

// Traceparent builds a W3C traceparent header value for traceID, or returns ""
// when traceID cannot be expressed as a 32-hex W3C trace id (or is all zeros,
// which the specification forbids).
func Traceparent(traceID string) string {
	if !Valid(traceID) {
		return ""
	}
	t := strings.ToLower(strings.ReplaceAll(traceID, "-", ""))
	if len(t) != 32 || strings.Trim(t, "0") == "" {
		return ""
	}
	parent := make([]byte, 8)
	for {
		if _, err := rand.Read(parent); err != nil {
			return ""
		}
		if !allZero(parent) {
			break
		}
	}
	return "00-" + t + "-" + hex.EncodeToString(parent) + "-01"
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// TraceIDFromTraceparent extracts the trace id from a W3C traceparent header
// ("00-<32 hex>-<16 hex>-<2 hex>"). It returns "" for anything malformed.
func TraceIDFromTraceparent(v string) string {
	parts := strings.Split(strings.TrimSpace(v), "-")
	if len(parts) < 4 || len(parts[0]) != 2 || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return ""
	}
	if parts[0] == "ff" {
		return ""
	}
	t := strings.ToLower(parts[1])
	if !Valid(t) || strings.Trim(t, "0") == "" {
		return ""
	}
	return t
}

// FromInbound fills whichever of ctx's ids are missing from an inbound request.
//
// respHeader is the response header map of the handler being served, and is
// consulted first: a host's RequestIDMiddleware sets X-Request-ID (and often
// X-Trace-ID) on the response before calling next, so that is the id the host
// itself logs. The inbound request headers are the fallback: X-Request-ID,
// then traceparent, then X-Trace-ID. respHeader may be nil.
func FromInbound(ctx context.Context, respHeader http.Header, r *http.Request) context.Context {
	rid, tid := From(ctx)
	if rid != "" && tid != "" {
		return ctx
	}
	if rid == "" {
		rid = firstValid(headerGet(respHeader, HeaderRequestID), requestHeader(r, HeaderRequestID))
	}
	if tid == "" {
		tid = firstValid(
			headerGet(respHeader, HeaderTraceID),
			TraceIDFromTraceparent(requestHeader(r, HeaderTraceparent)),
			requestHeader(r, HeaderTraceID),
		)
	}
	return With(ctx, rid, tid)
}

func headerGet(h http.Header, key string) string {
	if h == nil {
		return ""
	}
	return h.Get(key)
}

func requestHeader(r *http.Request, key string) string {
	if r == nil {
		return ""
	}
	return r.Header.Get(key)
}

func firstValid(candidates ...string) string {
	for _, c := range candidates {
		if Valid(c) {
			return c
		}
	}
	return ""
}

// Transport is an http.RoundTripper that stamps the ids carried by each
// request's context (see With) onto the request before sending it. It clones
// the request first, as the RoundTripper contract requires.
//
// Ids are read per request, never captured, so a Transport shared by a cached
// client (OIDC discovery, a remote key set) never replays one caller's ids on
// another caller's request.
type Transport struct {
	// Base is the underlying transport; nil means http.DefaultTransport.
	Base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	rid, tid := From(req.Context())
	if rid == "" && tid == "" {
		return base.RoundTrip(req)
	}
	clone := req.Clone(req.Context())
	Apply(clone, rid, tid)
	return base.RoundTrip(clone)
}
