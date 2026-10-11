package correlate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

const (
	uuidTrace  = "4BF92F35-77B3-4DA6-A3CE-929D0E0E4736"
	hex32Trace = "4bf92f3577b34da6a3ce929d0e0e4736"
	hex16      = "0af7651916cd43dd"
)

var traceparentRe = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-01$`)

func TestValid(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{"", false},
		{hex16, true},
		{"deadbeef", true},
		{"deadbee", false},                // 7 hex: too short
		{string(make([]byte, 65)), false}, // too long / not hex
		{uuidTrace, true},                 // uppercase UUID
		{"4bf92f35-77b3-4da6-a3ce-929d0e0e473", false}, // malformed UUID
		{"req-123", false},
		{"abc\r\nX-Evil: 1", false},
		{"g0000000", false},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			if got := Valid(tc.id); got != tc.want {
				t.Fatalf("Valid(%q) = %v, want %v", tc.id, got, tc.want)
			}
		})
	}
}

func TestWithFrom(t *testing.T) {
	ctx := With(context.Background(), hex16, uuidTrace)
	rid, tid := From(ctx)
	if rid != hex16 || tid != uuidTrace {
		t.Fatalf("From = %q, %q", rid, tid)
	}

	// Invalid values never land, and never clobber a valid one already held.
	ctx2 := With(ctx, "not valid", "")
	if rid, tid := From(ctx2); rid != hex16 || tid != uuidTrace {
		t.Fatalf("invalid With clobbered ids: %q, %q", rid, tid)
	}
	if rid, tid := From(With(context.Background(), "nope", "also nope")); rid != "" || tid != "" {
		t.Fatalf("invalid ids stored: %q, %q", rid, tid)
	}
	if rid, tid := From(context.Background()); rid != "" || tid != "" {
		t.Fatalf("empty ctx returned ids")
	}
}

func TestApply(t *testing.T) {
	cases := []struct {
		name            string
		requestID       string
		traceID         string
		preset          map[string]string
		wantRequestID   string
		wantTraceID     string
		wantTraceparent string // "" = absent, "gen:<traceid>" = generated for that trace id, else exact
		wantUA          string
	}{
		{
			name:   "no ids",
			wantUA: UserAgent,
		},
		{
			name:            "valid request id and UUID trace",
			requestID:       hex16,
			traceID:         uuidTrace,
			wantRequestID:   hex16,
			wantTraceID:     uuidTrace,
			wantTraceparent: "gen:" + hex32Trace,
			wantUA:          UserAgent,
		},
		{
			name:            "32-hex trace id",
			traceID:         hex32Trace,
			wantTraceID:     hex32Trace,
			wantTraceparent: "gen:" + hex32Trace,
			wantUA:          UserAgent,
		},
		{
			name:        "16-hex trace id gets X-Trace-ID but no traceparent",
			traceID:     hex16,
			wantTraceID: hex16,
			wantUA:      UserAgent,
		},
		{
			name:      "invalid ids are never forwarded",
			requestID: "abc\r\nX-Evil: 1",
			traceID:   "trace-please",
			wantUA:    UserAgent,
		},
		{
			name:      "caller-set headers are not overwritten",
			requestID: hex16,
			traceID:   uuidTrace,
			preset: map[string]string{
				HeaderRequestID:   "cafebabecafebabe",
				HeaderTraceID:     "feedfacefeedface",
				HeaderTraceparent: "00-" + hex32Trace + "-" + hex16 + "-00",
				HeaderUserAgent:   "my-service/2",
			},
			wantRequestID:   "cafebabecafebabe",
			wantTraceID:     "feedfacefeedface",
			wantTraceparent: "00-" + hex32Trace + "-" + hex16 + "-00",
			wantUA:          "my-service/2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://idp.test/userinfo", nil)
			req.Header.Del(HeaderUserAgent)
			for k, v := range tc.preset {
				req.Header.Set(k, v)
			}
			Apply(req, tc.requestID, tc.traceID)

			if got := req.Header.Get(HeaderRequestID); got != tc.wantRequestID {
				t.Errorf("X-Request-ID = %q, want %q", got, tc.wantRequestID)
			}
			if got := req.Header.Get(HeaderTraceID); got != tc.wantTraceID {
				t.Errorf("X-Trace-ID = %q, want %q", got, tc.wantTraceID)
			}
			if got := req.Header.Get(HeaderUserAgent); got != tc.wantUA {
				t.Errorf("User-Agent = %q, want %q", got, tc.wantUA)
			}
			tp := req.Header.Get(HeaderTraceparent)
			switch {
			case tc.wantTraceparent == "":
				if tp != "" {
					t.Errorf("traceparent = %q, want absent", tp)
				}
			case len(tc.wantTraceparent) > 4 && tc.wantTraceparent[:4] == "gen:":
				m := traceparentRe.FindStringSubmatch(tp)
				if m == nil {
					t.Fatalf("traceparent = %q, not W3C shaped", tp)
				}
				if m[1] != tc.wantTraceparent[4:] {
					t.Errorf("traceparent trace id = %q, want %q", m[1], tc.wantTraceparent[4:])
				}
				if m[2] == "0000000000000000" {
					t.Errorf("parent id is all zeros")
				}
			default:
				if tp != tc.wantTraceparent {
					t.Errorf("traceparent = %q, want %q", tp, tc.wantTraceparent)
				}
			}
		})
	}
}

func TestTraceparent_AllZeroRejected(t *testing.T) {
	if tp := Traceparent("00000000000000000000000000000000"); tp != "" {
		t.Fatalf("all-zero trace id produced %q", tp)
	}
}

func TestTraceIDFromTraceparent(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"00-" + hex32Trace + "-" + hex16 + "-01", hex32Trace},
		{"00-4BF92F3577B34DA6A3CE929D0E0E4736-" + hex16 + "-01", hex32Trace},
		{"00-00000000000000000000000000000000-" + hex16 + "-01", ""},
		{"ff-" + hex32Trace + "-" + hex16 + "-01", ""},
		{"00-" + hex32Trace + "-01", ""},
		{"garbage", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := TraceIDFromTraceparent(tc.in); got != tc.want {
			t.Errorf("TraceIDFromTraceparent(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFromInbound(t *testing.T) {
	cases := []struct {
		name    string
		ctx     context.Context
		resp    http.Header
		reqHdr  map[string]string
		wantRID string
		wantTID string
	}{
		{
			name:    "response header wins over request header",
			resp:    http.Header{"X-Request-Id": {"aaaaaaaaaaaaaaaa"}, "X-Trace-Id": {uuidTrace}},
			reqHdr:  map[string]string{HeaderRequestID: "bbbbbbbbbbbbbbbb", HeaderTraceID: "cccccccccccccccc"},
			wantRID: "aaaaaaaaaaaaaaaa",
			wantTID: uuidTrace,
		},
		{
			name:    "request headers, traceparent before X-Trace-ID",
			reqHdr:  map[string]string{HeaderRequestID: "bbbbbbbbbbbbbbbb", HeaderTraceparent: "00-" + hex32Trace + "-" + hex16 + "-01", HeaderTraceID: "cccccccccccccccc"},
			wantRID: "bbbbbbbbbbbbbbbb",
			wantTID: hex32Trace,
		},
		{
			name:    "ctx ids are kept",
			ctx:     With(context.Background(), "dddddddddddddddd", "eeeeeeeeeeeeeeee"),
			reqHdr:  map[string]string{HeaderRequestID: "bbbbbbbbbbbbbbbb", HeaderTraceID: "cccccccccccccccc"},
			wantRID: "dddddddddddddddd",
			wantTID: "eeeeeeeeeeeeeeee",
		},
		{
			name:   "invalid inbound ids are ignored",
			reqHdr: map[string]string{HeaderRequestID: "<script>", HeaderTraceID: "x"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := tc.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tc.reqHdr {
				r.Header.Set(k, v)
			}
			rid, tid := From(FromInbound(ctx, tc.resp, r))
			if rid != tc.wantRID || tid != tc.wantTID {
				t.Fatalf("got %q, %q; want %q, %q", rid, tid, tc.wantRID, tc.wantTID)
			}
		})
	}
}

func TestTransport(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	defer srv.Close()
	client := &http.Client{Transport: &Transport{}}

	// No ids: request passes through untouched.
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got.Get(HeaderRequestID) != "" || got.Get(HeaderUserAgent) == UserAgent {
		t.Fatalf("headers applied without ids: %v", got)
	}

	// Ids in ctx: stamped, and the caller's request is not mutated.
	req, _ = http.NewRequestWithContext(With(context.Background(), hex16, uuidTrace), http.MethodGet, srv.URL, nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got.Get(HeaderRequestID) != hex16 || got.Get(HeaderTraceID) != uuidTrace || got.Get(HeaderTraceparent) == "" {
		t.Fatalf("ids not stamped: %v", got)
	}
	if req.Header.Get(HeaderRequestID) != "" {
		t.Fatalf("Transport mutated the caller's request")
	}
}
