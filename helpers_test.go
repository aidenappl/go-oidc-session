package oidcsession_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func farFuture() time.Time { return time.Now().Add(time.Hour) }
func longPast() time.Time  { return time.Now().Add(-time.Hour) }

// codeFromAuthorize drives the authorize endpoint the way a browser would and
// returns the authorization code from the redirect.
//
// It does NOT follow the final redirect to the RP callback — that host does not
// exist in a test — so the client is configured to stop at the first response and
// the Location header is parsed directly.
func codeFromAuthorize(t *testing.T, authURL string) string {
	t.Helper()

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize returned %d, want 302", resp.StatusCode)
	}

	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in the authorize redirect: %s", loc.String())
	}
	return code
}
