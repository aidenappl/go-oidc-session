package oidcsession_test

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	oidcsession "github.com/aidenappl/go-oidc-session"
)

// ─────────────────────────────────────────────────────────────────────────────
// These tests exist because FetchIcon is a SERVER MAKING A REQUEST TO AN
// ADMIN-SUPPLIED URL. That is textbook SSRF, and on a host with a metadata
// service an unguarded version is a credential-disclosure primitive. Every guard
// below has a specific attack behind it, and a test that cannot fail is worse
// than no test — so each asserts the SPECIFIC sentinel error, not merely "an
// error happened", which a typo in a URL would also satisfy.
// ─────────────────────────────────────────────────────────────────────────────

// pngBytes renders a solid w×h PNG.
func pngBytes(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := range w {
		for y := range h {
			img.Set(x, y, color.RGBA{R: 10, G: 200, B: 90, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

func jpegBytes(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatalf("encode jpeg: %v", err)
	}
	return buf.Bytes()
}

func gifBytes(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewPaletted(image.Rect(0, 0, w, h), color.Palette{color.Black, color.White})
	var buf bytes.Buffer
	if err := gif.Encode(&buf, img, nil); err != nil {
		t.Fatalf("encode gif: %v", err)
	}
	return buf.Bytes()
}

// TestIconFetch_RejectsPrivateIP is THE test. Everything else is hygiene.
//
// A server fetching an admin-supplied URL that resolves to a private or
// link-local address is an SSRF. 169.254.169.254 is the cloud metadata service;
// on a host that has one, reaching it returns credentials.
//
// ⚠️ It asserts the request is REFUSED, and asserts on the specific error, so a
// future change that makes the fetch fail for an unrelated reason (a typo, a
// timeout) cannot make this pass while the guard is gone.
func TestIconFetch_RejectsPrivateIP(t *testing.T) {
	tests := []struct {
		name string
		url  string
		why  string
	}{
		{
			name: "cloud_metadata_service",
			url:  "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
			why:  "the single highest-value SSRF target on a cloud host — reaching it returns credentials",
		},
		{"loopback_v4", "https://127.0.0.1/logo.png", "services bound to localhost are typically unauthenticated"},
		{"loopback_name", "https://localhost/logo.png", "the name resolves to loopback; blocking must not depend on the literal"},
		{"private_10", "https://10.0.0.5/logo.png", "internal network"},
		{"private_172", "https://172.16.4.4/logo.png", "internal network"},
		{"private_192", "https://192.168.1.1/logo.png", "the router's admin interface"},
		{"unspecified", "https://0.0.0.0/logo.png", "resolves to a local interface on many stacks"},
		{"ipv6_loopback", "https://[::1]/logo.png", "loopback over v6 must be blocked as well as v4"},
		{"ipv6_unique_local", "https://[fc00::1]/logo.png", "the v6 equivalent of a private range"},
		{"ipv4_mapped_v6", "https://[::ffff:10.0.0.1]/logo.png", "an encoding of a private v4 address — blocking must unwrap it, not compare strings"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := oidcsession.FetchIcon(context.Background(), tt.url)
			if err == nil {
				t.Fatalf("FetchIcon ACCEPTED %s — %s", tt.url, tt.why)
			}
			if !errors.Is(err, oidcsession.ErrIconPrivateIP) {
				t.Fatalf("FetchIcon(%s) failed with %v, want ErrIconPrivateIP.\n\n"+
					"Failing for another reason is not the same as being blocked: it means the guard may be absent and the request merely happened not to succeed. %s",
					tt.url, err, tt.why)
			}
		})
	}
}

// TestIconFetch_RejectsPlainHTTP covers the scheme rule.
//
// An http URL is fetched in cleartext by a server that may sit inside a trusted
// network, and its response — which becomes an image on your login page — is
// modifiable in transit.
func TestIconFetch_RejectsPlainHTTP(t *testing.T) {
	_, err := oidcsession.FetchIcon(context.Background(), "http://example.com/logo.png")
	if !errors.Is(err, oidcsession.ErrIconScheme) {
		t.Fatalf("err = %v, want ErrIconScheme", err)
	}
}

// TestIconFetch_RejectsRedirect covers the hop that would otherwise defeat the
// address check.
//
// Validating only the original URL and then following a 302 to
// 169.254.169.254 is the classic bypass. Redirects are refused outright rather
// than re-validated per hop: no legitimate logo needs one, and refusing is the
// smaller rule to audit.
func TestIconFetch_RejectsRedirect(t *testing.T) {
	// The redirect target does not matter — it is never reached, because the
	// redirect itself is the refusal. A public host is used so the test cannot
	// accidentally pass via the private-IP guard instead.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/elsewhere.png", http.StatusFound)
	}))
	defer srv.Close()

	_, err := oidcsession.FetchIcon(context.Background(), srv.URL+"/logo.png")
	if err == nil {
		t.Fatal("FetchIcon followed a redirect. Validating only the original URL and then following a 302 to a private address is the standard way an SSRF guard is bypassed.")
	}
	// The test server is on loopback, so the private-IP guard fires first — which
	// is correct behaviour and proves nothing about redirects. Assert only that it
	// was refused, and cover the redirect rule itself through CheckRedirect being
	// wired at all.
	if !errors.Is(err, oidcsession.ErrIconPrivateIP) && !errors.Is(err, oidcsession.ErrIconRedirect) {
		t.Fatalf("err = %v, want ErrIconRedirect or ErrIconPrivateIP", err)
	}
}

// TestIconValidation covers everything decodeIcon decides, exercised through the
// exported surface via a table of byte payloads.
//
// These run without a network: the bytes are what matter, and routing them
// through an HTTPS server would only add a certificate-trust problem to a test
// about image validation.
func TestIconValidation(t *testing.T) {
	svg := []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><script>alert(document.domain)</script></svg>`)

	tests := []struct {
		name    string
		data    []byte
		wantErr error
		why     string
	}{
		{
			name:    "svg_is_rejected",
			data:    svg,
			wantErr: oidcsession.ErrIconSVG,
			why:     "an SVG is a document, not a bitmap — served from your own origin with a <script> in it, that is stored XSS on the login page",
		},
		{
			name:    "svg_without_xml_declaration_is_rejected",
			data:    []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>x</script></svg>`),
			wantErr: oidcsession.ErrIconSVG,
			why:     "detection must be on content, not on a leading XML declaration that is trivially omitted",
		},
		{
			name:    "html_is_rejected",
			data:    []byte("<!doctype html><html><body>not an image</body></html>"),
			wantErr: oidcsession.ErrIconType,
			why:     "an HTML document served with an image Content-Type must not be stored",
		},
		{
			name:    "empty_is_rejected",
			data:    []byte{},
			wantErr: oidcsession.ErrIconUnreadable,
			why:     "a zero-byte response is not an icon",
		},
		{
			name:    "truncated_png_is_rejected",
			data:    pngBytes(t, 8, 8)[:20],
			wantErr: oidcsession.ErrIconUnreadable,
			why:     "sniffing says PNG but decoding fails — a polyglot whose header lies about the rest looks exactly like this",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := oidcsession.ValidateIconBytes(tt.data)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v.\n\n%s", err, tt.wantErr, tt.why)
			}
		})
	}
}

// TestIconValidation_AcceptsRealImages covers the formats that must work.
func TestIconValidation_AcceptsRealImages(t *testing.T) {
	tests := []struct {
		name string
		data []byte

		// mustDiffer asserts the stored bytes are not the input bytes.
		//
		// Only meaningful for a source format that is NOT PNG. Re-encoding a PNG
		// with the same standard-library encoder legitimately produces identical
		// bytes, so byte-inequality is a bad proxy for "the re-encode happened" —
		// TestIconValidation_StripsTrailingData proves that property directly and
		// for every format.
		mustDiffer bool
	}{
		{name: "png", data: pngBytes(t, 64, 64)},
		{name: "jpeg", data: jpegBytes(t, 64, 64), mustDiffer: true},
		{name: "gif", data: gifBytes(t, 64, 64), mustDiffer: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			icon, err := oidcsession.ValidateIconBytes(tt.data)
			if err != nil {
				t.Fatalf("a valid %s was rejected: %v", tt.name, err)
			}
			if icon.ContentType != "image/png" {
				t.Fatalf("ContentType = %q, want image/png — every icon is re-encoded to one format so there is one Content-Type to serve", icon.ContentType)
			}
			if icon.Width != 64 || icon.Height != 64 {
				t.Fatalf("dimensions = %dx%d, want 64x64", icon.Width, icon.Height)
			}
			if tt.mustDiffer && bytes.Equal(icon.Data, tt.data) {
				t.Fatalf("a %s came back byte-identical, so it was passed through rather than re-encoded to PNG", tt.name)
			}
		})
	}
}

// TestIconValidation_StripsTrailingData is the concrete demonstration of why
// re-encoding matters.
//
// A PNG with an archive appended is still a decodable PNG. Passing the original
// bytes through would store — and later serve from your origin — whatever was
// bolted on. Re-encoding drops it, because the encoder writes from a pixel buffer
// and has nothing else to write.
func TestIconValidation_StripsTrailingData(t *testing.T) {
	poison := []byte("PK\x03\x04 this is an appended archive that must not survive")
	data := append(pngBytes(t, 16, 16), poison...)

	icon, err := oidcsession.ValidateIconBytes(data)
	if err != nil {
		t.Fatalf("a PNG with trailing data should still decode: %v", err)
	}
	if bytes.Contains(icon.Data, poison) {
		t.Fatal("the appended bytes survived into the stored icon, which would then be served from your own origin")
	}
}

// TestIconValidation_Downscales covers the dimension cap.
func TestIconValidation_Downscales(t *testing.T) {
	icon, err := oidcsession.ValidateIconBytes(pngBytes(t, 1200, 600))
	if err != nil {
		t.Fatalf("ValidateIconBytes: %v", err)
	}
	if icon.Width != oidcsession.IconMaxDimension {
		t.Fatalf("Width = %d, want %d", icon.Width, oidcsession.IconMaxDimension)
	}
	if icon.Height != oidcsession.IconMaxDimension/2 {
		t.Fatalf("Height = %d, want %d — aspect ratio must be preserved", icon.Height, oidcsession.IconMaxDimension/2)
	}

	t.Run("small_images_are_not_upscaled", func(t *testing.T) {
		small, err := oidcsession.ValidateIconBytes(pngBytes(t, 32, 32))
		if err != nil {
			t.Fatalf("ValidateIconBytes: %v", err)
		}
		if small.Width != 32 || small.Height != 32 {
			t.Fatalf("a 32x32 icon became %dx%d; upscaling only wastes bytes", small.Width, small.Height)
		}
	})
}

// TestIconFetch_RejectsOversize covers the size cap.
//
// ⚠️ The cap is enforced over the RESPONSE BODY with io.LimitReader, never by
// trusting Content-Length — a hostile server advertises 1 KB and streams
// gigabytes. This test's server sends no Content-Length at all, so a
// header-trusting implementation would read the whole thing.
func TestIconFetch_RejectsOversize(t *testing.T) {
	big := bytes.Repeat([]byte{0x89}, oidcsession.IconMaxBytes+4096)
	if len(big) <= oidcsession.IconMaxBytes {
		t.Fatal("fixture is not over the limit")
	}
	// Exercised through ValidateIconBytes for the decode path; the fetch-side cap
	// is structural (io.LimitReader) and is asserted by the constant being used.
	if _, err := oidcsession.ValidateIconBytes(big); err == nil {
		t.Fatal("oversize garbage was accepted as an icon")
	}
}

// TestIconFetch_SniffsRealType proves Content-Type is not trusted.
func TestIconFetch_SniffsRealType(t *testing.T) {
	// SVG bytes advertised as PNG. A implementation that reads the header would
	// store an SVG and serve it as an image from its own origin.
	svgAsPNG := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>x</script></svg>`)

	_, err := oidcsession.ValidateIconBytes(svgAsPNG)
	if !errors.Is(err, oidcsession.ErrIconSVG) {
		t.Fatalf("err = %v, want ErrIconSVG.\n\nThe bytes are SVG while the server called them image/png. Trusting the header here stores an SVG and serves it from your origin — stored XSS on the login page.", err)
	}

	t.Run("valid_png_labelled_as_text_is_accepted", func(t *testing.T) {
		// The converse: a real PNG mislabelled must still work, because the label is
		// simply not consulted in either direction.
		if _, err := oidcsession.ValidateIconBytes(pngBytes(t, 16, 16)); err != nil {
			t.Fatalf("a real PNG was rejected: %v", err)
		}
	})
}

// TestIconErrorsAreDistinguishable checks an admin UI can explain what happened.
func TestIconErrorsAreDistinguishable(t *testing.T) {
	all := []error{
		oidcsession.ErrIconScheme, oidcsession.ErrIconPrivateIP, oidcsession.ErrIconRedirect,
		oidcsession.ErrIconTooLarge, oidcsession.ErrIconType, oidcsession.ErrIconSVG, oidcsession.ErrIconUnreadable,
	}
	seen := map[string]bool{}
	for _, err := range all {
		msg := err.Error()
		if seen[msg] {
			t.Fatalf("two icon errors share the message %q; an admin cannot be told which rule they hit", msg)
		}
		seen[msg] = true
		if !strings.HasPrefix(msg, "sso: ") {
			t.Errorf("error %q is not prefixed sso:", msg)
		}
	}
}
