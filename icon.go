package oidcsession

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/image/draw"
)

// ─────────────────────────────────────────────────────────────────────────────
// THIRD-PARTY PROVIDER ICONS: FETCH ONCE, VALIDATE HARD, SERVE FROM YOUR ORIGIN
//
// An administrator supplies a URL for a provider's logo. This package fetches it
// ONCE, at save time, validates it, and returns bytes the application stores. The
// login page then serves those bytes from its own origin.
//
// ⚠️ THE LOGIN PAGE MUST NEVER HOT-LINK THE ADMIN'S URL. That would:
//
//   - leak every unauthenticated visitor's IP, User-Agent and Referer to a third
//     party, on the one page you can be certain every user loads;
//   - make your login page's availability depend on someone else's uptime and TLS
//     certificate;
//   - let whoever controls that URL swap the image later, after review.
//
// ⚠️ AND THE FETCH ITSELF IS A SERVER-SIDE REQUEST TO AN ATTACKER-INFLUENCED URL.
// That is textbook SSRF. On a host with a cloud metadata service, an unguarded
// version of this function is a credential-disclosure primitive — which is why
// FetchIcon refuses private, loopback, link-local and metadata addresses, refuses
// redirects outright, and re-checks the resolved address at connect time to close
// the DNS-rebinding window.
// ─────────────────────────────────────────────────────────────────────────────

// IconMaxBytes caps a fetched icon.
//
// Enforced with io.LimitReader over the RESPONSE BODY, never by trusting
// Content-Length — a hostile server can advertise 1 KB and stream gigabytes.
const IconMaxBytes = 256 * 1024

// IconMaxDimension caps width and height. Anything larger is scaled down.
const IconMaxDimension = 512

// iconFetchTimeout bounds the whole fetch. An admin pressing Save must not wait
// on a slow third party, and a hung request must not hold a handler open.
const iconFetchTimeout = 5 * time.Second

// Icon is a validated, re-encoded provider icon ready to store.
type Icon struct {
	// Data is the re-encoded image. It is NOT the bytes that came off the wire —
	// see FetchIcon for why re-encoding rather than passing through is the point.
	Data []byte

	// ContentType is the sniffed type of Data, for the Content-Type header when
	// serving it back. Always one of the allowed types below.
	ContentType string

	Width  int
	Height int
}

// Errors from FetchIcon. Each is distinguishable so an admin UI can explain what
// went wrong rather than saying "failed".
var (
	ErrIconScheme     = errors.New("sso: icon URL must be https")
	ErrIconPrivateIP  = errors.New("sso: icon URL resolves to a private, loopback or link-local address")
	ErrIconRedirect   = errors.New("sso: icon URL redirected, which is not followed")
	ErrIconTooLarge   = errors.New("sso: icon exceeds the size limit")
	ErrIconType       = errors.New("sso: icon is not an allowed image type")
	ErrIconSVG        = errors.New("sso: SVG icons are not accepted")
	ErrIconUnreadable = errors.New("sso: icon could not be decoded as an image")
)

// FetchIcon retrieves, validates and re-encodes an administrator-supplied icon.
//
// It is deliberately strict. Every check below has a specific attack behind it,
// and none is optional:
//
//	https only          — an http URL is fetched in cleartext from a server that
//	                      may sit inside a trusted network
//	no redirects        — a 302 to 169.254.169.254 defeats an address check
//	                      performed only on the original URL
//	address re-check    — performed at CONNECT time on the address actually
//	                      dialled, which is what closes DNS rebinding
//	sniff the bytes     — Content-Type is attacker-controlled and means nothing
//	reject SVG          — see below; this one is not negotiable
//	size cap on the body— Content-Length is also attacker-controlled
//	decode + re-encode  — strips EXIF, ICC profiles, trailing data and anything
//	                      polyglot; what you store is what your decoder produced,
//	                      not what they sent
//
// ⚠️ SVG IS REJECTED OUTRIGHT AND THIS IS NOT AN OVERSIGHT. An SVG is a document,
// not a bitmap: it can carry <script>, event handlers and external references.
// Served from your own origin it is stored XSS on the login page — the highest
// value page you have — and there are live advisories in exactly this "admin
// uploads a logo" shape. Supporting SVG safely needs a real sanitiser AND a
// separate cookie-less serving origin, which is its own piece of work, not a
// content-type addition.
func FetchIcon(ctx context.Context, rawURL string) (*Icon, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("sso: icon URL is not parseable: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, ErrIconScheme
	}
	if u.Host == "" {
		return nil, fmt.Errorf("sso: icon URL has no host")
	}

	ctx, cancel := context.WithTimeout(ctx, iconFetchTimeout)
	defer cancel()

	client := &http.Client{
		Timeout: iconFetchTimeout,
		// ⚠️ REDIRECTS ARE REFUSED, NOT RE-VALIDATED. Re-validating each hop is
		// possible but strictly more code on a path where being wrong is an SSRF,
		// and no legitimate logo URL needs a redirect. Refusing is the smaller,
		// more auditable rule.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrIconRedirect
		},
		Transport: &http.Transport{
			// ⚠️ THE ADDRESS CHECK LIVES HERE, AT DIAL TIME, ON PURPOSE.
			//
			// Resolving the hostname up front and then handing the URL to a normal
			// client leaves a window: a hostile DNS server can answer the validation
			// lookup with a public address and the connection lookup with
			// 169.254.169.254. Checking the address actually being dialled removes
			// the window, because there is only one lookup that matters.
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, err
				}
				for _, ip := range ips {
					if isBlockedIP(ip.IP) {
						return nil, ErrIconPrivateIP
					}
				}
				// Dial the address we just vetted, by IP, so the connection cannot
				// resolve to something else.
				d := &net.Dialer{Timeout: iconFetchTimeout}
				return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
			},
			TLSHandshakeTimeout:   iconFetchTimeout,
			ResponseHeaderTimeout: iconFetchTimeout,
			DisableKeepAlives:     true,
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("sso: icon request: %w", err)
	}
	req.Header.Set("Accept", "image/png,image/jpeg,image/webp,image/gif")

	resp, err := client.Do(req)
	if err != nil {
		// Unwrap the sentinel errors the client surfaces through url.Error, so a
		// caller can errors.Is them.
		if errors.Is(err, ErrIconRedirect) {
			return nil, ErrIconRedirect
		}
		if errors.Is(err, ErrIconPrivateIP) {
			return nil, ErrIconPrivateIP
		}
		return nil, fmt.Errorf("sso: icon fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sso: icon fetch returned status %d", resp.StatusCode)
	}

	// Read one byte past the cap so an exactly-at-limit image is accepted and an
	// over-limit one is detectable without reading it all.
	data, err := io.ReadAll(io.LimitReader(resp.Body, IconMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("sso: icon read: %w", err)
	}
	if len(data) > IconMaxBytes {
		return nil, ErrIconTooLarge
	}
	if len(data) == 0 {
		return nil, ErrIconUnreadable
	}

	return ValidateIconBytes(data)
}

// ValidateIconBytes sniffs, validates and re-encodes image bytes.
//
// Exported because the validation must be identical whether the bytes arrived
// from a URL (FetchIcon) or from a future upload form — a second, subtly
// different copy for uploads is exactly how an SVG eventually gets stored. It is
// also what the icon tests exercise directly: the bytes are the whole subject, and
// routing them through an HTTPS server would add a certificate-trust problem to a
// test about image validation.
//
// ⚠️ Callers that accept bytes from a user MUST enforce a size cap BEFORE calling
// this — it validates content, not transfer. FetchIcon does so with
// io.LimitReader over the response body.
func ValidateIconBytes(data []byte) (*Icon, error) {
	// Checked here rather than only in FetchIcon: this function is exported, so it
	// cannot assume a caller has already looked. Empty bytes sniff as text/plain
	// and would otherwise be reported as "not an allowed type", which sends an
	// administrator hunting for a format problem that does not exist.
	if len(data) == 0 {
		return nil, ErrIconUnreadable
	}

	// ⚠️ SNIFF THE BYTES. http.DetectContentType reads magic numbers; the server's
	// Content-Type header is attacker-controlled and is never consulted.
	sniffed := http.DetectContentType(data)

	// SVG is checked explicitly and first, so the error says SVG rather than the
	// generic "not an allowed type". DetectContentType reports SVG as XML or plain
	// text, so the sniffed type alone would not make the reason obvious.
	if isSVG(data, sniffed) {
		return nil, ErrIconSVG
	}

	var (
		img image.Image
		err error
	)
	switch {
	case strings.HasPrefix(sniffed, "image/png"):
		img, err = png.Decode(bytes.NewReader(data))
	case strings.HasPrefix(sniffed, "image/jpeg"):
		img, err = jpeg.Decode(bytes.NewReader(data))
	case strings.HasPrefix(sniffed, "image/gif"):
		img, err = gif.Decode(bytes.NewReader(data))
	default:
		// image/webp is advertised in Accept because many providers serve it, but
		// the standard library cannot decode it and this package will not add a
		// decoder dependency for a logo. A webp is refused clearly rather than
		// stored undecoded — storing bytes we could not decode would defeat the
		// re-encode step that strips everything hostile.
		return nil, fmt.Errorf("%w (sniffed %q)", ErrIconType, sniffed)
	}
	if err != nil {
		// Sniffed as an image but would not decode: truncated, corrupt, or a
		// polyglot whose header lies about the rest.
		return nil, fmt.Errorf("%w: %v", ErrIconUnreadable, err)
	}

	img = downscale(img)

	// ⚠️ ALWAYS RE-ENCODE, AND ALWAYS TO PNG. The stored bytes are produced by our
	// encoder from a decoded pixel buffer, so EXIF, ICC profiles, appended
	// archives and anything else riding along in the original are gone by
	// construction rather than by a filter someone has to keep current. One output
	// format also means one Content-Type to serve and no format-specific
	// surprises later.
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		return nil, fmt.Errorf("sso: icon re-encode: %w", err)
	}

	b := img.Bounds()
	return &Icon{
		Data:        out.Bytes(),
		ContentType: "image/png",
		Width:       b.Dx(),
		Height:      b.Dy(),
	}, nil
}

// isSVG reports whether the bytes look like SVG.
//
// Checked on content rather than on the URL's extension or the server's
// Content-Type, both of which the supplier controls. The leading bytes are
// searched for an <svg root within a short prefix, which covers a plain document
// and one preceded by an XML declaration, a DOCTYPE or a comment.
func isSVG(data []byte, sniffed string) bool {
	if strings.Contains(sniffed, "image/svg") {
		return true
	}
	prefix := data
	if len(prefix) > 1024 {
		prefix = prefix[:1024]
	}
	lower := bytes.ToLower(prefix)
	return bytes.Contains(lower, []byte("<svg"))
}

// downscale shrinks an image that exceeds IconMaxDimension, preserving aspect
// ratio. A smaller image is returned untouched — upscaling a small logo would
// only waste bytes.
func downscale(img image.Image) image.Image {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= IconMaxDimension && h <= IconMaxDimension {
		return img
	}

	var nw, nh int
	if w >= h {
		nw = IconMaxDimension
		nh = h * IconMaxDimension / w
	} else {
		nh = IconMaxDimension
		nw = w * IconMaxDimension / h
	}
	if nw < 1 {
		nw = 1
	}
	if nh < 1 {
		nh = 1
	}

	dst := image.NewRGBA(image.Rect(0, 0, nw, nh))
	draw.CatmullRom.Scale(dst, dst.Bounds(), img, b, draw.Over, nil)
	return dst
}

// isBlockedIP reports whether an address must not be fetched from.
//
// ⚠️ THIS IS THE SSRF BOUNDARY. It is an ALLOW-NOTHING-PRIVATE rule rather than a
// deny-list of known-bad addresses, because the interesting targets differ per
// host and a deny-list is only ever as current as the last time someone updated
// it. 169.254.169.254 — the cloud metadata service — is covered by the
// link-local rule rather than being named, which is the point.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	// IPv4-mapped IPv6 (::ffff:10.0.0.1) — unwrap so the v4 rules above apply
	// rather than being bypassed by the encoding.
	if v4 := ip.To4(); v4 != nil && !ip.Equal(v4) {
		return isBlockedIP(v4)
	}
	// Unique-local IPv6 (fc00::/7). net.IP.IsPrivate covers it, but it is asserted
	// explicitly so a future change to that helper cannot silently widen this.
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return true
	}
	return false
}
