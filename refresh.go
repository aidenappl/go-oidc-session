package oidcsession

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/oauth2"
)

// params renders AuthOptions as authorization request parameters.
func (o AuthOptions) params() []oauth2.AuthCodeOption {
	var out []oauth2.AuthCodeOption
	if o.Prompt != "" {
		out = append(out, oauth2.SetAuthURLParam("prompt", o.Prompt))
	}
	if o.LoginHint != "" {
		out = append(out, oauth2.SetAuthURLParam("login_hint", o.LoginHint))
	}
	return out
}

// refreshWith performs one refresh_token grant (RFC 6749 §6).
//
// It goes through TokenSource rather than a hand-built request so client
// authentication, the token endpoint's auth style and response parsing match
// the code exchange exactly. The input carries no access token, so it is never
// Valid() and TokenSource always calls the endpoint. When the response omits
// refresh_token (a provider that does not rotate), x/oauth2 carries the input
// one over, so the result always holds the refresh token to use next.
func refreshWith(ctx context.Context, cfg *oauth2.Config, refreshToken string) (*oauth2.Token, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("oidcsession: refresh: %w", ErrGrantInvalid)
	}
	tok, err := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.ErrorCode == "invalid_grant" {
			return nil, fmt.Errorf("oidcsession: refresh: %w", ErrGrantInvalid)
		}
		return nil, fmt.Errorf("oidcsession: refresh: %w", err)
	}
	return tok, nil
}

// tokenSetFrom copies the fields a session keeps from an oauth2.Token.
func tokenSetFrom(t *oauth2.Token) *TokenSet {
	return &TokenSet{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		Expiry:       t.Expiry,
	}
}
