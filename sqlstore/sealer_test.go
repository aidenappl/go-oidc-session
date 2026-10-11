package sqlstore

import (
	"bytes"
	"strings"
	"testing"
)

func TestAESGCM(t *testing.T) {
	s, err := NewAESGCM(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		in   string
	}{
		{"empty stays empty", ""},
		{"token", "eyJhbGciOiJSUzI1NiJ9.payload.sig"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sealed, err := s.Seal(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if tt.in != "" && (sealed == tt.in || !strings.HasPrefix(sealed, sealPrefix)) {
				t.Fatalf("Seal(%q) = %q, want versioned ciphertext", tt.in, sealed)
			}
			got, err := s.Open(sealed)
			if err != nil || got != tt.in {
				t.Fatalf("Open(Seal(%q)) = %q, %v", tt.in, got, err)
			}
		})
	}

	t.Run("nonce is random", func(t *testing.T) {
		a, _ := s.Seal("x")
		b, _ := s.Seal("x")
		if a == b {
			t.Fatal("two seals of one value are identical")
		}
	})
	t.Run("wrong key fails", func(t *testing.T) {
		other, _ := NewAESGCM(bytes.Repeat([]byte{8}, 32))
		sealed, _ := s.Seal("secret")
		if _, err := other.Open(sealed); err == nil {
			t.Fatal("opened with the wrong key")
		}
	})
	t.Run("bad key length", func(t *testing.T) {
		if _, err := NewAESGCM([]byte("short")); err == nil {
			t.Fatal("accepted a short key")
		}
	})
}
