package sqlstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Sealer encrypts token material at rest. Seal("") must return "" and
// Open("") must return "", so an absent token stays absent.
type Sealer interface {
	Seal(plaintext string) (string, error)
	Open(sealed string) (string, error)
}

// sealPrefix versions the ciphertext format so the algorithm can change
// without guessing at what a stored value is.
const sealPrefix = "v1:"

// AESGCM is a Sealer using AES-256-GCM with a random 96-bit nonce per value.
type AESGCM struct {
	aead cipher.AEAD
}

// NewAESGCM returns a Sealer for a 32-byte key.
func NewAESGCM(key []byte) (*AESGCM, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("sqlstore: AES-256-GCM key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AESGCM{aead: aead}, nil
}

// NewAESGCMFromBase64 decodes a base64 (std or URL, padded or not) 32-byte key.
func NewAESGCMFromBase64(encoded string) (*AESGCM, error) {
	encoded = strings.TrimSpace(encoded)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err := enc.DecodeString(encoded); err == nil {
			return NewAESGCM(key)
		}
	}
	return nil, errors.New("sqlstore: session key is not valid base64")
}

func (s *AESGCM) Seal(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("sqlstore: nonce: %w", err)
	}
	out := s.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return sealPrefix + base64.RawStdEncoding.EncodeToString(out), nil
}

func (s *AESGCM) Open(sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	if !strings.HasPrefix(sealed, sealPrefix) {
		return "", errors.New("sqlstore: unrecognised ciphertext format")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(sealed, sealPrefix))
	if err != nil {
		return "", fmt.Errorf("sqlstore: ciphertext: %w", err)
	}
	n := s.aead.NonceSize()
	if len(raw) < n {
		return "", errors.New("sqlstore: ciphertext too short")
	}
	pt, err := s.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return "", fmt.Errorf("sqlstore: decrypt: %w", err)
	}
	return string(pt), nil
}
