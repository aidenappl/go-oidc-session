package oidcsession_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	oidcsession "github.com/aidenappl/go-oidc-session"
	"github.com/aidenappl/go-oidc-session/oidctest"
)

func TestGenerateState_ProducesAllThreeSecrets(t *testing.T) {
	ctx := context.Background()
	store := oidctest.NewMemoryStateStore()

	state, nonce, verifier, err := oidcsession.GenerateState(ctx, store, "fake", "/dashboard")
	if err != nil {
		t.Fatalf("GenerateState: %v", err)
	}

	for _, tt := range []struct {
		name  string
		value string
		why   string
	}{
		{"state", state, "without it there is no CSRF protection on the callback"},
		{"nonce", nonce, "without it an id_token from another session is accepted"},
		{"verifier", verifier, "without it a stolen authorization code is redeemable"},
	} {
		t.Run(tt.name+"_is_generated", func(t *testing.T) {
			if tt.value == "" {
				t.Fatalf("%s is empty — %s", tt.name, tt.why)
			}
		})
	}

	t.Run("all_three_differ", func(t *testing.T) {
		// A shared value would mean one leaking discloses the others: state travels
		// through the browser in the clear, so state == nonce would put the nonce in
		// the URL bar.
		if state == nonce || state == verifier || nonce == verifier {
			t.Fatal("two of {state, nonce, verifier} are equal; state is public, so sharing it with either secret discloses that secret")
		}
	})

	t.Run("values_are_unguessable_length", func(t *testing.T) {
		// 32 bytes base64url = 43 chars. Checked as a floor rather than an exact
		// value so a future change to a longer token does not fail here.
		if len(state) < 43 || len(nonce) < 43 || len(verifier) < 43 {
			t.Fatalf("token too short: state=%d nonce=%d verifier=%d; these must resist online guessing", len(state), len(nonce), len(verifier))
		}
	})

	t.Run("record_round_trips", func(t *testing.T) {
		sd, err := oidcsession.ConsumeState(ctx, store, state)
		if err != nil {
			t.Fatalf("ConsumeState: %v", err)
		}
		if sd.Provider != "fake" {
			t.Errorf("Provider = %q, want %q", sd.Provider, "fake")
		}
		if sd.ReturnURL != "/dashboard" {
			t.Errorf("ReturnURL = %q, want %q", sd.ReturnURL, "/dashboard")
		}
		if sd.Nonce != nonce || sd.Verifier != verifier {
			t.Error("the consumed record does not carry the nonce and verifier that were generated; the callback would validate against the wrong values")
		}
	})
}

// TestConsumeState_IsSingleUse is the replay defence.
//
// A state that can be consumed twice is a state an attacker can replay: capture
// the callback URL, let the real one complete, then replay it. Single use is what
// makes the captured URL worthless.
func TestConsumeState_IsSingleUse(t *testing.T) {
	ctx := context.Background()
	store := oidctest.NewMemoryStateStore()

	state, _, _, err := oidcsession.GenerateState(ctx, store, "fake", "/")
	if err != nil {
		t.Fatalf("GenerateState: %v", err)
	}

	if _, err := oidcsession.ConsumeState(ctx, store, state); err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	if _, err := oidcsession.ConsumeState(ctx, store, state); err == nil {
		t.Fatal("the SAME state was consumed TWICE — a captured callback URL can be replayed")
	}
	if store.Count() != 0 {
		t.Fatalf("%d record(s) left in the store after consumption", store.Count())
	}
}

// TestConsumeState_ConcurrentCallersExactlyOneWins is the property that a
// SELECT-then-DELETE implementation silently fails.
//
// It is the reason StateStore.ConsumeState documents atomicity as the
// implementation's job in the strongest terms available: a single-goroutine test
// passes against a racy store, so only a concurrent test can tell the difference.
func TestConsumeState_ConcurrentCallersExactlyOneWins(t *testing.T) {
	ctx := context.Background()
	store := oidctest.NewMemoryStateStore()

	state, _, _, err := oidcsession.GenerateState(ctx, store, "fake", "/")
	if err != nil {
		t.Fatalf("GenerateState: %v", err)
	}

	const n = 16
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := oidcsession.ConsumeState(ctx, store, state); err == nil {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if winners != 1 {
		t.Fatalf("%d of %d concurrent callers consumed the same state; want exactly 1. A store whose consume is not atomic lets a replayed state authenticate alongside the real callback.", winners, n)
	}
}

func TestConsumeState_Rejections(t *testing.T) {
	ctx := context.Background()

	t.Run("empty_state", func(t *testing.T) {
		store := oidctest.NewMemoryStateStore()
		if _, err := oidcsession.ConsumeState(ctx, store, ""); !errors.Is(err, oidcsession.ErrNoState) {
			t.Fatalf("err = %v, want ErrNoState", err)
		}
	})

	t.Run("unknown_state", func(t *testing.T) {
		store := oidctest.NewMemoryStateStore()
		if _, err := oidcsession.ConsumeState(ctx, store, "never-issued"); !errors.Is(err, oidcsession.ErrNoState) {
			t.Fatalf("err = %v, want ErrNoState", err)
		}
	})

	t.Run("corrupt_record_is_treated_as_absent", func(t *testing.T) {
		store := oidctest.NewMemoryStateStore()
		// A record that is not JSON. It must not panic and must not be usable.
		if err := store.SaveState(ctx, "corrupt", []byte("{not json"), farFuture()); err != nil {
			t.Fatalf("SaveState: %v", err)
		}
		if _, err := oidcsession.ConsumeState(ctx, store, "corrupt"); !errors.Is(err, oidcsession.ErrNoState) {
			t.Fatalf("err = %v, want ErrNoState", err)
		}
	})

	t.Run("expired_record", func(t *testing.T) {
		store := oidctest.NewMemoryStateStore()
		if err := store.SaveState(ctx, "old", []byte(`{"provider":"fake"}`), longPast()); err != nil {
			t.Fatalf("SaveState: %v", err)
		}
		if _, err := oidcsession.ConsumeState(ctx, store, "old"); !errors.Is(err, oidcsession.ErrNoState) {
			t.Fatalf("err = %v, want ErrNoState", err)
		}
	})
}

func TestGenerateLinkState_RequiresAUser(t *testing.T) {
	ctx := context.Background()
	store := oidctest.NewMemoryStateStore()

	if _, _, _, err := oidcsession.GenerateLinkState(ctx, store, "fake", "/", 0); err == nil {
		t.Fatal("a link flow with user id 0 was accepted; it would silently become a LOGIN flow and resolve or provision a different user")
	}

	state, _, _, err := oidcsession.GenerateLinkState(ctx, store, "fake", "/", 42)
	if err != nil {
		t.Fatalf("GenerateLinkState: %v", err)
	}
	sd, err := oidcsession.ConsumeState(ctx, store, state)
	if err != nil {
		t.Fatalf("ConsumeState: %v", err)
	}
	if sd.LinkUserID != 42 {
		t.Fatalf("LinkUserID = %d, want 42", sd.LinkUserID)
	}
}
