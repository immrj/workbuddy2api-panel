package panelauth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func testHash(t *testing.T, password string) string {
	t.Helper()
	h, err := HashPasswordWithParams(password, HashParams{
		Memory: 8 * 1024, Time: 1, Threads: 1, SaltLength: 16, KeyLength: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHashPasswordRoundTrip(t *testing.T) {
	h := testHash(t, "s3cret-pass")
	if !strings.HasPrefix(h, "argon2id$") {
		t.Fatalf("hash prefix=%q", h)
	}
	if !verifyPassword("s3cret-pass", h) {
		t.Fatal("correct password rejected")
	}
	if verifyPassword("wrong", h) {
		t.Fatal("wrong password accepted")
	}
	if err := ValidateHash(h); err != nil {
		t.Fatalf("ValidateHash: %v", err)
	}
	if err := ValidateHash("bcrypt$whatever"); err == nil {
		t.Fatal("invalid hash accepted")
	}
}

func TestLoginSessionAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, err := New(Config{
		Enabled:      true,
		Username:     "admin",
		PasswordHash: testHash(t, "password-123"),
		SessionTTL:   time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now }

	if _, _, err := s.Login("admin", "wrong", "127.0.0.1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password err=%v", err)
	}
	token, sess, err := s.Login("admin", "password-123", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || sess.CSRFToken == "" {
		t.Fatal("empty token/csrf")
	}
	if got, ok := s.Authenticate(token); !ok || got.Username != "admin" {
		t.Fatalf("session=%+v ok=%v", got, ok)
	}
	if s.VerifyCSRF(sess, "bad") {
		t.Fatal("invalid csrf accepted")
	}
	if !s.VerifyCSRF(sess, sess.CSRFToken) {
		t.Fatal("valid csrf rejected")
	}
	now = now.Add(2 * time.Hour)
	if _, ok := s.Authenticate(token); ok {
		t.Fatal("expired session accepted")
	}
}

func TestLoginRateLimit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, err := New(Config{
		Enabled:      true,
		Username:     "admin",
		PasswordHash: testHash(t, "password-123"),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now }
	for i := 0; i < maxLoginFailures; i++ {
		if _, _, err := s.Login("admin", "wrong", "1.2.3.4"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d err=%v", i+1, err)
		}
	}
	_, _, err = s.Login("admin", "password-123", "1.2.3.4")
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.RetryAfter <= 0 {
		t.Fatalf("want rate-limit error, got %v", err)
	}
	// 另一个客户端不受影响；时间窗口过后恢复。
	if _, _, err := s.Login("admin", "password-123", "5.6.7.8"); err != nil {
		t.Fatalf("other client blocked: %v", err)
	}
	now = now.Add(loginBlockTime + time.Second)
	if _, _, err := s.Login("admin", "password-123", "1.2.3.4"); err != nil {
		t.Fatalf("after block: %v", err)
	}
}

func TestUpdateInvalidatesSessionsOnPasswordChange(t *testing.T) {
	s, err := New(Config{
		Enabled:      true,
		Username:     "admin",
		PasswordHash: testHash(t, "old-password"),
	})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := s.Login("admin", "old-password", "ip")
	if err != nil {
		t.Fatal(err)
	}
	changed, err := s.Update(Config{
		Enabled:      true,
		Username:     "admin",
		PasswordHash: testHash(t, "new-password"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("password change did not invalidate sessions")
	}
	if _, ok := s.Authenticate(token); ok {
		t.Fatal("old session survived password change")
	}
}
