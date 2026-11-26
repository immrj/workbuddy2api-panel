package keyquota

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedTime(t *testing.T, hour int) time.Time {
	t.Helper()
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	return time.Date(2026, 11, 26, hour, 30, 0, 0, loc)
}

func TestLedgerSeparatesKeysAndResetsNextDay(t *testing.T) {
	l := New("")
	now := fixedTime(t, 10)
	l.Settle("sk-a", now, 2.5)
	l.Settle("sk-a", now, 0.5)
	l.Settle("sk-b", now, 7)

	if got := l.Used("sk-a", now); got != 3 {
		t.Fatalf("sk-a used=%v want 3", got)
	}
	if got := l.Used("sk-b", now); got != 7 {
		t.Fatalf("sk-b used=%v want 7", got)
	}
	if got := l.Used("sk-a", now.Add(24*time.Hour)); got != 0 {
		t.Fatalf("next day should reset, got %v", got)
	}
}

func TestLedgerPersistsAndDoesNotStorePlaintextSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key-quota.json")
	now := fixedTime(t, 12)
	l := New(path)
	l.Settle("sk-secret-value", now, 4.25)
	l.Save()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "sk-secret-value") {
		t.Fatal("额度账本不应保存密钥明文")
	}

	again := New(path)
	if got := again.Used("sk-secret-value", now); got != 4.25 {
		t.Fatalf("restored used=%v want 4.25", got)
	}
}

func TestNextResetUsesLocalMidnight(t *testing.T) {
	now := fixedTime(t, 23)
	got := NextReset(now)
	want := time.Date(2026, 11, 27, 0, 0, 0, 0, now.Location())
	if !got.Equal(want) {
		t.Fatalf("NextReset=%v want %v", got, want)
	}
}
