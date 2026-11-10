package server

import (
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/reqlog"
)

func TestRoutingRecordCapturesRateLimitAndSuccessfulRetry(t *testing.T) {
	var calls atomic.Int32
	up := newFakeUpstream(t, func(string) (int, string, bool) {
		if calls.Add(1) == 1 {
			return 429, "rate limit", false
		}
		return 200, sseOK, true
	})
	log := reqlog.New(reqlog.Config{})
	h := NewHandler(Config{Pool: testPoolWith(
		&auth.Auth{UID: "account-111111111", AccessToken: "secret-a", ExpiresAt: 9999999999},
		&auth.Auth{UID: "account-222222222", AccessToken: "secret-b", ExpiresAt: 9999999999},
	), Upstream: up, RequestLog: log})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"glm-5.2","stream":true,"messages":[]}`)))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	e := log.Snapshot().Recent[0]
	if e.Attempts != 2 || len(e.Routing) != 1 || e.Routing[0].Reason != "rate_limit" {
		t.Fatalf("unexpected routing: attempts=%d routing=%+v", e.Attempts, e.Routing)
	}
	if strings.Contains(e.Routing[0].Account, "111111111") || strings.Contains(e.Routing[0].Account, "secret") {
		t.Fatal("routing contains full UID or credential")
	}
}
