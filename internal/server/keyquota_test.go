package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/keyquota"
	"github.com/linguo2625469/workbuddy2api-panel/internal/livecfg"
)

func quotaRequest(method, path, key string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("Authorization", "Bearer "+key)
	return r
}

func TestDailyCreditLimitBlocksNextChatAndHotReloads(t *testing.T) {
	const (
		secret = "sk-quota-prod"
		limit  = 5.0
	)
	quota := keyquota.New("")
	quota.Settle(secret, time.Now(), limit)
	live := livecfg.New(livecfg.Snapshot{APIKeys: []livecfg.APIKey{{
		Name: "prod", Key: secret, Enabled: true, DailyCreditLimit: limit,
	}}})
	h := NewHandler(Config{Live: live, Quota: quota})

	nextCalls := 0
	next := func(http.ResponseWriter, *http.Request) { nextCalls++ }

	rec := httptest.NewRecorder()
	h.withAuth(next)(rec, quotaRequest(http.MethodPost, "/v1/chat/completions", secret))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit code=%d want 429, body=%s", rec.Code, rec.Body)
	}
	if nextCalls != 0 {
		t.Fatalf("over-limit request reached handler %d times", nextCalls)
	}
	if got := rec.Header().Get("X-Daily-Credit-Used"); got != "5" {
		t.Fatalf("used header=%q want 5", got)
	}
	if got := rec.Header().Get("X-Daily-Credit-Remaining"); got != "0" {
		t.Fatalf("remaining header=%q want 0", got)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 must include Retry-After")
	}
	if !strings.Contains(rec.Body.String(), `"code":"daily_credit_limit_exceeded"`) {
		t.Fatalf("body missing quota code: %s", rec.Body)
	}

	// 状态/模型类端点不消耗聊天积分，额度触顶也不能把整个密钥锁死。
	rec = httptest.NewRecorder()
	h.withAuth(next)(rec, quotaRequest(http.MethodGet, "/status", secret))
	if rec.Code != http.StatusOK || nextCalls != 1 {
		t.Fatalf("status should stay reachable: code=%d next=%d", rec.Code, nextCalls)
	}

	// 面板热改额度后，下一个请求立即按新上限判断。
	live.Store(livecfg.Snapshot{APIKeys: []livecfg.APIKey{{
		Name: "prod", Key: secret, Enabled: true, DailyCreditLimit: 6,
	}}})
	rec = httptest.NewRecorder()
	h.withAuth(next)(rec, quotaRequest(http.MethodPost, "/v1/chat/completions", secret))
	if rec.Code != http.StatusOK || nextCalls != 2 {
		t.Fatalf("raised limit should allow next chat: code=%d next=%d body=%s", rec.Code, nextCalls, rec.Body)
	}
	if got := rec.Header().Get("X-Daily-Credit-Remaining"); got != "1" {
		t.Fatalf("remaining header=%q want 1", got)
	}
}

func TestDailyCreditLimitIsPerKeyAndUnlimitedZero(t *testing.T) {
	const (
		limited   = "sk-limited"
		unlimited = "sk-unlimited"
	)
	quota := keyquota.New("")
	quota.Settle(limited, time.Now(), 10)
	live := livecfg.New(livecfg.Snapshot{APIKeys: []livecfg.APIKey{
		{Name: "limited", Key: limited, Enabled: true, DailyCreditLimit: 10},
		{Name: "unlimited", Key: unlimited, Enabled: true, DailyCreditLimit: 0},
	}})
	h := NewHandler(Config{Live: live, Quota: quota})

	for _, c := range []struct {
		key  string
		want int
	}{
		{limited, http.StatusTooManyRequests},
		{unlimited, http.StatusOK},
	} {
		rec := httptest.NewRecorder()
		h.withAuth(func(http.ResponseWriter, *http.Request) {})(rec, quotaRequest(http.MethodPost, "/v1/chat/completions", c.key))
		if rec.Code != c.want {
			t.Fatalf("key %s code=%d want %d", c.key, rec.Code, c.want)
		}
	}
}

func TestChatSettlesCreditThenBlocksNextRequest(t *testing.T) {
	const (
		secret = "sk-settle-prod"
		sse    = "data: {\"id\":\"chatcmpl-quota\",\"object\":\"chat.completion.chunk\",\"created\":1753600000,\"model\":\"glm-5.2\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"}}]}\n\n" +
			"data: {\"id\":\"chatcmpl-quota\",\"object\":\"chat.completion.chunk\",\"created\":1753600000,\"model\":\"glm-5.2\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":6,\"total_tokens\":10,\"credit\":1.25}}\n\n" +
			"data: [DONE]\n\n"
	)
	var calls atomic.Int32
	up := newFakeUpstream(t, func(string) (int, string, bool) {
		calls.Add(1)
		return http.StatusOK, sse, true
	})
	quota := keyquota.New("")
	live := livecfg.New(livecfg.Snapshot{APIKeys: []livecfg.APIKey{{
		Name: "prod", Key: secret, Enabled: true, DailyCreditLimit: 1.25,
	}}})
	h := NewHandler(Config{
		Pool:     testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999}),
		Upstream: up,
		Live:     live,
		Quota:    quota,
	})
	body := `{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}],"stream":true}`

	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+secret)
	h.ServeHTTP(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first code=%d body=%s", first.Code, first.Body)
	}
	if got := quota.Used(secret, time.Now()); got != 1.25 {
		t.Fatalf("settled credit=%v want 1.25", got)
	}

	second := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+secret)
	h.ServeHTTP(second, req)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second code=%d want 429, body=%s", second.Code, second.Body)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls=%d want 1 (blocked request must not consume an account)", got)
	}
}

func TestNonStreamCreditWithoutTotalTokensSettlesQuota(t *testing.T) {
	const (
		secret = "sk-settle-sync"
		sse    = "data: {\"id\":\"chatcmpl-quota-sync\",\"object\":\"chat.completion.chunk\",\"created\":1753600000,\"model\":\"glm-5.2\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"}}],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":6,\"credit\":1.25}}\n\n" +
			"data: [DONE]\n\n"
	)
	var calls atomic.Int32
	up := newFakeUpstream(t, func(string) (int, string, bool) {
		calls.Add(1)
		return http.StatusOK, sse, true
	})
	quota := keyquota.New("")
	live := livecfg.New(livecfg.Snapshot{APIKeys: []livecfg.APIKey{{
		Name: "prod", Key: secret, Enabled: true, DailyCreditLimit: 1.25,
	}}})
	h := NewHandler(Config{
		Pool:     testPoolWith(&auth.Auth{UID: "u1", AccessToken: "at1", ExpiresAt: 9999999999}),
		Upstream: up,
		Live:     live,
		Quota:    quota,
	})
	body := `{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}],"stream":false}`

	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+secret)
	h.ServeHTTP(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first code=%d body=%s", first.Code, first.Body)
	}
	if got := quota.Used(secret, time.Now()); got != 1.25 {
		t.Fatalf("settled credit=%v want 1.25 even without total_tokens", got)
	}

	second := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+secret)
	h.ServeHTTP(second, req)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second code=%d want 429, body=%s", second.Code, second.Body)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls=%d want 1 (blocked request must not consume an account)", got)
	}
}
