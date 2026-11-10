package pool

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

func TestFallbackProbeThrottlesConcurrentAndRecovers(t *testing.T) {
	p := New("")
	p.Add(&auth.Auth{UID: "probe"})
	p.Cooldown("probe", CoolSoft, time.Minute, "test")
	var selected atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if p.PickExcludingForModel(nil, "m") != nil {
				selected.Add(1)
			}
		}()
	}
	wg.Wait()
	if selected.Load() != 1 {
		t.Fatalf("selected %d probes, want 1", selected.Load())
	}
	// 不同模型独立限频；正在途时则禁止同账号的任何提前探测。
	if !p.Acquire("probe") {
		t.Fatal("acquire")
	}
	if p.PickExcludingForModel(nil, "other") != nil {
		t.Fatal("probe while account in flight")
	}
	p.Release("probe")
	if p.PickExcludingForModel(nil, "other") == nil {
		t.Fatal("other model should be independent")
	}
	p.mu.Lock()
	p.fallbackProbe["probe\x00m"] = time.Now().Add(-31 * time.Second)
	p.mu.Unlock()
	if p.PickExcludingForModel(nil, "m") == nil {
		t.Fatal("probe interval elapsed")
	}
	// 正常恢复不受探测窗口约束。
	p.Revive("probe")
	if p.PickExcludingForModel(nil, "m") == nil {
		t.Fatal("healthy account should be available")
	}
}
