package livecfg

import "testing"

// TestLoadCopiesSlice Load 必须返回独立切片。
//
// 回归点：Snapshot 一直是值拷贝（*s），换成 []APIKey 后值拷贝只复制切片头，
// 底层数组仍与 Holder 共享。面板渲染密钥列表若对 Load() 的返回值做 sort.Slice
// 或就地改元素，就会在每个并发请求读快照时与之数据竞争——这类竞争通常不立刻
// 崩，只会让密钥偶尔"变成别人的"，极难排查。
func TestLoadCopiesSlice(t *testing.T) {
	h := New(Snapshot{APIKeys: []APIKey{{Name: "prod", Key: "k1", Enabled: true}}})

	got := h.Load()
	if len(got.APIKeys) != 1 || got.APIKeys[0].Name != "prod" {
		t.Fatalf("Load 应返回原值，实际 %+v", got.APIKeys)
	}

	got.APIKeys[0].Name = "tampered"

	again := h.Load()
	if again.APIKeys[0].Name != "prod" {
		t.Fatalf("读者侧改动泄漏到了 Holder：%q", again.APIKeys[0].Name)
	}
}

// TestLoadNilHolder nil 接收者必须返回零值快照（既有契约，不能回归）。
func TestLoadNilHolder(t *testing.T) {
	var h *Holder
	s := h.Load()
	if s.APIKeys != nil || s.RecordClientInfo {
		t.Fatalf("nil Holder 应返回零值快照，实际 %+v", s)
	}
}

// TestStoreReplacesWholesale 整体替换语义。
func TestStoreReplacesWholesale(t *testing.T) {
	h := New(Snapshot{APIKeys: []APIKey{{Name: "a", Enabled: true}}})
	h.Store(Snapshot{APIKeys: []APIKey{{Name: "b"}, {Name: "c"}}})
	got := h.Load()
	if len(got.APIKeys) != 2 || got.APIKeys[0].Name != "b" || got.APIKeys[1].Name != "c" {
		t.Fatalf("Store 后应为 b,c，实际 %+v", got.APIKeys)
	}
}
