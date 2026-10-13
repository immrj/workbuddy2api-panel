package usage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBucketKeyRoundTripPreservesKey 是加密钥维度后**最关键**的一条回归：
// 落盘再重建（等价于进程重启）不得让同形状不同密钥的桶互相挤掉。
//
// 背景：桶在内存里是 map[string]*bucket，键是拼接字符串。加密钥维度时若只改了
// Add 却漏改 load 重建键的表达式，重启后同一 (scope,realm,uid,model,rate) 的多个
// 密钥会落到同一个 map 槽——静默丢数据，不报错、不崩溃。
func TestBucketKeyRoundTripPreservesKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.json")

	now := time.Now()
	r := New(path)
	r.AddWithKey(now, "cn", "u1", "glm", "prod", Delta{TotalTokens: 100, HasTotal: true}, true)
	r.AddWithKey(now, "cn", "u1", "glm", "staging", Delta{TotalTokens: 300, HasTotal: true}, true)
	r.Save() // 同步落盘，不依赖 Start 的后台 goroutine（Stop 会等 r.done）

	// 重新打开 = 走 load() 重建路径
	r2 := New(path)
	snap := r2.Snapshot(0, nil)

	if got := len(snap.ByAPIKey); got != 2 {
		t.Fatalf("重启后密钥维度应为 2 行，实际 %d 行：%+v", got, snap.ByAPIKey)
	}
	if snap.Totals.TotalTokens != 400 {
		t.Fatalf("重启后总 token 应为 400，实际 %d（桶被覆盖会少掉一部分）", snap.Totals.TotalTokens)
	}
}

// TestRollupPreservesKey 覆盖小时桶→日桶折叠：两个密钥不得被折进同一个日桶。
//
// 背景：折叠发生在 90 天后（hourlyKeep）。若折叠目标键漏了密钥维度，历史上
// 不同密钥的用量会在那天静默合并成一行，且**不可逆**（源桶已 delete）。
func TestRollupPreservesKey(t *testing.T) {
	r := New("") // 纯内存，不落盘

	// 构造一个超过 hourlyKeep 的小时桶，让 fold 能选中它
	old := time.Now().Add(-hourlyKeep - 48*time.Hour).Truncate(time.Hour)
	r.AddWithKey(old, "cn", "u1", "glm", "prod", Delta{TotalTokens: 100, HasTotal: true}, true)
	r.AddWithKey(old, "cn", "u1", "glm", "staging", Delta{TotalTokens: 300, HasTotal: true}, true)

	r.Rollup(time.Now())
	after := r.Snapshot(0, nil)
	if len(after.ByAPIKey) != 2 {
		t.Fatalf("折叠后仍应是 2 个密钥，实际 %d", len(after.ByAPIKey))
	}
}

// TestLoadMigratesEmptyKey 存量 usage.json（无 k 字段）不得丢数据，统一归入默认密钥。
func TestLoadMigratesEmptyKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.json")

	// 手写一份"加密钥维度之前"的 usage.json：桶里完全没有 k 字段
	legacy := `{"version":4,"saved":"2026-01-01T00:00:00+08:00","buckets":[
	  {"s":"h:2026-01-01T10","r":"cn","u":"u1","m":"glm","q":2,"p":10,"c":20,"t":30},
	  {"s":"h:2026-01-01T10","r":"cn","u":"u2","m":"glm","q":1,"p":5,"c":5,"t":10}
	]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	r := New(path)
	snap := r.Snapshot(0, nil)

	if snap.Totals.TotalTokens != 40 {
		t.Fatalf("迁移后总 token 应为 40，实际 %d（存量数据丢了）", snap.Totals.TotalTokens)
	}
	if len(snap.ByAPIKey) != 1 {
		t.Fatalf("存量桶应全部归入 1 个默认密钥，实际 %d 行", len(snap.ByAPIKey))
	}
	if snap.ByAPIKey[0].Key != defaultKeyName {
		t.Fatalf("存量桶归属应为 %q，实际 %q", defaultKeyName, snap.ByAPIKey[0].Key)
	}
}

// TestAddWithKeyEmptyNameNormalizes 空密钥名必须归一到默认值，
// 否则同一批请求会因调用方传了 "" 或没传而分成两个维度。
func TestAddWithKeyEmptyNameNormalizes(t *testing.T) {
	r := New("")
	now := time.Now()
	r.Add(now, "cn", "u1", "glm", Delta{TotalTokens: 10, HasTotal: true}, true)
	r.AddWithKey(now, "cn", "u2", "glm", "", Delta{TotalTokens: 20, HasTotal: true}, true)

	snap := r.Snapshot(0, nil)
	if len(snap.ByAPIKey) != 1 || snap.ByAPIKey[0].Key != defaultKeyName {
		t.Fatalf("空名应归一到默认密钥，实际 %+v", snap.ByAPIKey)
	}
	if snap.ByAPIKey[0].TotalTokens != 30 {
		t.Fatalf("默认密钥下 token 应为 30，实际 %d", snap.ByAPIKey[0].TotalTokens)
	}
}

// TestFileVersionBumped 新格式标记升到 5（仅为记录，迁移不依赖它）。
func TestFileVersionBumped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.json")
	r := New(path)
	r.AddWithKey(time.Now(), "cn", "u1", "glm", "prod", Delta{TotalTokens: 1, HasTotal: true}, true)
	r.Save() // 同步落盘，不依赖 Start 的后台 goroutine（Stop 会等 r.done）

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 5 {
		t.Fatalf("fileVersion 应为 5，实际 %d", f.Version)
	}
}

// TestCreditByAPIKey 积分扣除历史按密钥维度（AC-5）。
func TestCreditByAPIKey(t *testing.T) {
	r := New("")
	now := time.Now()
	r.AddWithKey(now, "cn", "u1", "glm", "prod", Delta{TotalTokens: 1_000_000, HasTotal: true, Credit: 10, HasCredit: true}, true)
	r.AddWithKey(now, "cn", "u2", "glm", "staging", Delta{TotalTokens: 2_000_000, HasTotal: true, Credit: 40, HasCredit: true}, true)

	snap := r.Snapshot(0, nil)
	if len(snap.CreditByAPIKey) != 2 {
		t.Fatalf("积分维度应为 2 行，实际 %d：%+v", len(snap.CreditByAPIKey), snap.CreditByAPIKey)
	}
	byKey := map[string]float64{}
	for _, c := range snap.CreditByAPIKey {
		byKey[c.Key] = c.Credits
	}
	if byKey["prod"] != 10 || byKey["staging"] != 40 {
		t.Fatalf("各密钥积分应独立，prod=%v staging=%v", byKey["prod"], byKey["staging"])
	}
}

// TestBucketKeyDelimiterCannotCollide 复合桶键的分隔符不允许被字段内容"撞"出来。
//
// 构造一对桶，它们在 "|" 作分隔符时会拼出**完全相同**的键：
//
//	(rate="x",   key="y|z")  →  ...|x|y|z
//	(rate="x|y", key="z")    →  ...|x|y|z
//
// 用可打印分隔符时两者落进同一个 map 槽：第二个请求直接累加到第一个的桶上，
// 两个不同来源的用量被静默合并，且事后无法区分。NUL 分隔符下它们必须独立。
func TestBucketKeyDelimiterCannotCollide(t *testing.T) {
	r := New("")
	now := time.Now()
	r.AddWithKey(now, "cn", "u1", "glm", "y|z", Delta{ModelRate: "x", TotalTokens: 10, HasTotal: true}, true)
	r.AddWithKey(now, "cn", "u1", "glm", "z", Delta{ModelRate: "x|y", TotalTokens: 20, HasTotal: true}, true)

	snap := r.Snapshot(0, nil)
	if len(snap.ByAPIKey) != 2 {
		t.Fatalf("两个来源应保持独立（2 行），实际 %d 行：%+v —— 分隔符被字段内容撞出，桶被合并了",
			len(snap.ByAPIKey), snap.ByAPIKey)
	}
	got := map[string]int64{}
	for _, k := range snap.ByAPIKey {
		got[k.Key] = k.TotalTokens
	}
	if got["y|z"] != 10 || got["z"] != 20 {
		t.Fatalf("各来源用量应独立，实际 %+v", got)
	}
}

// TestSnapshotWindowKeyFilter 总览的密钥筛选（下拉框）。
//
// 三件事必须同时对：
//  1. totals / 各维度 / 时序 都被收窄到所选密钥——筛选在服务端做，整页同口径；
//  2. Window.Key 为空 = 全部（下拉框"全部密钥"这一档）；
//  3. **KeyOptions 不受筛选影响**：它是下拉框的选项来源，若跟着被收窄，选中一把
//     之后选项就只剩它自己，用户再也切不回别的密钥。这是最容易写错的一条。
func TestSnapshotWindowKeyFilter(t *testing.T) {
	r := New("")
	now := time.Now()
	r.AddWithKey(now, "cn", "u1", "glm", "prod", Delta{TotalTokens: 100, HasTotal: true, Credit: 1, HasCredit: true}, true)
	r.AddWithKey(now, "cn", "u2", "glm", "qa", Delta{TotalTokens: 300, HasTotal: true, Credit: 3, HasCredit: true}, true)

	// 1) 全部
	all := r.SnapshotWindow(Window{}, nil, nil)
	if all.Totals.TotalTokens != 400 {
		t.Fatalf("不筛选时总量应为 400，实际 %d", all.Totals.TotalTokens)
	}
	if len(all.KeyOptions) != 2 {
		t.Fatalf("不筛选时选项应为 2 个，实际 %+v", all.KeyOptions)
	}
	if len(all.ByAPIKey) != 2 {
		t.Fatalf("不筛选时按密钥应有 2 行，实际 %d", len(all.ByAPIKey))
	}

	// 2) 只选 prod
	only := r.SnapshotWindow(Window{Key: "prod"}, nil, nil)
	if only.Totals.TotalTokens != 100 {
		t.Fatalf("筛选 prod 后总量应为 100，实际 %d", only.Totals.TotalTokens)
	}
	if only.Totals.Requests != 1 {
		t.Fatalf("筛选 prod 后请求数应为 1，实际 %d", only.Totals.Requests)
	}
	if len(only.ByAPIKey) != 1 || only.ByAPIKey[0].Key != "prod" {
		t.Fatalf("筛选后按密钥维度应只剩 prod，实际 %+v", only.ByAPIKey)
	}
	if len(only.ByAccount) != 1 || only.ByAccount[0].Key != "u1" {
		t.Fatalf("筛选后按账号应只剩 u1，实际 %+v", only.ByAccount)
	}
	if len(only.ByModel) != 1 {
		t.Fatalf("筛选后按模型应收窄，实际 %d 行", len(only.ByModel))
	}
	if len(only.Series) != 1 {
		t.Fatalf("筛选后时序应收窄到 1 个时间片，实际 %d", len(only.Series))
	}
	if only.Totals.Credits != 1 {
		t.Fatalf("筛选后积分应为 1，实际 %v", only.Totals.Credits)
	}
	if len(only.CreditByAPIKey) != 1 || only.CreditByAPIKey[0].Key != "prod" {
		t.Fatalf("筛选后积分按密钥应只剩 prod，实际 %+v", only.CreditByAPIKey)
	}

	// 3) 选项不受筛选影响 —— 下拉框必须永远列全集
	if len(only.KeyOptions) != 2 {
		t.Fatalf("KeyOptions 不应被筛选收窄（否则下拉框只剩选中项、切不回去），实际 %+v", only.KeyOptions)
	}
	if only.KeyOptions[0] != "prod" || only.KeyOptions[1] != "qa" {
		t.Fatalf("KeyOptions 应排序后为 [prod qa]，实际 %+v", only.KeyOptions)
	}
}

// TestSnapshotWindowKeyFilterUnknownKey 选一个窗口内没有流量的密钥：数字归零，
// 但选项仍然是全集（用户能切回去），且不该报错或返回 nil 切片。
func TestSnapshotWindowKeyFilterUnknownKey(t *testing.T) {
	r := New("")
	now := time.Now()
	r.AddWithKey(now, "cn", "u1", "glm", "prod", Delta{TotalTokens: 100, HasTotal: true}, true)

	got := r.SnapshotWindow(Window{Key: "no-such-key"}, nil, nil)
	if got.Totals.TotalTokens != 0 || got.Totals.Requests != 0 {
		t.Fatalf("不存在的密钥应全为 0，实际 tokens=%d reqs=%d", got.Totals.TotalTokens, got.Totals.Requests)
	}
	if len(got.KeyOptions) != 1 || got.KeyOptions[0] != "prod" {
		t.Fatalf("选项应仍是计划内全集，实际 %+v", got.KeyOptions)
	}
	if got.ByAPIKey == nil || len(got.ByAPIKey) != 0 {
		t.Fatalf("按密钥应为空切片（非 nil，面板直接 .length），实际 %+v", got.ByAPIKey)
	}
}
