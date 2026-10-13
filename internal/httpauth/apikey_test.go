package httpauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newReq(authz string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	return r
}

func table() []APIKey {
	return []APIKey{
		{Name: "prod", Key: "sk-prod-secret-value", Enabled: true},
		{Name: "staging", Key: "sk-staging-secret-value", Enabled: true},
		{Name: "old", Key: "sk-retired-secret-value", Enabled: false},
	}
}

func TestVerifyAnyBearerHit(t *testing.T) {
	cases := []struct{ authz, wantName string }{
		{"Bearer sk-prod-secret-value", "prod"},
		{"Bearer sk-staging-secret-value", "staging"},
	}
	for _, c := range cases {
		got, ok := VerifyAnyBearer(newReq(c.authz), table())
		if !ok || got.Name != c.wantName {
			t.Fatalf("%s → (%q,%v) want (%q,true)", c.authz, got.Name, ok, c.wantName)
		}
	}
}

func TestVerifyAnyBearerMiss(t *testing.T) {
	for _, authz := range []string{
		"Bearer sk-wrong",
		"Bearer ",
		"Basic sk-prod-secret-value",
		"sk-prod-secret-value",
		"",
	} {
		if _, ok := VerifyAnyBearer(newReq(authz), table()); ok {
			t.Fatalf("凭据 %q 不应通过", authz)
		}
	}
}

// TestVerifyAnyBearerDisabledRejected 禁用的密钥必须被拒——否则"停用某把密钥"
// 这个运维动作在数据面毫无效果，只是面板上少了一行。
func TestVerifyAnyBearerDisabledRejected(t *testing.T) {
	if _, ok := VerifyAnyBearer(newReq("Bearer sk-retired-secret-value"), table()); ok {
		t.Fatal("已禁用的密钥不应通过鉴权")
	}
}

// TestVerifyAnyBearerNoAuthWhenNoneEnabled 全禁用或空表 = 未启用鉴权，恒放行。
// 这条语义与既有单键 VerifyBearer("") 恒 true 一致，改造不得让"不鉴权"退化。
func TestVerifyAnyBearerNoAuthWhenNoneEnabled(t *testing.T) {
	cases := [][]APIKey{
		nil,
		{},
		{{Name: "a", Key: "k", Enabled: false}},
		{{Name: "a", Key: "k", Enabled: false}, {Name: "b", Key: "k2", Enabled: false}},
	}
	for i, tbl := range cases {
		if _, ok := VerifyAnyBearer(newReq("Bearer anything"), tbl); !ok {
			t.Fatalf("case %d：无启用密钥时应放行", i)
		}
	}
}

// TestVerifyAnyBearerScansWholeTable 命中后必须扫完整张表。
//
// 这是抗计时侧信道的回归点：若实现里写了 break，命中第 1 个与命中第 5 个的
// 耗时就会差出一整个循环体的时间，攻击者能据此枚举出"哪一把密钥存在"。
//
// 断言手法：放两条**密钥值相同**但名称不同的候选，然后要求返回**最后**一条。
//   - 不 break 的实现：遍历到底，后命中者覆盖先命中者 → 返回 "last"；
//   - break 的实现：命中即返回 → 返回 "first"。
//
// 这是"扫完整表"这一行为唯一可观测的后果，因此能真正钉住它。
//
// 为什么不用"给 digest 装钩子计数"那种写法：那需要为测试在生产路径上引入
// 可变全局状态（钩子），既不美观又会与并行测试竞争；而断行为不需要改动任何
// 生产代码，变异验证（加回 break 必须 FAIL）同样有效。
//
// 注：这里重复密钥值只是为了构造可区分的两种行为。生产配置层
// （cmd/server 的 normalizeAPIKeys）会拒绝重复密钥值，所以这种表不会来自 config；
// 本测试针对的是鉴权原语自身的契约，与配置层校验是两件事。
func TestVerifyAnyBearerScansWholeTable(t *testing.T) {
	table := []APIKey{
		{Name: "first", Key: "sk-same-value", Enabled: true},
		{Name: "middle", Key: "sk-other-value", Enabled: true},
		{Name: "last", Key: "sk-same-value", Enabled: true},
	}

	got, ok := VerifyAnyBearer(newReq("Bearer sk-same-value"), table)
	if !ok {
		t.Fatal("应命中")
	}
	if got.Name != "last" {
		t.Fatalf("命中后应遍历完整表并返回最后一条匹配（last），实际返回 %q —— "+
			"若返回 first 说明实现里存在提前 break，命中位置会通过耗时泄露", got.Name)
	}
}

// TestVerifyAnyBearerSkipsDisabledDuringFullScan 全表扫描时禁用的候选必须被跳过，
// 且"最后一条匹配"只在 enabled 的候选里算。
func TestVerifyAnyBearerSkipsDisabledDuringFullScan(t *testing.T) {
	table := []APIKey{
		{Name: "enabled-first", Key: "sk-dup", Enabled: true},
		{Name: "disabled-last", Key: "sk-dup", Enabled: false},
	}

	got, ok := VerifyAnyBearer(newReq("Bearer sk-dup"), table)
	if !ok {
		t.Fatal("应命中启用的那条")
	}
	if got.Name != "enabled-first" {
		t.Fatalf("禁用的候选不参与匹配，应返回 enabled-first，实际 %q", got.Name)
	}
}

// TestVerifyAnyBearerSingleKeyMatchesLegacy 单密钥表的行为必须与老实现一致。
func TestVerifyAnyBearerSingleKeyMatchesLegacy(t *testing.T) {
	tbl := []APIKey{{Name: "only", Key: "sk-legacy-key-value", Enabled: true}}
	for _, authz := range []string{"Bearer sk-legacy-key-value", "Bearer nope", "", "x"} {
		want := VerifyBearer(newReq(authz), "sk-legacy-key-value")
		_, got := VerifyAnyBearer(newReq(authz), tbl)
		if want != got {
			t.Fatalf("authz=%q 单键表新实现=%v 与老实现=%v 不一致", authz, got, want)
		}
	}
}

func TestHasEnabled(t *testing.T) {
	cases := []struct {
		tbl  []APIKey
		want bool
	}{
		{nil, false},
		{[]APIKey{}, false},
		{[]APIKey{{Enabled: false}}, false},
		{[]APIKey{{Enabled: false}, {Enabled: true}}, true},
	}
	for i, c := range cases {
		if got := HasEnabled(c.tbl); got != c.want {
			t.Fatalf("case %d: HasEnabled=%v want %v", i, got, c.want)
		}
	}
}
