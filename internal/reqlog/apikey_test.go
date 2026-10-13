package reqlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newArchive 建一个只写归档的 Recorder，返回它与归档目录。
func newArchive(t *testing.T) (*Recorder, string) {
	t.Helper()
	dir := t.TempDir()
	return New(Config{Enabled: true, Dir: dir, MaxBytes: 1 << 20, RetentionDays: 7}), dir
}

// rawArchive 读出归档目录里全部 JSONL 的原始文本。
func rawArchive(t *testing.T, dir string) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "requests-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sb.Write(b)
	}
	return sb.String()
}

// TestArchivePersistsMaskedKeyAndName 密钥维度的落盘契约。
//
//	AC-2 的核心安全承诺是"归档里不出现完整密钥明文"，而这条承诺完全依赖
//	调用方（server 侧）传入的是掩码值。本测试钉住：reqlog **原样存取**给它什么，
//	并断言落盘内容里不含完整明文——一旦有人把明文塞进 Event.APIKey，这里会红。
//
// 身份（名称）与展示（掩码值）是两个独立字段，都必须往返。
func TestArchivePersistsMaskedKeyAndName(t *testing.T) {
	r, dir := newArchive(t)
	defer r.Close()

	const fullKey = "sk-prod-abcdef123456"
	masked := "sk-************456" // 与 logfmt.MaskKey 同形

	r.Record(Event{
		Time: time.Now(), RequestID: "a", Model: "glm-5.3",
		Status: 200, OK: true, Outcome: OutcomeSuccess,
		APIKey: masked, APIKeyName: "prod",
	})
	r.Close()

	got, err := r.ReadArchive(10, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("应有 1 条，实际 %d", len(got))
	}
	if got[0].APIKey != masked {
		t.Fatalf("api_key 应原样往返 %q，实际 %q", masked, got[0].APIKey)
	}
	if got[0].APIKeyName != "prod" {
		t.Fatalf("api_key_name 应往返为 prod，实际 %q", got[0].APIKeyName)
	}

	// 归档是会被备份/传阅/贴工单的产物：完整明文绝不能落在里面。
	if raw := rawArchive(t, dir); strings.Contains(raw, fullKey) {
		t.Fatalf("归档中出现了完整密钥明文：\n%s", raw)
	}
}

// TestArchiveFilterByAPIKeyAndName 两个筛选分支的语义差异。
//
//	掩码值走"包含"匹配（方便按前缀捞同一把密钥）；
//	名称走**精确**匹配——若也做成包含，"prod" 会命中 "prod-eu"，误筛比漏筛更难查。
func TestArchiveFilterByAPIKeyAndName(t *testing.T) {
	r, _ := newArchive(t)
	base := time.Now().Add(-time.Minute)
	rows := []Event{
		{RequestID: "a", Model: "glm-5.3", Status: 200, OK: true, Outcome: OutcomeSuccess,
			APIKey: "sk-aaa****aaa", APIKeyName: "prod"},
		{RequestID: "b", Model: "glm-5.3", Status: 200, OK: true, Outcome: OutcomeSuccess,
			APIKey: "sk-bbb****bbb", APIKeyName: "staging"},
		{RequestID: "c", Model: "glm-5.3", Status: 200, OK: true, Outcome: OutcomeSuccess,
			APIKey: "sk-ccc****ccc", APIKeyName: "prod-eu"},
		{RequestID: "d", Model: "glm-5.3", Status: 200, OK: true, Outcome: OutcomeSuccess},
	}
	for i, e := range rows {
		e.Time = base.Add(time.Duration(i) * time.Second)
		r.Record(e)
	}
	r.Close()

	// 名称：精确匹配，只命中 prod，不得命中 prod-eu
	got, err := r.ReadArchive(10, Filter{APIKeyName: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].RequestID != "a" {
		t.Fatalf("名称精确匹配应只命中 a，实际 %+v", ids(got))
	}

	// 名称精确：prod 不得命中 prod-eu（前缀子串）
	got, _ = r.ReadArchive(10, Filter{APIKeyName: "prod-eu"})
	if len(got) != 1 || got[0].RequestID != "c" {
		t.Fatalf("名称精确匹配应命中 c，实际 %+v", ids(got))
	}

	// 掩码值：包含匹配，一段片段应捞到对应那把
	got, _ = r.ReadArchive(10, Filter{APIKey: "bbb"})
	if len(got) != 1 || got[0].RequestID != "b" {
		t.Fatalf("掩码包含匹配应命中 b，实际 %+v", ids(got))
	}

	// 星号片段：三把都有，应全部命中
	got, _ = r.ReadArchive(10, Filter{APIKey: "****"})
	if len(got) != 3 {
		t.Fatalf("星号片段应命中 3 条，实际 %+v", ids(got))
	}

	// 来源为空的旧事件不得被非空密钥条件误命中
	got, _ = r.ReadArchive(10, Filter{APIKeyName: "nope"})
	if len(got) != 0 {
		t.Fatalf("不存在名称为 nope 的密钥，应 0 条，实际 %+v", ids(got))
	}
}

func ids(es []Event) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.RequestID)
	}
	return out
}

// TestArchiveOmitsAbsentAPIKey 无凭据（鉴权关闭）时两个字段都不该出现在归档里。
//
//	omitempty 在这里不是省字节：一个空字符串的 "api_key":"" 会让面板显示一列
//	空值，读者无法区分"没有密钥维度"与"这条请求没带密钥"。
func TestArchiveOmitsAbsentAPIKey(t *testing.T) {
	r, dir := newArchive(t)
	defer r.Close()

	r.Record(Event{
		Time: time.Now(), RequestID: "a", Model: "glm-5.3",
		Status: 200, OK: true, Outcome: OutcomeSuccess,
	})
	r.Close()

	raw := rawArchive(t, dir)
	if strings.Contains(raw, "api_key") {
		t.Fatalf("未设置密钥时不应落 api_key/api_key_name 字段：\n%s", raw)
	}
}
