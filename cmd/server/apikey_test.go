package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustParse(t *testing.T, raw string) *Config {
	t.Helper()
	c, err := ParseConfig([]byte(raw))
	if err != nil {
		t.Fatalf("ParseConfig(%s): %v", raw, err)
	}
	return c
}

func keyNames(c *Config) []string {
	var out []string
	for _, k := range c.EffectiveAPIKeys() {
		out = append(out, k.Name)
	}
	return out
}

// TestEffectiveAPIKeysLegacy 老配置只有一个 api_key：必须仍能鉴权（向后兼容）。
func TestEffectiveAPIKeysLegacy(t *testing.T) {
	c := mustParse(t, `{"api_key":"sk-legacy-value"}`)
	ks := c.EffectiveAPIKeys()
	if len(ks) != 1 || ks[0].Key != "sk-legacy-value" || !ks[0].Enabled {
		t.Fatalf("老配置应得到一条启用的密钥，实际 %+v", ks)
	}
	if ks[0].Name != DefaultKeyName {
		t.Fatalf("老密钥名应为 %q，实际 %q", DefaultKeyName, ks[0].Name)
	}
}

// TestEffectiveAPIKeysNoAuth 两处都空 = 空表 = 不鉴权（既有语义不得回归）。
func TestEffectiveAPIKeysNoAuth(t *testing.T) {
	c := mustParse(t, `{"listen":":7863"}`)
	if got := c.EffectiveAPIKeys(); len(got) != 0 {
		t.Fatalf("未配置密钥时应为空表，实际 %+v", got)
	}
}

// TestEffectiveAPIKeysTable 表非空时以表为准，但老字段若没被搬进来要自动追加。
func TestEffectiveAPIKeysTable(t *testing.T) {
	c := mustParse(t, `{"api_key":"sk-legacy","api_keys":[
	  {"name":"prod","key":"sk-prod"},
	  {"name":"staging","key":"sk-staging"}
	]}`)
	ks := c.EffectiveAPIKeys()
	if len(ks) != 3 {
		t.Fatalf("应为 3 条（表 2 条 + 老字段补 1），实际 %d：%+v", len(ks), ks)
	}
	if got := keyNames(c); strings.Join(got, ",") != "prod,staging,默认" {
		t.Fatalf("名称顺序 %v", got)
	}
}

// TestEffectiveAPIKeysNoDuplicate 老字段已在表里时不得重复追加。
func TestEffectiveAPIKeysNoDuplicate(t *testing.T) {
	c := mustParse(t, `{"api_key":"sk-same","api_keys":[{"name":"prod","key":"sk-same"}]}`)
	ks := c.EffectiveAPIKeys()
	if len(ks) != 1 {
		t.Fatalf("同一个密钥不该登记两次，实际 %+v", ks)
	}
}

// TestEffectiveAPIKeysEnabledDefault 缺省 enabled 视为启用；显式 false 为禁用。
func TestEffectiveAPIKeysEnabledDefault(t *testing.T) {
	c := mustParse(t, `{"api_keys":[
	  {"name":"a","key":"k1"},
	  {"name":"b","key":"k2","enabled":false}
	]}`)
	ks := c.EffectiveAPIKeys()
	if !ks[0].Enabled {
		t.Fatal("缺省 enabled 应视为启用")
	}
	if ks[1].Enabled {
		t.Fatal("显式 enabled:false 应为禁用")
	}
}

// TestEffectiveAPIKeysIsPureProjection 投影不得回写字段，
// 否则 WriteDefault 生成的配置里同一个机密会出现两次（api_key 与 api_keys[0].key）。
func TestEffectiveAPIKeysIsPureProjection(t *testing.T) {
	c := mustParse(t, `{"api_key":"sk-legacy"}`)
	before := len(c.APIKeys)
	_ = c.EffectiveAPIKeys()
	if len(c.APIKeys) != before {
		t.Fatalf("EffectiveAPIKeys 回写了 c.APIKeys：before=%d after=%d", before, len(c.APIKeys))
	}
}

// TestWriteDefaultNoDuplicateSecret 首启自动生成的配置不得在两处写同一个密钥。
func TestWriteDefaultNoDuplicateSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	key, err := WriteDefault(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(raw), key); n != 1 {
		t.Fatalf("生成的密钥明文出现 %d 次，期望恰好 1 次：\n%s", n, raw)
	}
	// 回读确认它确实能鉴权
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ks := c.EffectiveAPIKeys()
	if len(ks) != 1 || ks[0].Key != key || !ks[0].Enabled {
		t.Fatalf("自动生成的配置应产生一条可用密钥，实际 %+v", ks)
	}
}

// TestNormalizeRejectsDuplicateName 名称重复必须报错——它是日志/用量的归属标识。
func TestNormalizeRejectsDuplicateName(t *testing.T) {
	_, err := ParseConfig([]byte(`{"api_keys":[{"name":"prod","key":"k1"},{"name":"prod","key":"k2"}]}`))
	if err == nil {
		t.Fatal("重复 name 应报错")
	}
	if !strings.Contains(err.Error(), "重复") {
		t.Fatalf("错误信息应点明重复，实际 %v", err)
	}
}

// TestNormalizeRejectsEmptyKey 表内空 key 是配置错误（要关鉴权应删掉整项）。
func TestNormalizeRejectsEmptyKey(t *testing.T) {
	_, err := ParseConfig([]byte(`{"api_keys":[{"name":"a","key":""}]}`))
	if err == nil {
		t.Fatal("空 key 应报错，而不是被静默跳过")
	}
	if !strings.Contains(err.Error(), "key") {
		t.Fatalf("错误信息应点明 key 字段，实际 %v", err)
	}
}

// TestNormalizeRejectsDuplicateKeyValue 同一个密钥值登记两次无意义。
func TestNormalizeRejectsDuplicateKeyValue(t *testing.T) {
	_, err := ParseConfig([]byte(`{"api_keys":[{"name":"a","key":"same"},{"name":"b","key":"same"}]}`))
	if err == nil {
		t.Fatal("重复 key 值应报错")
	}
}

// TestAPIKeysOmittedWhenEmpty 空表不应写进 JSON（omitempty，保持配置文件干净）。
func TestAPIKeysOmittedWhenEmpty(t *testing.T) {
	c := Default()
	_ = c.normalize()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"api_keys"`) {
		t.Fatalf("空表不应出现在序列化结果里：\n%s", raw)
	}
}

// TestNormalizeRejectsNameCollidingWithLegacyKey 是名称唯一性缺口的回归点（审查发现）。
//
// 旧 api_key 会被合成进生效表并占用名称「默认」。若用户在 api_keys 里也写了同名
// 条目，修复前 normalize 只校验 c.APIKeys（看不见合成项），于是生效表里出现两条
// 同名密钥——usage 按名称分桶，两个不同凭证的统计会静默合并成一行。
func TestNormalizeRejectsNameCollidingWithLegacyKey(t *testing.T) {
	_, err := ParseConfig([]byte(`{"api_key":"sk-legacy-root","api_keys":[{"name":"默认","key":"sk-explicit-tenant"}]}`))
	if err == nil {
		t.Fatal("旧 api_key 合成的「默认」与手写同名条目冲突，应报错而不是静默合并")
	}
	if !strings.Contains(err.Error(), "默认") {
		t.Fatalf("错误信息应点出冲突的名称，实际 %v", err)
	}
}

// TestEffectiveAPIKeysNamesAreUniqueWhenNormalized 属性断言：任何通过 normalize 的
// 配置，其生效表名称必然唯一。这是 usage 按名称分桶正确性的前置条件。
func TestEffectiveAPIKeysNamesAreUniqueWhenNormalized(t *testing.T) {
	raws := []string{
		`{"api_key":"sk-a"}`,
		`{"api_keys":[{"name":"p","key":"k1"},{"name":"q","key":"k2"}]}`,
		`{"api_key":"sk-legacy","api_keys":[{"name":"p","key":"k1"}]}`,
		`{"api_key":"sk-z","api_keys":[{"name":"p","key":"k9"}]}`,
		`{"api_key":"sk-padded","api_keys":[{"name":"p","key":"k-padded"}]}`,
	}
	for _, raw := range raws {
		c, err := ParseConfig([]byte(raw))
		if err != nil {
			t.Fatalf("配置 %s 应通过: %v", raw, err)
		}
		seen := map[string]bool{}
		for _, k := range c.EffectiveAPIKeys() {
			if seen[k.Name] {
				t.Fatalf("配置 %s 的生效表出现重名 %q", raw, k.Name)
			}
			seen[k.Name] = true
		}
	}
}

// TestKeyValuesAreTrimmed 判空用 TrimSpace，存值也必须裁过。否则手写配置里一个
// 多余空格会让客户端必须逐字节带上空格才能通过鉴权（而配置看起来完全正常）。
func TestKeyValuesAreTrimmed(t *testing.T) {
	c := mustParse(t, `{"api_key":"  sk-legacy-padded  ","api_keys":[{"name":"p","key":"  sk-padded  "}]}`)
	ks := c.EffectiveAPIKeys()
	if len(ks) != 2 {
		t.Fatalf("应得到 2 条，实际 %d：%+v", len(ks), ks)
	}
	for _, k := range ks {
		if k.Key != strings.TrimSpace(k.Key) {
			t.Fatalf("密钥值未裁剪: %q", k.Key)
		}
	}
}

// TestNormalizeRejectsAnonymousEntryCollidingWithLegacy 无名字条目会被归一成
// 「默认」，因此它与旧 api_key 合成项必然同名——这条路径更隐蔽（用户没写名字，
// 不容易意识到自己撞了名），必须同样被拦住。
func TestNormalizeRejectsAnonymousEntryCollidingWithLegacy(t *testing.T) {
	_, err := ParseConfig([]byte(`{"api_key":"sk-legacy","api_keys":[{"key":"k9"}]}`))
	if err == nil {
		t.Fatal("无名字条目归一成「默认」后与旧 api_key 撞名，应报错")
	}
}

// TestExampleConfigLoads config.example.json 必须始终可被加载。
//
// 它是用户直接复制使用的模板，字段写错（例如 api_keys 结构不对）只会在照抄的人
// 启动时炸。同时断言示例里的占位密钥是**停用**的：示例文件会被直接复制运行，
// 塞一把已知值的启用密钥等于给所有照抄的人发同一把可用凭证。
func TestExampleConfigLoads(t *testing.T) {
	raw, err := os.ReadFile("../../config.example.json")
	if err != nil {
		t.Skipf("示例配置不可读: %v", err)
	}
	c, err := ParseConfig(raw)
	if err != nil {
		t.Fatalf("config.example.json 无法加载: %v", err)
	}
	ks := c.EffectiveAPIKeys()
	enabled := 0
	for _, k := range ks {
		if k.Enabled {
			enabled++
		}
	}
	if len(ks) != 2 {
		t.Fatalf("示例应产生 2 条密钥（1 条停用占位 + 旧 api_key），实际 %d：%+v", len(ks), ks)
	}
	if enabled != 1 {
		t.Fatalf("示例中启用密钥应恰好 1 把（旧 api_key），实际 %d —— "+
			"示例里的占位密钥必须是 enabled:false，否则照抄的人会拿到已知弱凭证", enabled)
	}
}
