package panelauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// HashParams Argon2id 参数。默认值面向单进程管理面板，兼顾抗离线爆破与
// 常见 1C/2G 容器：64 MiB 内存、3 轮、2 并发。
type HashParams struct {
	Memory     uint32
	Time       uint32
	Threads    uint8
	SaltLength uint32
	KeyLength  uint32
}

// DefaultHashParams 新密码默认使用的 Argon2id 参数。
var DefaultHashParams = HashParams{
	Memory:     64 * 1024,
	Time:       3,
	Threads:    2,
	SaltLength: 16,
	KeyLength:  32,
}

const hashPrefix = "argon2id"

// HashPassword 用默认参数生成 PHC 字符串：
// argon2id$v=19$m=65536,t=3,p=2$<salt-b64>$<hash-b64>
func HashPassword(password string) (string, error) {
	return HashPasswordWithParams(password, DefaultHashParams)
}

// HashPasswordWithParams 生成指定参数的哈希（测试与未来参数迁移用）。
func HashPasswordWithParams(password string, p HashParams) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password 不能为空")
	}
	if err := validateParams(p); err != nil {
		return "", err
	}
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("gen salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLength)
	return fmt.Sprintf("%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		hashPrefix, argon2.Version, p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// ValidateHash 校验 PHC 字符串结构及参数边界，不执行昂贵派生。
func ValidateHash(encoded string) error {
	_, _, _, err := parseHash(encoded)
	return err
}

func verifyPassword(password, encoded string) bool {
	p, salt, want, err := parseHash(encoded)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLength)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func parseHash(encoded string) (HashParams, []byte, []byte, error) {
	parts := strings.Split(strings.TrimSpace(encoded), "$")
	if len(parts) != 5 || parts[0] != hashPrefix {
		return HashParams{}, nil, nil, fmt.Errorf("密码哈希格式无效（需要 argon2id PHC 字符串）")
	}
	var version int
	if _, err := fmt.Sscanf(parts[1], "v=%d", &version); err != nil || version != argon2.Version {
		return HashParams{}, nil, nil, fmt.Errorf("密码哈希版本无效")
	}
	var memory, timeCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return HashParams{}, nil, nil, fmt.Errorf("密码哈希参数无效")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return HashParams{}, nil, nil, fmt.Errorf("密码哈希 salt 无效")
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return HashParams{}, nil, nil, fmt.Errorf("密码哈希 key 无效")
	}
	p := HashParams{
		Memory:     memory,
		Time:       timeCost,
		Threads:    threads,
		SaltLength: uint32(len(salt)),
		KeyLength:  uint32(len(key)),
	}
	if err := validateParams(p); err != nil {
		return HashParams{}, nil, nil, err
	}
	return p, salt, key, nil
}

func validateParams(p HashParams) error {
	if p.Memory < 8*1024 || p.Memory > 1024*1024 {
		return fmt.Errorf("argon2 memory 必须在 8192..1048576 KiB")
	}
	if p.Time < 1 || p.Time > 10 {
		return fmt.Errorf("argon2 time 必须在 1..10")
	}
	if p.Threads < 1 || p.Threads > 64 {
		return fmt.Errorf("argon2 threads 必须在 1..64")
	}
	if p.SaltLength < 8 || p.SaltLength > 64 {
		return fmt.Errorf("argon2 salt 长度必须在 8..64 字节")
	}
	if p.KeyLength < 16 || p.KeyLength > 64 {
		return fmt.Errorf("argon2 key 长度必须在 16..64 字节")
	}
	return nil
}
