// panelpass 生成 config.json 中 panel_auth.password_hash 所需的 Argon2id 哈希。
//
// 用法：
//
//	go run ./cmd/panelpass
//	# 或从管道读取（避免密码进 shell history）：
//	printf '%s' 'your-password' | go run ./cmd/panelpass
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/linguo2625469/workbuddy2api-panel/internal/panelauth"
)

func main() {
	password := flag.String("password", "", "明文密码（不建议；留空则从标准输入读取）")
	flag.Parse()

	pw := *password
	if pw == "" {
		pw = readPassword()
	}
	if pw == "" {
		fmt.Fprintln(os.Stderr, "密码不能为空")
		os.Exit(2)
	}
	if utf8.RuneCountInString(pw) < 8 {
		fmt.Fprintln(os.Stderr, "密码至少 8 个字符")
		os.Exit(2)
	}
	if len(pw) > 128 {
		fmt.Fprintln(os.Stderr, "密码不能超过 128 字节")
		os.Exit(2)
	}
	hash, err := panelauth.HashPassword(pw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "生成哈希失败:", err)
		os.Exit(1)
	}
	fmt.Println(hash)
}

func readPassword() string {
	fmt.Fprint(os.Stderr, "面板密码（输入会显示）: ")
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}
