# Gin 实现 GitHub Webhook Secret 校验中间件

# Gin 实现 GitHub Webhook Secret 校验中间件

## 核心要点

1. 必须读取**原始 Body**，不能用 `c.ShouldBindJSON`（会消费 body，且格式化后哈希不一致）

2. 使用 `hmac-sha256` \+ 时序安全比对

3. 中间件全局 / 单路由挂载均可

4. Secret 通过环境变量传入，禁止硬编码

## 完整代码

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

// GitHubWebhookSecretMiddleware 校验github webhook签名中间件
func GitHubWebhookSecretMiddleware(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. 获取签名头
		signHeader := c.GetHeader("X-Hub-Signature-256")
		if signHeader == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"msg": "missing X-Hub-Signature-256 header"})
			return
		}

		// 2. 分割 sha256=xxx
		const prefix = "sha256="
		if len(signHeader) <= len(prefix) || signHeader[:len(prefix)] != prefix {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"msg": "invalid signature prefix"})
			return
		}
		signHex := signHeader[len(prefix):]

		// 3. 读取原始body（关键：不消费请求体，存回buffer）
		rawBody, err := c.GetRawData()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"msg": "read body failed"})
			return
		}
		// 把body放回ctx，后续handler才能正常读取json
		c.Request.Body = http.NoBody
		c.Request.Body = &bufferedBody{data: rawBody, read: 0}

		// 4. 本地计算hmac-sha256
		h := hmac.New(sha256.New, []byte(secret))
		h.Write(rawBody)
		localSignHex := hex.EncodeToString(h.Sum(nil))

		// 5. 时序安全比对，防止计时攻击
		if !hmac.Equal([]byte(signHex), []byte(localSignHex)) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"msg": "signature mismatch, reject request"})
			return
		}

		// 校验通过，放行
		c.Next()
	}
}

// 包装原始body，读取后可重复使用
type bufferedBody struct {
	data []byte
	read int
}

func (b *bufferedBody) Read(p []byte) (int, error) {
	if b.read >= len(b.data) {
		return 0, errors.New("EOF")
	}
	n := copy(p, b.data[b.read:])
	b.read += n
	return n, nil
}

func (b *bufferedBody) Close() error {
	return nil
}

func main() {
	// 从环境变量读取webhook secret
	webhookSecret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	if webhookSecret == "" {
		panic("env GITHUB_WEBHOOK_SECRET not set")
	}

	r := gin.Default()

	// 仅webhook路由使用该中间件
	webhookGroup := r.Group("/webhook")
	webhookGroup.Use(GitHubWebhookSecretMiddleware(webhookSecret))
	{
		webhookGroup.POST("/github", func(c *gin.Context) {
			var payload map[string]interface{}
			if err := c.ShouldBindJSON(&payload); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"status": "ok", "event": c.GetHeader("X-GitHub-Event")})
		})
	}

	_ = r.Run(":8080")
}
```

## 使用说明

### 1\. 启动时传入 Secret

```bash
# Linux/Mac
export GITHUB_WEBHOOK_SECRET="你的github webhook密钥"
go run main.go

# Windows PowerShell
$env:GITHUB_WEBHOOK_SECRET="你的密钥"; go run main.go
```

### 2\. GitHub 配置对应 Secret

仓库 → Settings → Webhooks → Add webhook

- Payload URL：`http://你的服务地址:8080/webhook/github`

- Content type：`application/json`

- Secret：填入和环境变量一致的密钥

- 勾选需要触发的事件（push/pull\_request 等）

## 关键避坑说明

1. **body 复用问题**
Gin 默认 `c.GetRawData()` 读完后 body 关闭，后续 `ShouldBindJSON` 拿不到数据，所以用 `bufferedBody` 重新包装放回 `c.Request.Body`。

2. **不能解析 JSON 后重算哈希**
JSON 格式化、空格、key 顺序变化会导致哈希完全不一致，必须用原始二进制 payload 计算签名。

3. 必须用 `hmac.Equal`
普通字符串 `==` 比对存在时序漏洞，攻击者可暴力枚举密钥。

4. 弃用 sha1
代码只校验 `sha256=` 签名头，忽略老旧不安全的 sha1。

## 扩展优化方案

1. 全局统一日志打印签名校验失败请求，方便攻击排查

2. 增加请求限流，防止高频恶意请求

3. 中间件内校验 `X-GitHub-Event` 做事件过滤

4. 使用配置中心 / 密钥管理服务替代环境变量存储 secret

> （注：部分内容可能由 AI 生成）
