// Package middleware provides Tork governance middleware for Go web frameworks.
package middleware

import (
	"encoding/json"
	"net/http"

	tork "github.com/torkjacobs/tork-go-sdk"
)

// GinContext is a minimal interface for Gin context
type GinContext interface {
	Request() *http.Request
	Set(key string, value interface{})
	Get(key string) (interface{}, bool)
	AbortWithStatusJSON(code int, obj interface{})
	Next()
	GetRawData() ([]byte, error)
}

// GinConfig holds configuration for Gin middleware
type GinConfig struct {
	Client         *tork.Client
	SkipPaths      []string
	ExtractContent func(body map[string]interface{}) string
	OnBlock        func(c GinContext, result tork.GovernResult)
}

// DefaultGinConfig returns default Gin middleware configuration
func DefaultGinConfig() GinConfig {
	return GinConfig{
		Client:         tork.NewClient(),
		SkipPaths:      []string{},
		ExtractContent: defaultExtractContent,
		OnBlock:        nil,
	}
}

// TorkGin creates a Gin middleware for Tork governance
//
// Example:
//
//	r := gin.Default()
//	r.Use(middleware.TorkGin(middleware.GinConfig{
//	    Client: tork.NewClient(),
//	}))
//
//	r.POST("/chat", func(c *gin.Context) {
//	    result, _ := c.Get("tork_result")
//	    c.JSON(200, gin.H{"message": "ok"})
//	})
func TorkGin(config GinConfig) func(c GinContext) {
	if config.Client == nil {
		config.Client = tork.NewClient()
	}
	if config.ExtractContent == nil {
		config.ExtractContent = defaultExtractContent
	}

	return func(c GinContext) {
		// Skip non-mutating methods
		method := c.Request().Method
		if method != "POST" && method != "PUT" && method != "PATCH" {
			c.Next()
			return
		}

		// Check skip paths
		path := c.Request().URL.Path
		for _, skip := range config.SkipPaths {
			if path == skip || (len(skip) > 0 && skip[len(skip)-1] == '*' && len(path) >= len(skip)-1 && path[:len(skip)-1] == skip[:len(skip)-1]) {
				c.Next()
				return
			}
		}

		// Read body
		body, err := c.GetRawData()
		if err != nil || len(body) == 0 {
			c.Next()
			return
		}

		// Parse JSON
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			c.Next()
			return
		}

		// Extract content
		content := config.ExtractContent(data)
		if content == "" {
			c.Next()
			return
		}

		// Govern
		result := config.Client.Govern(content)
		c.Set("tork_result", result)

		// Handle deny action
		if result.Action == tork.ActionDeny {
			if config.OnBlock != nil {
				config.OnBlock(c, result)
				return
			}
			c.AbortWithStatusJSON(http.StatusForbidden, map[string]interface{}{
				"error":      "Request blocked by governance policy",
				"receipt_id": result.Receipt.ID,
				"pii_types":  tork.PIITypesToStrings(result.PII.Types),
			})
			return
		}

		c.Next()
	}
}

// TorkGinHandler creates a type-safe Gin handler wrapper
//
// Example:
//
//	handler := middleware.TorkGinHandler(tork.NewClient())
//	r.POST("/chat", handler(func(c *gin.Context, result tork.GovernResult) {
//	    c.JSON(200, gin.H{"output": result.Output})
//	}))
func TorkGinHandler(client *tork.Client) func(fn func(c GinContext, result tork.GovernResult)) func(c GinContext) {
	if client == nil {
		client = tork.NewClient()
	}

	return func(fn func(c GinContext, result tork.GovernResult)) func(c GinContext) {
		return func(c GinContext) {
			// Get result from context or create new one
			var result tork.GovernResult
			if v, exists := c.Get("tork_result"); exists {
				result = v.(tork.GovernResult)
			}
			fn(c, result)
		}
	}
}

// GetTorkResult retrieves the Tork result from Gin context
func GetTorkResult(c GinContext) (tork.GovernResult, bool) {
	if v, exists := c.Get("tork_result"); exists {
		if result, ok := v.(tork.GovernResult); ok {
			return result, true
		}
	}
	return tork.GovernResult{}, false
}

// defaultExtractContent extracts content from common body fields
func defaultExtractContent(body map[string]interface{}) string {
	keys := []string{"content", "message", "text", "prompt", "query", "input"}
	for _, key := range keys {
		if v, ok := body[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
