package middleware

import (
	"encoding/json"
	"io"
	"net/http"

	tork "github.com/torkjacobs/tork-go-sdk"
)

// EchoContext is a minimal interface for Echo context
type EchoContext interface {
	Request() *http.Request
	Response() EchoResponse
	Set(key string, val interface{})
	Get(key string) interface{}
	JSON(code int, i interface{}) error
	NoContent(code int) error
}

// EchoResponse is a minimal interface for Echo response
type EchoResponse interface {
	Writer() http.ResponseWriter
}

// EchoConfig holds configuration for Echo middleware
type EchoConfig struct {
	Client         *tork.Client
	SkipPaths      []string
	ExtractContent func(body map[string]interface{}) string
	OnBlock        func(c EchoContext, result tork.GovernResult) error
}

// DefaultEchoConfig returns default Echo middleware configuration
func DefaultEchoConfig() EchoConfig {
	return EchoConfig{
		Client:         tork.NewClient(),
		SkipPaths:      []string{},
		ExtractContent: defaultExtractContent,
		OnBlock:        nil,
	}
}

// TorkEcho creates an Echo middleware for Tork governance
//
// Example:
//
//	e := echo.New()
//	e.Use(middleware.TorkEcho(middleware.EchoConfig{
//	    Client: tork.NewClient(),
//	}))
//
//	e.POST("/chat", func(c echo.Context) error {
//	    result := c.Get("tork_result").(tork.GovernResult)
//	    return c.JSON(200, map[string]string{"message": "ok"})
//	})
func TorkEcho(config EchoConfig) func(next func(EchoContext) error) func(EchoContext) error {
	if config.Client == nil {
		config.Client = tork.NewClient()
	}
	if config.ExtractContent == nil {
		config.ExtractContent = defaultExtractContent
	}

	return func(next func(EchoContext) error) func(EchoContext) error {
		return func(c EchoContext) error {
			// Skip non-mutating methods
			method := c.Request().Method
			if method != "POST" && method != "PUT" && method != "PATCH" {
				return next(c)
			}

			// Check skip paths
			path := c.Request().URL.Path
			for _, skip := range config.SkipPaths {
				if matchPath(path, skip) {
					return next(c)
				}
			}

			// Read body
			body, err := io.ReadAll(c.Request().Body)
			if err != nil || len(body) == 0 {
				return next(c)
			}

			// Parse JSON
			var data map[string]interface{}
			if err := json.Unmarshal(body, &data); err != nil {
				return next(c)
			}

			// Extract content
			content := config.ExtractContent(data)
			if content == "" {
				return next(c)
			}

			// Govern
			result := config.Client.Govern(content)
			c.Set("tork_result", result)

			// Handle deny action
			if result.Action == tork.ActionDeny {
				if config.OnBlock != nil {
					return config.OnBlock(c, result)
				}
				return c.JSON(http.StatusForbidden, map[string]interface{}{
					"error":      "Request blocked by governance policy",
					"receipt_id": result.Receipt.ID,
					"pii_types":  tork.PIITypesToStrings(result.PII.Types),
				})
			}

			return next(c)
		}
	}
}

// TorkEchoMiddleware is a simplified middleware creator using default config
//
// Example:
//
//	e := echo.New()
//	e.Use(middleware.TorkEchoMiddleware())
func TorkEchoMiddleware() func(next func(EchoContext) error) func(EchoContext) error {
	return TorkEcho(DefaultEchoConfig())
}

// GetTorkResultEcho retrieves the Tork result from Echo context
func GetTorkResultEcho(c EchoContext) (tork.GovernResult, bool) {
	if v := c.Get("tork_result"); v != nil {
		if result, ok := v.(tork.GovernResult); ok {
			return result, true
		}
	}
	return tork.GovernResult{}, false
}

// matchPath checks if a path matches a pattern (supports * wildcard at end)
func matchPath(path, pattern string) bool {
	if pattern == path {
		return true
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(path) >= len(prefix) && path[:len(prefix)] == prefix
	}
	return false
}
