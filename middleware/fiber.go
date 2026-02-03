package middleware

import (
	"encoding/json"

	tork "github.com/torkjacobs/tork-go-sdk"
)

// FiberContext is a minimal interface for Fiber context
type FiberContext interface {
	Method() string
	Path() string
	Body() []byte
	Locals(key interface{}, value ...interface{}) interface{}
	Status(status int) FiberContext
	JSON(data interface{}) error
	Next() error
}

// FiberConfig holds configuration for Fiber middleware
type FiberConfig struct {
	Client         *tork.Client
	SkipPaths      []string
	ExtractContent func(body map[string]interface{}) string
	OnBlock        func(c FiberContext, result tork.GovernResult) error
}

// DefaultFiberConfig returns default Fiber middleware configuration
func DefaultFiberConfig() FiberConfig {
	return FiberConfig{
		Client:         tork.NewClient(),
		SkipPaths:      []string{},
		ExtractContent: defaultExtractContent,
		OnBlock:        nil,
	}
}

// TorkFiber creates a Fiber middleware for Tork governance
//
// Example:
//
//	app := fiber.New()
//	app.Use(middleware.TorkFiber(middleware.FiberConfig{
//	    Client: tork.NewClient(),
//	}))
//
//	app.Post("/chat", func(c *fiber.Ctx) error {
//	    result := c.Locals("tork_result").(tork.GovernResult)
//	    return c.JSON(fiber.Map{"message": "ok"})
//	})
func TorkFiber(config FiberConfig) func(FiberContext) error {
	if config.Client == nil {
		config.Client = tork.NewClient()
	}
	if config.ExtractContent == nil {
		config.ExtractContent = defaultExtractContent
	}

	return func(c FiberContext) error {
		// Skip non-mutating methods
		method := c.Method()
		if method != "POST" && method != "PUT" && method != "PATCH" {
			return c.Next()
		}

		// Check skip paths
		path := c.Path()
		for _, skip := range config.SkipPaths {
			if matchPath(path, skip) {
				return c.Next()
			}
		}

		// Get body
		body := c.Body()
		if len(body) == 0 {
			return c.Next()
		}

		// Parse JSON
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			return c.Next()
		}

		// Extract content
		content := config.ExtractContent(data)
		if content == "" {
			return c.Next()
		}

		// Govern
		result := config.Client.Govern(content)
		c.Locals("tork_result", result)

		// Handle deny action
		if result.Action == tork.ActionDeny {
			if config.OnBlock != nil {
				return config.OnBlock(c, result)
			}
			return c.Status(403).JSON(map[string]interface{}{
				"error":      "Request blocked by governance policy",
				"receipt_id": result.Receipt.ID,
				"pii_types":  tork.PIITypesToStrings(result.PII.Types),
			})
		}

		return c.Next()
	}
}

// TorkFiberMiddleware is a simplified middleware creator using default config
//
// Example:
//
//	app := fiber.New()
//	app.Use(middleware.TorkFiberMiddleware())
func TorkFiberMiddleware() func(FiberContext) error {
	return TorkFiber(DefaultFiberConfig())
}

// GetTorkResultFiber retrieves the Tork result from Fiber context
func GetTorkResultFiber(c FiberContext) (tork.GovernResult, bool) {
	if v := c.Locals("tork_result"); v != nil {
		if result, ok := v.(tork.GovernResult); ok {
			return result, true
		}
	}
	return tork.GovernResult{}, false
}

// TorkFiberHandler wraps a handler function with governance result access
//
// Example:
//
//	app.Post("/chat", middleware.TorkFiberHandler(func(c *fiber.Ctx, result tork.GovernResult) error {
//	    return c.JSON(fiber.Map{"output": result.Output})
//	}))
func TorkFiberHandler(fn func(c FiberContext, result tork.GovernResult) error) func(FiberContext) error {
	return func(c FiberContext) error {
		result, _ := GetTorkResultFiber(c)
		return fn(c, result)
	}
}
