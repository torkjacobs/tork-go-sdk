package middleware

import (
	"encoding/json"
	"io"
	"net/http"

	tork "github.com/torkjacobs/tork-go-sdk"
)

// BeegoContext is a minimal interface for Beego context
type BeegoContext interface {
	Input() BeegoInput
	Output() BeegoOutput
}

// BeegoInput is a minimal interface for Beego input
type BeegoInput interface {
	RequestBody() []byte
	Method() string
	URI() string
	SetData(key string, val interface{})
	GetData(key string) interface{}
}

// BeegoOutput is a minimal interface for Beego output
type BeegoOutput interface {
	SetStatus(status int)
	JSON(data interface{}, hasIndent bool, encoding bool) error
}

// BeegoConfig holds configuration for Beego middleware
type BeegoConfig struct {
	Client         *tork.Client
	SkipPaths      []string
	ExtractContent func(body map[string]interface{}) string
	OnBlock        func(ctx BeegoContext, result tork.GovernResult)
}

// DefaultBeegoConfig returns default Beego middleware configuration
func DefaultBeegoConfig() BeegoConfig {
	return BeegoConfig{
		Client:         tork.NewClient(),
		SkipPaths:      []string{},
		ExtractContent: defaultExtractContent,
		OnBlock:        nil,
	}
}

// TorkBeegoFilter creates a Beego filter function for Tork governance.
//
// Example:
//
//	beego.InsertFilter("/*", beego.BeforeRouter, middleware.TorkBeegoFilter(middleware.BeegoConfig{
//	    Client: tork.NewClient(),
//	}))
func TorkBeegoFilter(config BeegoConfig) func(ctx BeegoContext) {
	if config.Client == nil {
		config.Client = tork.NewClient()
	}
	if config.ExtractContent == nil {
		config.ExtractContent = defaultExtractContent
	}

	return func(ctx BeegoContext) {
		input := ctx.Input()

		// Skip non-mutating methods
		method := input.Method()
		if method != "POST" && method != "PUT" && method != "PATCH" {
			return
		}

		// Check skip paths
		path := input.URI()
		for _, skip := range config.SkipPaths {
			if matchPath(path, skip) {
				return
			}
		}

		// Read body
		body := input.RequestBody()
		if len(body) == 0 {
			return
		}

		// Parse JSON
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			return
		}

		// Extract content
		content := config.ExtractContent(data)
		if content == "" {
			return
		}

		// Govern
		result := config.Client.Govern(content)
		input.SetData("tork_result", result)

		// Handle deny action
		if result.Action == tork.ActionDeny {
			if config.OnBlock != nil {
				config.OnBlock(ctx, result)
				return
			}
			ctx.Output().SetStatus(http.StatusForbidden)
			ctx.Output().JSON(map[string]interface{}{
				"error":      "Request blocked by governance policy",
				"receipt_id": result.Receipt.ID,
				"pii_types":  tork.PIITypesToStrings(result.PII.Types),
			}, false, false)
			return
		}
	}
}

// TorkBeegoHandler creates a standard net/http middleware for Beego's newer API
//
// Example:
//
//	web.InsertFilterChain("/*", middleware.TorkBeegoHandler(middleware.DefaultBeegoConfig()))
func TorkBeegoHandler(config BeegoConfig) func(http.Handler) http.Handler {
	if config.Client == nil {
		config.Client = tork.NewClient()
	}
	if config.ExtractContent == nil {
		config.ExtractContent = defaultExtractContent
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" && r.Method != "PUT" && r.Method != "PATCH" {
				next.ServeHTTP(w, r)
				return
			}

			for _, skip := range config.SkipPaths {
				if matchPath(r.URL.Path, skip) {
					next.ServeHTTP(w, r)
					return
				}
			}

			body, err := io.ReadAll(r.Body)
			if err != nil || len(body) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			defer r.Body.Close()

			var data map[string]interface{}
			if err := json.Unmarshal(body, &data); err != nil {
				next.ServeHTTP(w, r)
				return
			}

			content := config.ExtractContent(data)
			if content == "" {
				next.ServeHTTP(w, r)
				return
			}

			result := config.Client.Govern(content)
			r = SetTorkResult(r, result)

			if result.Action == tork.ActionDeny {
				if config.OnBlock != nil {
					config.OnBlock(nil, result)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":      "Request blocked by governance policy",
					"receipt_id": result.Receipt.ID,
					"pii_types":  tork.PIITypesToStrings(result.PII.Types),
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetTorkResultBeego retrieves the Tork result from Beego context
func GetTorkResultBeego(ctx BeegoContext) (tork.GovernResult, bool) {
	v := ctx.Input().GetData("tork_result")
	if v != nil {
		if result, ok := v.(tork.GovernResult); ok {
			return result, true
		}
	}
	return tork.GovernResult{}, false
}
