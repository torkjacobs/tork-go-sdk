package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	tork "github.com/torkjacobs/tork-go-sdk"
)

// TorkResultKey is the context key for Tork governance result
type TorkResultKey struct{}

// ChiConfig holds configuration for Chi middleware
type ChiConfig struct {
	Client         *tork.Client
	SkipPaths      []string
	ExtractContent func(body map[string]interface{}) string
	OnBlock        func(w http.ResponseWriter, r *http.Request, result tork.GovernResult)
}

// DefaultChiConfig returns default Chi middleware configuration
func DefaultChiConfig() ChiConfig {
	return ChiConfig{
		Client:         tork.NewClient(),
		SkipPaths:      []string{},
		ExtractContent: defaultExtractContent,
		OnBlock:        nil,
	}
}

// TorkChi creates a Chi middleware for Tork governance
//
// Example:
//
//	r := chi.NewRouter()
//	r.Use(middleware.TorkChi(middleware.ChiConfig{
//	    Client: tork.NewClient(),
//	}))
//
//	r.Post("/chat", func(w http.ResponseWriter, r *http.Request) {
//	    result := middleware.GetTorkResultChi(r)
//	    json.NewEncoder(w).Encode(map[string]string{"message": "ok"})
//	})
func TorkChi(config ChiConfig) func(http.Handler) http.Handler {
	if config.Client == nil {
		config.Client = tork.NewClient()
	}
	if config.ExtractContent == nil {
		config.ExtractContent = defaultExtractContent
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip non-mutating methods
			if r.Method != "POST" && r.Method != "PUT" && r.Method != "PATCH" {
				next.ServeHTTP(w, r)
				return
			}

			// Check skip paths
			for _, skip := range config.SkipPaths {
				if matchPath(r.URL.Path, skip) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Read body
			body, err := io.ReadAll(r.Body)
			if err != nil || len(body) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			// Restore body for downstream handlers
			r.Body = io.NopCloser(bytes.NewReader(body))

			// Parse JSON
			var data map[string]interface{}
			if err := json.Unmarshal(body, &data); err != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Extract content
			content := config.ExtractContent(data)
			if content == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Govern
			result := config.Client.Govern(content)

			// Store result in context
			ctx := context.WithValue(r.Context(), TorkResultKey{}, result)
			r = r.WithContext(ctx)

			// Handle deny action
			if result.Action == tork.ActionDeny {
				if config.OnBlock != nil {
					config.OnBlock(w, r, result)
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

// TorkChiMiddleware is a simplified middleware creator using default config
//
// Example:
//
//	r := chi.NewRouter()
//	r.Use(middleware.TorkChiMiddleware())
func TorkChiMiddleware() func(http.Handler) http.Handler {
	return TorkChi(DefaultChiConfig())
}

// GetTorkResultChi retrieves the Tork result from Chi request context
func GetTorkResultChi(r *http.Request) (tork.GovernResult, bool) {
	if v := r.Context().Value(TorkResultKey{}); v != nil {
		if result, ok := v.(tork.GovernResult); ok {
			return result, true
		}
	}
	return tork.GovernResult{}, false
}

// TorkChiHandler wraps a handler with Tork governance for a specific route
//
// Example:
//
//	client := tork.NewClient()
//	r.Post("/chat", middleware.TorkChiHandler(client, func(w http.ResponseWriter, r *http.Request, result tork.GovernResult) {
//	    json.NewEncoder(w).Encode(map[string]string{"output": result.Output})
//	}))
func TorkChiHandler(client *tork.Client, fn func(w http.ResponseWriter, r *http.Request, result tork.GovernResult)) http.HandlerFunc {
	if client == nil {
		client = tork.NewClient()
	}

	return func(w http.ResponseWriter, r *http.Request) {
		result, _ := GetTorkResultChi(r)
		fn(w, r, result)
	}
}
