package middleware

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	tork "github.com/torkjacobs/tork-go-sdk"
)

// SetTorkResult stores a governance result in the request context
func SetTorkResult(r *http.Request, result tork.GovernResult) *http.Request {
	ctx := context.WithValue(r.Context(), TorkResultKey{}, result)
	return r.WithContext(ctx)
}

// GetTorkResultFromRequest retrieves the Tork result from a standard request
func GetTorkResultFromRequest(r *http.Request) (tork.GovernResult, bool) {
	if v := r.Context().Value(TorkResultKey{}); v != nil {
		if result, ok := v.(tork.GovernResult); ok {
			return result, true
		}
	}
	return tork.GovernResult{}, false
}

// GorillaConfig holds configuration for Gorilla Mux middleware
type GorillaConfig struct {
	Client         *tork.Client
	SkipPaths      []string
	ExtractContent func(body map[string]interface{}) string
	OnBlock        func(w http.ResponseWriter, r *http.Request, result tork.GovernResult)
}

// DefaultGorillaConfig returns default Gorilla Mux middleware configuration
func DefaultGorillaConfig() GorillaConfig {
	return GorillaConfig{
		Client:         tork.NewClient(),
		SkipPaths:      []string{},
		ExtractContent: defaultExtractContent,
		OnBlock:        nil,
	}
}

// TorkGorilla creates a Gorilla Mux middleware for Tork governance.
//
// Example:
//
//	r := mux.NewRouter()
//	r.Use(middleware.TorkGorilla(middleware.GorillaConfig{
//	    Client: tork.NewClient(),
//	}))
//
//	r.HandleFunc("/chat", func(w http.ResponseWriter, r *http.Request) {
//	    result := middleware.GetTorkResultFromRequest(r)
//	    json.NewEncoder(w).Encode(map[string]string{"message": "ok"})
//	}).Methods("POST")
func TorkGorilla(config GorillaConfig) func(http.Handler) http.Handler {
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
			defer r.Body.Close()

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

			// Store result in request context
			r = SetTorkResult(r, result)

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

// TorkGorillaMiddleware is a simplified middleware using default config
func TorkGorillaMiddleware() func(http.Handler) http.Handler {
	return TorkGorilla(DefaultGorillaConfig())
}
