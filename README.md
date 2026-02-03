# Tork Governance Go SDK

On-device AI governance SDK for Go with PII detection, redaction, and cryptographic receipts.

[![Go Reference](https://pkg.go.dev/badge/github.com/torknetwork/tork-go-sdk.svg)](https://pkg.go.dev/github.com/torknetwork/tork-go-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
go get github.com/torknetwork/tork-go-sdk
```

## Quick Start

```go
package main

import (
    "fmt"
    tork "github.com/torknetwork/tork-go-sdk"
)

func main() {
    // Create a new client
    client := tork.NewClient()

    // Govern text - detects and redacts PII
    result := client.Govern("My SSN is 123-45-6789")

    fmt.Println("Action:", result.Action)           // "redact"
    fmt.Println("Output:", result.Output)           // "My SSN is [SSN_REDACTED]"
    fmt.Println("Receipt ID:", result.Receipt.ID)   // "rcpt_..."
    fmt.Println("Has PII:", result.PII.HasPII)      // true
}
```

## Supported Frameworks (4 Adapters)

### Web Frameworks
- **Gin** - Middleware for Gin router
- **Echo** - Middleware for Echo framework
- **Fiber** - Middleware for Fiber (Express-like)
- **Chi** - Middleware for Chi router

## Framework Examples

### Gin Middleware

```go
import (
    "github.com/gin-gonic/gin"
    tork "github.com/torknetwork/tork-go-sdk"
    "github.com/torknetwork/tork-go-sdk/middleware"
)

func main() {
    r := gin.Default()

    // Add Tork governance middleware
    r.Use(middleware.GinMiddleware(middleware.Config{
        SkipPaths: []string{"/health"},
    }))

    r.POST("/chat", func(c *gin.Context) {
        // Access governance result
        result, _ := c.Get("torkResult")
        torkResult := result.(*tork.GovernanceResult)

        c.JSON(200, gin.H{
            "receipt_id": torkResult.Receipt.ID,
            "status":     "ok",
        })
    })

    r.Run(":8080")
}
```

### Echo Middleware

```go
import (
    "github.com/labstack/echo/v4"
    tork "github.com/torknetwork/tork-go-sdk"
    "github.com/torknetwork/tork-go-sdk/middleware"
)

func main() {
    e := echo.New()

    // Add Tork governance middleware
    e.Use(middleware.EchoMiddleware(middleware.Config{
        SkipPaths: []string{"/health"},
    }))

    e.POST("/chat", func(c echo.Context) error {
        result := c.Get("torkResult").(*tork.GovernanceResult)
        return c.JSON(200, map[string]interface{}{
            "receipt_id": result.Receipt.ID,
        })
    })

    e.Start(":8080")
}
```

### Fiber Middleware

```go
import (
    "github.com/gofiber/fiber/v2"
    tork "github.com/torknetwork/tork-go-sdk"
    "github.com/torknetwork/tork-go-sdk/middleware"
)

func main() {
    app := fiber.New()

    // Add Tork governance middleware
    app.Use(middleware.FiberMiddleware(middleware.Config{
        SkipPaths: []string{"/health"},
    }))

    app.Post("/chat", func(c *fiber.Ctx) error {
        result := c.Locals("torkResult").(*tork.GovernanceResult)
        return c.JSON(fiber.Map{
            "receipt_id": result.Receipt.ID,
        })
    })

    app.Listen(":8080")
}
```

### Chi Middleware

```go
import (
    "net/http"
    "github.com/go-chi/chi/v5"
    tork "github.com/torknetwork/tork-go-sdk"
    "github.com/torknetwork/tork-go-sdk/middleware"
)

func main() {
    r := chi.NewRouter()

    // Add Tork governance middleware
    r.Use(middleware.ChiMiddleware(middleware.Config{
        SkipPaths: []string{"/health"},
    }))

    r.Post("/chat", func(w http.ResponseWriter, r *http.Request) {
        result := r.Context().Value("torkResult").(*tork.GovernanceResult)
        // Use governed content
    })

    http.ListenAndServe(":8080", r)
}
```

## Features

- **PII Detection**: SSN, credit cards, emails, phones, addresses, IP addresses, dates of birth
- **Automatic Redaction**: Replace sensitive data with type-specific placeholders
- **Cryptographic Receipts**: SHA256 hashes for audit trails
- **High Performance**: Compiled regex patterns, no external dependencies
- **Thread Safe**: Safe for concurrent use

## API

### Client

```go
// Create with default config
client := tork.NewClient()

// Create with custom config
config := tork.Config{
    PolicyVersion: "2.0.0",
    DefaultAction: tork.ActionDeny,
}
client := tork.NewClientWithConfig(config)

// Govern text
result := client.Govern("My SSN is 123-45-6789")

// Get statistics
stats := client.GetStats()
fmt.Printf("Total calls: %d\n", stats.TotalCalls)

// Reset statistics
client.ResetStats()
```

### PII Detection

```go
// Detect PII in text
result := tork.DetectPII("Contact: john@example.com")
fmt.Println("Has PII:", result.HasPII)      // true
fmt.Println("Types:", result.Types)          // [email]
fmt.Println("Count:", result.Count)          // 1
fmt.Println("Redacted:", result.RedactedText) // "Contact: [EMAIL_REDACTED]"

// Quick checks
hasPII := tork.ContainsPII("test@example.com") // true
redacted := tork.RedactPII("SSN: 123-45-6789") // "SSN: [SSN_REDACTED]"
```

### Receipts

```go
// Receipts are generated automatically
result := client.Govern("test")
receipt := result.Receipt

fmt.Println("ID:", receipt.ID)                    // "rcpt_..."
fmt.Println("Timestamp:", receipt.Timestamp)      // 2026-01-30T...
fmt.Println("Input Hash:", receipt.InputHash)     // "sha256:..."
fmt.Println("Action:", receipt.Action)            // "allow"

// Verify receipt
valid := receipt.Verify(input, output) // true/false
```

## Supported PII Types

| Type | Example | Redaction |
|------|---------|-----------|
| SSN | 123-45-6789 | [SSN_REDACTED] |
| Credit Card | 4111-1111-1111-1111 | [CARD_REDACTED] |
| Email | john@example.com | [EMAIL_REDACTED] |
| Phone | 555-123-4567 | [PHONE_REDACTED] |
| Address | 123 Main Street | [ADDRESS_REDACTED] |
| IP Address | 192.168.1.1 | [IP_REDACTED] |
| Date of Birth | 01/15/1990 | [DOB_REDACTED] |

## Governance Actions

- `ActionAllow` - Allow the text through unchanged
- `ActionDeny` - Block the text entirely
- `ActionRedact` - Replace PII with redaction markers (default)
- `ActionEscalate` - Flag for human review

## Performance

Benchmarks on Apple M1:

```
BenchmarkDetectPII-10    500000    2400 ns/op
BenchmarkGovern-10       300000    4100 ns/op
```

## License

MIT
