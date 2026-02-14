// Package tork provides on-device AI governance with PII detection,
// redaction, and cryptographic receipts.
//
// Example usage:
//
//	client := tork.NewClient()
//	result := client.Govern("My SSN is 123-45-6789")
//	fmt.Println(result.Output) // "My SSN is [SSN_REDACTED]"
//	fmt.Println(result.Receipt.ID) // "rcpt_..."
package tork

import (
	"time"
)

// Config holds configuration for the Tork client
type Config struct {
	PolicyVersion string
	DefaultAction Action
}

// DefaultConfig returns the default configuration
func DefaultConfig() Config {
	return Config{
		PolicyVersion: "1.0.0",
		DefaultAction: ActionRedact,
	}
}

// Client is the main Tork governance client
type Client struct {
	config Config
	stats  Stats
}

// Stats holds usage statistics
type Stats struct {
	TotalCalls        int64
	TotalPIIDetected  int64
	TotalProcessingNs int64
	ActionCounts      map[Action]int64
}

// GovernOptions contains optional parameters for the Govern method
type GovernOptions struct {
	Region   []string // Regional PII profiles to activate (e.g. []string{"ae", "in"})
	Industry string   // Industry profile to activate (e.g. "healthcare", "finance", "legal")
}

// GovernResult contains the result of a governance operation
type GovernResult struct {
	Action   Action
	Output   string
	PII      PIIResult
	Receipt  Receipt
	Region   []string // Regional profiles that were activated
	Industry string   // Industry profile that was activated
}

// NewClient creates a new Tork client with default configuration
func NewClient() *Client {
	return NewClientWithConfig(DefaultConfig())
}

// NewClientWithConfig creates a new Tork client with custom configuration
func NewClientWithConfig(config Config) *Client {
	return &Client{
		config: config,
		stats: Stats{
			ActionCounts: make(map[Action]int64),
		},
	}
}

// GovernWithOptions applies governance rules with optional region/industry parameters
func (c *Client) GovernWithOptions(input string, opts GovernOptions) GovernResult {
	result := c.Govern(input)
	result.Region = opts.Region
	result.Industry = opts.Industry
	return result
}

// Govern applies governance rules to the input text
func (c *Client) Govern(input string) GovernResult {
	start := time.Now()

	// Detect PII
	pii := DetectPII(input)

	// Determine action and output
	var action Action
	var output string

	if pii.HasPII {
		action = c.config.DefaultAction
		if action == ActionRedact {
			output = pii.RedactedText
		} else {
			output = input
		}
	} else {
		action = ActionAllow
		output = input
	}

	processingTimeNs := time.Since(start).Nanoseconds()

	// Generate receipt
	receipt := GenerateReceipt(
		input,
		output,
		action,
		pii.Types,
		pii.Count,
		c.config.PolicyVersion,
		processingTimeNs,
	)

	// Update stats
	c.stats.TotalCalls++
	if pii.HasPII {
		c.stats.TotalPIIDetected++
	}
	c.stats.TotalProcessingNs += processingTimeNs
	c.stats.ActionCounts[action]++

	return GovernResult{
		Action:  action,
		Output:  output,
		PII:     pii,
		Receipt: receipt,
	}
}

// GetStats returns current usage statistics
func (c *Client) GetStats() Stats {
	return c.stats
}

// ResetStats resets all statistics
func (c *Client) ResetStats() {
	c.stats = Stats{
		ActionCounts: make(map[Action]int64),
	}
}

// GetConfig returns the current configuration
func (c *Client) GetConfig() Config {
	return c.config
}

// SetConfig updates the configuration
func (c *Client) SetConfig(config Config) {
	c.config = config
}

// SetDefaultAction updates the default action
func (c *Client) SetDefaultAction(action Action) {
	c.config.DefaultAction = action
}

// SetPolicyVersion updates the policy version
func (c *Client) SetPolicyVersion(version string) {
	c.config.PolicyVersion = version
}
