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
	"sync"
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

// Client is the main Tork governance client.
//
// A Client is safe for concurrent use by multiple goroutines: Govern,
// GovernWithOptions, GetStats, ResetStats, GetConfig and the three setters may
// be called from HTTP handlers or a goroutine pool without external locking.
// This is how the middleware adapters in this module use it — one shared Client
// across every request. Reconfiguring a live Client while it serves traffic is
// supported; in-flight calls complete against either the old or the new
// configuration, never a mixture of the two.
//
// A Client must not be copied after first use — it contains a mutex. Always
// pass it as *Client; NewClient and NewClientWithConfig return one.
type Client struct {
	// mu guards both config and stats.
	//
	// One mutex covers both because no code path holds one while touching the
	// other: Govern snapshots the config and releases the lock before it takes
	// it again to record statistics. A second mutex would buy nothing —
	// configuration is written rarely — and would introduce a lock ordering to
	// get wrong.
	//
	// It is held only for the snapshot or update itself, never across PII
	// detection or receipt generation.
	mu     sync.Mutex
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

// SessionContext holds optional agent/session context for multi-agent governance tracking.
//
// All fields are pointers to indicate optionality. When provided, these fields
// are included in the POST body to /api/v1/govern and returned in the receipt.
type SessionContext struct {
	AgentID     *string `json:"agent_id,omitempty"`     // Identifier for the agent making the call
	AgentRole   *string `json:"agent_role,omitempty"`   // Role of the agent: "planner", "worker", or "judge"
	SessionID   *string `json:"session_id,omitempty"`   // Groups all calls from the same agent session
	SessionTurn *int    `json:"session_turn,omitempty"` // Position in the conversation (1, 2, 3...)
}

// GovernOptions contains optional parameters for the Govern method
type GovernOptions struct {
	Region         []string        // Regional PII profiles to activate (e.g. []string{"ae", "in"})
	Industry       string          // Industry profile to activate (e.g. "healthcare", "finance", "legal")
	SessionContext *SessionContext // Optional agent/session context
}

// GovernResult contains the result of a governance operation
type GovernResult struct {
	Action         Action
	Output         string
	PII            PIIResult
	Receipt        Receipt
	Region         []string        // Regional profiles that were activated
	Industry       string          // Industry profile that was activated
	SessionContext *SessionContext `json:"session_context,omitempty"` // Agent/session context when provided
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

// GovernWithOptions applies governance rules with optional region/industry/session parameters
func (c *Client) GovernWithOptions(input string, opts GovernOptions) GovernResult {
	result := c.Govern(input)
	result.Region = opts.Region
	result.Industry = opts.Industry
	if opts.SessionContext != nil {
		result.SessionContext = opts.SessionContext
		result.Receipt.SessionContext = opts.SessionContext
	}
	return result
}

// Govern applies governance rules to the input text
func (c *Client) Govern(input string) GovernResult {
	start := time.Now()

	// Take one configuration snapshot up front and use it for the whole call.
	// Re-reading c.config at each point of use would let a concurrent setter
	// land in between, so a single call could choose an action under the old
	// configuration and then stamp the new policy version onto the receipt
	// describing that decision.
	cfg := c.snapshotConfig()

	// Detect PII
	pii := DetectPII(input)

	// Determine action and output
	var action Action
	var output string

	if pii.HasPII {
		action = cfg.DefaultAction
		output = pii.RedactedText
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
		cfg.PolicyVersion,
		processingTimeNs,
	)

	// Update stats. All shared-state mutation happens here, under the lock —
	// everything above this point works on goroutine-local values.
	c.recordCall(action, pii.HasPII, processingTimeNs)

	return GovernResult{
		Action:  action,
		Output:  output,
		PII:     pii,
		Receipt: receipt,
	}
}

// recordCall folds a single Govern call into the statistics.
//
// The lock is taken for the duration of this function only. The deferred
// unlock matters: a nil ActionCounts map would otherwise panic mid-update
// while holding the lock, deadlocking every subsequent caller.
func (c *Client) recordCall(action Action, hasPII bool, processingTimeNs int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats.TotalCalls++
	if hasPII {
		c.stats.TotalPIIDetected++
	}
	c.stats.TotalProcessingNs += processingTimeNs

	// Defensive: a zero-value Client (not built via NewClient) has a nil map,
	// and assigning into a nil map panics.
	if c.stats.ActionCounts == nil {
		c.stats.ActionCounts = make(map[Action]int64)
	}
	c.stats.ActionCounts[action]++
}

// GetStats returns a snapshot of current usage statistics.
//
// The returned Stats is a deep copy: its ActionCounts map is independent of
// the client's, so the caller may read, range over or mutate it freely while
// other goroutines continue calling Govern.
func (c *Client) GetStats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()

	snapshot := c.stats
	snapshot.ActionCounts = make(map[Action]int64, len(c.stats.ActionCounts))
	for action, count := range c.stats.ActionCounts {
		snapshot.ActionCounts[action] = count
	}
	return snapshot
}

// ResetStats resets all statistics
func (c *Client) ResetStats() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats = Stats{
		ActionCounts: make(map[Action]int64),
	}
}

// snapshotConfig copies the configuration under the lock.
//
// Callers get a value that is stable for as long as they need it, so the lock
// is never held across the actual governance work.
func (c *Client) snapshotConfig() Config {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.config
}

// GetConfig returns a snapshot of the current configuration.
//
// The returned Config shares nothing with the client: every field is a value
// type, so a copy is already a deep copy and the caller may mutate it freely.
// If a reference-typed field is ever added to Config — a []string of regions, a
// map, a pointer — this must copy it explicitly, the way GetStats copies
// ActionCounts, or callers will be handed a live view of SDK internals.
func (c *Client) GetConfig() Config {
	return c.snapshotConfig()
}

// SetConfig updates the configuration.
//
// Safe to call while other goroutines are calling Govern.
func (c *Client) SetConfig(config Config) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.config = config
}

// SetDefaultAction updates the default action.
//
// Safe to call while other goroutines are calling Govern.
func (c *Client) SetDefaultAction(action Action) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.config.DefaultAction = action
}

// SetPolicyVersion updates the policy version.
//
// Safe to call while other goroutines are calling Govern.
func (c *Client) SetPolicyVersion(version string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.config.PolicyVersion = version
}
