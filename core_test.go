package tork

import (
	"strings"
	"testing"
)

// ============================================================================
// Action Tests
// ============================================================================

func TestActionAllow(t *testing.T) {
	if ActionAllow != Action("allow") {
		t.Errorf("Expected ActionAllow to be 'allow', got %s", ActionAllow)
	}
}

func TestActionDeny(t *testing.T) {
	if ActionDeny != Action("deny") {
		t.Errorf("Expected ActionDeny to be 'deny', got %s", ActionDeny)
	}
}

func TestActionRedact(t *testing.T) {
	if ActionRedact != Action("redact") {
		t.Errorf("Expected ActionRedact to be 'redact', got %s", ActionRedact)
	}
}

func TestActionEscalate(t *testing.T) {
	if ActionEscalate != Action("escalate") {
		t.Errorf("Expected ActionEscalate to be 'escalate', got %s", ActionEscalate)
	}
}

// ============================================================================
// DefaultConfig Tests
// ============================================================================

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.PolicyVersion != "1.0.0" {
		t.Errorf("Expected PolicyVersion '1.0.0', got '%s'", config.PolicyVersion)
	}
	if config.DefaultAction != ActionRedact {
		t.Errorf("Expected DefaultAction ActionRedact, got %s", config.DefaultAction)
	}
}

// ============================================================================
// NewClient Tests
// ============================================================================

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("Expected client to not be nil")
	}
}

func TestNewClient_HasDefaultConfig(t *testing.T) {
	client := NewClient()
	config := client.GetConfig()
	if config.PolicyVersion != "1.0.0" {
		t.Errorf("Expected PolicyVersion '1.0.0', got '%s'", config.PolicyVersion)
	}
}

func TestNewClientWithConfig(t *testing.T) {
	config := Config{
		PolicyVersion: "2.0.0",
		DefaultAction: ActionDeny,
	}
	client := NewClientWithConfig(config)
	if client.GetConfig().PolicyVersion != "2.0.0" {
		t.Errorf("Expected PolicyVersion '2.0.0', got '%s'", client.GetConfig().PolicyVersion)
	}
	if client.GetConfig().DefaultAction != ActionDeny {
		t.Errorf("Expected DefaultAction ActionDeny, got %s", client.GetConfig().DefaultAction)
	}
}

// ============================================================================
// Govern Tests
// ============================================================================

func TestGovern_NoPII(t *testing.T) {
	client := NewClient()
	result := client.Govern("Hello world")
	if result.Action != ActionAllow {
		t.Errorf("Expected Action ActionAllow, got %s", result.Action)
	}
	if result.Output != "Hello world" {
		t.Errorf("Expected Output 'Hello world', got '%s'", result.Output)
	}
}

func TestGovern_WithPII_Redact(t *testing.T) {
	client := NewClient()
	result := client.Govern("My SSN is 123-45-6789")
	if result.Action != ActionRedact {
		t.Errorf("Expected Action ActionRedact, got %s", result.Action)
	}
	if result.Output != "My SSN is [SSN_REDACTED]" {
		t.Errorf("Expected redacted output, got '%s'", result.Output)
	}
}

func TestGovern_WithPII_HasReceipt(t *testing.T) {
	client := NewClient()
	result := client.Govern("test")
	if result.Receipt.ID == "" {
		t.Error("Expected Receipt ID to not be empty")
	}
	if !strings.HasPrefix(result.Receipt.ID, "rcpt_") {
		t.Errorf("Expected Receipt ID to start with 'rcpt_', got '%s'", result.Receipt.ID)
	}
}

func TestGovern_WithPII_HasPIIResult(t *testing.T) {
	client := NewClient()
	result := client.Govern("SSN: 123-45-6789")
	if !result.PII.HasPII {
		t.Error("Expected PII.HasPII to be true")
	}
}

func TestGovern_Receipt_HasHashes(t *testing.T) {
	client := NewClient()
	result := client.Govern("test")
	if !strings.HasPrefix(result.Receipt.InputHash, "sha256:") {
		t.Errorf("Expected InputHash to start with 'sha256:', got '%s'", result.Receipt.InputHash)
	}
	if !strings.HasPrefix(result.Receipt.OutputHash, "sha256:") {
		t.Errorf("Expected OutputHash to start with 'sha256:', got '%s'", result.Receipt.OutputHash)
	}
}

func TestGovern_DenyAction(t *testing.T) {
	config := Config{
		PolicyVersion: "1.0.0",
		DefaultAction: ActionDeny,
	}
	client := NewClientWithConfig(config)
	result := client.Govern("SSN: 123-45-6789")
	if result.Action != ActionDeny {
		t.Errorf("Expected Action ActionDeny, got %s", result.Action)
	}
	// Output must always be redacted when PII is present, regardless of action
	if result.Output != "SSN: [SSN_REDACTED]" {
		t.Errorf("Expected redacted output with deny action, got '%s'", result.Output)
	}
}

func TestGovern_MultipleGoverns(t *testing.T) {
	client := NewClient()
	client.Govern("test1")
	client.Govern("test2")
	stats := client.GetStats()
	if stats.TotalCalls != 2 {
		t.Errorf("Expected TotalCalls 2, got %d", stats.TotalCalls)
	}
}

// ============================================================================
// GetStats Tests
// ============================================================================

func TestGetStats_Initial(t *testing.T) {
	client := NewClient()
	stats := client.GetStats()
	if stats.TotalCalls != 0 {
		t.Errorf("Expected TotalCalls 0, got %d", stats.TotalCalls)
	}
	if stats.TotalPIIDetected != 0 {
		t.Errorf("Expected TotalPIIDetected 0, got %d", stats.TotalPIIDetected)
	}
}

func TestGetStats_TracksTotalCalls(t *testing.T) {
	client := NewClient()
	client.Govern("test")
	client.Govern("test2")
	if client.GetStats().TotalCalls != 2 {
		t.Errorf("Expected TotalCalls 2, got %d", client.GetStats().TotalCalls)
	}
}

func TestGetStats_TracksPIIDetected(t *testing.T) {
	client := NewClient()
	client.Govern("SSN: 123-45-6789")
	client.Govern("clean text")
	if client.GetStats().TotalPIIDetected != 1 {
		t.Errorf("Expected TotalPIIDetected 1, got %d", client.GetStats().TotalPIIDetected)
	}
}

func TestGetStats_TracksActionCounts(t *testing.T) {
	client := NewClient()
	client.Govern("SSN: 123-45-6789")
	client.Govern("clean text")
	stats := client.GetStats()
	if stats.ActionCounts[ActionRedact] != 1 {
		t.Errorf("Expected ActionCounts[Redact] 1, got %d", stats.ActionCounts[ActionRedact])
	}
	if stats.ActionCounts[ActionAllow] != 1 {
		t.Errorf("Expected ActionCounts[Allow] 1, got %d", stats.ActionCounts[ActionAllow])
	}
}

// ============================================================================
// ResetStats Tests
// ============================================================================

func TestResetStats(t *testing.T) {
	client := NewClient()
	client.Govern("SSN: 123-45-6789")
	client.Govern("test")
	client.ResetStats()
	stats := client.GetStats()
	if stats.TotalCalls != 0 {
		t.Errorf("Expected TotalCalls 0 after reset, got %d", stats.TotalCalls)
	}
	if stats.TotalPIIDetected != 0 {
		t.Errorf("Expected TotalPIIDetected 0 after reset, got %d", stats.TotalPIIDetected)
	}
}

func TestResetStats_ResetsActionCounts(t *testing.T) {
	client := NewClient()
	client.Govern("SSN: 123-45-6789")
	client.ResetStats()
	if client.GetStats().ActionCounts[ActionRedact] != 0 {
		t.Errorf("Expected ActionCounts[Redact] 0 after reset, got %d", client.GetStats().ActionCounts[ActionRedact])
	}
}

// ============================================================================
// GetConfig / SetConfig Tests
// ============================================================================

func TestGetConfig(t *testing.T) {
	client := NewClient()
	config := client.GetConfig()
	if config.PolicyVersion == "" {
		t.Error("Expected PolicyVersion to not be empty")
	}
}

func TestSetConfig(t *testing.T) {
	client := NewClient()
	newConfig := Config{
		PolicyVersion: "3.0.0",
		DefaultAction: ActionEscalate,
	}
	client.SetConfig(newConfig)
	config := client.GetConfig()
	if config.PolicyVersion != "3.0.0" {
		t.Errorf("Expected PolicyVersion '3.0.0', got '%s'", config.PolicyVersion)
	}
	if config.DefaultAction != ActionEscalate {
		t.Errorf("Expected DefaultAction ActionEscalate, got %s", config.DefaultAction)
	}
}

func TestSetDefaultAction(t *testing.T) {
	client := NewClient()
	client.SetDefaultAction(ActionDeny)
	if client.GetConfig().DefaultAction != ActionDeny {
		t.Errorf("Expected DefaultAction ActionDeny, got %s", client.GetConfig().DefaultAction)
	}
}

func TestSetPolicyVersion(t *testing.T) {
	client := NewClient()
	client.SetPolicyVersion("5.0.0")
	if client.GetConfig().PolicyVersion != "5.0.0" {
		t.Errorf("Expected PolicyVersion '5.0.0', got '%s'", client.GetConfig().PolicyVersion)
	}
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestGovern_LongText(t *testing.T) {
	client := NewClient()
	longText := strings.Repeat("A", 100000)
	result := client.Govern(longText)
	if result.Action != ActionAllow {
		t.Errorf("Expected Action ActionAllow for text without PII, got %s", result.Action)
	}
}

func TestGovern_Unicode(t *testing.T) {
	client := NewClient()
	result := client.Govern("Hello \u4e16\u754c, SSN: 123-45-6789")
	if !result.PII.HasPII {
		t.Error("Expected PII.HasPII to be true")
	}
}

func TestGovern_SpecialCharacters(t *testing.T) {
	client := NewClient()
	result := client.Govern("Special chars: !@#$%^&*()")
	if result.Action != ActionAllow {
		t.Errorf("Expected Action ActionAllow, got %s", result.Action)
	}
}

func TestGovern_Newlines(t *testing.T) {
	client := NewClient()
	result := client.Govern("Line1\nLine2\nSSN: 123-45-6789")
	if !result.PII.HasPII {
		t.Error("Expected PII.HasPII to be true")
	}
}

func TestGovern_Tabs(t *testing.T) {
	client := NewClient()
	result := client.Govern("Tab\there\tSSN: 123-45-6789")
	if !result.PII.HasPII {
		t.Error("Expected PII.HasPII to be true")
	}
}

func TestGovern_RepeatedGoverns(t *testing.T) {
	client := NewClient()
	for i := 0; i < 100; i++ {
		result := client.Govern("Test")
		if result.Receipt.ID == "" {
			t.Errorf("Expected Receipt ID at iteration %d", i)
		}
	}
	if client.GetStats().TotalCalls != 100 {
		t.Errorf("Expected TotalCalls 100, got %d", client.GetStats().TotalCalls)
	}
}

func TestGovern_EmptyString(t *testing.T) {
	client := NewClient()
	result := client.Govern("")
	if result.Action != ActionAllow {
		t.Errorf("Expected Action ActionAllow for empty string, got %s", result.Action)
	}
}

// ============================================================================
// Receipt Tests
// ============================================================================

func TestReceipt_UniqueIDs(t *testing.T) {
	client := NewClient()
	result1 := client.Govern("test1")
	result2 := client.Govern("test2")
	if result1.Receipt.ID == result2.Receipt.ID {
		t.Error("Expected unique Receipt IDs")
	}
}

func TestReceipt_HasTimestamp(t *testing.T) {
	client := NewClient()
	result := client.Govern("test")
	if result.Receipt.Timestamp.IsZero() {
		t.Error("Expected Receipt Timestamp to not be zero")
	}
}

func TestReceipt_HasPolicyVersion(t *testing.T) {
	client := NewClient()
	result := client.Govern("test")
	if result.Receipt.PolicyVersion != "1.0.0" {
		t.Errorf("Expected PolicyVersion '1.0.0', got '%s'", result.Receipt.PolicyVersion)
	}
}

func TestReceipt_HasProcessingTime(t *testing.T) {
	client := NewClient()
	result := client.Govern("test")
	if result.Receipt.ProcessingTimeNs < 0 {
		t.Errorf("Expected ProcessingTimeNs >= 0, got %d", result.Receipt.ProcessingTimeNs)
	}
}

func TestReceipt_HasAction(t *testing.T) {
	client := NewClient()
	result := client.Govern("test")
	validActions := []Action{ActionAllow, ActionDeny, ActionRedact, ActionEscalate}
	found := false
	for _, a := range validActions {
		if result.Receipt.Action == a {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected valid action, got %s", result.Receipt.Action)
	}
}
