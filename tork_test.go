package tork

import (
	"strings"
	"testing"
)

func TestDetectSSN(t *testing.T) {
	result := DetectPII("My SSN is 123-45-6789")
	if !result.HasPII {
		t.Error("Expected PII to be detected")
	}
	if !containsType(result.Types, PIITypeSSN) {
		t.Error("Expected SSN type to be detected")
	}
	if result.RedactedText != "My SSN is [SSN_REDACTED]" {
		t.Errorf("Expected redacted text, got: %s", result.RedactedText)
	}
}

func TestDetectEmail(t *testing.T) {
	result := DetectPII("Contact: john@example.com")
	if !result.HasPII {
		t.Error("Expected PII to be detected")
	}
	if !containsType(result.Types, PIITypeEmail) {
		t.Error("Expected email type to be detected")
	}
}

func TestDetectCreditCard(t *testing.T) {
	result := DetectPII("Card: 4111-1111-1111-1111")
	if !result.HasPII {
		t.Error("Expected PII to be detected")
	}
	if !containsType(result.Types, PIITypeCreditCard) {
		t.Error("Expected credit card type to be detected")
	}
}

func TestDetectPhone(t *testing.T) {
	result := DetectPII("Call 555-123-4567")
	if !result.HasPII {
		t.Error("Expected PII to be detected")
	}
	if !containsType(result.Types, PIITypePhone) {
		t.Error("Expected phone type to be detected")
	}
}

func TestNoPII(t *testing.T) {
	result := DetectPII("Hello world, no sensitive data here.")
	if result.HasPII {
		t.Error("Expected no PII to be detected")
	}
	if result.Count != 0 {
		t.Errorf("Expected count 0, got %d", result.Count)
	}
}

func TestMultiplePIITypes(t *testing.T) {
	result := DetectPII("SSN: 123-45-6789, Email: test@test.com")
	if !result.HasPII {
		t.Error("Expected PII to be detected")
	}
	if !containsType(result.Types, PIITypeSSN) {
		t.Error("Expected SSN type to be detected")
	}
	if !containsType(result.Types, PIITypeEmail) {
		t.Error("Expected email type to be detected")
	}
	if result.Count != 2 {
		t.Errorf("Expected count 2, got %d", result.Count)
	}
}

func TestClientGovernWithPII(t *testing.T) {
	client := NewClient()
	result := client.Govern("My SSN is 123-45-6789")

	if result.Action != ActionRedact {
		t.Errorf("Expected action redact, got %s", result.Action)
	}
	if result.Output != "My SSN is [SSN_REDACTED]" {
		t.Errorf("Expected redacted output, got: %s", result.Output)
	}
	if !result.PII.HasPII {
		t.Error("Expected PII to be detected")
	}
}

func TestClientGovernWithoutPII(t *testing.T) {
	client := NewClient()
	result := client.Govern("Hello world")

	if result.Action != ActionAllow {
		t.Errorf("Expected action allow, got %s", result.Action)
	}
	if result.Output != "Hello world" {
		t.Errorf("Expected original output, got: %s", result.Output)
	}
}

func TestReceiptGeneration(t *testing.T) {
	client := NewClient()
	result := client.Govern("Test input")

	if !strings.HasPrefix(result.Receipt.ID, "rcpt_") {
		t.Errorf("Expected receipt ID prefix 'rcpt_', got: %s", result.Receipt.ID)
	}
	if !strings.HasPrefix(result.Receipt.InputHash, "sha256:") {
		t.Errorf("Expected input hash prefix 'sha256:', got: %s", result.Receipt.InputHash)
	}
	if result.Receipt.Timestamp.IsZero() {
		t.Error("Expected non-zero timestamp")
	}
}

func TestClientStatistics(t *testing.T) {
	client := NewClient()
	client.Govern("Text 1")
	client.Govern("SSN: 123-45-6789")
	client.Govern("Text 3")

	stats := client.GetStats()
	if stats.TotalCalls != 3 {
		t.Errorf("Expected 3 total calls, got %d", stats.TotalCalls)
	}
	if stats.TotalPIIDetected != 1 {
		t.Errorf("Expected 1 PII detected, got %d", stats.TotalPIIDetected)
	}
}

func TestHashTextConsistency(t *testing.T) {
	hash1 := HashText("test")
	hash2 := HashText("test")
	if hash1 != hash2 {
		t.Error("Expected consistent hash")
	}
	if !strings.HasPrefix(hash1, "sha256:") {
		t.Errorf("Expected sha256 prefix, got: %s", hash1)
	}
	// SHA256 produces 64 hex chars
	if len(hash1) != 7+64 {
		t.Errorf("Expected hash length 71, got %d", len(hash1))
	}
}

func TestReceiptIDUniqueness(t *testing.T) {
	id1 := GenerateReceiptID()
	id2 := GenerateReceiptID()
	if id1 == id2 {
		t.Error("Expected unique receipt IDs")
	}
	if !strings.HasPrefix(id1, "rcpt_") {
		t.Errorf("Expected 'rcpt_' prefix, got: %s", id1)
	}
}

func TestReceiptVerify(t *testing.T) {
	input := "test input"
	output := "test output"
	receipt := GenerateReceipt(input, output, ActionAllow, nil, 0, "1.0.0", 1000)

	if !receipt.Verify(input, output) {
		t.Error("Expected receipt verification to pass")
	}
	if receipt.Verify("wrong", output) {
		t.Error("Expected receipt verification to fail with wrong input")
	}
}

func BenchmarkDetectPII(b *testing.B) {
	text := "My SSN is 123-45-6789 and email is test@example.com"
	for i := 0; i < b.N; i++ {
		DetectPII(text)
	}
}

func BenchmarkGovern(b *testing.B) {
	client := NewClient()
	text := "My SSN is 123-45-6789 and email is test@example.com"
	for i := 0; i < b.N; i++ {
		client.Govern(text)
	}
}
