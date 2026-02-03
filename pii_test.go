package tork

import (
	"regexp"
	"strings"
	"testing"
)

// ============================================================================
// PIIType Tests
// ============================================================================

func TestPIITypeSSN(t *testing.T) {
	if PIITypeSSN != "ssn" {
		t.Errorf("Expected PIITypeSSN to be 'ssn', got %s", PIITypeSSN)
	}
}

func TestPIITypeCreditCard(t *testing.T) {
	if PIITypeCreditCard != "credit_card" {
		t.Errorf("Expected PIITypeCreditCard to be 'credit_card', got %s", PIITypeCreditCard)
	}
}

func TestPIITypeEmail(t *testing.T) {
	if PIITypeEmail != "email" {
		t.Errorf("Expected PIITypeEmail to be 'email', got %s", PIITypeEmail)
	}
}

func TestPIITypePhone(t *testing.T) {
	if PIITypePhone != "phone" {
		t.Errorf("Expected PIITypePhone to be 'phone', got %s", PIITypePhone)
	}
}

func TestPIITypeAddress(t *testing.T) {
	if PIITypeAddress != "address" {
		t.Errorf("Expected PIITypeAddress to be 'address', got %s", PIITypeAddress)
	}
}

func TestPIITypeIPAddress(t *testing.T) {
	if PIITypeIPAddress != "ip_address" {
		t.Errorf("Expected PIITypeIPAddress to be 'ip_address', got %s", PIITypeIPAddress)
	}
}

func TestPIITypeDOB(t *testing.T) {
	if PIITypeDOB != "date_of_birth" {
		t.Errorf("Expected PIITypeDOB to be 'date_of_birth', got %s", PIITypeDOB)
	}
}

// ============================================================================
// DetectPII Tests
// ============================================================================

func TestDetectPII_SSN(t *testing.T) {
	result := DetectPII("My SSN is 123-45-6789")
	if !result.HasPII {
		t.Error("Expected HasPII to be true")
	}
	if !containsType(result.Types, PIITypeSSN) {
		t.Error("Expected types to contain SSN")
	}
}

func TestDetectPII_Email(t *testing.T) {
	result := DetectPII("Contact me at john@example.com")
	if !result.HasPII {
		t.Error("Expected HasPII to be true")
	}
	if !containsType(result.Types, PIITypeEmail) {
		t.Error("Expected types to contain Email")
	}
}

func TestDetectPII_CreditCard(t *testing.T) {
	result := DetectPII("Card: 4111-1111-1111-1111")
	if !result.HasPII {
		t.Error("Expected HasPII to be true")
	}
	if !containsType(result.Types, PIITypeCreditCard) {
		t.Error("Expected types to contain CreditCard")
	}
}

func TestDetectPII_Phone(t *testing.T) {
	result := DetectPII("Call me at 555-123-4567")
	if !result.HasPII {
		t.Error("Expected HasPII to be true")
	}
	if !containsType(result.Types, PIITypePhone) {
		t.Error("Expected types to contain Phone")
	}
}

func TestDetectPII_IPAddress(t *testing.T) {
	result := DetectPII("Server IP: 192.168.1.1")
	if !result.HasPII {
		t.Error("Expected HasPII to be true")
	}
	if !containsType(result.Types, PIITypeIPAddress) {
		t.Error("Expected types to contain IPAddress")
	}
}

func TestDetectPII_DOB(t *testing.T) {
	result := DetectPII("DOB: 01/15/1990")
	if !result.HasPII {
		t.Error("Expected HasPII to be true")
	}
	if !containsType(result.Types, PIITypeDOB) {
		t.Error("Expected types to contain DOB")
	}
}

func TestDetectPII_NoPII(t *testing.T) {
	result := DetectPII("Hello world, no sensitive data here")
	if result.HasPII {
		t.Error("Expected HasPII to be false")
	}
	if result.Count != 0 {
		t.Errorf("Expected count to be 0, got %d", result.Count)
	}
}

func TestDetectPII_MultiplePIITypes(t *testing.T) {
	result := DetectPII("SSN: 123-45-6789, Email: test@test.com")
	if !result.HasPII {
		t.Error("Expected HasPII to be true")
	}
	if result.Count != 2 {
		t.Errorf("Expected count to be 2, got %d", result.Count)
	}
	if !containsType(result.Types, PIITypeSSN) {
		t.Error("Expected types to contain SSN")
	}
	if !containsType(result.Types, PIITypeEmail) {
		t.Error("Expected types to contain Email")
	}
}

func TestDetectPII_RedactsSSN(t *testing.T) {
	result := DetectPII("My SSN is 123-45-6789")
	expected := "My SSN is [SSN_REDACTED]"
	if result.RedactedText != expected {
		t.Errorf("Expected redacted text '%s', got '%s'", expected, result.RedactedText)
	}
}

func TestDetectPII_RedactsEmail(t *testing.T) {
	result := DetectPII("Contact: john@example.com")
	expected := "Contact: [EMAIL_REDACTED]"
	if result.RedactedText != expected {
		t.Errorf("Expected redacted text '%s', got '%s'", expected, result.RedactedText)
	}
}

func TestDetectPII_RedactsCreditCard(t *testing.T) {
	result := DetectPII("Card: 4111-1111-1111-1111")
	expected := "Card: [CARD_REDACTED]"
	if result.RedactedText != expected {
		t.Errorf("Expected redacted text '%s', got '%s'", expected, result.RedactedText)
	}
}

func TestDetectPII_RedactsMultipleSSN(t *testing.T) {
	result := DetectPII("SSN: 123-45-6789, Another: 987-65-4321")
	if result.Count != 2 {
		t.Errorf("Expected count to be 2, got %d", result.Count)
	}
	if !strings.Contains(result.RedactedText, "[SSN_REDACTED]") {
		t.Error("Expected redacted text to contain [SSN_REDACTED]")
	}
}

func TestDetectPII_EmptyString(t *testing.T) {
	result := DetectPII("")
	if result.HasPII {
		t.Error("Expected HasPII to be false for empty string")
	}
	if result.Count != 0 {
		t.Errorf("Expected count to be 0, got %d", result.Count)
	}
	if result.RedactedText != "" {
		t.Errorf("Expected empty redacted text, got '%s'", result.RedactedText)
	}
}

func TestDetectPII_MatchIndices(t *testing.T) {
	result := DetectPII("SSN: 123-45-6789")
	if len(result.Matches) == 0 {
		t.Fatal("Expected at least one match")
	}
	match := result.Matches[0]
	if match.StartIndex < 0 {
		t.Errorf("Expected StartIndex >= 0, got %d", match.StartIndex)
	}
	if match.EndIndex <= match.StartIndex {
		t.Errorf("Expected EndIndex > StartIndex, got %d <= %d", match.EndIndex, match.StartIndex)
	}
}

// ============================================================================
// RedactPII Tests
// ============================================================================

func TestRedactPII_SSN(t *testing.T) {
	result := RedactPII("My SSN is 123-45-6789")
	expected := "My SSN is [SSN_REDACTED]"
	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}
}

func TestRedactPII_NoPII(t *testing.T) {
	input := "Hello world"
	result := RedactPII(input)
	if result != input {
		t.Errorf("Expected '%s', got '%s'", input, result)
	}
}

func TestRedactPII_MultipleTypes(t *testing.T) {
	result := RedactPII("SSN: 123-45-6789 Email: test@test.com")
	if !strings.Contains(result, "[SSN_REDACTED]") {
		t.Error("Expected [SSN_REDACTED] in result")
	}
	if !strings.Contains(result, "[EMAIL_REDACTED]") {
		t.Error("Expected [EMAIL_REDACTED] in result")
	}
}

// ============================================================================
// ContainsPII Tests
// ============================================================================

func TestContainsPII_True(t *testing.T) {
	if !ContainsPII("SSN: 123-45-6789") {
		t.Error("Expected ContainsPII to return true")
	}
}

func TestContainsPII_False(t *testing.T) {
	if ContainsPII("Hello world") {
		t.Error("Expected ContainsPII to return false")
	}
}

func TestContainsPII_Email(t *testing.T) {
	if !ContainsPII("Email: test@example.com") {
		t.Error("Expected ContainsPII to return true for email")
	}
}

func TestContainsPII_CreditCard(t *testing.T) {
	if !ContainsPII("Card: 4111111111111111") {
		t.Error("Expected ContainsPII to return true for credit card")
	}
}

// ============================================================================
// PIITypesToStrings Tests
// ============================================================================

func TestPIITypesToStrings(t *testing.T) {
	types := []PIIType{PIITypeSSN, PIITypeEmail}
	result := PIITypesToStrings(types)
	if len(result) != 2 {
		t.Errorf("Expected 2 strings, got %d", len(result))
	}
}

func TestPIITypesToStrings_Empty(t *testing.T) {
	types := []PIIType{}
	result := PIITypesToStrings(types)
	if len(result) != 0 {
		t.Errorf("Expected 0 strings, got %d", len(result))
	}
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestDetectPII_LongText(t *testing.T) {
	longText := strings.Repeat("A", 100000)
	result := DetectPII(longText)
	if result.HasPII {
		t.Error("Expected HasPII to be false for text without PII")
	}
}

func TestDetectPII_Unicode(t *testing.T) {
	result := DetectPII("Hello \u4e16\u754c, SSN: 123-45-6789")
	if !result.HasPII {
		t.Error("Expected HasPII to be true")
	}
}

func TestDetectPII_SpecialCharacters(t *testing.T) {
	result := DetectPII("Special chars: !@#$%^&*()")
	if result.HasPII {
		t.Error("Expected HasPII to be false")
	}
}

func TestDetectPII_Newlines(t *testing.T) {
	result := DetectPII("Line1\nLine2\nSSN: 123-45-6789")
	if !result.HasPII {
		t.Error("Expected HasPII to be true")
	}
}

func TestDetectPII_Tabs(t *testing.T) {
	result := DetectPII("Tab\there\tSSN: 123-45-6789")
	if !result.HasPII {
		t.Error("Expected HasPII to be true")
	}
}

func TestDetectPII_AdjacentPII(t *testing.T) {
	result := DetectPII("123-45-6789 987-65-4321")
	if result.Count != 2 {
		t.Errorf("Expected 2 matches, got %d", result.Count)
	}
}

func TestDetectPII_Address(t *testing.T) {
	result := DetectPII("Address: 123 Main Street")
	if !result.HasPII {
		t.Error("Expected HasPII to be true for address")
	}
	if !containsType(result.Types, PIITypeAddress) {
		t.Error("Expected types to contain Address")
	}
}

// ============================================================================
// Custom Patterns Tests
// ============================================================================

func TestDetectPIIWithPatterns_Custom(t *testing.T) {
	customPatterns := []PIIPattern{
		{
			Type:      "order_id",
			Pattern:   mustCompile(`ORD-\d{8}`),
			Redaction: "[ORDER_REDACTED]",
		},
	}
	result := DetectPIIWithPatterns("Order: ORD-12345678", customPatterns)
	if !result.HasPII {
		t.Error("Expected HasPII to be true")
	}
	if result.RedactedText != "Order: [ORDER_REDACTED]" {
		t.Errorf("Expected 'Order: [ORDER_REDACTED]', got '%s'", result.RedactedText)
	}
}

func TestDetectPIIWithPatterns_EmptyPatterns(t *testing.T) {
	result := DetectPIIWithPatterns("SSN: 123-45-6789", []PIIPattern{})
	if result.HasPII {
		t.Error("Expected HasPII to be false with empty patterns")
	}
}

// Helper function
func mustCompile(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
