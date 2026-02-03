package tork

import (
	"regexp"
	"strings"
)

// PIIType represents a type of personally identifiable information
type PIIType string

const (
	PIITypeSSN        PIIType = "ssn"
	PIITypeCreditCard PIIType = "credit_card"
	PIITypeEmail      PIIType = "email"
	PIITypePhone      PIIType = "phone"
	PIITypeAddress    PIIType = "address"
	PIITypeIPAddress  PIIType = "ip_address"
	PIITypeDOB        PIIType = "date_of_birth"
)

// PIIPattern defines a pattern for detecting PII
type PIIPattern struct {
	Type      PIIType
	Pattern   *regexp.Regexp
	Redaction string
}

// PIIMatch represents a detected PII match
type PIIMatch struct {
	Type       PIIType
	Value      string
	StartIndex int
	EndIndex   int
}

// PIIResult contains the results of PII detection
type PIIResult struct {
	HasPII       bool
	Types        []PIIType
	Count        int
	Matches      []PIIMatch
	RedactedText string
}

// Default PII patterns
var defaultPatterns = []PIIPattern{
	{
		Type:      PIITypeSSN,
		Pattern:   regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		Redaction: "[SSN_REDACTED]",
	},
	{
		Type:      PIITypeCreditCard,
		Pattern:   regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`),
		Redaction: "[CARD_REDACTED]",
	},
	{
		Type:      PIITypeEmail,
		Pattern:   regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
		Redaction: "[EMAIL_REDACTED]",
	},
	{
		Type:      PIITypePhone,
		Pattern:   regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
		Redaction: "[PHONE_REDACTED]",
	},
	{
		Type:      PIITypeAddress,
		Pattern:   regexp.MustCompile(`(?i)\b\d{1,5}\s+\w+(?:\s+\w+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b`),
		Redaction: "[ADDRESS_REDACTED]",
	},
	{
		Type:      PIITypeIPAddress,
		Pattern:   regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
		Redaction: "[IP_REDACTED]",
	},
	{
		Type:      PIITypeDOB,
		Pattern:   regexp.MustCompile(`\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b`),
		Redaction: "[DOB_REDACTED]",
	},
}

// DetectPII scans text for PII and returns detection results
func DetectPII(text string) PIIResult {
	return DetectPIIWithPatterns(text, defaultPatterns)
}

// DetectPIIWithPatterns scans text using custom patterns
func DetectPIIWithPatterns(text string, patterns []PIIPattern) PIIResult {
	var matches []PIIMatch
	typeSet := make(map[PIIType]bool)
	redactedText := text

	for _, p := range patterns {
		found := p.Pattern.FindAllStringIndex(text, -1)
		for _, loc := range found {
			match := PIIMatch{
				Type:       p.Type,
				Value:      text[loc[0]:loc[1]],
				StartIndex: loc[0],
				EndIndex:   loc[1],
			}
			matches = append(matches, match)
			typeSet[p.Type] = true
		}
		redactedText = p.Pattern.ReplaceAllString(redactedText, p.Redaction)
	}

	var types []PIIType
	for t := range typeSet {
		types = append(types, t)
	}

	return PIIResult{
		HasPII:       len(matches) > 0,
		Types:        types,
		Count:        len(matches),
		Matches:      matches,
		RedactedText: redactedText,
	}
}

// RedactPII replaces all PII in text with redaction markers
func RedactPII(text string) string {
	result := DetectPII(text)
	return result.RedactedText
}

// ContainsPII checks if text contains any PII
func ContainsPII(text string) bool {
	result := DetectPII(text)
	return result.HasPII
}

// containsType checks if a slice contains a specific PII type
func containsType(types []PIIType, target PIIType) bool {
	for _, t := range types {
		if t == target {
			return true
		}
	}
	return false
}

// String returns the string representation of PIIType
func (p PIIType) String() string {
	return string(p)
}

// PIITypesToStrings converts a slice of PIIType to strings
func PIITypesToStrings(types []PIIType) []string {
	result := make([]string, len(types))
	for i, t := range types {
		result[i] = strings.ToLower(string(t))
	}
	return result
}
