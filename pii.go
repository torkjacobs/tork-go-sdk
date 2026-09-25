package tork

import (
	"regexp"
	"strings"
)

// PIIType represents a type of personally identifiable information
type PIIType string

const (
	PIITypeSSN            PIIType = "ssn"
	PIITypeCreditCard     PIIType = "credit_card"
	PIITypeEmail          PIIType = "email"
	PIITypePhone          PIIType = "phone"
	PIITypeAddress        PIIType = "address"
	PIITypeIPAddress      PIIType = "ip_address"
	PIITypeDOB            PIIType = "date_of_birth"
	PIITypePassport       PIIType = "passport"
	PIITypeDriversLicense PIIType = "drivers_license"
	PIITypeBankAccount    PIIType = "bank_account"
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
	// CountryMatches holds country-registry detections. Kept separate from
	// Matches so PIIType stays the closed ten-value set it has always been.
	CountryMatches []CountryPIIMatch
	// CountryLabels are the redaction labels of those matches, e.g. "NATIONAL_ID".
	CountryLabels []string
	// Regions are the country profiles the text activated, in registry order.
	Regions []string
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
	// The three patterns below close SDK-GO-PII-DETECTOR-DROPS-THREE-DECLARED-TYPES:
	// PIIType declared 7 values but only 7 of the JS SDK's 10-type basic PII
	// vocabulary (pii.ts PII_PATTERNS) had a corresponding pattern here.
	// passport, drivers_license and bank_account passed through DetectPII
	// unflagged and unmasked. Ported verbatim from tork-js-sdk/src/pii.ts,
	// appended in the same order JS declares them so the chained-replace
	// semantics below (each pattern redacts over the previous pattern's
	// already-redacted text) match byte for byte.
	{
		Type:      PIITypePassport,
		Pattern:   regexp.MustCompile(`\b[A-Z]{1,2}\d{6,9}\b`),
		Redaction: "[PASSPORT_REDACTED]",
	},
	{
		Type:      PIITypeDriversLicense,
		Pattern:   regexp.MustCompile(`\b[A-Z]\d{7,14}\b`),
		Redaction: "[DL_REDACTED]",
	},
	{
		Type:      PIITypeBankAccount,
		Pattern:   regexp.MustCompile(`\b\d{8,17}\b`),
		Redaction: "[ACCOUNT_REDACTED]",
	},
}

// DetectPII scans text for PII and returns detection results
func DetectPII(text string) PIIResult {
	return detect(text, defaultPatterns, nil, true)
}

// DetectPIIInRegions forces a set of country profiles on instead of inferring
// them from the content. Region codes are case-insensitive.
func DetectPIIInRegions(text string, regions []string) PIIResult {
	return detect(text, defaultPatterns, regions, true)
}

// DetectPIIWithPatterns scans text using custom patterns.
//
// The country layer is NOT applied here: a caller who supplies its own pattern
// set is asking for exactly that set. Use DetectPII or DetectPIIInRegions for
// the country registry.
func DetectPIIWithPatterns(text string, patterns []PIIPattern) PIIResult {
	return detect(text, patterns, nil, false)
}

// detect is the single implementation behind all three entry points.
//
// REDACTION IS ONE PASS. Until 0.3.0 each pattern was redacted with its own
// ReplaceAllString over text a previous pattern had already rewritten, while
// Matches carried indices into the ORIGINAL text. Two patterns matching
// overlapping spans could leave half an identifier standing beside a redaction
// token -- digits exposed in output the caller had been told was redacted.
// Every match is now collected against the original text, overlaps are resolved
// before anything is rewritten, and the surviving spans are spliced right to
// left in a single pass.
func detect(text string, patterns []PIIPattern, regionOverride []string, withCountry bool) PIIResult {
	var matches []PIIMatch
	typeSet := make(map[PIIType]bool)

	type l0hit struct {
		match     PIIMatch
		redaction string
	}
	var l0 []l0hit
	for _, p := range patterns {
		for _, loc := range p.Pattern.FindAllStringIndex(text, -1) {
			if loc[0] == loc[1] {
				continue
			}
			l0 = append(l0, l0hit{
				match: PIIMatch{
					Type:       p.Type,
					Value:      "[REDACTED]",
					StartIndex: loc[0],
					EndIndex:   loc[1],
				},
				redaction: p.Redaction,
			})
		}
	}

	var regions []string
	var countryMatches []CountryPIIMatch
	if withCountry {
		if len(regionOverride) > 0 {
			regions = make([]string, 0, len(regionOverride))
			for _, r := range regionOverride {
				regions = append(regions, strings.ToUpper(r))
			}
		} else {
			regions = InferRegions(text)
		}
		countryMatches = DetectCountryPIIWithPatterns(text, PatternsForRegions(regions))
	}

	// Resolve overlaps before anything is rewritten. A country identifier
	// supersedes any L0 span it fully contains -- the cloud does the same, which
	// is how a Saudi national ID stops coming back as [PHONE_REDACTED].
	type span struct{ start, end int }
	var claimed []span
	var spans []RedactionSpan
	for _, c := range countryMatches {
		claimed = append(claimed, span{c.StartIndex, c.EndIndex})
		spans = append(spans, RedactionSpan{c.StartIndex, c.EndIndex, c.Redaction})
	}

	for _, hit := range l0 {
		s, e := hit.match.StartIndex, hit.match.EndIndex
		var overlapping []span
		for _, c := range claimed {
			if s < c.end && e > c.start {
				overlapping = append(overlapping, c)
			}
		}
		if len(overlapping) > 0 {
			swallowsAll := true
			for _, c := range overlapping {
				cs, ce := trimmedCore(text, c.start, c.end)
				if !(s <= cs && e >= ce) {
					swallowsAll = false
					break
				}
			}
			if !swallowsAll {
				continue
			}
			// An L0 span that fully contains a country span still loses: the
			// country label is the more specific claim.
			hitsCountry := false
			for _, o := range overlapping {
				for _, c := range countryMatches {
					if c.StartIndex == o.start && c.EndIndex == o.end {
						hitsCountry = true
						break
					}
				}
			}
			if hitsCountry {
				continue
			}
			for _, o := range overlapping {
				for i, c := range claimed {
					if c == o {
						claimed = append(claimed[:i], claimed[i+1:]...)
						break
					}
				}
				for i, sp := range spans {
					if sp.StartIndex == o.start && sp.EndIndex == o.end {
						spans = append(spans[:i], spans[i+1:]...)
						break
					}
				}
			}
		}
		claimed = append(claimed, span{s, e})
		spans = append(spans, RedactionSpan{s, e, hit.redaction})
		matches = append(matches, hit.match)
		typeSet[hit.match.Type] = true
	}

	var types []PIIType
	for t := range typeSet {
		types = append(types, t)
	}

	var labels []string
	seenLabel := make(map[string]bool)
	for _, c := range countryMatches {
		if !seenLabel[c.Label] {
			seenLabel[c.Label] = true
			labels = append(labels, c.Label)
		}
	}

	for i := 1; i < len(matches); i++ {
		for j := i; j > 0 && matches[j].StartIndex < matches[j-1].StartIndex; j-- {
			matches[j], matches[j-1] = matches[j-1], matches[j]
		}
	}

	return PIIResult{
		HasPII:         len(matches)+len(countryMatches) > 0,
		Types:          types,
		Count:          len(matches) + len(countryMatches),
		Matches:        matches,
		RedactedText:   ApplyRedactions(text, spans),
		CountryMatches: countryMatches,
		CountryLabels:  labels,
		Regions:        regions,
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
