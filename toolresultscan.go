// Tool-result scanning (DECIDED-TACT2-V2-C), ported from
// tork-js-sdk/src/tool-result-scan.ts.
//
// A tool result returned by an MCP server -- or by any external system the
// caller does not control -- is untrusted input that is about to be
// appended to a model's context. ScanToolResult scans it BEFORE that
// happens, on-device, for two things:
//
//  1. PII, using the SAME on-device detector as Client.Govern (DetectPII in
//     pii.go). Nothing new was written for this: same patterns, same
//     redaction labels, same zero-network guarantee.
//  2. Prompt injection, using the conservative heuristic pattern set in
//     injection.go. Every injection finding is labelled `heuristic:<type>`
//     so no caller can mistake a regex hit for a verified determination.
//
// ZERO NETWORK. Every function here is pure: no HTTP client, no I/O, no
// clock read beyond the processing-time measurement Client.ScanToolResult
// takes for its receipt. The payload never leaves the machine.
//
// WHAT THIS IS NOT: this is a client-side control that the CALLER runs and
// the caller attests to. It is not gateway-side enforcement -- a
// compromised or simply careless caller can skip it entirely, and Tork
// cannot tell. Enforcement at the gateway, where skipping is not an
// option, is a separate and later control.
//
// PARITY TIER: this port matches Tier 1 of the JS SDK -- the 10-type basic
// PII vocabulary (ssn, credit_card, email, phone, address, ip_address,
// date_of_birth, passport, drivers_license, bank_account) with JS-identical
// labels and redaction markers. It does NOT carry the Python SDK's
// regional/industry pattern tier (AU/US/GB/EU/AE/... profiles) — this SDK's
// regional detection (see GovernOptions.Region) is a separate, older
// mechanism and is not wired into ScanToolResult.
package tork

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
)

// ============================================================================
// Types
// ============================================================================

// ToolResultFindingKind is either "pii" (a detector match) or "injection"
// (a heuristic pattern match).
type ToolResultFindingKind string

const (
	ToolResultFindingKindPII       ToolResultFindingKind = "pii"
	ToolResultFindingKindInjection ToolResultFindingKind = "injection"
)

// ToolResultFinding is one (kind, type, location) match tally.
type ToolResultFinding struct {
	// Kind is "pii" for a detector match, "injection" for a heuristic
	// pattern match.
	Kind ToolResultFindingKind
	// Type is a PIIType string ("ssn", "email", ...) for kind "pii", or
	// always `heuristic:<name>` for kind "injection" -- the prefix is part
	// of the value, not decoration, so a downstream reader of a receipt
	// cannot mistake a pattern hit for a verified determination.
	Type string
	// Count is the number of matches of this (kind, type) at this location.
	Count int
	// Location is the JSON path of the string the matches were found in,
	// e.g. "$.content[0].text".
	Location string
}

// ToolResultScanInput is the input to ScanToolResult.
type ToolResultScanInput struct {
	// ToolName is the name of the tool that produced this result. Recorded
	// on the receipt.
	ToolName string
	// ServerURI is the URI of the MCP server (or other origin). Recorded on
	// the receipt when present.
	ServerURI *string
	// Payload is the tool result itself: any JSON-shaped value (as produced
	// by json.Unmarshal into interface{} -- map[string]interface{},
	// []interface{}, string, float64, bool, nil) or, more generally, any
	// value reachable via Go maps and slices. It never leaves the machine.
	Payload interface{}
}

// ToolResultScanOptions are the optional parameters to ScanToolResult.
type ToolResultScanOptions struct {
	// BlockOnInjection blocks the result when the injection heuristics
	// fire. Default false: detect and report, let the caller decide. When
	// true and an injection pattern matches, the result's Blocked is true,
	// Reason is set, and Sanitized is nil -- there is deliberately no
	// masked payload to accidentally append.
	BlockOnInjection bool
	// CustomPatterns are extra redaction patterns, same shape and
	// semantics as the JS SDK's TorkConfig.customPatterns. NOTE (inherited
	// from DetectPII): custom patterns redact but are not counted, so they
	// can change Sanitized without producing a finding.
	CustomPatterns map[string]*regexp.Regexp
	// MaxDepth is the maximum nesting depth to walk. Deeper values are
	// passed through unscanned and unmodified. Zero means "use the
	// default" (32); to scan nothing but the root value itself, this
	// cannot express JS's literal maxDepth:0 -- see the package docs for
	// this documented Go-idiom simplification.
	MaxDepth int
}

// ToolResultScanResult is the result of ScanToolResult.
type ToolResultScanResult struct {
	// Sanitized is the payload with PII masked in place, structurally
	// identical otherwise. nil when Blocked is true. Sub-trees containing
	// no PII keep their original identity, so a clean payload's containers
	// come back as the same map/slice values that were passed in.
	Sanitized interface{}
	Findings  []ToolResultFinding
	Blocked   bool
	// Reason is set only when Blocked is true.
	Reason string
}

const defaultToolResultScanMaxDepth = 32

var toolResultLocationIdentifier = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)

func toolResultChildPath(parent, key string) string {
	if toolResultLocationIdentifier.MatchString(key) {
		return parent + "." + key
	}
	return parent + "[" + strconv.Quote(key) + "]"
}

// ============================================================================
// String scanning
// ============================================================================

// scanToolResultString scans one string: PII (via the shared detector) then
// injection heuristics. Returns the masked string; findings are appended in
// place, keyed to location.
func scanToolResultString(text, location string, customPatterns map[string]*regexp.Regexp, findings *[]ToolResultFinding) string {
	pii := DetectPII(text)

	if pii.Count > 0 {
		// Counts per type, emitted in a stable (sorted) order so two runs
		// over the same payload produce identical findings.
		perType := make(map[PIIType]int)
		for _, m := range pii.Matches {
			perType[m.Type]++
		}
		types := make([]string, 0, len(perType))
		for t := range perType {
			types = append(types, string(t))
		}
		sort.Strings(types)
		for _, t := range types {
			*findings = append(*findings, ToolResultFinding{
				Kind:     ToolResultFindingKindPII,
				Type:     t,
				Count:    perType[PIIType(t)],
				Location: location,
			})
		}
	}

	perInjection := make(map[string]int)
	for _, ip := range injectionPatterns {
		count := len(ip.Pattern.FindAllString(text, -1))
		if count > 0 {
			perInjection[ip.Type] += count
		}
	}
	itypes := make([]string, 0, len(perInjection))
	for t := range perInjection {
		itypes = append(itypes, t)
	}
	sort.Strings(itypes)
	for _, t := range itypes {
		*findings = append(*findings, ToolResultFinding{
			Kind:     ToolResultFindingKindInjection,
			Type:     InjectionHeuristicPrefix + t,
			Count:    perInjection[t],
			Location: location,
		})
	}

	redacted := pii.RedactedText

	// Extra caller-supplied patterns, applied AFTER default detection and
	// redaction, for redaction only -- they never produce a finding. Applied
	// in sorted-name order for determinism (the JS source iterates
	// Object.entries insertion order instead; since these are redact-only,
	// order matters only when two custom patterns overlap the same span, an
	// edge case, so this is a documented Go traversal-order difference, not
	// a semantic one).
	if len(customPatterns) > 0 {
		names := make([]string, 0, len(customPatterns))
		for name := range customPatterns {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			redacted = customPatterns[name].ReplaceAllString(redacted, "["+upperASCII(name)+"_REDACTED]")
		}
	}

	return redacted
}

func upperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}

// ============================================================================
// Traversal
// ============================================================================

// walkToolResult walks the payload, scanning every string. Returns a
// structure with PII masked in place, and whether anything changed.
// Sub-trees with nothing to mask keep their original identity (an
// untouched map or slice comes back as the same value that was passed in).
//
// Only strings are scanned. Numbers, booleans, and anything that is not a
// string, map or slice/array pass through untouched -- a bank account
// stored as a JSON number is NOT detected, matching the JS behaviour.
// Cycles (self-referential maps or slices) are left as-is and not
// re-entered.
func walkToolResult(
	value interface{},
	location string,
	depth, maxDepth int,
	customPatterns map[string]*regexp.Regexp,
	findings *[]ToolResultFinding,
	seen map[uintptr]bool,
) (interface{}, bool) {
	if s, ok := value.(string); ok {
		masked := scanToolResultString(s, location, customPatterns, findings)
		return masked, masked != s
	}

	if value == nil || depth >= maxDepth {
		return value, false
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Map:
		if rv.IsNil() {
			return value, false
		}
		ptr := rv.Pointer()
		if seen[ptr] {
			return value, false
		}
		seen[ptr] = true

		keys := rv.MapKeys()
		keyStrs := make([]string, len(keys))
		for i, k := range keys {
			keyStrs[i] = fmt.Sprint(k.Interface())
		}
		order := make([]int, len(keys))
		for i := range order {
			order[i] = i
		}
		sort.Slice(order, func(a, b int) bool { return keyStrs[order[a]] < keyStrs[order[b]] })

		out := reflect.MakeMapWithSize(rv.Type(), len(keys))
		changed := false
		for _, idx := range order {
			k := keys[idx]
			item := rv.MapIndex(k).Interface()
			next, ch := walkToolResult(item, toolResultChildPath(location, keyStrs[idx]), depth+1, maxDepth, customPatterns, findings, seen)
			if ch {
				changed = true
			}
			out.SetMapIndex(k, reflect.ValueOf(next))
		}
		if changed {
			return out.Interface(), true
		}
		return value, false

	case reflect.Slice:
		if rv.IsNil() {
			return value, false
		}
		ptr := rv.Pointer()
		if seen[ptr] {
			return value, false
		}
		seen[ptr] = true

		n := rv.Len()
		out := reflect.MakeSlice(rv.Type(), n, n)
		changed := false
		for i := 0; i < n; i++ {
			item := rv.Index(i).Interface()
			next, ch := walkToolResult(item, fmt.Sprintf("%s[%d]", location, i), depth+1, maxDepth, customPatterns, findings, seen)
			if ch {
				changed = true
			}
			out.Index(i).Set(reflect.ValueOf(next))
		}
		if changed {
			return out.Interface(), true
		}
		return value, false

	case reflect.Array:
		n := rv.Len()
		out := reflect.New(rv.Type()).Elem()
		changed := false
		for i := 0; i < n; i++ {
			item := rv.Index(i).Interface()
			next, ch := walkToolResult(item, fmt.Sprintf("%s[%d]", location, i), depth+1, maxDepth, customPatterns, findings, seen)
			if ch {
				changed = true
			}
			out.Index(i).Set(reflect.ValueOf(next))
		}
		if changed {
			return out.Interface(), true
		}
		return value, false

	default:
		return value, false
	}
}

// ============================================================================
// Public API
// ============================================================================

// ScanToolResult scans a tool result for PII and prompt injection before it
// is appended to model context. Pure and synchronous: makes no network call
// and mutates nothing reachable from input.Payload.
//
// For the receipt-linked form (attested_by="client", capture_mode="edge"),
// use Client.ScanToolResult, which wraps this and records the scan.
func ScanToolResult(input ToolResultScanInput, opts ToolResultScanOptions) ToolResultScanResult {
	maxDepth := opts.MaxDepth
	if maxDepth == 0 {
		maxDepth = defaultToolResultScanMaxDepth
	}

	var findings []ToolResultFinding
	sanitized, _ := walkToolResult(input.Payload, "$", 0, maxDepth, opts.CustomPatterns, &findings, make(map[uintptr]bool))

	injectionCount := 0
	for _, f := range findings {
		if f.Kind == ToolResultFindingKindInjection {
			injectionCount += f.Count
		}
	}
	blocked := opts.BlockOnInjection && injectionCount > 0

	if blocked {
		typeSet := make(map[string]struct{})
		for _, f := range findings {
			if f.Kind == ToolResultFindingKindInjection {
				typeSet[f.Type] = struct{}{}
			}
		}
		types := make([]string, 0, len(typeSet))
		for t := range typeSet {
			types = append(types, t)
		}
		sort.Strings(types)

		reason := fmt.Sprintf(
			"Blocked: %d prompt-injection heuristic match(es) [%s] in the result of tool %q. "+
				"These are heuristic pattern matches (%s), not a verified determination. "+
				"sanitized is nil so no masked copy can be appended to context by accident.",
			injectionCount, joinComma(types), input.ToolName, InjectionRuleset,
		)

		return ToolResultScanResult{
			Sanitized: nil,
			Findings:  findings,
			Blocked:   true,
			Reason:    reason,
		}
	}

	return ToolResultScanResult{Sanitized: sanitized, Findings: findings, Blocked: false}
}

func joinComma(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// ============================================================================
// Receipt block
// ============================================================================

// ToolResultScanFindingCounts carries per-type match counts for one kind
// (pii or injection). Injection type keys keep their "heuristic:" prefix.
type ToolResultScanFindingCounts struct {
	Injection map[string]int `json:"injection"`
	PII       map[string]int `json:"pii"`
}

// ToolResultScanTotals carries the total match count per kind.
type ToolResultScanTotals struct {
	Injection int `json:"injection"`
	PII       int `json:"pii"`
}

// ToolResultScanReceiptBlock is the tool_result_scan block recorded on the
// Receipt.
//
// snake_case, keys emitted in alphabetical order (guaranteed here by
// declaring the struct fields in alphabetical order, since Go's
// encoding/json marshals struct fields in declaration order), optional keys
// OMITTED entirely rather than emitted null -- the same discipline as the
// JS SDK's TORK-DNA-v2 canonical form, and for the same reason: every SDK
// that mirrors this must produce a byte-identical block for the same scan.
//
// It carries COUNTS ONLY. No payload, no matched substring, no location
// path, no tool argument ever appears here.
type ToolResultScanReceiptBlock struct {
	// AttestedBy is always "client". This scan ran in the caller's
	// process; Tork did not execute it.
	AttestedBy string `json:"attested_by"`
	Blocked    bool   `json:"blocked"`
	// CaptureMode is always "edge" -- the capture_mode this SDK's
	// client-side work is recorded under.
	CaptureMode string `json:"capture_mode"`
	// Findings carries counts by kind, then by type.
	Findings ToolResultScanFindingCounts `json:"findings"`
	// InjectionRuleset identifies the injection ruleset that produced the
	// injection counts.
	InjectionRuleset string `json:"injection_ruleset"`
	// Reason is present only when Blocked is true.
	Reason string `json:"reason,omitempty"`
	// SDKLanguage is always "go".
	SDKLanguage string `json:"sdk_language"`
	SDKVersion  string `json:"sdk_version"`
	// ServerURI is present only when the caller supplied one.
	ServerURI *string              `json:"server_uri,omitempty"`
	ToolName  string               `json:"tool_name"`
	Totals    ToolResultScanTotals `json:"totals"`
}

func toolResultCountsByType(findings []ToolResultFinding, kind ToolResultFindingKind) map[string]int {
	totals := make(map[string]int)
	for _, f := range findings {
		if f.Kind != kind {
			continue
		}
		totals[f.Type] += f.Count
	}
	return totals
}

func sumCounts(counts map[string]int) int {
	sum := 0
	for _, v := range counts {
		sum += v
	}
	return sum
}

// BuildToolResultScanBlockParams are the parameters to
// BuildToolResultScanBlock.
type BuildToolResultScanBlockParams struct {
	ToolName   string
	ServerURI  *string
	Result     ToolResultScanResult
	SDKVersion string
}

// BuildToolResultScanBlock builds the receipt block for a completed scan.
func BuildToolResultScanBlock(params BuildToolResultScanBlockParams) ToolResultScanReceiptBlock {
	pii := toolResultCountsByType(params.Result.Findings, ToolResultFindingKindPII)
	injection := toolResultCountsByType(params.Result.Findings, ToolResultFindingKindInjection)

	block := ToolResultScanReceiptBlock{
		AttestedBy:       "client",
		Blocked:          params.Result.Blocked,
		CaptureMode:      "edge",
		Findings:         ToolResultScanFindingCounts{Injection: injection, PII: pii},
		InjectionRuleset: InjectionRuleset,
		Reason:           params.Result.Reason,
		SDKLanguage:      "go",
		SDKVersion:       params.SDKVersion,
		ServerURI:        params.ServerURI,
		ToolName:         params.ToolName,
		Totals:           ToolResultScanTotals{Injection: sumCounts(injection), PII: sumCounts(pii)},
	}

	return block
}

// ScanPIITypes returns the distinct PII types in a scan result, for the
// attestation canonical form.
func ScanPIITypes(findings []ToolResultFinding) []string {
	set := make(map[string]struct{})
	for _, f := range findings {
		if f.Kind == ToolResultFindingKindPII {
			set[f.Type] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// ScanPIICount returns the total PII match count in a scan result.
func ScanPIICount(findings []ToolResultFinding) int {
	n := 0
	for _, f := range findings {
		if f.Kind == ToolResultFindingKindPII {
			n += f.Count
		}
	}
	return n
}

// ScanInjectionCount returns the total injection match count in a scan
// result.
func ScanInjectionCount(findings []ToolResultFinding) int {
	n := 0
	for _, f := range findings {
		if f.Kind == ToolResultFindingKindInjection {
			n += f.Count
		}
	}
	return n
}
