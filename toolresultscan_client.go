package tork

import (
	"encoding/json"
	"time"
)

// ScanToolResultResult is the result of Client.ScanToolResult: the scan
// result (Sanitized, Findings, Blocked, Reason) plus the Receipt that
// records it.
type ScanToolResultResult struct {
	Sanitized interface{}
	Findings  []ToolResultFinding
	Blocked   bool
	// Reason is set only when Blocked is true.
	Reason  string
	Receipt Receipt
}

// toolResultScanAction applies the four-way action mapping shared with the
// JS and Python SDKs: blocked -> deny, an injection finding present ->
// escalate, otherwise a PII finding present -> redact, otherwise -> allow.
// Injection takes priority over PII when a scan contains both, matching a
// payload that is both leaking data and carrying an attempted takeover.
func toolResultScanAction(scan ToolResultScanResult) Action {
	if scan.Blocked {
		return ActionDeny
	}

	hasInjection := false
	hasPII := false
	for _, f := range scan.Findings {
		switch f.Kind {
		case ToolResultFindingKindInjection:
			hasInjection = true
		case ToolResultFindingKindPII:
			hasPII = true
		}
	}

	if hasInjection {
		return ActionEscalate
	}
	if hasPII {
		return ActionRedact
	}
	return ActionAllow
}

// hashJSONForReceipt hashes a JSON-shaped value the same way Govern hashes
// its input/output strings: HashText over a canonical text form. Go's
// encoding/json sorts map keys when marshaling, so this is deterministic
// for the same logical value regardless of the source map's iteration
// order.
//
// NOTE (Go-specific, not part of the byte-identical tool_result_scan block
// contract): the JS SDK's Tork#scanToolResult method that produces
// receipt.inputHash/outputHash for a scan is not part of this port's
// reference material (only tool-result-scan.ts, pii.ts and their tests
// were in scope). Hashing a JSON encoding of the payload/sanitized value is
// this SDK's own choice for those two Receipt-level fields, consistent
// with how Govern already hashes text -- it does not affect the
// tool_result_scan block itself, which carries counts only.
func hashJSONForReceipt(value interface{}) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return HashText("")
	}
	return HashText(string(encoded))
}

// ScanToolResult scans a tool result for PII and prompt injection, then
// records the scan as a governance Receipt carrying a tool_result_scan
// block (attested_by="client", capture_mode="edge").
//
// The action on the returned receipt follows the four-way mapping in
// toolResultScanAction. Statistics (Client.GetStats) are updated exactly as
// Govern updates them: one call, one PII-detected flag, one action tally.
func (c *Client) ScanToolResult(input ToolResultScanInput, opts ToolResultScanOptions) ScanToolResultResult {
	start := time.Now()

	scan := ScanToolResult(input, opts)
	action := toolResultScanAction(scan)

	var outputHash string
	if scan.Blocked {
		// No output hash of content: nothing was produced to hash.
		outputHash = HashText("")
	} else {
		outputHash = hashJSONForReceipt(scan.Sanitized)
	}

	cfg := c.snapshotConfig()
	processingTimeNs := time.Since(start).Nanoseconds()

	receipt := Receipt{
		ID:               GenerateReceiptID(),
		Timestamp:        time.Now().UTC(),
		InputHash:        hashJSONForReceipt(input.Payload),
		OutputHash:       outputHash,
		Action:           action,
		PIITypes:         piiTypesFromFindings(scan.Findings),
		PIICount:         ScanPIICount(scan.Findings),
		PolicyVersion:    cfg.PolicyVersion,
		ProcessingTimeNs: processingTimeNs,
	}
	block := BuildToolResultScanBlock(BuildToolResultScanBlockParams{
		ToolName:   input.ToolName,
		ServerURI:  input.ServerURI,
		Result:     scan,
		SDKVersion: SDKVersion,
	})
	receipt.ToolResultScan = &block

	c.recordCall(action, ScanPIICount(scan.Findings) > 0, processingTimeNs)

	return ScanToolResultResult{
		Sanitized: scan.Sanitized,
		Findings:  scan.Findings,
		Blocked:   scan.Blocked,
		Reason:    scan.Reason,
		Receipt:   receipt,
	}
}

func piiTypesFromFindings(findings []ToolResultFinding) []PIIType {
	strs := ScanPIITypes(findings)
	types := make([]PIIType, len(strs))
	for i, s := range strs {
		types[i] = PIIType(s)
	}
	return types
}
