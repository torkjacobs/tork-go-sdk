package tork

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Action represents a governance action
type Action string

const (
	ActionAllow    Action = "allow"
	ActionDeny     Action = "deny"
	ActionRedact   Action = "redact"
	ActionEscalate Action = "escalate"
)

// Receipt represents a cryptographic governance receipt
type Receipt struct {
	ID              string    `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	InputHash       string    `json:"input_hash"`
	OutputHash      string    `json:"output_hash"`
	Action          Action    `json:"action"`
	PIITypes        []PIIType `json:"pii_types"`
	PIICount        int       `json:"pii_count"`
	PolicyVersion   string    `json:"policy_version"`
	ProcessingTimeNs int64    `json:"processing_time_ns"`
}

// GenerateReceiptID creates a unique receipt ID
func GenerateReceiptID() string {
	return fmt.Sprintf("rcpt_%s", uuid.New().String()[:32])
}

// HashText generates a SHA256 hash of the input text
func HashText(text string) string {
	hash := sha256.Sum256([]byte(text))
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(hash[:]))
}

// GenerateReceipt creates a new governance receipt
func GenerateReceipt(input, output string, action Action, piiTypes []PIIType, piiCount int, policyVersion string, processingTimeNs int64) Receipt {
	return Receipt{
		ID:               GenerateReceiptID(),
		Timestamp:        time.Now().UTC(),
		InputHash:        HashText(input),
		OutputHash:       HashText(output),
		Action:           action,
		PIITypes:         piiTypes,
		PIICount:         piiCount,
		PolicyVersion:    policyVersion,
		ProcessingTimeNs: processingTimeNs,
	}
}

// String returns the action as a string
func (a Action) String() string {
	return string(a)
}

// Verify checks if the receipt hashes match the provided input/output
func (r *Receipt) Verify(input, output string) bool {
	return r.InputHash == HashText(input) && r.OutputHash == HashText(output)
}
