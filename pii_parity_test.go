package tork

import (
	"encoding/json"
	"strings"
	"testing"
)

// declaredPIITypes is every PIIType constant this SDK declares. A declared
// type with no pattern is a false claim, so each one needs a positive and a
// negative example below and a live entry in defaultPatterns.
var declaredPIITypes = []PIIType{
	PIITypeSSN, PIITypeCreditCard, PIITypeEmail, PIITypePhone, PIITypeAddress,
	PIITypeIPAddress, PIITypeDOB, PIITypePassport, PIITypeDriversLicense, PIITypeBankAccount,
}

var piiExamples = map[PIIType]struct{ positive, negative string }{
	PIITypeSSN:            {"My SSN is 123-45-6789", "Order 123-456-789 shipped"},
	PIITypeCreditCard:     {"Card: 4111-1111-1111-1111", "Card: 4111-1111-1111"},
	PIITypeEmail:          {"Contact me at john@example.com", "john at example dot com"},
	PIITypePhone:          {"Call me at 555-123-4567", "Call extension 12345"},
	PIITypeAddress:        {"I live at 123 Main Street", "Main Street is lovely"},
	PIITypeIPAddress:      {"Server IP: 192.168.1.1", "Version 1.2.3 released"},
	PIITypeDOB:            {"DOB: 01/15/1990", "Date 13/45/1990"},
	PIITypePassport:       {"Passport AB1234567", "passport ab1234567"},
	PIITypeDriversLicense: {"License A1234567890", "license a1234567890"},
	PIITypeBankAccount:    {"Account number: 123456789012", "Account number: 1234567"},
}

func TestEachDeclaredPIITypeHasPositiveAndNegativeExample(t *testing.T) {
	patterned := map[PIIType]bool{}
	for _, p := range defaultPatterns {
		patterned[p.Type] = true
	}
	if len(piiExamples) != len(declaredPIITypes) {
		t.Fatalf("examples for %d types, declared %d", len(piiExamples), len(declaredPIITypes))
	}
	for _, typ := range declaredPIITypes {
		typ := typ
		t.Run(string(typ), func(t *testing.T) {
			if !patterned[typ] {
				t.Fatalf("declared type %q has no pattern", typ)
			}
			ex, ok := piiExamples[typ]
			if !ok {
				t.Fatalf("no examples for %q", typ)
			}
			if got := DetectPII(ex.positive); !containsType(got.Types, typ) {
				t.Errorf("positive %q: types %v, want %q", ex.positive, got.Types, typ)
			}
			if got := DetectPII(ex.negative); containsType(got.Types, typ) {
				t.Errorf("negative %q: types %v, must not contain %q", ex.negative, got.Types, typ)
			}
		})
	}
}

func TestSessionContextTelemetryFields(t *testing.T) {
	c := NewClient()
	id, role, sid, turn := "agent-7", "planner", "sess-1", 3
	res := c.GovernWithOptions("hello", GovernOptions{SessionContext: &SessionContext{
		AgentID: &id, AgentRole: &role, SessionID: &sid, SessionTurn: &turn,
	}})
	b, err := json.Marshal(res.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	sc, _ := m["session_context"].(map[string]any)
	if sc["agent_id"] != "agent-7" || sc["agent_role"] != "planner" || sc["session_id"] != "sess-1" || sc["session_turn"] != float64(3) {
		t.Errorf("session_context = %v", sc)
	}
}

func TestSessionContextOmittedWhenUnset(t *testing.T) {
	c := NewClient()
	b, _ := json.Marshal(c.GovernWithOptions("hello", GovernOptions{}).Receipt)
	if strings.Contains(string(b), "session_context") {
		t.Errorf("unset context must be omitted: %s", b)
	}
	// Partial: only set fields appear.
	sid := "s"
	b, _ = json.Marshal(c.GovernWithOptions("hello", GovernOptions{SessionContext: &SessionContext{SessionID: &sid}}).Receipt)
	s := string(b)
	if !strings.Contains(s, `"session_id":"s"`) || strings.Contains(s, "agent_id") || strings.Contains(s, "session_turn") {
		t.Errorf("partial context wrong: %s", s)
	}
}
