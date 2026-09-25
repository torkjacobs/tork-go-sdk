// Country-layer parity tests.
//
// The fixtures are generated from the cloud's own evidence, not written here:
//
//	pii_unit_cases.json  one valid sample per registry pattern, a
//	                     checksum-broken variant for each pattern whose
//	                     checksum is a gate, and the Indonesian boundary cases.
//	pii_vectors.json     all 2,092 inputs of the cloud's golden snapshot: every
//	                     country-corpus sentence for all 249 ISO jurisdictions,
//	                     and the whole 1,523-line business false-positive corpus.
//
// ExpectedOutput is the COUNTRY LAYER alone. Where the cloud's own output
// differs, the case carries CloudOutput and a Divergence naming the cause, so
// the fixture states its distance from the cloud instead of hiding it. There
// are exactly two causes and this suite asserts there are no others.

package tork

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/torkjacobs/tork-go-sdk/torkpii"
)

type unitCase struct {
	Pattern        string `json:"pattern"`
	Country        string `json:"country"`
	Label          string `json:"label"`
	Redaction      string `json:"redaction"`
	Input          string `json:"input"`
	Sample         string `json:"sample"`
	ExpectDetected bool   `json:"expectDetected"`
	Note           string `json:"note"`
}

type vector struct {
	ID              string   `json:"id"`
	Kind            string   `json:"kind"`
	Input           string   `json:"input"`
	ExpectedOutput  string   `json:"expectedOutput"`
	ExpectedRegions []string `json:"expectedRegions"`
	ExpectedLabels  []string `json:"expectedLabels"`
	ExpectedNames   []string `json:"expectedNames"`
	CloudOutput     string   `json:"cloudOutput"`
	Divergence      string   `json:"divergence"`
}

type vectorFile struct {
	BundleVersion string   `json:"bundleVersion"`
	ContentHash   string   `json:"contentHash"`
	Cases         []vector `json:"cases"`
}

func loadFixture(t *testing.T, name string, into any) {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(b, into); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
}

func vectors(t *testing.T) vectorFile {
	t.Helper()
	var v vectorFile
	loadFixture(t, "pii_vectors.json", &v)
	return v
}

func patternByName(name string) (torkpii.Pattern, bool) {
	for _, p := range torkpii.Patterns {
		if p.Name == name {
			return p, true
		}
	}
	return torkpii.Pattern{}, false
}

func redact(content string, matches []CountryPIIMatch) string {
	return ApplyRedactions(content, RedactionSpansOf(matches))
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func distinct(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ── the bundle ──────────────────────────────────────────────────────────────

func TestBundleIsTheVersionAndContentTheFixturesWereGeneratedFrom(t *testing.T) {
	v := vectors(t)
	if torkpii.RegistryVersion != v.BundleVersion {
		t.Errorf("registry version = %s, fixtures = %s", torkpii.RegistryVersion, v.BundleVersion)
	}
	if torkpii.ContentHash != v.ContentHash {
		t.Errorf("content hash = %s, fixtures = %s", torkpii.ContentHash, v.ContentHash)
	}
}

func TestBundleCarries54PatternsAcross24ProfilesWith51Signals(t *testing.T) {
	if len(torkpii.Patterns) != 54 {
		t.Errorf("patterns = %d, want 54", len(torkpii.Patterns))
	}
	if len(torkpii.Countries) != 24 {
		t.Errorf("countries = %d, want 24", len(torkpii.Countries))
	}
	if len(torkpii.Signals) != 51 {
		t.Errorf("signals = %d, want 51", len(torkpii.Signals))
	}
}

func TestBundleCoversIndonesia(t *testing.T) {
	var found bool
	for _, c := range torkpii.Countries {
		if c.Code == "ID" {
			found = true
			if len(c.Patterns) == 0 || c.Patterns[0] != "id_nik" {
				t.Errorf("ID patterns = %v, want id_nik", c.Patterns)
			}
		}
	}
	if !found {
		t.Fatal("Indonesia is missing from the bundle")
	}
	nik, ok := patternByName("id_nik")
	if !ok {
		t.Fatal("id_nik is missing from the bundle")
	}
	if nik.Label != "NIK" {
		t.Errorf("id_nik label = %s, want NIK", nik.Label)
	}
	if !strings.Contains(strings.Join(nik.WholeWordKeywords, ","), "nik") {
		t.Errorf("id_nik whole-word keywords = %v", nik.WholeWordKeywords)
	}
}

func TestWindowsComeFromTheBundleAndAreNotAllTheSameNumber(t *testing.T) {
	if KeywordWindowBefore != 60 || KeywordWindowAfter != 40 || ContextWindow != 60 {
		t.Errorf("windows = %d/%d/%d, want 60/40/60", KeywordWindowBefore, KeywordWindowAfter, ContextWindow)
	}
	if KeywordWindowBefore == KeywordWindowAfter {
		t.Error("the keyword window is asymmetric; these must differ")
	}
}

func TestEveryPatternThatDeclaresAChecksumNamesAFunction(t *testing.T) {
	for _, p := range torkpii.Patterns {
		if p.Checksum == "" {
			continue
		}
		if _, ok := ChecksumFunctions[p.Checksum]; !ok {
			t.Errorf("%s -> %s has no function", p.Name, p.Checksum)
		}
	}
}

func TestOnlyThePortableRegexSubsetIsUsed(t *testing.T) {
	forbidden := []struct{ re, why string }{
		{`\(\?=`, "lookahead"}, {`\(\?!`, "negative lookahead"}, {`\(\?<[=!]`, "lookbehind"},
		{`\\[1-9]`, "backreference"}, {`\\[pP]\{`, "unicode property escape"}, {`\(\?>`, "atomic group"},
	}
	sources := []string{}
	for _, p := range torkpii.Patterns {
		sources = append(sources, p.Regex)
	}
	for _, s := range torkpii.Signals {
		sources = append(sources, s.Regex)
	}
	for _, src := range sources {
		for _, f := range forbidden {
			if regexp.MustCompile(f.re).MatchString(src) {
				t.Errorf("%s uses %s", src, f.why)
			}
		}
	}
}

// ── per-pattern unit cases ──────────────────────────────────────────────────

func TestUnitCases(t *testing.T) {
	var cases []unitCase
	loadFixture(t, "pii_unit_cases.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no unit cases")
	}
	for _, c := range cases {
		name := c.Pattern + "/" + map[bool]string{true: "detects", false: "rejects"}[c.ExpectDetected]
		if c.Note != "" {
			name += "/" + strings.ReplaceAll(c.Note, " ", "_")
		}
		t.Run(name, func(t *testing.T) {
			p, ok := patternByName(c.Pattern)
			if !ok {
				t.Fatalf("%s is not in the bundle", c.Pattern)
			}
			found := DetectCountryPIIWithPatterns(c.Input, []torkpii.Pattern{p})
			var hit *CountryPIIMatch
			for i := range found {
				if found[i].Name == c.Pattern {
					hit = &found[i]
					break
				}
			}
			if c.ExpectDetected {
				if hit == nil {
					t.Fatalf("expected %s to match %q", c.Pattern, c.Input)
				}
				if got := c.Input[hit.StartIndex:hit.EndIndex]; got != c.Sample {
					t.Errorf("matched %q, want %q", got, c.Sample)
				}
				if hit.Redaction != c.Redaction {
					t.Errorf("redaction = %s, want %s", hit.Redaction, c.Redaction)
				}
			} else if hit != nil {
				t.Fatalf("expected %s NOT to match %q", c.Pattern, c.Input)
			}
		})
	}
}

// ── golden-snapshot parity ──────────────────────────────────────────────────

func TestCorpusVectors(t *testing.T) {
	v := vectors(t)
	for _, c := range v.Cases {
		if c.Kind == "business-fp" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			if got := InferRegions(c.Input); !eqStrings(got, c.ExpectedRegions) {
				t.Errorf("activation = %v, want %v", got, c.ExpectedRegions)
			}
			matches := DetectCountryPII(c.Input)
			if got := redact(c.Input, matches); got != c.ExpectedOutput {
				t.Errorf("redaction\n got %q\nwant %q", got, c.ExpectedOutput)
			}
			labels, names := []string{}, []string{}
			for _, m := range matches {
				labels = append(labels, m.Label)
				names = append(names, m.Name)
			}
			if got := distinct(labels); !eqStrings(got, c.ExpectedLabels) {
				t.Errorf("labels = %v, want %v", got, c.ExpectedLabels)
			}
			if got := distinct(names); !eqStrings(got, c.ExpectedNames) {
				t.Errorf("names = %v, want %v", got, c.ExpectedNames)
			}
		})
	}
}

func TestBusinessCorpusGetsNoFalsePositive(t *testing.T) {
	v := vectors(t)
	n := 0
	for _, c := range v.Cases {
		if c.Kind != "business-fp" {
			continue
		}
		n++
		if got := InferRegions(c.Input); !eqStrings(got, c.ExpectedRegions) {
			t.Errorf("%s: activation = %v, want %v", c.ID, got, c.ExpectedRegions)
		}
		if m := DetectCountryPII(c.Input); len(m) > 0 {
			t.Errorf("%s: false positive %v in %q", c.ID, m[0].Name, c.Input)
		}
	}
	if n < 1500 {
		t.Errorf("business corpus = %d lines, want > 1500", n)
	}
}

func TestDivergesFromTheCloudForOnlyTheL0Reason(t *testing.T) {
	v := vectors(t)
	gaps := map[string]bool{}
	for _, c := range v.Cases {
		if c.Divergence == "" {
			continue
		}
		if !strings.HasPrefix(c.Divergence, "L0:") && !strings.HasPrefix(c.Divergence, "BUNDLE GAP:") {
			t.Errorf("%s: unexplained divergence %q", c.ID, c.Divergence)
		}
		if strings.HasPrefix(c.Divergence, "BUNDLE GAP:") {
			gaps[strings.Split(c.ID, "/")[1]] = true
		}
	}
	// Bundle 1.2.0 ships au_tfn, au_abn and au_medicare as AlwaysOn patterns,
	// so the bundle-gap cause that used to name them is gone; only the
	// cloud-only L0 layer (SSN, credit card, email, etc.) remains.
	if len(gaps) != 0 {
		t.Errorf("bundle gaps = %v, want none", gaps)
	}
}

func TestNothingIsEverPartiallyRedacted(t *testing.T) {
	v := vectors(t)
	bad := regexp.MustCompile(`\d\[[A-Z_]+_REDACTED\]|\[[A-Z_]+_REDACTED\]\d`)
	for _, c := range v.Cases {
		matches := DetectCountryPII(c.Input)
		out := redact(c.Input, matches)
		if bad.MatchString(out) {
			t.Errorf("%s: digit beside a redaction token: %q", c.ID, out)
		}
		for _, m := range matches {
			if raw := c.Input[m.StartIndex:m.EndIndex]; strings.Contains(out, raw) {
				t.Errorf("%s: %q survived redaction", c.ID, raw)
			}
		}
	}
}

// ── Indonesia, the rule 1.1.0 added ─────────────────────────────────────────

const nik = "3171010101900001"

func TestIndonesiaShortSpellingIsAWholeWordKeyword(t *testing.T) {
	s := "NIK " + nik + " untuk pendaftaran rekening di Jakarta, Indonesia."
	if got := InferRegions(s); !eqStrings(got, []string{"ID"}) {
		t.Fatalf("regions = %v, want [ID]", got)
	}
	want := "NIK [NIK_REDACTED] untuk pendaftaran rekening di Jakarta, Indonesia."
	if got := redact(s, DetectCountryPII(s)); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestIndonesiaLongSpellingIsAnOrdinarySubstringKeyword(t *testing.T) {
	s := "Nomor Induk Kependudukan " + nik + " untuk pendaftaran."
	if got := redact(s, DetectCountryPII(s)); !strings.Contains(got, "[NIK_REDACTED]") {
		t.Errorf("got %q", got)
	}
}

func TestNikInsideAnOrdinaryIndonesianWordDoesNotOpenTheGate(t *testing.T) {
	for _, word := range []string{"teknik", "elektronik", "klinik", "pabrik", "piknik"} {
		s := "Faktur " + word + " " + nik + " untuk pelanggan."
		if m := DetectCountryPII(s); len(m) > 0 {
			t.Errorf("%q opened the gate", word)
		}
	}
}

func TestABareNikIsNotRedacted(t *testing.T) {
	if m := DetectCountryPII(nik); len(m) > 0 {
		t.Errorf("a bare NIK was redacted as %v", m[0].Name)
	}
}

// ── the rules 1.1.0 added to the SDK half of the contract ───────────────────

func TestRule6ChecksumFailingIdentifierIsRedactedGenerically(t *testing.T) {
	s := "South African ID number 8001015009088 for the FICA check."
	out := redact(s, DetectCountryPII(s))
	if strings.Contains(out, "8001015009088") {
		t.Errorf("released in clear: %q", out)
	}
	if !strings.Contains(out, "[NATIONAL_ID_REDACTED]") {
		t.Errorf("no near-miss redaction: %q", out)
	}
}

func TestRule7ColumnHeaderIsTheContextForABareValueCell(t *testing.T) {
	csv := strings.Join([]string{"Name,CNIC,City", "Ali,42201-1234567-1,Karachi",
		"Sana,42201-7654321-2,Lahore", "Omar,42201-1111111-3,Multan"}, "\n")
	if len(tableScopes(csv)) == 0 {
		t.Fatal("not recognised as a table")
	}
	if out := redact(csv, DetectCountryPII(csv)); strings.Contains(out, "42201-1234567-1") {
		t.Errorf("column header did not act as context: %q", out)
	}
}

func TestRule7GenericHeaderDoesNotActAsContext(t *testing.T) {
	csv := strings.Join([]string{"Name,Order ID Number,City", "Ali,42201-1234567-1,Karachi",
		"Sana,42201-7654321-2,Lahore", "Omar,42201-1111111-3,Multan"}, "\n")
	if m := DetectCountryPII(csv); len(m) > 0 {
		t.Errorf("a generic header opened the gate: %v", m[0].Name)
	}
}

func TestRule7bCloserCommercialLabelClosesTheGate(t *testing.T) {
	s := "Please do not send your CNIC. Use the job number 4220112345671."
	at := strings.Index(s, "4220112345671")
	if !LabelledAsReference(s, at, at+13, []string{"cnic"}) {
		t.Error("expected the job number to be labelled as a reference")
	}
	if out := redact(s, DetectCountryPII(s)); !strings.Contains(out, "4220112345671") {
		t.Errorf("an order number was redacted: %q", out)
	}
}

func TestRule7bCanOnlyCloseAGateNeverOpenOne(t *testing.T) {
	if m := DetectCountryPII("Order 12345678901234 with no identifier word anywhere."); len(m) > 0 {
		t.Errorf("rule 7b invented a redaction: %v", m[0].Name)
	}
}

func TestRule5CountryMatchSupersedesAWiderL0Range(t *testing.T) {
	s := "CPF 529.982.247-25 para a nota fiscal no Brasil."
	at := strings.Index(s, "529.982.247-25")
	res := DetectCountryPIIWithRanges(s, PatternsForRegions(InferRegions(s)), [][2]int{{at - 1, at + 14}})
	var got bool
	for _, m := range res.Matches {
		if m.Name == "br_cpf" {
			got = true
		}
	}
	if !got {
		t.Error("br_cpf did not match")
	}
	if len(res.SupersededRanges) != 1 {
		t.Errorf("superseded = %d, want 1", len(res.SupersededRanges))
	}
}

func TestWholeWordMatchingRespectsBoundaries(t *testing.T) {
	if !HasWholeWordContextAround("nik 123", 4, 7, []string{"nik"}) {
		t.Error("a whole-word nik was missed")
	}
	if HasWholeWordContextAround("teknik 123", 7, 10, []string{"nik"}) {
		t.Error("nik inside teknik opened the gate")
	}
}
