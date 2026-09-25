// The country layer: 24 country profiles, 51 patterns, 20 check digits.
//
// This implements the seven rules that generated/sdk-registry/README.md marks
// SDK, from the bundle alone. Bundle 1.1.0 carries the data all seven need --
// the activation signals, the country map, the three windows, the whole-word
// vocabulary, the near-miss policy, the table constants and the reference
// labels -- so nothing here is hand-written registry data and no window is
// hard-coded. The bundle itself is the torkpii subpackage, byte-identical to
// landing/generated/sdk-registry/go/pii_registry.go.
//
//	1. ACTIVATE   a country's patterns run only when one of its signals fires.
//	2. MATCH      the regex, case-sensitively, globally.
//	3. KEYWORD    whole-word (symmetric ContextWindow) or column verdict or the
//	              ASYMMETRIC substring window (60 before, 40 after); then 7b may
//	              close the gate again.
//	4. CHECKSUM   when required. Advisory checksums never reject.
//	5. SUPERSEDE  a match containing every range it overlaps takes them.
//	6. NEAR MISS  a checksum-failing identifier is redacted generically.
//	7. COLUMN     in a delimited table a bare value cell is judged by its header.
//	7b. NEAREST LABEL  a closer commercial label closes the gate.
//
// Still cloud-only, by design: the universal (L0) patterns, the slot, context,
// gravity and name layers, industry profiles and org configuration.
//
// Offsets are BYTE offsets, matching Go's regexp package.

package tork

import (
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/torkjacobs/tork-go-sdk/torkpii"
)

// Window constants, read from the bundle rather than restated here.
const (
	// KeywordWindowBefore is the characters before a match that count as nearby.
	KeywordWindowBefore = torkpii.KeywordWindowBefore
	// KeywordWindowAfter is the characters after a match that count. It is
	// deliberately NOT the same number as KeywordWindowBefore.
	KeywordWindowAfter = torkpii.KeywordWindowAfter
	// ContextWindow is the symmetric window: whole-word keywords and near misses.
	ContextWindow = torkpii.ContextWindow
)

// RegistryVersion and ContentHash identify the bundle this SDK shipped.
const (
	RegistryVersion = torkpii.RegistryVersion
	ContentHash     = torkpii.ContentHash
)

// CountryPIIMatch is one country identifier found in the content.
type CountryPIIMatch struct {
	// Name is the registry pattern name, e.g. "za_id_number".
	Name string
	// Country is ISO 3166-1 alpha-2, or "EU" for the bloc profile. Empty for a near miss.
	Country string
	// Label is the shared redaction label. The receipt block hashes labels.
	Label string
	// Type is the registry type, or "national_id_near_miss" for a rule 6 span.
	Type       string
	Redaction  string
	StartIndex int
	EndIndex   int
}

type tableScope struct {
	start, end       int
	header           string
	rowStart, rowEnd int
}

var (
	once             sync.Once
	compiled         map[string]*regexp.Regexp
	patternsByName   map[string]torkpii.Pattern
	compiledSignals  []*regexp.Regexp
	signalOrder      []string
	signalsByCountry map[string][]int
	countryPatterns  map[string][]string
	nationalIDWords  []string
	genericSet       map[string]struct{}
)

func initRegistry() {
	once.Do(func() {
		compiled = make(map[string]*regexp.Regexp, len(torkpii.Patterns))
		patternsByName = make(map[string]torkpii.Pattern, len(torkpii.Patterns))
		for _, p := range torkpii.Patterns {
			compiled[p.Name] = regexp.MustCompile(p.Regex)
			patternsByName[p.Name] = p
		}
		compiledSignals = make([]*regexp.Regexp, len(torkpii.Signals))
		signalsByCountry = make(map[string][]int)
		for i, s := range torkpii.Signals {
			src := s.Regex
			if strings.Contains(s.Flags, "i") {
				src = "(?i)" + src
			}
			compiledSignals[i] = regexp.MustCompile(src)
			if _, seen := signalsByCountry[s.Country]; !seen {
				signalOrder = append(signalOrder, s.Country)
			}
			signalsByCountry[s.Country] = append(signalsByCountry[s.Country], i)
		}
		countryPatterns = make(map[string][]string, len(torkpii.Countries))
		for _, c := range torkpii.Countries {
			countryPatterns[c.Code] = c.Patterns
		}
		nationalIDWords = append(append([]string{}, torkpii.GenericIDKeywords...), torkpii.LocalIDKeywords...)
		genericSet = make(map[string]struct{}, len(torkpii.GenericIDKeywords))
		for _, k := range torkpii.GenericIDKeywords {
			genericSet[k] = struct{}{}
		}
	})
}

func isAlnumASCII(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z')
}

// allKeywordsOf is a pattern's whole vocabulary: substring and whole-word.
func allKeywordsOf(p torkpii.Pattern) []string {
	if len(p.WholeWordKeywords) == 0 {
		return p.Keywords
	}
	return append(append([]string{}, p.Keywords...), p.WholeWordKeywords...)
}

// specificKeywords is the half of a vocabulary naming ONE country's identifier.
func specificKeywords(keywords []string) []string {
	out := make([]string, 0, len(keywords))
	for _, k := range keywords {
		if _, generic := genericSet[k]; !generic {
			out = append(out, k)
		}
	}
	return out
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// hasNearbyContext is rule 3's substring half: ASYMMETRIC, 60 before, 40 after.
func hasNearbyContext(content string, start, end int, keywords []string) bool {
	before := strings.ToLower(content[clamp(start-KeywordWindowBefore, 0, len(content)):start])
	after := strings.ToLower(content[end:clamp(end+KeywordWindowAfter, 0, len(content))])
	for _, kw := range keywords {
		if strings.Contains(before, kw) || strings.Contains(after, kw) {
			return true
		}
	}
	return false
}

// hasContextAround is the symmetric ContextWindow, substring. Used by rule 6.
func hasContextAround(content string, start, end int, keywords []string) bool {
	w := strings.ToLower(content[clamp(start-ContextWindow, 0, len(content)):clamp(end+ContextWindow, 0, len(content))])
	for _, kw := range keywords {
		if strings.Contains(w, kw) {
			return true
		}
	}
	return false
}

// HasWholeWordContextAround is rule 3's whole-word half: symmetric
// ContextWindow with a boundary on each side, a boundary being "not a letter
// or digit".
//
// This is the gate Indonesia needs: "nik" sits inside teknik, elektronik,
// klinik and pabrik, so a substring test would open the gate on a sales ledger.
func HasWholeWordContextAround(content string, start, end int, words []string) bool {
	if len(words) == 0 {
		return false
	}
	w := strings.ToLower(content[clamp(start-ContextWindow, 0, len(content)):clamp(end+ContextWindow, 0, len(content))])
	for _, word := range words {
		from := 0
		for {
			i := strings.Index(w[from:], word)
			if i < 0 {
				break
			}
			i += from
			beforeOK := i == 0 || !isAlnumASCII(w[i-1])
			j := i + len(word)
			afterOK := j >= len(w) || !isAlnumASCII(w[j])
			if beforeOK && afterOK {
				return true
			}
			from = i + 1
		}
	}
	return false
}

func documentHasWholeWord(content string, words []string) bool {
	if len(words) == 0 {
		return false
	}
	return HasWholeWordContextAround(content, 0, len(content), words)
}

// InferRegions returns the countries this text activates, in the bundle's
// signal order. Pure and local: no network, no clock.
func InferRegions(content string) []string {
	initRegistry()
	regions := []string{}
	lower := strings.ToLower(content)
	for _, code := range signalOrder {
		for _, idx := range signalsByCountry[code] {
			s := torkpii.Signals[idx]
			if !compiledSignals[idx].MatchString(content) {
				continue
			}
			bySubstring := false
			for _, k := range s.Keywords {
				if strings.Contains(lower, k) {
					bySubstring = true
					break
				}
			}
			byWholeWord := documentHasWholeWord(content, s.WholeWordKeywords)
			// Both lists empty means the shape alone is distinctive enough.
			if (len(s.Keywords) > 0 || len(s.WholeWordKeywords) > 0) && !bySubstring && !byWholeWord {
				continue
			}
			target := s.Activates
			if target == "" {
				target = code
			}
			seen := false
			for _, r := range regions {
				if r == target {
					seen = true
					break
				}
			}
			if !seen {
				regions = append(regions, target)
			}
			break // one signal per country is enough
		}
	}
	return regions
}

// PatternsForRegions returns the patterns those regions switch on, in registry
// order, preceded by the AlwaysOn patterns (bundle 1.2.0's AU TFN/ABN/Medicare):
// rule 1a runs those unconditionally, whether or not any region activated.
func PatternsForRegions(regions []string) []torkpii.Pattern {
	initRegistry()
	out := []torkpii.Pattern{}
	seen := map[string]bool{}
	for _, p := range torkpii.Patterns {
		if p.AlwaysOn && !seen[p.Name] {
			seen[p.Name] = true
			out = append(out, p)
		}
	}
	for _, code := range regions {
		for _, name := range countryPatterns[strings.ToUpper(code)] {
			if seen[name] {
				continue
			}
			p, ok := patternsByName[name]
			if !ok {
				continue
			}
			seen[name] = true
			out = append(out, p)
		}
	}
	return out
}

// ── rule 7: the column is the context ───────────────────────────────────────

var (
	headerHasLetter   = regexp.MustCompile(`[A-Za-z\x{00C0}-\x{FFFF}]`)
	headerAllNumeric  = regexp.MustCompile(`^\+?[\d\s.\-/]+$`)
	headerHasSentence = regexp.MustCompile(`[.?!]`)
	whitespaceRun     = regexp.MustCompile(`\s+`)
)

func looksLikeHeader(cells []string, delimiter string) bool {
	minimum := 2
	if delimiter == "," {
		minimum = torkpii.TableMinCommaColumns
	}
	if len(cells) < minimum {
		return false
	}
	for _, c := range cells {
		t := strings.TrimSpace(c)
		if t == "" || len(t) > torkpii.TableMaxHeaderLength {
			return false
		}
		if !headerHasLetter.MatchString(t) || headerAllNumeric.MatchString(t) || headerHasSentence.MatchString(t) {
			return false
		}
		if len(whitespaceRun.Split(t, -1)) > torkpii.TableMaxHeaderWords {
			return false
		}
	}
	return true
}

// tableScopes returns the cells of content when it is a delimited table.
func tableScopes(content string) []tableScope {
	lines := strings.Split(content, "\n")
	if len(lines) < torkpii.TableMinRows {
		return nil
	}
	offsets := make([]int, len(lines))
	at := 0
	for i, line := range lines {
		offsets[i] = at
		at += len(line) + 1
	}
	for _, delimiter := range torkpii.TableDelimiters {
		headerCells := strings.Split(lines[0], delimiter)
		if !looksLikeHeader(headerCells, delimiter) {
			continue
		}
		width := len(headerCells)
		dataRows := []int{}
		for i := 1; i < len(lines); i++ {
			if strings.TrimSpace(lines[i]) == "" {
				continue
			}
			if len(strings.Split(lines[i], delimiter)) != width {
				return nil
			}
			dataRows = append(dataRows, i)
		}
		if len(dataRows) < torkpii.TableMinRows-1 {
			continue
		}
		scopes := []tableScope{}
		for _, row := range dataRows {
			cells := strings.Split(lines[row], delimiter)
			rowStart := offsets[row]
			rowEnd := rowStart + len(lines[row])
			cellStart := rowStart
			for col := 0; col < width; col++ {
				scopes = append(scopes, tableScope{
					start: cellStart, end: cellStart + len(cells[col]),
					header:   strings.ToLower(strings.TrimSpace(headerCells[col])),
					rowStart: rowStart, rowEnd: rowEnd,
				})
				cellStart += len(cells[col]) + len(delimiter)
			}
		}
		return scopes
	}
	return nil
}

// headerNames is a whole-word match, not a substring.
func headerNames(header string, keywords []string) bool {
	for _, kw := range keywords {
		i := strings.Index(header, kw)
		if i < 0 {
			continue
		}
		beforeOK := i == 0 || !isAlnumASCII(header[i-1])
		j := i + len(kw)
		afterOK := j >= len(header) || !isAlnumASCII(header[j])
		if beforeOK && afterOK {
			return true
		}
	}
	return false
}

// columnVerdict returns nil when the window should be consulted as usual.
func columnVerdict(content string, scopes []tableScope, start, end int, all, specific []string) *bool {
	if len(scopes) == 0 {
		return nil
	}
	var cell *tableScope
	for i := range scopes {
		if start >= scopes[i].start && end <= scopes[i].end {
			cell = &scopes[i]
			break
		}
	}
	if cell == nil {
		return nil
	}
	// A cell whose own row names the identifier is prose in a delimited block.
	rowText := strings.ToLower(content[cell.rowStart:cell.rowEnd])
	for _, k := range all {
		if strings.Contains(rowText, k) {
			return nil
		}
	}
	v := len(specific) > 0 && headerNames(cell.header, specific)
	return &v
}

// ── rule 7b: nearest label wins ─────────────────────────────────────────────

func closestBefore(before string, keywords []string) int {
	best := -1
	for _, kw := range keywords {
		i := strings.LastIndex(before, kw)
		if i < 0 {
			continue
		}
		d := len(before) - (i + len(kw))
		if best < 0 || d < best {
			best = d
		}
	}
	return best
}

func closestAfter(after string, keywords []string) int {
	best := -1
	for _, kw := range keywords {
		i := strings.Index(after, kw)
		if i < 0 {
			continue
		}
		if best < 0 || i < best {
			best = i
		}
	}
	return best
}

// LabelledAsReference reports whether the number is labelled as a commercial
// reference more closely than as an identifier. It can only ever close a gate.
func LabelledAsReference(content string, start, end int, identifierKeywords []string) bool {
	before := strings.ToLower(content[clamp(start-torkpii.LabelWindow, 0, len(content)):start])
	ref := closestBefore(before, torkpii.ReferenceLabels)
	if ref < 0 || ref > torkpii.LabelReach {
		return false
	}
	if len(identifierKeywords) == 0 {
		return true
	}
	if idBefore := closestBefore(before, identifierKeywords); idBefore >= 0 && idBefore <= ref {
		return false
	}
	after := strings.ToLower(content[end:clamp(end+torkpii.LabelWindow, 0, len(content))])
	if idAfter := closestAfter(after, identifierKeywords); idAfter >= 0 && idAfter <= ref {
		return false
	}
	return true
}

// ── the pass ────────────────────────────────────────────────────────────────

// trimmedCore is the span with leading and trailing non-alphanumerics removed.
func trimmedCore(content string, start, end int) (int, int) {
	s, e := start, end
	for s < e && !isAlnumASCII(content[s]) {
		s++
	}
	for e > s && !isAlnumASCII(content[e-1]) {
		e--
	}
	if s == e {
		return start, end
	}
	return s, e
}

type span struct{ start, end int }

// CountryPIIResult carries the matches and, for rule 5, the caller's own L0
// ranges that a country match superseded.
type CountryPIIResult struct {
	Matches          []CountryPIIMatch
	SupersededRanges [][2]int
}

// DetectCountryPII returns the country matches for content, de-overlapped and
// ordered by position.
func DetectCountryPII(content string) []CountryPIIMatch {
	return DetectCountryPIIWithRanges(content, PatternsForRegions(InferRegions(content)), nil).Matches
}

// DetectCountryPIIWithPatterns runs an explicit pattern set, bypassing activation.
func DetectCountryPIIWithPatterns(content string, active []torkpii.Pattern) []CountryPIIMatch {
	return DetectCountryPIIWithRanges(content, active, nil).Matches
}

// DetectCountryPIIWithRanges is the full pass. Pass your own L0 spans as
// existingRanges so rule 5 can supersede them, and read SupersededRanges back.
func DetectCountryPIIWithRanges(content string, active []torkpii.Pattern, existingRanges [][2]int) CountryPIIResult {
	initRegistry()
	if len(active) == 0 {
		return CountryPIIResult{Matches: []CountryPIIMatch{}}
	}

	tables := tableScopes(content)
	activeExisting := append([][2]int{}, existingRanges...)
	superseded := [][2]int{}
	claimed := []span{}
	found := []CountryPIIMatch{}
	nearMisses := []span{}

	for _, pattern := range active {
		for _, loc := range compiled[pattern.Name].FindAllStringIndex(content, -1) {
			start, end := loc[0], loc[1]
			if start == end {
				continue
			}

			// Rules 3, 7 and 7b.
			if pattern.RequiresKeyword && len(pattern.Keywords) > 0 {
				all := allKeywordsOf(pattern)
				ok := HasWholeWordContextAround(content, start, end, pattern.WholeWordKeywords)
				if !ok {
					if v := columnVerdict(content, tables, start, end, all, specificKeywords(all)); v != nil {
						ok = *v
					} else {
						ok = hasNearbyContext(content, start, end, pattern.Keywords)
					}
				}
				if !ok {
					continue
				}
				if LabelledAsReference(content, start, end, pattern.Keywords) {
					continue
				}
			}

			// Rule 4, and rule 6's candidate.
			if pattern.ChecksumRequired && pattern.Checksum != "" {
				if fn, ok := ChecksumFunctions[pattern.Checksum]; ok && !fn(content[start:end]) {
					if pattern.NearMissFallback {
						vocabulary := nationalIDWords
						extra := pattern.NearMissKeywords
						if len(extra) == 0 {
							extra = pattern.Keywords
						}
						if len(extra) > 0 {
							vocabulary = append(append([]string{}, nationalIDWords...), extra...)
						}
						if hasContextAround(content, start, end, vocabulary) {
							nearMisses = append(nearMisses, span{start, end})
						}
					}
					continue
				}
			}

			// Rule 5.
			overlapping := []span{}
			for _, r := range activeExisting {
				if start < r[1] && end > r[0] {
					overlapping = append(overlapping, span{r[0], r[1]})
				}
			}
			for _, c := range claimed {
				if start < c.end && end > c.start {
					overlapping = append(overlapping, c)
				}
			}
			if len(overlapping) > 0 {
				supersedesAll := true
				for _, o := range overlapping {
					cs, ce := trimmedCore(content, o.start, o.end)
					if !(start <= cs && end >= ce) {
						supersedesAll = false
						break
					}
				}
				if !supersedesAll {
					continue
				}
				for _, o := range overlapping {
					for i, r := range activeExisting {
						if r[0] == o.start && r[1] == o.end {
							superseded = append(superseded, r)
							activeExisting = append(activeExisting[:i], activeExisting[i+1:]...)
							break
						}
					}
					for i, c := range claimed {
						if c == o {
							claimed = append(claimed[:i], claimed[i+1:]...)
							break
						}
					}
					for i, f := range found {
						if f.StartIndex == o.start && f.EndIndex == o.end {
							found = append(found[:i], found[i+1:]...)
							break
						}
					}
				}
			}

			claimed = append(claimed, span{start, end})
			found = append(found, CountryPIIMatch{
				Name: pattern.Name, Country: pattern.Country, Label: pattern.Label,
				Type: pattern.Type, Redaction: pattern.Redaction,
				StartIndex: start, EndIndex: end,
			})
		}
	}

	// Rule 6, last: a near miss can only ever fill a hole.
	taken := append([]span{}, claimed...)
	for _, r := range activeExisting {
		taken = append(taken, span{r[0], r[1]})
	}
	for _, c := range nearMisses {
		clash := false
		for _, t := range taken {
			if c.start < t.end && c.end > t.start {
				clash = true
				break
			}
		}
		if clash {
			continue
		}
		taken = append(taken, c)
		found = append(found, CountryPIIMatch{
			Name: torkpii.NearMissType, Country: "", Label: "NATIONAL_ID",
			Type: torkpii.NearMissType, Redaction: torkpii.NearMissRedaction,
			StartIndex: c.start, EndIndex: c.end,
		})
	}

	sort.SliceStable(found, func(i, j int) bool { return found[i].StartIndex < found[j].StartIndex })
	return CountryPIIResult{Matches: found, SupersededRanges: superseded}
}

// RedactionSpan is a span of the original text and the token that replaces it.
type RedactionSpan struct {
	StartIndex int
	EndIndex   int
	Redaction  string
}

// RedactionSpansOf turns country matches into redaction spans.
func RedactionSpansOf(matches []CountryPIIMatch) []RedactionSpan {
	spans := make([]RedactionSpan, len(matches))
	for i, m := range matches {
		spans[i] = RedactionSpan{m.StartIndex, m.EndIndex, m.Redaction}
	}
	return spans
}

// ApplyRedactions replaces every span with its redaction, right to left.
//
// Right to left is what keeps the earlier indices valid, and splicing whole
// spans in one pass is what guarantees no partial redaction: a digit can never
// be left standing beside a redaction token, because nothing is ever matched
// against text a previous replacement has already rewritten.
//
// spans must not overlap. DetectCountryPII guarantees that.
func ApplyRedactions(text string, spans []RedactionSpan) string {
	if len(spans) == 0 {
		return text
	}
	ordered := append([]RedactionSpan{}, spans...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].StartIndex < ordered[j].StartIndex })
	out := text
	for i := len(ordered) - 1; i >= 0; i-- {
		s := ordered[i]
		out = out[:s.StartIndex] + s.Redaction + out[s.EndIndex:]
	}
	return out
}
