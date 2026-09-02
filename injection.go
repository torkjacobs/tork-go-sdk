package tork

import (
	"regexp"
	"sort"
)

// Prompt-injection heuristics for tool-result scanning (DECIDED-TACT2-V2-C).
//
// Ported verbatim from tork-js-sdk/src/tool-result-scan.ts. The regex
// SOURCES below are byte-identical to the JS patterns modulo syntax that
// differs only in how a regex literal is written, never in what it matches:
//
//   - JS /pattern/gi becomes Go "(?i)pattern" — Go's regexp (RE2) has no
//     separate flags argument, so case-insensitivity is an inline flag and
//     "global" match-all is just how FindAllString already behaves.
//   - JS /pattern/gim becomes Go "(?im)pattern" for the same reason.
//   - JS's forward slashes (https:\/\/) are unescaped in Go, since Go
//     regexp literals are not slash-delimited and \/ has no special meaning.
//
// No pattern here uses lookahead/lookbehind, so none needed a lookaround
// substitution: RE2 (which Go's regexp package uses, and which has no
// lookaround support at all) accepts every one of these patterns unchanged.

// InjectionHeuristicPrefix prefixes every injection finding's Type. Not
// cosmetic: these are regexes over untrusted text, so they carry false
// positives and false negatives, and the label travels with the finding
// into the receipt so a downstream reader can never mistake a pattern hit
// for a verified determination.
const InjectionHeuristicPrefix = "heuristic:"

// InjectionRuleset identifies this exact pattern set in receipts. Bump when
// the patterns change, so a receipt says which ruleset produced its counts.
// Every SDK mirroring this implementation must emit the SAME value for the
// same ruleset — it is a shared identifier, not a per-language one.
const InjectionRuleset = "tork-injection-heuristics-v1"

type injectionPattern struct {
	Type    string
	Pattern *regexp.Regexp
}

// injectionPatterns is conservative on purpose. Each pattern targets a
// phrase that has no plausible reason to appear in a legitimate tool
// result — a database row, a search hit, a file listing. Broader
// "suspicious language" matching would fire on ordinary documentation and
// support tickets, and an alert nobody believes is worse than no alert.
var injectionPatterns = []injectionPattern{
	// -- instruction override --------------------------------------------
	{
		Type:    "instruction_override",
		Pattern: regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|earlier|above|preceding|all|any)\b[^.\n]{0,30}\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines)\b`),
	},
	{
		Type:    "instruction_override",
		Pattern: regexp.MustCompile(`(?i)\b(?:the\s+)?(?:instructions?|prompts?|rules?)\s+(?:above|below|before\s+this)\s+(?:are|is)\s+(?:now\s+)?(?:void|invalid|obsolete|outdated|no\s+longer\s+(?:valid|active|in\s+effect))\b`),
	},
	{
		Type:    "instruction_override",
		Pattern: regexp.MustCompile(`(?i)\bdisregard\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|guidelines?)\b`),
	},

	// -- role reassignment ------------------------------------------------
	{
		Type:    "role_reassignment",
		Pattern: regexp.MustCompile(`(?i)\byou\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\b`),
	},
	{
		Type:    "role_reassignment",
		Pattern: regexp.MustCompile(`(?i)\b(?:from\s+now\s+on|starting\s+now|for\s+the\s+rest\s+of\s+this\s+(?:conversation|session))\b[^.\n]{0,30}\byou\s+(?:are|will|must|should)\b`),
	},
	{
		Type:    "role_reassignment",
		Pattern: regexp.MustCompile(`(?i)\bnew\s+(?:system\s+)?(?:instructions?|prompt|persona|role)\s*:`),
	},
	{
		Type:    "role_reassignment",
		Pattern: regexp.MustCompile(`(?i)\b(?:enable|enter|activate|switch\s+to)\s+(?:developer|god|dan|jailbreak|unrestricted)\s+mode\b`),
	},
	{
		Type:    "role_reassignment",
		Pattern: regexp.MustCompile(`(?i)\b(?:act|behave|respond|pretend\s+to\s+be)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:dan|unrestricted|unfiltered|uncensored|jailbroken)\b`),
	},
	{
		// A role header smuggled into content -- "system:" / "<|im_start|>system"
		// at the start of a line is a conversation-structure forgery, not prose.
		Type:    "role_reassignment",
		Pattern: regexp.MustCompile(`(?im)^[ \t>*-]*(?:<\|im_start\|>\s*)?(?:system|assistant|developer)\s*(?::|\]|>)`),
	},

	// -- exfiltration -----------------------------------------------------
	{
		// A markdown image/link whose URL carries the content out as a query
		// parameter -- the classic zero-click exfiltration shape.
		Type:    "exfiltration_url",
		Pattern: regexp.MustCompile(`(?i)!?\[[^\]\n]*\]\(\s*https?://[^)\s]*[?&][^)\s]*(?:data|payload|prompt|content|text|secret|token|key|conversation|history)=[^)\s]*\)`),
	},
	{
		Type:    "exfiltration_url",
		Pattern: regexp.MustCompile(`(?i)\bhttps?://\S*[?&](?:data|payload|secret|token|api[_-]?key|apikey|password|credential|conversation|history)=`),
	},
	{
		Type:    "exfiltration_url",
		Pattern: regexp.MustCompile(`(?i)\b(?:send|post|upload|forward|transmit|exfiltrate|leak|report)\b[^.\n]{0,60}\bto\s+https?://\S+`),
	},
}

// InjectionTypes lists the distinct injection types the ruleset can emit,
// for documentation/tests: exfiltration_url, instruction_override,
// role_reassignment.
var InjectionTypes = func() []string {
	set := make(map[string]struct{}, 3)
	for _, p := range injectionPatterns {
		set[p.Type] = struct{}{}
	}
	types := make([]string, 0, len(set))
	for t := range set {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}()
