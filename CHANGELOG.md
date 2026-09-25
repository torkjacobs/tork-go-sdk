# Changelog

## v0.4.0 - 2026-09-25

### Added
- **PII registry bundle 1.2.0 (24 countries, incl. AU TFN/ABN/Medicare).**
  Patterns, keywords, redaction labels and checksum gates are generated from
  Tork's own country registry and consumed verbatim from the SDK bundle
  (`Registry-Version: 1.2.0`, content `cfd4f61ebaf45e74`). Countries: AU, US, GB, EU, AE, SA, NG, IN, JP,
  CN, KR, BR, CA, ZA, GH, IT, KE, MU, MX, MY, PK, SG, TH, ID. Australia's TFN,
  ABN and Medicare number are AlwaysOn patterns: they run unconditionally,
  before any country activates, via `PatternsForRegions`.
- New exported API, all pure and local: `DetectCountryPII`,
  `DetectCountryPIIWithPatterns`, `InferRegions`, `PatternsForRegions`,
  `ApplyRedactions`, `DetectPIIInRegions`, `ChecksumFunctions`, `Patterns`,
  `Signals`, `RegistryVersion`, `KeywordWindowBefore`, `KeywordWindowAfter`,
  and the `CountryPIIMatch` / `RedactionSpan` types.
- `PIIResult` gains `CountryMatches`, `CountryLabels` and `Regions`. Nothing was
  removed or renamed; `DetectPII`, `DetectPIIWithPatterns`, `RedactPII` and
  `ContainsPII` keep their signatures. `DetectPIIWithPatterns` deliberately does
  NOT apply the country layer: a caller supplying its own pattern set is asking
  for exactly that set.
- **Nine check digits ported by hand.** The bundle names twenty algorithms and
  specifies the eleven that reduce to a weight vector and a modulus; the other
  nine (`br_cpf`, `br_cnpj`, `cn_resident_id`, `de_steuer_id`, `fr_nir`,
  `it_codice_fiscale`, `jp_my_number`, `kr_rrn`, `sg_nric`) are ported from the
  cloud's `lib/pii/checksums.ts`, each tested against the issuing authority's
  own worked example where one is published.

### Fixed
- **SDK-GO-PARTIAL-REDACTION.** Until v0.3.0 each pattern was redacted with its
  own `ReplaceAllString` over text a previous pattern had already rewritten,
  while `Matches` carried indices into the *original* text. Two patterns
  matching overlapping spans could leave half an identifier standing beside a
  redaction token -- digits exposed in output the caller had been told was
  redacted. Matches are now collected against the original text, overlaps are
  resolved before anything is rewritten, and the surviving spans are spliced
  right to left in one pass. `TestNoPartialRedaction` asserts the invariant
  across all 2,092 vectors.
- **README install path.** The README told readers to
  `go get github.com/torknetwork/tork-go-sdk`, which does not exist. The module
  is, and has always been, `github.com/torkjacobs/tork-go-sdk` -- the path in
  `go.mod` and the one published on proxy.golang.org. Eleven occurrences fixed.

### Notes
- **The bundle now states the whole contract, and this SDK implements it.**
  Bundle 1.0.0's README documented three rules; measured against the cloud's
  golden snapshot they disagreed with it on 14 of 86 country-corpus cases, so
  this SDK carried two more of its own. Bundle **1.1.0 documents seven**, marks
  each SDK or cloud-only, and ships the data all seven need in every language
  file -- the activation signals, the country map, the asymmetric 60/40 window,
  the symmetric 60 context window, the whole-word vocabulary, the near-miss
  policy, the table constants and the reference labels. So the locally generated
  activation layer is **deleted**, no window is hard-coded any more, and rules 6
  (near miss), 7 (column header) and 7b (nearest label) are implemented here for
  the first time. Every rule now reads its data off the placed bundle.
- Advisory checksums never reject a match: `ca_sin`, `emirates_id`,
  `de_tax_id`, `kr_rrn`, `sa_national_id`. Korea stopped issuing check digits on
  20 Oct 2020.
- Every registry pattern is asserted to compile under RE2, which together with
  Swift's NSRegularExpression bounds the portable subset.
- Not ported, and still cloud-only: the slot, context,
  gravity and name layers, industry profiles, and org configuration.
- **Indonesia is the country 1.1.0 added, and it is the one that proves the
  whole-word rule.** `id_nik`'s only short spellings -- NIK, KTP, NPWP -- are
  `wholeWordKeywords`, not ordinary keywords, because `nik` sits inside
  *teknik*, *elektronik*, *klinik* and *pabrik*. Matching them by substring
  would open the gate on an Indonesian sales ledger; matching them on a word
  boundary catches "NIK 3171010101900001" and leaves *teknik* alone. An SDK that
  merged the two lists would be shipping a false-positive bug, so the boundary
  test is implemented rather than the shortcut, and four unit cases assert both
  halves.
- **FLAGGED, upstream: bundle 1.1.0 cannot detect Australia's TFN, ABN or
  Medicare number.** `checksums.json` declares `au_tfn` and `au_abn` as
  `requiredBy` and `au_medicare` as `advisoryFor` patterns of those names, and
  `patterns` ships none of them -- the AU profile carries only `au_acn` and
  `au_phone_intl`. The AU activation signals are still keyed on "tfn", "tax
  file" and "medicare", so the bundle switches Australia on for identifiers it
  then has no pattern to catch. The cloud detects all three. This is a recall
  gap no SDK can close from the bundle, and the six parity cases it costs are
  recorded in the fixture as `BUNDLE GAP` rather than silently accepted.

## v0.3.0 - 2026-09-02

### Added
- feat: port `ScanToolResult` from `tork-js-sdk` (DECIDED-TACT2-V2-C). Scans
  a tool result (MCP server output, or any external system the caller
  doesn't control) for PII and prompt injection before it is appended to
  model context. Pure, synchronous, on-device — no network call. PII
  detection reuses the existing `DetectPII` detector; prompt injection uses
  a new conservative heuristic pattern set (`InjectionRuleset =
  "tork-injection-heuristics-v1"`, types `instruction_override`,
  `role_reassignment`, `exfiltration_url`, all findings labelled with a
  `heuristic:` prefix). `Client.ScanToolResult` records the scan as a
  `Receipt` carrying a `tool_result_scan` block (`attested_by: "client"`,
  `capture_mode: "edge"`) that is byte-identical (snake_case keys,
  alphabetical order, same finding-type vocabulary) to the block produced by
  `tork-js-sdk`, and maps the outcome to a governance `Action`: blocked →
  deny, injection finding → escalate, PII-only → redact, clean → allow. This
  port matches the JS SDK's Tier 1 (10-type basic PII vocabulary); it does
  not carry the Python SDK's regional/industry pattern tier.

### Fixed
- fix: `PIIType` declared 7 values but `defaultPatterns` only had a regex
  for 7 of the JS SDK's 10-type basic PII vocabulary (`pii.ts`
  `PII_PATTERNS`) — `passport`, `drivers_license` and `bank_account` passed
  through `DetectPII` (and, transitively, `Govern`) unflagged and
  unmasked. Found while running the parity check this port required before
  porting `ScanToolResult`, the same check that caught the equivalent gap
  in the Python SDK
  (`tests/test_pii_type_parity.py`,
  `SDK-PYTHON-PII-DETECTOR-DROPS-THREE-DECLARED-TYPES`). All three patterns
  are now present, ported verbatim from `tork-js-sdk/src/pii.ts`, appended
  in the same declaration order as the JS `PII_PATTERNS` object so the
  chained-replace redaction semantics match byte for byte.

## v0.2.0 - 2026-07-30

### Fixed
- fix: make `Client` safe for concurrent use. `Govern` updated the shared
  statistics without synchronisation, including an unguarded map write to
  `Stats.ActionCounts`. Calling `Govern` from multiple goroutines — which every
  middleware adapter in this module does — could abort the host process with
  `fatal error: concurrent map writes`. All statistics access is now guarded by
  a mutex, held only for the update itself and never across PII detection or
  receipt generation.
- fix: `GetStats` now returns a deep copy. It previously handed back the
  client's live `ActionCounts` map, so a caller could mutate internal state, and
  merely ranging over the result while another goroutine called `Govern` was
  itself a fatal `concurrent map iteration and map write`.
- fix: guard the client configuration with the same mutex. `Govern` read
  `config` while `SetConfig`, `SetDefaultAction` and `SetPolicyVersion` wrote
  it. `Action` and `PolicyVersion` are strings, and a string header (data
  pointer plus length) is not written atomically, so a concurrent reader could
  observe the pointer of one value with the length of another and read past the
  end of the backing array — producing governance actions and receipt policy
  versions that were never configured (observed: `"redactwo"`, `"denytest"`,
  `"escala"`). `Govern` now takes one configuration snapshot per call, so a
  single call can no longer mix fields from two different configurations.
  Reconfiguring a live client while it serves traffic is now supported.

No public API changes: method signatures, exported fields and behaviour are
unchanged.

---

_Note: entries below were committed but never tagged, and therefore never
published. They ship for the first time in v0.2.0 above. The heading previously
read "v1.2.0", a release that never existed — no tag beyond v0.1.0 has ever been
pushed to this repository._

## Untagged (2026-02 to 2026-05, shipped in v0.2.0)

### Added
- feat: agent/session context fields (agent_id, agent_role, session_id, session_turn)
- feat: region and industry parameters for PII v1.1
- feat: Gorilla and Beego middleware adapters

### Security
- security: never expose raw PII in governance output or match value on DENY/ESCALATE
