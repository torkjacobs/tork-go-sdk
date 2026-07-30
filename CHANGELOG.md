# Changelog

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

## Unreleased

_Nothing yet._

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
