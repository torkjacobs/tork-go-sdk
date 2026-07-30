# Changelog

## Unreleased

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

No public API changes: method signatures, exported fields and behaviour are
unchanged.

## v1.2.0 - 2026-03-09

### Added
- feat: agent/session context fields (agent_id, agent_role, session_id, session_turn)
