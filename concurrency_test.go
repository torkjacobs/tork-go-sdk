package tork

import (
	"sync"
	"testing"
)

// These tests exercise Client from many goroutines at once, which is how the
// shipped middlewares (chi, echo, gin, fiber, gorilla, beego) use it: one
// Client shared across every HTTP handler invocation.
//
// Run with -race to catch unsynchronised access to the statistics.

const (
	concurrentGoroutines = 64
	concurrentIterations = 100
)

// TestConcurrentGovern hammers a single Client from many goroutines and
// asserts the statistics are exact afterwards.
//
// Against an unsynchronised Client this fails in two ways: the counters lose
// increments to lost updates, and ActionCounts triggers the unrecoverable
// runtime abort "fatal error: concurrent map writes".
func TestConcurrentGovern(t *testing.T) {
	client := NewClient()

	// Each iteration issues one PII call and one clean call, so the expected
	// per-action totals are known exactly.
	const callsPerIteration = 2
	totalCalls := int64(concurrentGoroutines * concurrentIterations * callsPerIteration)
	expectedPII := int64(concurrentGoroutines * concurrentIterations)

	var wg sync.WaitGroup
	start := make(chan struct{})

	for g := 0; g < concurrentGoroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release everyone at once to maximise contention
			for i := 0; i < concurrentIterations; i++ {
				client.Govern("SSN: 123-45-6789")
				client.Govern("no sensitive data here")
			}
		}()
	}

	close(start)
	wg.Wait()

	stats := client.GetStats()

	if stats.TotalCalls != totalCalls {
		t.Errorf("TotalCalls: expected %d, got %d (lost %d increments)",
			totalCalls, stats.TotalCalls, totalCalls-stats.TotalCalls)
	}
	if stats.TotalPIIDetected != expectedPII {
		t.Errorf("TotalPIIDetected: expected %d, got %d", expectedPII, stats.TotalPIIDetected)
	}
	if stats.TotalProcessingNs <= 0 {
		t.Errorf("TotalProcessingNs: expected positive, got %d", stats.TotalProcessingNs)
	}
	if stats.ActionCounts[ActionRedact] != expectedPII {
		t.Errorf("ActionCounts[redact]: expected %d, got %d", expectedPII, stats.ActionCounts[ActionRedact])
	}
	if stats.ActionCounts[ActionAllow] != expectedPII {
		t.Errorf("ActionCounts[allow]: expected %d, got %d", expectedPII, stats.ActionCounts[ActionAllow])
	}

	// ActionCounts must reconcile with TotalCalls: every recorded call landed
	// in exactly one action bucket.
	var sum int64
	for _, count := range stats.ActionCounts {
		sum += count
	}
	if sum != stats.TotalCalls {
		t.Errorf("ActionCounts sum %d does not reconcile with TotalCalls %d", sum, stats.TotalCalls)
	}
}

// TestConcurrentGovernWithOptions covers the options path, which delegates to
// Govern and so shares the same statistics.
func TestConcurrentGovernWithOptions(t *testing.T) {
	client := NewClient()

	agentID := "agent-1"
	agentRole := "worker"
	sessionID := "session-1"
	turn := 1
	opts := GovernOptions{
		Region:   []string{"ae", "in"},
		Industry: "healthcare",
		SessionContext: &SessionContext{
			AgentID:     &agentID,
			AgentRole:   &agentRole,
			SessionID:   &sessionID,
			SessionTurn: &turn,
		},
	}

	var wg sync.WaitGroup
	for g := 0; g < concurrentGoroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < concurrentIterations; i++ {
				result := client.GovernWithOptions("SSN: 123-45-6789", opts)
				// The security guarantee must hold under concurrency too:
				// raw PII never reaches the output.
				if result.Output != "SSN: [SSN_REDACTED]" {
					t.Errorf("raw PII leaked into output: %q", result.Output)
					return
				}
			}
		}()
	}
	wg.Wait()

	expected := int64(concurrentGoroutines * concurrentIterations)
	stats := client.GetStats()
	if stats.TotalCalls != expected {
		t.Errorf("TotalCalls: expected %d, got %d", expected, stats.TotalCalls)
	}
	if stats.ActionCounts[ActionRedact] != expected {
		t.Errorf("ActionCounts[redact]: expected %d, got %d", expected, stats.ActionCounts[ActionRedact])
	}
}

// TestConcurrentGovernAndGetStats runs readers alongside writers. Reading a
// map while another goroutine writes it is itself a fatal runtime error
// ("concurrent map iteration and map write"), so GetStats must snapshot under
// the same lock Govern uses.
func TestConcurrentGovernAndGetStats(t *testing.T) {
	client := NewClient()

	var writers, readers sync.WaitGroup
	done := make(chan struct{})

	// Readers: range over the returned map while writers are active.
	for r := 0; r < 8; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
					stats := client.GetStats()
					for range stats.ActionCounts {
					}
				}
			}
		}()
	}

	for g := 0; g < concurrentGoroutines; g++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for i := 0; i < concurrentIterations; i++ {
				client.Govern("SSN: 123-45-6789")
			}
		}()
	}

	// Stop the readers once the writers have finished their fixed workload.
	writers.Wait()
	close(done)
	readers.Wait()

	expected := int64(concurrentGoroutines * concurrentIterations)

	if got := client.GetStats().TotalCalls; got != expected {
		t.Errorf("TotalCalls: expected %d, got %d", expected, got)
	}
}

// TestConcurrentResetStats interleaves ResetStats with Govern. Exact totals
// are not predictable, but the invariant is: ResetStats zeroes the counters
// and the map together, so ActionCounts must always reconcile with TotalCalls.
func TestConcurrentResetStats(t *testing.T) {
	client := NewClient()

	var wg sync.WaitGroup
	for g := 0; g < concurrentGoroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < concurrentIterations; i++ {
				client.Govern("SSN: 123-45-6789")
				if id%16 == 0 && i%25 == 0 {
					client.ResetStats()
				}
			}
		}(g)
	}
	wg.Wait()

	stats := client.GetStats()
	var sum int64
	for _, count := range stats.ActionCounts {
		sum += count
	}
	if sum != stats.TotalCalls {
		t.Errorf("ActionCounts sum %d does not reconcile with TotalCalls %d after interleaved resets",
			sum, stats.TotalCalls)
	}

	// A reset must leave the map usable, never nil.
	client.ResetStats()
	client.Govern("SSN: 123-45-6789")
	if client.GetStats().ActionCounts[ActionRedact] != 1 {
		t.Error("client did not record correctly after ResetStats")
	}
}

// TestGetStatsReturnsIndependentCopy asserts GetStats hands back a deep copy.
// If ActionCounts is shared by reference, a caller can corrupt internal state
// and can fatally race the map against a concurrent Govern.
func TestGetStatsReturnsIndependentCopy(t *testing.T) {
	client := NewClient()
	client.Govern("SSN: 123-45-6789")
	client.Govern("clean text")

	snapshot := client.GetStats()
	if snapshot.ActionCounts[ActionRedact] != 1 {
		t.Fatalf("setup: expected ActionCounts[redact] 1, got %d", snapshot.ActionCounts[ActionRedact])
	}

	// Mutate every way a caller could: overwrite, add, delete.
	snapshot.ActionCounts[ActionRedact] = 9999
	snapshot.ActionCounts[ActionEscalate] = 42
	delete(snapshot.ActionCounts, ActionAllow)
	snapshot.TotalCalls = 9999

	fresh := client.GetStats()
	if fresh.ActionCounts[ActionRedact] != 1 {
		t.Errorf("caller mutation leaked into client state: ActionCounts[redact] is %d, expected 1",
			fresh.ActionCounts[ActionRedact])
	}
	if _, ok := fresh.ActionCounts[ActionEscalate]; ok {
		t.Error("caller-added key leaked into client state: ActionCounts[escalate] should not exist")
	}
	if fresh.ActionCounts[ActionAllow] != 1 {
		t.Errorf("caller deletion leaked into client state: ActionCounts[allow] is %d, expected 1",
			fresh.ActionCounts[ActionAllow])
	}
	if fresh.TotalCalls != 2 {
		t.Errorf("TotalCalls: expected 2, got %d", fresh.TotalCalls)
	}

	// Two snapshots must not alias each other either.
	a := client.GetStats()
	b := client.GetStats()
	a.ActionCounts[ActionRedact] = 1234
	if b.ActionCounts[ActionRedact] == 1234 {
		t.Error("two GetStats snapshots share the same ActionCounts map")
	}
}

// ============================================================================
// Configuration races
// ============================================================================

// TestConcurrentGovernAndSetters races the three configuration setters against
// Govern. c.config is plain struct fields rather than a map, so this cannot
// abort the process the way ActionCounts did; the race detector is what makes
// the bug visible, hence the emphasis on running this suite with -race.
//
// The assertion is on the observed values, not just on staying alive: every
// action Govern chooses must be one that was actually configured at some point,
// and every policy version stamped into a receipt must be one that was actually
// set. A read torn between two configurations would surface here as a value
// that was never written.
func TestConcurrentGovernAndSetters(t *testing.T) {
	client := NewClient()

	actions := []Action{ActionRedact, ActionDeny, ActionEscalate}
	versions := []string{"1.0.0", "2.0.0", "3.0.0"}

	validAction := map[Action]bool{}
	for _, a := range actions {
		validAction[a] = true
	}
	validVersion := map[string]bool{}
	for _, v := range versions {
		validVersion[v] = true
	}

	var writers, readers sync.WaitGroup
	done := make(chan struct{})

	// Writers: churn the configuration through every setter continuously.
	for w := 0; w < 8; w++ {
		writers.Add(1)
		go func(id int) {
			defer writers.Done()
			for i := 0; ; i++ {
				select {
				case <-done:
					return
				default:
				}
				switch (id + i) % 3 {
				case 0:
					client.SetDefaultAction(actions[i%len(actions)])
				case 1:
					client.SetPolicyVersion(versions[i%len(versions)])
				case 2:
					client.SetConfig(Config{
						PolicyVersion: versions[i%len(versions)],
						DefaultAction: actions[i%len(actions)],
					})
				}
			}
		}(w)
	}

	// Readers: Govern and GetConfig concurrently with the churn.
	for g := 0; g < concurrentGoroutines; g++ {
		readers.Add(1)
		go func(id int) {
			defer readers.Done()
			for i := 0; i < concurrentIterations; i++ {
				result := client.Govern("SSN: 123-45-6789")

				if !validAction[result.Action] {
					t.Errorf("Govern produced action %q, which was never configured", result.Action)
					return
				}
				if !validVersion[result.Receipt.PolicyVersion] {
					t.Errorf("receipt carries policy version %q, which was never configured",
						result.Receipt.PolicyVersion)
					return
				}

				// The security guarantee holds regardless of which action won
				// the race: raw PII must never reach the output.
				if result.Output != "SSN: [SSN_REDACTED]" {
					t.Errorf("raw PII leaked into output: %q", result.Output)
					return
				}

				cfg := client.GetConfig()
				if !validAction[cfg.DefaultAction] || !validVersion[cfg.PolicyVersion] {
					t.Errorf("GetConfig returned an unconfigured value: %+v", cfg)
					return
				}
			}
		}(g)
	}

	readers.Wait()
	close(done)
	writers.Wait()
}

// TestGovernUsesConsistentConfigSnapshot pins the subtler half of the bug.
//
// Govern reads DefaultAction and PolicyVersion at two different points. Locking
// each read individually would still be wrong: a SetConfig landing between them
// lets one call pick DefaultAction from the old configuration and PolicyVersion
// from the new one, producing a receipt describing a decision no configuration
// ever specified. Govern must therefore snapshot the config once, up front.
//
// The setters here only ever move between two self-consistent pairings, so any
// mismatched (action, version) combination proves a torn read.
func TestGovernUsesConsistentConfigSnapshot(t *testing.T) {
	const (
		versionA = "10.0.0"
		versionB = "20.0.0"
	)
	// Pairings are what must stay together: redact always with versionA,
	// escalate always with versionB.
	pairA := Config{PolicyVersion: versionA, DefaultAction: ActionRedact}
	pairB := Config{PolicyVersion: versionB, DefaultAction: ActionEscalate}

	// Start from pairA rather than NewClient(). The default configuration is a
	// third, unrelated pairing, and a reader scheduled before the first writer
	// would legitimately observe it and fail the assertion below.
	client := NewClientWithConfig(pairA)

	var writers, readers sync.WaitGroup
	done := make(chan struct{})

	for w := 0; w < 4; w++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for i := 0; ; i++ {
				select {
				case <-done:
					return
				default:
				}
				if i%2 == 0 {
					client.SetConfig(pairA)
				} else {
					client.SetConfig(pairB)
				}
			}
		}()
	}

	for g := 0; g < concurrentGoroutines; g++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for i := 0; i < concurrentIterations; i++ {
				result := client.Govern("SSN: 123-45-6789")

				action := result.Action
				version := result.Receipt.PolicyVersion

				matched := (action == pairA.DefaultAction && version == pairA.PolicyVersion) ||
					(action == pairB.DefaultAction && version == pairB.PolicyVersion)
				if !matched {
					t.Errorf("torn config read: action %q paired with policy version %q, "+
						"a combination that was never configured", action, version)
					return
				}
			}
		}()
	}

	readers.Wait()
	close(done)
	writers.Wait()
}

// TestGetConfigReturnsIndependentCopy is the config-side counterpart to
// TestGetStatsReturnsIndependentCopy.
//
// Config currently holds only value types (a string and a string-based Action),
// so returning it by value already shares nothing with the client. This test
// exists to keep that true: if a reference-typed field (a []string of regions,
// a map, a pointer) is ever added to Config, GetConfig must start deep-copying
// it the way GetStats copies ActionCounts, and this test is what fails first.
func TestGetConfigReturnsIndependentCopy(t *testing.T) {
	client := NewClientWithConfig(Config{
		PolicyVersion: "7.0.0",
		DefaultAction: ActionRedact,
	})

	snapshot := client.GetConfig()
	snapshot.PolicyVersion = "mutated"
	snapshot.DefaultAction = ActionDeny

	fresh := client.GetConfig()
	if fresh.PolicyVersion != "7.0.0" {
		t.Errorf("caller mutation leaked into client state: PolicyVersion is %q, expected \"7.0.0\"",
			fresh.PolicyVersion)
	}
	if fresh.DefaultAction != ActionRedact {
		t.Errorf("caller mutation leaked into client state: DefaultAction is %q, expected %q",
			fresh.DefaultAction, ActionRedact)
	}

	// The client must still behave according to its own configuration.
	if got := client.Govern("SSN: 123-45-6789"); got.Action != ActionRedact {
		t.Errorf("client action changed after caller mutated a GetConfig result: got %q", got.Action)
	}
	if got := client.Govern("SSN: 123-45-6789"); got.Receipt.PolicyVersion != "7.0.0" {
		t.Errorf("client policy version changed after caller mutated a GetConfig result: got %q",
			got.Receipt.PolicyVersion)
	}
}

// BenchmarkGovernSerial and BenchmarkGovernParallel use identical input so
// the pair measures the cost of the lock: serial is the uncontended baseline,
// parallel is the same work under maximum contention on one shared Client.
func BenchmarkGovernSerial(b *testing.B) {
	client := NewClient()
	for i := 0; i < b.N; i++ {
		client.Govern("SSN: 123-45-6789")
	}
}

func BenchmarkGovernParallel(b *testing.B) {
	client := NewClient()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			client.Govern("SSN: 123-45-6789")
		}
	})
}
