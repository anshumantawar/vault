package ui

import "fmt"

// ProblemStatement is the brief, verbatim.
var ProblemStatement = []string{
	"Vault: Build a fault-tolerant distributed object storage system capable of storing, replicating, retrieving, and repairing large volumes of data across unreliable and independently failing storage nodes.",
	"The system must handle concurrent reads and writes, configurable replication and durability policies, node failures, partial network partitions, data corruption, replica inconsistency, background rebalancing, integrity verification, metadata consistency, and automatic replica repair while maintaining predictable availability and minimizing recovery time and storage overhead.",
}

// Requirement pairs a phrase from the brief with how Vault meets it.
type Requirement struct{ Need, How string }

var Requirements = []Requirement{
	{"Concurrent reads and writes", "Chunks are immutable; only the key → manifest pointer changes, serialized through Raft."},
	{"Configurable replication and durability", "Per-bucket policy: N copies, W acknowledgements before success."},
	{"Node failures", "Heartbeats every second; dead after 3 s. Reads fall through to another copy instantly."},
	{"Partial network partitions", "Every call has a deadline. Repair picks any source that can still reach the target."},
	{"Data corruption", "A chunk's name is its SHA-256, re-checked on every read. Bad copies are quarantined."},
	{"Replica inconsistency", "Content-addressed copies are either valid or absent, never different."},
	{"Background rebalancing", "Rendezvous hashing: a new node receives only its ~1/N share."},
	{"Integrity verification", "A scrubber re-hashes data at rest, so unread data can't rot unseen."},
	{"Metadata consistency", "3-member Raft group; every change is committed by a majority first."},
	{"Automatic replica repair", "The leader copies under-replicated chunks node-to-node, in parallel."},
	{"Predictable availability", "N=3, W=2: writes survive 1 failure, reads survive 2. Copies span zones."},
	{"Minimal recovery time", "Repair starts at detection. Time-to-repair is measured and shown live."},
	{"Minimal storage overhead", "Dedup by content hash, per-bucket N, metadata-only copies."},
}

// intro slides come first, then one slide per demo Step.
var introSlides = []string{"cover", "problem", "requirements", "architecture", "dataflow", "healing", "durability"}

var introTitles = map[string]string{
	"cover": "Vault", "problem": "Problem statement", "requirements": "What it must handle",
	"architecture": "Architecture", "dataflow": "How bytes move", "healing": "Self-healing",
	"durability": "Durability is a choice",
}

// Deck is one slide of the Present app.
type Deck struct {
	N, Total int
	Kind     string // an intro slide name, or "step"
	Title    string
	Step     Step
	StepNo   int
}

func DeckAt(n int) Deck {
	total := len(introSlides) + len(Steps)
	n = max(0, min(n, total-1))
	d := Deck{N: n, Total: total}
	if n < len(introSlides) {
		d.Kind = introSlides[n]
		d.Title = introTitles[d.Kind]
		return d
	}
	d.Kind = "step"
	d.StepNo = n - len(introSlides) + 1
	d.Step = Steps[d.StepNo-1]
	d.Title = d.Step.Title
	return d
}

func (d Deck) URL(n int) string { return fmt.Sprintf("/app/present?n=%d", n) }
func (d Deck) HasPrev() bool    { return d.N > 0 }
func (d Deck) HasNext() bool    { return d.N < d.Total-1 }
func (d Deck) Progress() string { return fmt.Sprintf("%d / %d", d.N+1, d.Total) }
func (d Deck) DemoLabel() string {
	return fmt.Sprintf("Live demo · %d of %d", d.StepNo, len(Steps))
}
