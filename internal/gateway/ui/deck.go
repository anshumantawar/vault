package ui

import "fmt"

// ProblemStatement is the brief, verbatim.
var ProblemStatement = []string{
	"Vault: Build a fault-tolerant distributed object storage system capable of storing, replicating, retrieving, and repairing large volumes of data across unreliable and independently failing storage nodes.",
	"The system must handle concurrent reads and writes, configurable replication and durability policies, node failures, partial network partitions, data corruption, replica inconsistency, background rebalancing, integrity verification, metadata consistency, and automatic replica repair while maintaining predictable availability and minimizing recovery time and storage overhead.",
}

// Requirement pairs a phrase from the brief with how Vault meets it, in plain words.
type Requirement struct{ Need, How string }

var Requirements = []Requirement{
	{"Many reads and writes at once", "Pieces never change once saved, so readers and writers never collide."},
	{"Configurable safety", "Each bucket picks how many copies to keep and how many must confirm."},
	{"Servers crash", "Noticed within 3 seconds; files are read from another copy meanwhile."},
	{"The network splits", "Every request has a time limit; repairs route around the break."},
	{"Disks corrupt data", "Each piece is named by its fingerprint and checked on every read."},
	{"Copies disagree", "A copy matches its fingerprint or is thrown away. Nothing to argue about."},
	{"Background rebalancing", "New servers automatically receive their fair share, and only that."},
	{"Integrity checks", "A background inspector keeps re-checking stored pieces."},
	{"A consistent catalog", "Three librarians vote; nothing counts until a majority agrees."},
	{"Automatic repair", "Missing copies are rebuilt server-to-server, many at once."},
	{"Predictable availability", "3 copies in 3 zones: files stay readable with 2 servers gone."},
	{"Fast recovery", "Repair starts the moment a failure is noticed, and is timed live."},
	{"Low storage overhead", "Identical pieces are stored once; cheaper safety levels per bucket."},
}

// Action is a button on a slide that does the thing the slide talks about.
type Action struct {
	Label, Post string
	Danger      bool
}

// Slide is one page of the Present app.
type Slide struct {
	Kind   string // cover | problem | idea | arch | flows | reqs | demo | safety | recap
	Kicker string
	Title  string
	Lead   string
	Say    []string
	Acts   []Action
	Cmd    string
	Live   string // live panel on demo slides: health | raft | bars
}

var saveSample = Action{Label: "Save a sample file", Post: "/ui/demo/sample"}
var openAll = Action{Label: "Open every file", Post: "/ui/demo/readall"}

var Slides = []Slide{
	{Kind: "cover"},
	{Kind: "problem", Kicker: "The challenge", Title: "Keep data safe on machines that fail",
		Lead: "In plain words: keep everyone's files safe and available even when computers crash, disks lie and networks break, and repair the damage automatically."},
	{Kind: "idea", Kicker: "The big idea", Title: "Split. Copy. Spread.",
		Lead: "Every file is cut into pieces, each piece is copied three times, and the copies live in different zones. No single failure can take a file away.",
		Acts: []Action{saveSample}},
	{Kind: "arch", Kicker: "How it's built", Title: "Four parts, each with one job",
		Lead: "The dots are live: this is the running cluster, not a drawing."},
	{Kind: "flows", Kicker: "Step by step", Title: "Saving and opening a file"},
	{Kind: "reqs", Kicker: "The brief, answered", Title: "Every requirement, covered"},
	{Kind: "demo", Kicker: "Live demo", Title: "Pull the plug on a server",
		Lead: "Servers fail all the time. Watch Vault notice and repair, by itself.",
		Say: []string{
			"Crash a server: its pieces are now down to two copies.",
			"Files still open instantly; Vault simply reads another copy.",
			"Within seconds every missing copy is rebuilt somewhere else.",
		},
		Acts: []Action{{Label: "Crash a server", Post: "/ui/demo/crash", Danger: true}, openAll, {Label: "Bring servers back", Post: "/ui/demo/heal"}},
		Live: "health"},
	{Kind: "demo", Kicker: "Live demo", Title: "A disk quietly lies",
		Lead: "The scariest failure: a disk hands back wrong data and reports no error.",
		Say: []string{
			"Every piece is named by its fingerprint, so damage can't hide.",
			"The bad copy is thrown away and replaced. You still get the right file.",
		},
		Acts: []Action{{Label: "Damage a piece on disk", Post: "/ui/demo/corrupt", Danger: true}, openAll},
		Live: "health"},
	{Kind: "demo", Kicker: "Live demo", Title: "The network splits",
		Lead: "A server keeps running, but the librarians can no longer hear it.",
		Say: []string{
			"Vault treats it as gone and makes fresh copies elsewhere.",
			"When the network heals, the extra copies are tidied away.",
		},
		Acts: []Action{{Label: "Cut a server off", Post: "/ui/demo/partition", Danger: true}, {Label: "Heal the network", Post: "/ui/demo/heal"}},
		Live: "health"},
	{Kind: "demo", Kicker: "Live demo", Title: "The head librarian leaves",
		Lead: "The catalog of what lives where must never be wrong or lost.",
		Say: []string{
			"Three librarians keep identical catalogs and vote on every change.",
			"If the leader disappears, the others elect a new one in about a second.",
			"Saving files keeps working the whole time.",
		},
		Acts: []Action{{Label: "Replace the head librarian", Post: "/ui/meta/stepdown", Danger: true}, saveSample},
		Live: "raft"},
	{Kind: "demo", Kicker: "Live demo", Title: "Growing is one command",
		Lead: "Add a server and Vault hands it its fair share of pieces, and only that share.",
		Cmd:  "scripts/demo.sh add-node n6 z4",
		Live: "bars"},
	{Kind: "safety", Kicker: "You choose", Title: "Pick a safety level per bucket"},
	{Kind: "recap", Kicker: "Recap", Title: "What you just saw",
		Acts: []Action{{Label: "Reset everything", Post: "/ui/demo/heal"}}},
}

// Deck is the slide being shown.
type Deck struct {
	Slide
	N, Total int
}

func DeckAt(n int) Deck {
	n = max(0, min(n, len(Slides)-1))
	return Deck{Slide: Slides[n], N: n, Total: len(Slides)}
}

func (d Deck) URL(n int) string { return fmt.Sprintf("/app/present?n=%d", n) }
func (d Deck) HasPrev() bool    { return d.N > 0 }
func (d Deck) HasNext() bool    { return d.N < d.Total-1 }
func (d Deck) Progress() string { return fmt.Sprintf("%d / %d", d.N+1, d.Total) }
func (d Deck) LiveURL() string  { return "/app/present/live?w=" + d.Live }

// ---- live panels ----

type LiveNode struct {
	ID, Zone, State string // State: up | impaired | down
	Chunks          int64
}

type Zone struct {
	Name  string
	Nodes []LiveNode
}

type LiveEvent struct{ Time, Kind, Icon, Text string }

// Live is the cluster as the slides show it.
type Live struct {
	Err                                  string
	Zones                                []Zone
	Nodes                                []LiveNode
	Raft                                 []Raft
	Events                               []LiveEvent
	Missing, Lost, Total, Objects        int64
	Repairs, MaxChunks                   int64
	Pct, MTTR, Healing, Stored, Overhead string
	Spark                                string // polyline points, 240×44
	SparkMax                             int64
}

func (l Live) Status() (label, class string) {
	switch {
	case l.Err != "":
		return "Catalog unreachable", "bad"
	case l.Lost > 0:
		return fmt.Sprintf("%d pieces lost", l.Lost), "bad"
	case l.Missing > 0 || l.Healing != "":
		return fmt.Sprintf("Repairing %d pieces", l.Missing), "warn"
	}
	return "Every piece fully copied", "ok"
}

func (n LiveNode) Width(max int64) string {
	if max <= 0 {
		return "display:block;width:0%"
	}
	return fmt.Sprintf("display:block;width:%.1f%%", float64(n.Chunks)/float64(max)*100)
}

// SampleResult is what "Save a sample file" shows: where each piece went.
type SampleResult struct {
	Name, Size string
	Pieces     []SamplePiece
}

type SamplePiece struct {
	N           int
	Fingerprint string
	Holders     []LiveNode
}
