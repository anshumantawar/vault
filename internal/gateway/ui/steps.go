package ui

// The guided demo for judges: what to say, what to click, what they should see.
// Node ids match scripts/demo.sh (n1..n5 in zones z1..z3, meta m1..m3).

type Action struct {
	Label, Post string
	Danger      bool
}

type Step struct {
	Title   string
	Say     []string
	Actions []Action
	Cmds    []string // terminal commands, shown with a copy button
	Watch   string
}

var Steps = []Step{
	{
		Title: "The problem: storage fails all the time",
		Say: []string{
			"At scale, disks die daily, bits silently rot and networks split in half.",
			"Vault is S3-compatible object storage that keeps every byte readable through all of that, and heals itself.",
			"In Stats: 3 metadata servers running Raft, and storage nodes spread across 3 failure zones.",
		},
		Actions: []Action{{Label: "Reset all faults", Post: "/ui/demo/heal"}},
		Watch:   "Stats: everything green, “fully redundant”; three Raft members, nodes spread over three zones.",
	},
	{
		Title: "It speaks real S3",
		Say: []string{
			"No custom client: this is the stock AWS CLI, signing requests with SigV4.",
			"Big files go up as multipart uploads, get cut into 4 MB chunks named by their SHA-256, and each chunk lands on 3 nodes in 3 different zones.",
		},
		Cmds: []string{
			"export AWS_ENDPOINT_URL=http://127.0.0.1:9000 AWS_ACCESS_KEY_ID=vaultadmin AWS_SECRET_ACCESS_KEY=vaultsecret AWS_DEFAULT_REGION=us-east-1",
			"aws s3 mb s3://photos",
			"aws s3 sync ./photos s3://photos",
		},
		Actions: []Action{{Label: "Create “photos” bucket", Post: "/ui/demo/setup"}},
		Watch:   "Files fills up; in Stats the object and chunk counts climb and overhead reads 3.00×.",
	},
	{
		Title: "Crash a storage node",
		Say: []string{
			"Let's pull the plug on n2 in the middle of the demo.",
			"Reads keep working immediately: the gateway just uses another copy.",
			"Within 3 seconds the metadata leader declares n2 dead and re-replicates every chunk it held onto healthy nodes, in parallel.",
		},
		Actions: []Action{{Label: "Kill n2", Post: "/ui/nodes/n2/kill", Danger: true}, {Label: "Read everything", Post: "/ui/demo/readall"}},
		Cmds:    []string{"scripts/demo.sh kill n2    # a real kill -9, if you prefer"},
		Watch:   "n2 turns red, “under-replicated” jumps, then drops to zero. “Last repair time” shows about 4s: recovery time, measured live.",
	},
	{
		Title: "Silent data corruption",
		Say: []string{
			"Now the scariest failure: the disk returns wrong bytes and reports no error. We flip one bit on disk.",
			"Every chunk's name is its SHA-256, so every read re-verifies it. The bad copy is never served.",
			"It's quarantined, and repair makes a fresh copy. A background scrubber catches this even for data nobody reads.",
		},
		Actions: []Action{{Label: "Corrupt a chunk on n1", Post: "/ui/nodes/n1/corrupt", Danger: true}, {Label: "Read everything", Post: "/ui/demo/readall"}},
		Watch:   "“Read everything” still reports every object verified. Repairs tick up and health returns to fully redundant.",
	},
	{
		Title: "Partial network partition",
		Say: []string{
			"Not every failure is a crash. Here n3 is alive, but can no longer talk to the metadata group.",
			"Metadata sees it as dead and repairs around it, while the gateway can still read from it. Two parts of the system disagree, and data stays safe anyway.",
			"When the link heals, the extra copies are trimmed back to the target.",
		},
		Actions: []Action{{Label: "Cut n3 ↔ metadata", Post: "/ui/nodes/n3/partition?peer=meta", Danger: true}, {Label: "Heal all links", Post: "/ui/demo/heal"}},
		Watch:   "n3 drops out for metadata and repair runs around it; after healing, extra copies are trimmed back to three.",
	},
	{
		Title: "Kill the metadata leader",
		Say: []string{
			"Metadata is the one thing that must never be wrong, so it runs on Raft: every change is committed by a majority before we acknowledge it.",
			"Kill the leader and a new one is elected in about a second. Uploads keep working.",
		},
		Cmds:    []string{"scripts/demo.sh kill $(curl -s http://127.0.0.1:8080/ui/leader)"},
		Actions: []Action{{Label: "Force an election", Post: "/ui/meta/stepdown"}},
		Watch:   "In Stats → Metadata, the Leader moves to another member and the term goes up.",
	},
	{
		Title: "Scale out",
		Say: []string{
			"Capacity grows by adding nodes. Rendezvous hashing means only the chunks the new node should own move to it, about 1/N of the data.",
			"Gateways are stateless too: run as many as you like behind a load balancer.",
		},
		Cmds:  []string{"scripts/demo.sh add-node n6 z4"},
		Watch: "n6 appears in zone z4 and its chunk count climbs as the rebalancer moves its share over.",
	},
	{
		Title: "Recap",
		Say: []string{
			"Survives: node crashes, silent corruption, partial partitions, metadata leader loss.",
			"Self-heals automatically, with recovery time measured, not claimed.",
			"Durability is a per-bucket choice: N copies, W acknowledgements.",
			"Next: erasure coding (1.5× overhead instead of 3×) and sharding metadata across Raft groups.",
		},
		Actions: []Action{{Label: "Reset all faults", Post: "/ui/demo/heal"}},
		Watch:   "Back to fully redundant.",
	},
}
