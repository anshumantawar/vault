// Package placement decides which nodes should hold a chunk, using
// rendezvous (highest-random-weight) hashing spread across zones.
// Adding or removing a node only moves the chunks that node wins or loses.
package placement

import (
	"hash/fnv"
	"sort"
)

type Node struct {
	ID   string
	Zone string
}

// Order returns all nodes ranked for key, best first, preferring distinct
// zones: the first len(zones) entries each come from a different zone.
func Order(key string, nodes []Node) []Node {
	ranked := make([]Node, len(nodes))
	copy(ranked, nodes)
	score := make(map[string]uint64, len(nodes))
	for _, n := range nodes {
		h := fnv.New64a()
		h.Write([]byte(key))
		h.Write([]byte{0})
		h.Write([]byte(n.ID))
		score[n.ID] = mix(h.Sum64())
	}
	sort.Slice(ranked, func(i, j int) bool {
		si, sj := score[ranked[i].ID], score[ranked[j].ID]
		if si != sj {
			return si > sj
		}
		return ranked[i].ID < ranked[j].ID
	})

	out := make([]Node, 0, len(ranked))
	usedZone := map[string]bool{}
	var rest []Node
	for _, n := range ranked {
		if usedZone[n.Zone] {
			rest = append(rest, n)
			continue
		}
		usedZone[n.Zone] = true
		out = append(out, n)
	}
	return append(out, rest...)
}

// Pick returns the top n nodes for key.
func Pick(key string, nodes []Node, n int) []Node {
	o := Order(key, nodes)
	if n < len(o) {
		o = o[:n]
	}
	return o
}

// mix is a 64-bit finalizer (splitmix64); FNV alone scores similar ids too similarly.
func mix(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}
