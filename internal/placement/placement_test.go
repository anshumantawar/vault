package placement

import (
	"fmt"
	"testing"
)

func cluster(n int) []Node {
	var ns []Node
	for i := range n {
		ns = append(ns, Node{ID: fmt.Sprintf("n%d", i+1), Zone: fmt.Sprintf("z%d", i%3)})
	}
	return ns
}

func TestPickDistinctZones(t *testing.T) {
	nodes := cluster(6)
	for i := range 1000 {
		got := Pick(fmt.Sprint(i), nodes, 3)
		zones := map[string]bool{}
		for _, n := range got {
			zones[n.Zone] = true
		}
		if len(got) != 3 || len(zones) != 3 {
			t.Fatalf("key %d: %v not spread over 3 zones", i, got)
		}
	}
}

func TestPickFewerZonesThanReplicas(t *testing.T) {
	nodes := []Node{{"a", "z"}, {"b", "z"}, {"c", "z"}}
	if got := Pick("k", nodes, 3); len(got) != 3 {
		t.Fatalf("want 3 nodes, got %v", got)
	}
	if got := Pick("k", nodes, 5); len(got) != 3 {
		t.Fatalf("want all 3 nodes, got %v", got)
	}
}

func TestMinimalMovementOnJoin(t *testing.T) {
	before := cluster(6)
	after := append(cluster(6), Node{ID: "n7", Zone: "z3"})
	const keys = 3000
	moved := 0
	for i := range keys {
		k := fmt.Sprint(i)
		a, b := Pick(k, before, 1)[0], Pick(k, after, 1)[0]
		if a.ID != b.ID {
			if b.ID != "n7" {
				t.Fatalf("key %s moved %s -> %s, not to the new node", k, a.ID, b.ID)
			}
			moved++
		}
	}
	// n7 is alone in z3, so it should win about 1/7 of primaries.
	if moved < keys/14 || moved > keys/4 {
		t.Fatalf("moved %d of %d keys, want roughly %d", moved, keys, keys/7)
	}
}
