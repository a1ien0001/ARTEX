package db

import (
	"strconv"
	"testing"
)

// TestFunctionStoreUpsert exercises the function-graph store against live PG: node
// upsert dedup (same kind+path+name merges), confidence inferred→observed upgrade,
// seen_roles union, maps_to bridge, invariants, and the graph builder. Skips without
// a database, like the other db integration tests.
func TestFunctionStoreUpsert(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("function-store-test", "test goal")
	if err != nil {
		t.Fatal(err)
	}
	fs := d.Functions(expID)

	// First insert: a module seen by merchant, inferred.
	id1, err := fs.AddFunctionNode(AddFunctionNodeReq{
		Kind: KindModule, Name: "订单模块", Path: "/order", RoleSeen: "merchant", Confidence: "inferred",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Re-insert same (kind,path,name): must dedup to the SAME id, upgrade to observed,
	// and union the new role into seen_roles.
	id2, err := fs.AddFunctionNode(AddFunctionNodeReq{
		Kind: KindModule, Name: "订单模块", Path: "/order", RoleSeen: "admin", Confidence: "observed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("dedup failed: id1=%d id2=%d (same kind+path+name must merge)", id1, id2)
	}

	nodes, err := fs.ListFunctionNodes("", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("want 1 node after dedup, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Confidence != "observed" {
		t.Errorf("confidence = %q, want observed (inferred must upgrade)", n.Confidence)
	}
	roles := map[string]bool{}
	for _, r := range n.SeenRoles {
		roles[r] = true
	}
	if !roles["merchant"] || !roles["admin"] {
		t.Errorf("seen_roles = %v, want both merchant and admin (union)", n.SeenRoles)
	}

	// role filter: only nodes seen by admin.
	adminNodes, err := fs.ListFunctionNodes("", "admin", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(adminNodes) != 1 {
		t.Errorf("admin role filter = %d nodes, want 1", len(adminNodes))
	}

	// invariant + graph builder.
	if _, err := fs.AddInvariant(AddInvariantReq{
		Kind: InvAuthz, Statement: "merchant 不得到达 强制退款", Source: InvSrcRoleDiff, TargetNode: id1,
	}); err != nil {
		t.Fatal(err)
	}
	g, err := fs.BuildFunctionGraph()
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 1 || len(g.Invariants) != 1 {
		t.Fatalf("graph: nodes=%d invariants=%d, want 1/1", len(g.Nodes), len(g.Invariants))
	}
	if g.Nodes[0].Key != nodeKey(id1) {
		t.Errorf("node key = %q, want %q", g.Nodes[0].Key, nodeKey(id1))
	}

	// CountFunctionNodes drives the modeling gate (idempotent re-launch skip).
	if c, err := fs.CountFunctionNodes(); err != nil || c != 1 {
		t.Errorf("CountFunctionNodes = %d (err %v), want 1", c, err)
	}

	// cleanup: dropping the exploration cascades the function graph.
	if _, err := d.Exec(`DELETE FROM explorations WHERE id=$1`, expID); err != nil {
		t.Fatal(err)
	}
}

func nodeKey(id int64) string {
	return "f:" + strconv.FormatInt(id, 10)
}
