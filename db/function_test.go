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

// TestFunctionStoreInvariantLifecycle exercises the P2 attack path: ListInvariants
// (the planner's open-target feed), SetInvariantStatus (the worker's resolve after
// testing), and MatrixCoverage (the situational signal). Real Postgres; skips without.
func TestFunctionStoreInvariantLifecycle(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("inv-lifecycle", "g")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	fs := d.Functions(expID)

	action, err := fs.AddFunctionNode(AddFunctionNodeReq{Kind: KindAction, Name: "强制退款", Path: "/admin/refund", RoleSeen: "admin", Confidence: "observed"})
	if err != nil {
		t.Fatal(err)
	}
	invID, err := fs.AddInvariant(AddInvariantReq{Kind: InvAuthz, Statement: "merchant 不得到达 强制退款", Source: InvSrcRoleDiff, TargetNode: action})
	if err != nil {
		t.Fatal(err)
	}

	// planner feed: open invariants carry the target node's name (joined), so an intent
	// can be phrased without a second lookup.
	open, err := fs.ListInvariants(InvStatusOpen, 50)
	if err != nil || len(open) != 1 {
		t.Fatalf("ListInvariants open = %d (err %v), want 1", len(open), err)
	}
	if open[0].TargetName != "强制退款" {
		t.Errorf("invariant target_name = %q, want 强制退款 (join failed)", open[0].TargetName)
	}

	// situational signal before testing: 1 open, 0 measured.
	if oi, cells := fs.MatrixCoverage(777); oi != 1 || cells != 0 {
		t.Errorf("MatrixCoverage before = (%d,%d), want (1,0)", oi, cells)
	}

	// worker tests it, finds a violation, records the cell + resolves the invariant.
	if err := fs.RecordFunctionAccess(777, action, "merchant", AccessAllowed, 0); err != nil {
		t.Fatal(err)
	}
	if err := fs.SetInvariantStatus(invID, InvStatusViolated); err != nil {
		t.Fatal(err)
	}

	// after: 0 open (resolved), 1 measured cell.
	if oi, cells := fs.MatrixCoverage(777); oi != 0 || cells != 1 {
		t.Errorf("MatrixCoverage after = (%d,%d), want (0,1)", oi, cells)
	}
	// the violated invariant is no longer in the open feed, but shows in the full graph.
	if open, _ := fs.ListInvariants(InvStatusOpen, 50); len(open) != 0 {
		t.Errorf("open invariants after resolve = %d, want 0", len(open))
	}
	g, err := fs.BuildFunctionGraph()
	if err != nil || len(g.Invariants) != 1 || g.Invariants[0].Status != "violated" {
		t.Errorf("graph invariant status = %+v, want 1 violated", g.Invariants)
	}
}

func nodeKey(id int64) string {
	return "f:" + strconv.FormatInt(id, 10)
}
