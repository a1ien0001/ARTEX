package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestTaskFunctionGraphHandler verifies the HTTP handler the frontend calls
// (/api/tasks/{id}/function-graph) returns the business function graph built by the
// modeler, against a real Postgres. Seeds a small graph directly via FunctionStore
// (the modeler's write path is covered by the agent E2E test), then asserts the
// handler serializes nodes + edges + invariants. Skips without a test DB.
func TestTaskFunctionGraphHandler(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Close() })

	expID, err := pg.CreateExploration("fg-handler", "goal")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })

	fs := pg.Functions(expID)
	modID, err := fs.AddFunctionNode(db.AddFunctionNodeReq{Kind: db.KindModule, Name: "订单模块", Path: "/order", RoleSeen: "merchant", Confidence: "observed"})
	if err != nil {
		t.Fatal(err)
	}
	actID, err := fs.AddFunctionNode(db.AddFunctionNodeReq{Kind: db.KindAction, Name: "退款", Path: "/order/refund", RoleSeen: "merchant", Confidence: "observed"})
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.LinkFunction(modID, db.RelContains, actID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.AddInvariant(db.AddInvariantReq{Kind: db.InvAuthz, Statement: "merchant 不得到达 强制退款", Source: db.InvSrcRoleDiff, TargetNode: actID}); err != nil {
		t.Fatal(err)
	}

	// Minimal Server + Manager holding a Task pointing at this exploration.
	taskID := "4242"
	s := &Server{ctx: context.Background(), m: &Manager{pg: pg, tasks: map[string]*Task{
		taskID: {ID: taskID, ExpID: expID},
	}}}

	r := httptest.NewRequest("GET", "/api/tasks/"+taskID+"/function-graph", nil)
	r.SetPathValue("id", taskID)
	w := httptest.NewRecorder()
	s.taskFunctionGraph(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var g db.FunctionGraphData
	if err := json.Unmarshal(w.Body.Bytes(), &g); err != nil {
		t.Fatalf("bad json: %v (body=%s)", err, w.Body.String())
	}
	if len(g.Nodes) != 2 {
		t.Errorf("nodes = %d, want 2", len(g.Nodes))
	}
	if len(g.Edges) != 1 || g.Edges[0].Rel != "contains" {
		t.Errorf("edges = %+v, want 1 contains edge", g.Edges)
	}
	if len(g.Invariants) != 1 || g.Invariants[0].Kind != "authz" {
		t.Errorf("invariants = %+v, want 1 authz", g.Invariants)
	}
	// node keys must be f:<id> (matches the frontend's expectation).
	foundMod := false
	for _, n := range g.Nodes {
		if n.Key == "f:"+strconv.FormatInt(modID, 10) {
			foundMod = true
		}
	}
	if !foundMod {
		t.Errorf("module node key f:%d not in response", modID)
	}

	// 404 for an unknown task.
	r2 := httptest.NewRequest("GET", "/api/tasks/9999/function-graph", nil)
	r2.SetPathValue("id", "9999")
	w2 := httptest.NewRecorder()
	s.taskFunctionGraph(w2, r2)
	if w2.Code != 404 {
		t.Errorf("unknown task status = %d, want 404", w2.Code)
	}
}
