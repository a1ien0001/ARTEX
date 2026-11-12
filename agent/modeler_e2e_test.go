package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/norma/llm"
)

// scriptedTurn is one LLM turn: a list of tool calls to emit (each becomes a
// tool_use block), or empty to end the turn.
type scriptedTurn struct {
	calls []scriptedCall
}
type scriptedCall struct {
	name  string
	input string
}

// TestModelerE2EBuildsFunctionGraph drives a REAL modeler-profile Worker end to end
// against a REAL Postgres, with a scripted provider standing in for the LLM. It
// proves the whole chain a live model would exercise — modeler Worker → ModelerTools
// → FunctionStore → DB → BuildFunctionGraph (the frontend API path) — is correct and
// wired, without depending on an external LLM. Skips when no test DB is configured.
func TestModelerE2EBuildsFunctionGraph(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	expID, err := d.CreateExploration("modeler-e2e", "重建业务功能图")
	if err != nil {
		t.Fatal(err)
	}
	ts := d.Exploration(expID)
	taskID := fmt.Sprint(expID)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, taskID)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	})

	// The scripted modeling session: exactly what a modeler LLM does after reading
	// two roles' menus. Turn 1 (merchant view): order module → refund feature →
	// submit-refund action. Turn 2 (admin view): admin module → force-refund action,
	// then the role-diff invariant (admin has it, merchant doesn't). Turn 3 ends.
	//
	// IDs: add_function_node returns "function node: <id>"; the script can't know the
	// serial ids ahead of time, so it builds the hierarchy by re-stating parent names
	// via separate nodes and lets the store dedup. To link parent→child deterministically
	// we drive each level in its own call and thread the returned id through — but since
	// the scripted provider can't read tool results mid-turn here, we instead assert the
	// nodes/edges that DON'T need a returned id (top-level nodes + invariant), which is
	// the integration surface that matters: tools actually persist to the graph.
	script := []scriptedTurn{
		{calls: []scriptedCall{
			{name: "add_function_node", input: `{"kind":"module","name":"订单模块","path":"/order","role_seen":"merchant","confidence":"observed","evidence":"merchant /api/menu 含订单"}`},
			{name: "add_function_node", input: `{"kind":"feature","name":"退款","path":"/order/refund","role_seen":"merchant","confidence":"observed","evidence":"退款入口"}`},
			{name: "add_function_node", input: `{"kind":"action","name":"提交退款申请","path":"/order/refund/submit","role_seen":"merchant","confidence":"observed","evidence":"POST /api/order/refund"}`},
		}},
		{calls: []scriptedCall{
			{name: "add_function_node", input: `{"kind":"module","name":"管理后台","path":"/admin","role_seen":"admin","confidence":"observed","evidence":"admin /api/menu 含管理后台"}`},
			{name: "add_function_node", input: `{"kind":"action","name":"强制退款","path":"/admin/refund","role_seen":"admin","confidence":"observed","evidence":"admin 独有"}`},
			{name: "add_invariant", input: `{"kind":"authz","statement":"merchant 不得到达 强制退款","source":"role_diff","evidence":"admin菜单有,merchant菜单无"}`},
		}},
		{calls: nil}, // end_turn
	}

	turn := 0
	provider := captureUsageProvider{stream: func(_ context.Context, yield func(llm.StreamEvent, error) bool) {
		var events []llm.StreamEvent
		if turn < len(script) && len(script[turn].calls) > 0 {
			for i, c := range script[turn].calls {
				events = append(events,
					llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: fmt.Sprintf("t%d-c%d", turn, i), ToolName: c.name},
					llm.StreamEvent{Type: llm.SEToolInputJSON, Text: c.input},
				)
			}
			events = append(events, llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "tool_use"})
		} else {
			events = []llm.StreamEvent{{Type: llm.SETextDelta, Text: "建模完成"}, {Type: llm.SEMessageDelta, StopReason: "end_turn"}}
		}
		turn++
		for _, ev := range events {
			if !yield(ev, nil) {
				return
			}
		}
	}}

	// A modeler intent (Origin == "modeler"), exactly as the engine seeds it.
	intentPayload := map[string]any{"summary": "业务建模:重建功能图"}
	intentID, err := ts.AddNode("intent", intentPayload, 9, "running", "modeler", nil)
	if err != nil {
		t.Fatal(err)
	}
	rawIntent, _ := json.Marshal(intentPayload)

	workDir := t.TempDir()
	ctx := context.Background()
	// Real modeler-profile worker: NewModelerWorker binds ModelerTools (function-graph
	// tools) and the modeler prompt. maxTurns high enough for the 3 scripted turns.
	w := NewModelerWorker(provider, "test-model", workDir, nil, 0, 10)
	_, wrote, err := w.Execute(ctx, "modeler#1", expID, nil, ts, &db.Node{ID: intentID, Payload: rawIntent},
		guard.New().Hooks(), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// 1) WriteCounts must reflect the function-graph writes (modeler persisted something).
	if wrote.FuncNodes < 5 {
		t.Errorf("FuncNodes written = %d, want >= 5 (modeler must persist the tree)", wrote.FuncNodes)
	}

	// 2) Read the graph back through the SAME path the frontend API uses.
	g, err := d.Functions(expID).BuildFunctionGraph()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]db.FunctionGraphNode{}
	for _, n := range g.Nodes {
		byName[n.Name] = n
	}
	for _, want := range []string{"订单模块", "退款", "提交退款申请", "管理后台", "强制退款"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("function graph missing node %q (nodes=%d)", want, len(g.Nodes))
		}
	}
	// role reachability landed: 强制退款 seen by admin, 订单模块 by merchant.
	if n := byName["强制退款"]; len(n.SeenRoles) != 1 || n.SeenRoles[0] != "admin" {
		t.Errorf("强制退款 seen_roles = %v, want [admin]", n.SeenRoles)
	}
	if n := byName["订单模块"]; len(n.SeenRoles) != 1 || n.SeenRoles[0] != "merchant" {
		t.Errorf("订单模块 seen_roles = %v, want [merchant]", n.SeenRoles)
	}
	// 3) the role-diff invariant (the oracle) landed, open and authz.
	if len(g.Invariants) != 1 {
		t.Fatalf("invariants = %d, want 1 (the role-diff authz invariant)", len(g.Invariants))
	}
	inv := g.Invariants[0]
	if inv.Kind != "authz" || inv.Status != "open" || inv.Statement == "" {
		t.Errorf("invariant = %+v, want authz/open with statement", inv)
	}
}
