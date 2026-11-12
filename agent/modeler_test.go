package agent

import (
	"testing"
)

// TestModelerToolSurface pins the modeler's red line at the tool surface: it MUST
// carry the function-graph write/read tools, and it MUST NOT carry report_finding or
// record_fact (nor any attack tooling) — "只建模不攻击" is enforced here, not only in
// the prompt. Built from a nil-store ToolSet (construction must not deref stores).
func TestModelerToolSurface(t *testing.T) {
	ts := NewToolSet(nil, "")
	names := map[string]bool{}
	for _, tool := range ts.ModelerTools() {
		names[tool.Name()] = true
	}

	// must have: the six function-graph tools + asset登记/回看.
	for _, want := range []string{
		"add_function_node", "map_function_to_endpoint", "add_invariant",
		"record_function_access", "list_function_nodes", "get_function_subtree",
		"insert_assets", "list_assets",
	} {
		if !names[want] {
			t.Errorf("modeler tools missing %q", want)
		}
	}

	// must NOT have: attack / finding / fact-writing tools (the red line).
	for _, forbidden := range []string{"report_finding", "record_fact", "add_intent", "prove_goal"} {
		if names[forbidden] {
			t.Errorf("modeler tools must not include %q (只建模不攻击 红线)", forbidden)
		}
	}
}

// TestModelerSeededAndBound ensures the catalog seeds the function-graph tools and
// binds them to the "modeler" agent (so ToolResolve keeps them for modeler on fresh
// databases), and that the modeler key made it into the seed iteration order.
func TestModelerSeededAndBound(t *testing.T) {
	byKey := map[string]ToolSeed{}
	for _, s := range BuiltinToolSeeds() {
		byKey[s.Key] = s
	}
	for _, key := range []string{"add_function_node", "add_invariant", "list_function_nodes"} {
		s, ok := byKey[key]
		if !ok {
			t.Errorf("function-graph tool %q not seeded", key)
			continue
		}
		bound := false
		for _, a := range s.Agents {
			if a == "modeler" {
				bound = true
			}
		}
		if !bound {
			t.Errorf("tool %q not bound to modeler: agents=%v", key, s.Agents)
		}
	}
	// modeler's default prompt must be seeded for the UI "restore default" path.
	if BuiltinPromptSeeds()["modeler"] == "" {
		t.Error("modeler prompt not in BuiltinPromptSeeds")
	}
}
