package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// hasSkillTool reports whether the packed tool set contains the Skill meta-tool.
func hasSkillTool(tools []actool.CoreTool) bool {
	for _, t := range tools {
		if t.Name() == "Skill" {
			return true
		}
	}
	return false
}

func hasMCPFlagValue(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

func TestBrowserMCPOutputDirectoryIsScopedToWorkerIntent(t *testing.T) {
	baseArgs, _ := json.Marshal([]string{"@playwright/mcp", "--headless", "--output-dir", "old-output", "--file-paths", "relative"})
	base := &db.MCPServer{Name: browserMCPName, Transport: "stdio", Command: "npx", Args: baseArgs}
	dataDir := t.TempDir()
	configured, ok, err := browserMCPForRun(base, dataDir, agent.RunInfo{TaskID: 51, IntentID: 82})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("worker browser MCP was not configured for screenshots")
	}
	args := jsonStrSlice(configured.Args)
	wantOutput := filepath.Join(dataDir, "tasks", "51", "i82", "screenshots")
	if !hasMCPFlagValue(args, "--output-dir", wantOutput) || !hasMCPFlagValue(args, "--file-paths", "absolute") {
		t.Fatalf("browser MCP screenshot args missing output scope: %#v", args)
	}
	if hasMCPFlagValue(args, "--output-dir", "old-output") || hasMCPFlagValue(args, "--file-paths", "relative") {
		t.Fatalf("browser MCP retained an overriding output configuration: %#v", args)
	}
	if string(base.Args) != string(baseArgs) {
		t.Fatal("per-run browser configuration mutated the saved MCP definition")
	}
	if _, err := os.Stat(wantOutput); err != nil {
		t.Fatalf("screenshot output directory was not created: %v", err)
	}
}

func TestBrowserMCPOutputDirectoryIsNotChangedOutsideWorkerRun(t *testing.T) {
	args, _ := json.Marshal([]string{"@playwright/mcp", "--headless"})
	base := &db.MCPServer{Name: browserMCPName, Transport: "stdio", Command: "npx", Args: args}
	for _, info := range []agent.RunInfo{{}, {TaskID: 51}} {
		got, configured, err := browserMCPForRun(base, t.TempDir(), info)
		if err != nil {
			t.Fatal(err)
		}
		if configured || got != base {
			t.Fatalf("non-worker browser MCP was unexpectedly configured: info=%+v", info)
		}
	}
}

func TestBrowserMCPOutputDirectoryLeavesOtherServerUntouched(t *testing.T) {
	args, _ := json.Marshal([]string{"some-other-browser-server"})
	base := &db.MCPServer{Name: browserMCPName, Transport: "stdio", Command: "npx", Args: args}
	got, configured, err := browserMCPForRun(base, t.TempDir(), agent.RunInfo{TaskID: 51, IntentID: 82})
	if err != nil {
		t.Fatal(err)
	}
	if configured || got != base {
		t.Fatal("a non-Playwright MCP definition was changed")
	}
}

// TestAssembleVisibleSkill verifies a filesystem skill made visible to an agent is
// packed into that agent's tool set (as the single Skill meta-tool) via the wired
// ToolAugment hook. Skills live on disk under skillDir; visibility is a per-agent
// (agent × skill_name) row keyed by the skill's directory name.
func TestAssembleVisibleSkill(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	// Filesystem skill fixture: <skillDir>/t-assemble/SKILL.md. The directory name
	// (t-assemble) is the visibility key matched against AgentSkillNames.
	skillDir := t.TempDir()
	const skillName = "t-assemble"
	if err := os.MkdirAll(filepath.Join(skillDir, skillName), 0o755); err != nil {
		t.Fatal(err)
	}
	md := "---\nname: t-assemble\ndescription: do the thing\n---\ndo the thing"
	if err := os.WriteFile(filepath.Join(skillDir, skillName, "SKILL.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}

	wireAgentAugment(pg, skillDir, t.TempDir(), nil)
	t.Cleanup(func() { agent.ToolAugment = nil })

	ag, _ := pg.GetAgentByKey("planner")
	if ag == nil {
		t.Fatal("planner agent missing")
	}

	// Isolate this test from whatever skill visibility the planner already has in the
	// shared DB: clear it now, restore it on cleanup.
	orig, _ := pg.AgentSkillNames(ag.ID)
	if err := pg.SetAgentSkillVisibility(ag.ID, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.SetAgentSkillVisibility(ag.ID, orig) })

	// before: skill not visible → no Skill meta-tool
	extra, _, cleanup := agent.ToolAugment(context.Background(), "planner")
	cleanup()
	if hasSkillTool(extra) {
		t.Fatalf("expected no Skill meta-tool before the skill is made visible")
	}

	// make the skill visible to planner
	if err := pg.ToggleSkillVisibility(ag.ID, skillName, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.ToggleSkillVisibility(ag.ID, skillName, false) })

	// after: the Skill meta-tool is packed in
	extra, _, cleanup = agent.ToolAugment(context.Background(), "planner")
	defer cleanup()
	if !hasSkillTool(extra) {
		t.Fatalf("expected the Skill meta-tool after making the skill visible")
	}

	// AugmentTools appends extra to base without filtering base
	combined, _, c2 := agent.AugmentTools(context.Background(), "planner", nil)
	defer c2()
	if !hasSkillTool(combined) {
		t.Fatalf("AugmentTools should surface the Skill meta-tool")
	}
}
