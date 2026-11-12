package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/skill"
)

func TestReporterContextAndSave(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	tools := s.orchestrationTools()
	tool := workflowTool(t, tools, "get_finding_report_context")
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: *finding.TaskID})
	result := workflowCall(t, ctx, tool, map[string]any{"finding_id": f.FindingID}, false)
	var reportContext struct {
		FindingID       int64 `json:"finding_id,string"`
		FindingNodeID   int64 `json:"finding_node_id,string"`
		EvidenceVersion int64 `json:"evidence_version"`
		Finding         struct {
			Evidence string `json:"evidence"`
		} `json:"finding"`
	}
	if err := json.Unmarshal([]byte(result), &reportContext); err != nil {
		t.Fatal(err)
	}
	if reportContext.FindingID != f.FindingID || reportContext.FindingNodeID != f.NodeID || reportContext.EvidenceVersion != 0 {
		t.Fatalf("wrong report context: %s", result)
	}
	workflowCall(t, ctx, s.toolUpdateFindingReport(), map[string]any{"finding_record_id": f.FindingID, "evidence_version": 0, "report": "## 复现步骤\n\n已有命令证据，无 HTTP 流量。"}, false)
	stored, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || stored == nil || !strings.Contains(stored.Report, "已有命令证据") || stored.ReportEvidenceVersion != 0 {
		t.Fatalf("report not saved: %+v %v", stored, err)
	}
	for _, input := range []map[string]any{
		{"finding_record_id": f.FindingID, "evidence_version": 0, "report": " \n\t"},
		{"finding_record_id": f.FindingID, "report": "missing version"},
		{"finding_record_id": f.FindingID, "evidence_version": -1, "report": "negative version"},
		{"finding_record_id": f.FindingID, "evidence_version": 99, "report": "stale version"},
		{"finding_record_id": f.FindingID, "finding_id": f.NodeID, "evidence_version": 0, "report": "ambiguous ids"},
	} {
		workflowCall(t, ctx, s.toolUpdateFindingReport(), input, true)
	}
	storedAfter, _ := s.m.pg.GetFinding(f.FindingID)
	if storedAfter.Report != stored.Report {
		t.Fatal("invalid save replaced previous report")
	}
	workflowCall(t, ctx, s.toolUpdateFindingReport(), map[string]any{"finding_id": f.NodeID, "evidence_version": 0, "report": "legacy node ID still works"}, false)
}

func TestReporterSaveRejectsInvalidJSON(t *testing.T) {
	s := &Server{}
	result, err := s.toolUpdateFindingReport().Call(context.Background(), json.RawMessage(`{"finding_id":1,"report":`), nil)
	if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "JSON") {
		t.Fatalf("expected JSON validation error, got %v %s", err, result.Flatten())
	}
}

func TestReporterContextEvidenceAndLineage(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	finding, _ := s.m.pg.GetFinding(f.FindingID)
	task, ok := s.m.Task(strconv.FormatInt(*finding.TaskID, 10))
	if !ok {
		t.Fatal("task missing")
	}
	intentID, err := task.Store.AddIntent(map[string]any{"summary": "use account A to request account B object"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := task.Store.Link(intentID, db.RelYields, f.NodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := task.Store.AddConstraint("deny", "do not modify account B data", "human"); err != nil {
		t.Fatal(err)
	}
	proof := strings.Repeat("saved evidence line\n", 200)
	assetID, err := s.m.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{URL: "http://reporter-context.test/", TaskID: *finding.TaskID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.Assets().DeleteByIDs([]int64{assetID}) })
	if _, err := s.m.pg.Exec(`UPDATE findings SET asset_ids=$1 WHERE id=$2`, []int64{assetID}, f.FindingID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Exec(`UPDATE findings SET evidence=$1 WHERE id=$2`, proof, f.FindingID); err != nil {
		t.Fatal(err)
	}
	seedServerEvidenceFlow(t, s, "reporter-proof", []byte(`{"owner":"B"}`))
	if _, err := s.evidenceStore().Bind(context.Background(), f.FindingID, []db.TrafficRef{{TrafficID: "reporter-proof", Role: "proof", Note: "A received B data"}}); err != nil {
		t.Fatal(err)
	}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: *finding.TaskID})
	text := workflowCall(t, ctx, s.toolGetFindingReportContext(), map[string]any{"finding_node_id": f.NodeID}, false)
	var out findingReportContext
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if out.Finding.Evidence != proof || out.EvidenceVersion != 1 || len(out.Traffic.Bindings) != 1 || out.Traffic.Bindings[0].Role != "proof" || out.Task == nil || len(out.Task.Constraints) != 1 || len(out.IntentIDs) != 1 || out.IntentIDs[0] != strconv.FormatInt(intentID, 10) {
		t.Fatalf("incomplete context: %+v", out)
	}
	if out.Traffic.Bindings[0].Snapshot.ReqHead != "" || out.Traffic.Bindings[0].Snapshot.RespHead != "" {
		t.Fatal("traffic list should remain metadata only")
	}
	if len(out.Finding.Assets) != 1 || out.Finding.Assets[0].ID != strconv.FormatInt(assetID, 10) || out.Finding.Assets[0].Label != "http://reporter-context.test" {
		t.Fatalf("missing asset context: %+v", out.Finding.Assets)
	}
	for _, input := range []map[string]any{{}, {"finding_id": f.FindingID, "finding_node_id": f.NodeID}, {"finding_id": -1}, {"finding_node_id": -1}} {
		workflowCall(t, ctx, s.toolGetFindingReportContext(), input, true)
	}
}

func TestReporterTaskBoundaryAndRetainedFinding(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	finding, _ := s.m.pg.GetFinding(f.FindingID)
	other, err := s.m.CreateTask("unrelated report task", "unrelated", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.DeleteTask(other.ID, DeleteTaskOptions{}) })
	otherCtx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: mustTaskID(t, other.ID)})
	workflowCall(t, otherCtx, s.toolGetFindingReportContext(), map[string]any{"finding_id": f.FindingID}, true)
	workflowCall(t, otherCtx, s.toolUpdateFindingReport(), map[string]any{"finding_record_id": f.FindingID, "evidence_version": 0, "report": "wrong task"}, true)
	child, err := s.m.CreateTaskWithOptions("inherited report task", "inherited", db.TaskCreateOptions{SourceTaskIDs: []int64{*finding.TaskID}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.DeleteTask(child.ID, DeleteTaskOptions{}) })
	childCtx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: mustTaskID(t, child.ID)})
	text := workflowCall(t, childCtx, s.toolGetFindingReportContext(), map[string]any{"finding_id": f.FindingID}, false)
	var out findingReportContext
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if out.Node != nil || len(out.IntentIDs) != 0 {
		t.Fatal("inherited context exposed source work")
	}
	workflowCall(t, childCtx, s.toolUpdateFindingReport(), map[string]any{"finding_record_id": f.FindingID, "evidence_version": 0, "report": "inherited overwrite"}, true)
	if _, err := s.m.pg.Exec(`DELETE FROM exploration_nodes WHERE id=$1`, f.NodeID); err != nil {
		t.Fatal(err)
	}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: *finding.TaskID})
	text = workflowCall(t, ctx, s.toolGetFindingReportContext(), map[string]any{"finding_id": f.FindingID}, false)
	out = findingReportContext{}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if out.FindingNodeID != nil {
		t.Fatal("deleted node still appears")
	}
	workflowCall(t, ctx, s.toolUpdateFindingReport(), map[string]any{"finding_record_id": f.FindingID, "evidence_version": 0, "report": "retained report"}, false)
}

func TestReporterUpgradePreservesCustomizations(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	reporter, err := pg.GetAgentByKey("reporter")
	if err != nil || reporter == nil {
		t.Fatal("missing reporter", err)
	}
	preserveReporterFixture(t, pg, reporter.ID)
	for _, custom := range []bool{false, true} {
		t.Run(fmt.Sprint("custom=", custom), func(t *testing.T) {
			prompt := agent.ReporterLegacyPrompt
			message := reporterToolCallMessageV2
			if custom {
				prompt = "USER REPORT PROMPT"
				message = "USER TRIGGER MESSAGE"
			}
			if _, err := pg.SavePrompt(reporter.ID, prompt, "fixture", "test"); err != nil {
				t.Fatal(err)
			}
			triggers, err := pg.ListTriggersFor("reporter")
			if err != nil || len(triggers) == 0 {
				t.Fatal("no trigger", err)
			}
			tr := triggers[0]
			tr.ToolCallMessage = message
			tr.Enabled = false
			if err := pg.UpdateTrigger(tr); err != nil {
				t.Fatal(err)
			}
			if _, err := pg.Exec(`DELETE FROM settings WHERE key=$1`, reporterCapabilityFlag); err != nil {
				t.Fatal(err)
			}
			if _, err := pg.Exec(`INSERT INTO agent_skill_visibility(agent_id,skill_name,enabled) VALUES($1,'vuln-report-writer',false) ON CONFLICT(agent_id,skill_name) DO UPDATE SET enabled=false`, reporter.ID); err != nil {
				t.Fatal(err)
			}
			if err := pg.RemoveAgentFromTool("reporter", "get_finding_report_context"); err != nil {
				t.Fatal(err)
			}
			legacySchema := json.RawMessage(`{"type":"object","properties":{"finding_id":{"type":"integer","description":"USER ID GUIDE"},"report":{"type":"string","description":"USER REPORT GUIDE"},"evidence_version":{"type":"integer"}},"required":["finding_id","report"]}`)
			if err := pg.UpdateTool("update_finding_report", "USER TOOL DESCRIPTION", legacySchema, json.RawMessage(`["reporter","auto"]`), false); err != nil {
				t.Fatal(err)
			}
			if err := s.upgradeReporterCapabilities(); err != nil {
				t.Fatal(err)
			}
			got, err := pg.CurrentPrompt(reporter.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !custom {
				prompt = agent.ReporterDefaultPrompt
				message = reporterToolCallMessage
			}
			if got != prompt {
				t.Fatalf("prompt changed incorrectly: %s", got)
			}
			triggers, _ = pg.ListTriggersFor("reporter")
			if triggers[0].Enabled || triggers[0].ToolCallMessage != message {
				t.Fatal("trigger customization lost")
			}
			names, _ := pg.AgentSkillNames(reporter.ID)
			if contains(names, "vuln-report-writer") {
				t.Fatal("disabled skill enabled")
			}
			tool, _ := pg.GetTool("get_finding_report_context")
			if !contains(tool.Agents, "reporter") {
				t.Fatal("context tool not bound")
			}
			save, _ := pg.GetTool("update_finding_report")
			var schema struct {
				Properties map[string]struct{ Description string }
				Required   []string
			}
			if err := json.Unmarshal(save.Schema, &schema); err != nil {
				t.Fatal(err)
			}
			if save.Enabled || save.Description != "USER TOOL DESCRIPTION" || !contains(save.Agents, "auto") || schema.Properties["finding_id"].Description != "USER ID GUIDE" || schema.Properties["report"].Description != "USER REPORT GUIDE" {
				t.Fatal("tool customization lost")
			}
			if _, ok := schema.Properties["finding_record_id"]; !ok || contains(schema.Required, "finding_id") || !contains(schema.Required, "report") || !contains(schema.Required, "evidence_version") {
				t.Fatalf("save schema does not match handler: %s", save.Schema)
			}
			if err := pg.RemoveAgentFromTool("reporter", "get_finding_report_context"); err != nil {
				t.Fatal(err)
			}
			if err := s.upgradeReporterCapabilities(); err != nil {
				t.Fatal(err)
			}
			tool, _ = pg.GetTool("get_finding_report_context")
			if contains(tool.Agents, "reporter") {
				t.Fatal("restart reversed user unbinding")
			}
		})
	}
}

// Restore every shared configuration row changed by migration tests, including
// prompt history and explicitly disabled skill rows, before closing the fixture.
func preserveReporterFixture(t *testing.T, pg *db.DB, agentID int64) {
	t.Helper()
	var promptID sql.NullInt64
	var maxVersion int
	if err := pg.QueryRow(`SELECT current_prompt_id FROM agents WHERE id=$1`, agentID).Scan(&promptID); err != nil {
		t.Fatal(err)
	}
	if err := pg.QueryRow(`SELECT COALESCE(max(version),0) FROM agent_prompts WHERE agent_id=$1`, agentID).Scan(&maxVersion); err != nil {
		t.Fatal(err)
	}
	triggers, err := pg.ListTriggersFor("reporter")
	if err != nil {
		t.Fatal(err)
	}
	flag, hadFlag, err := pg.GetSetting(reporterCapabilityFlag)
	if err != nil {
		t.Fatal(err)
	}
	imageFlag, hadImageFlag, err := pg.GetSetting(reporterImageSchemaFlag)
	if err != nil {
		t.Fatal(err)
	}
	var visible bool
	err = pg.QueryRow(`SELECT enabled FROM agent_skill_visibility WHERE agent_id=$1 AND skill_name='vuln-report-writer'`, agentID).Scan(&visible)
	if err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	hadVisibility := err == nil
	var originalTools []*db.Tool
	for _, key := range []string{"get_finding_report_context", "update_finding_report"} {
		tool, err := pg.GetTool(key)
		if err != nil || tool == nil {
			t.Fatal("missing tool", key, err)
		}
		originalTools = append(originalTools, tool)
	}
	t.Cleanup(func() {
		check := func(err error) {
			if err != nil {
				t.Error("restore reporter fixture:", err)
			}
		}
		_, err := pg.Exec(`UPDATE agents SET current_prompt_id=$1 WHERE id=$2`, promptID, agentID)
		check(err)
		_, err = pg.Exec(`DELETE FROM agent_prompts WHERE agent_id=$1 AND version>$2`, agentID, maxVersion)
		check(err)
		for _, tr := range triggers {
			check(pg.UpdateTrigger(tr))
		}
		if hadFlag {
			check(pg.SetSetting(reporterCapabilityFlag, flag))
		} else {
			_, err = pg.Exec(`DELETE FROM settings WHERE key=$1`, reporterCapabilityFlag)
			check(err)
		}
		if hadImageFlag {
			check(pg.SetSetting(reporterImageSchemaFlag, imageFlag))
		} else {
			_, err := pg.Exec(`DELETE FROM settings WHERE key=$1`, reporterImageSchemaFlag)
			check(err)
		}
		_, err = pg.Exec(`DELETE FROM agent_skill_visibility WHERE agent_id=$1 AND skill_name='vuln-report-writer'`, agentID)
		check(err)
		if hadVisibility {
			_, err = pg.Exec(`INSERT INTO agent_skill_visibility(agent_id,skill_name,enabled) VALUES($1,'vuln-report-writer',$2)`, agentID, visible)
			check(err)
		}
		for _, tool := range originalTools {
			bindings, err := json.Marshal(tool.Agents)
			check(err)
			check(pg.UpdateTool(tool.Key, tool.Description, tool.Schema, bindings, tool.Enabled))
		}
	})
}

func TestReporterUpgradeRetriesAndLoadsSkill(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	reporter, err := pg.GetAgentByKey("reporter")
	if err != nil || reporter == nil {
		t.Fatal("missing reporter", err)
	}
	preserveReporterFixture(t, pg, reporter.ID)
	legacyFlag, hadLegacyFlag, err := pg.GetSetting("reporter_trigger_evidence_version_v1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadLegacyFlag {
			pg.SetSetting("reporter_trigger_evidence_version_v1", legacyFlag)
		} else {
			pg.Exec(`DELETE FROM settings WHERE key='reporter_trigger_evidence_version_v1'`)
		}
	})
	triggers, err := pg.ListTriggersFor("reporter")
	if err != nil || len(triggers) == 0 {
		t.Fatal("no trigger", err)
	}
	triggers[0].ToolCallMessage = reporterToolCallMessageV1
	if err := pg.UpdateTrigger(triggers[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.SavePrompt(reporter.ID, agent.ReporterLegacyPrompt, "fixture", "test"); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`DELETE FROM settings WHERE key='reporter_reproduction_v1'`,
		`DELETE FROM settings WHERE key='reporter_trigger_evidence_version_v1'`,
		`DELETE FROM agent_skill_visibility WHERE agent_id=(SELECT id FROM agents WHERE key='reporter') AND skill_name='vuln-report-writer'`,
		`UPDATE tools SET schema='null'::jsonb WHERE key='update_finding_report'`,
	} {
		if _, err := pg.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if err := pg.RemoveAgentFromTool("reporter", "get_finding_report_context"); err != nil {
		t.Fatal(err)
	}
	if err := s.upgradeReporterCapabilities(); err == nil {
		t.Fatal("expected invalid schema to roll back migration")
	}
	// Exercise the full startup ordering too: a legacy trigger must not be
	// advanced independently when the capability/schema transaction fails.
	s.seedOrchestrationTools()
	triggers, err = pg.ListTriggersFor("reporter")
	if err != nil || triggers[0].ToolCallMessage != reporterToolCallMessageV1 {
		t.Fatal("failed startup upgrade changed legacy trigger", err)
	}
	if _, ok, err := pg.GetSetting(reporterCapabilityFlag); err != nil || ok {
		t.Fatal("failed migration marked complete", err)
	}
	prompt, _ := pg.CurrentPrompt(reporter.ID)
	tool, _ := pg.GetTool("get_finding_report_context")
	names, _ := pg.AgentSkillNames(reporter.ID)
	if prompt != agent.ReporterLegacyPrompt || contains(tool.Agents, "reporter") || contains(names, "vuln-report-writer") {
		t.Fatal("failed migration left partial changes")
	}
	schema, err := json.Marshal(s.toolUpdateFindingReport().InputSchema())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`UPDATE tools SET schema=$1::jsonb WHERE key='update_finding_report'`, string(schema)); err != nil {
		t.Fatal(err)
	}
	if err := s.upgradeReporterCapabilities(); err != nil {
		t.Fatal(err)
	}
	triggers, err = pg.ListTriggersFor("reporter")
	if err != nil || triggers[0].ToolCallMessage != reporterToolCallMessage {
		t.Fatal("retry did not upgrade legacy trigger", err)
	}
	names, _ = pg.AgentSkillNames(reporter.ID)
	if !contains(names, "vuln-report-writer") {
		t.Fatal("reporting skill not enabled by upgrade")
	}
	reg, err := skill.LoadDir(filepath.Join("..", "skills"))
	if err != nil {
		t.Fatal(err)
	}
	loaded, ok := reg.Get("vuln-report-writer")
	if !ok || loaded.Instructions == "" {
		t.Fatal("shipped reporting skill cannot be loaded")
	}
	oldAugment := agent.ToolAugment
	t.Cleanup(func() { agent.ToolAugment = oldAugment })
	wireAgentAugment(pg, filepath.Join("..", "skills"), t.TempDir(), nil)
	extra, _, cleanup := agent.ToolAugment(context.Background(), "reporter")
	defer cleanup()
	result, err := workflowTool(t, extra, "Skill").Call(context.Background(), json.RawMessage(`{"name":"vuln-report-writer"}`), nil)
	if err != nil || result.IsError || len(result.Extra) != 1 || !strings.Contains(result.Flatten(), "loaded") {
		t.Fatalf("reporter cannot invoke skill: %+v %v", result, err)
	}
}

func TestReporterUpgradeWithoutReporter(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	reporter, err := pg.GetAgentByKey("reporter")
	if err != nil || reporter == nil {
		t.Fatal("missing reporter fixture", err)
	}
	preserveReporterFixture(t, pg, reporter.ID)
	// Rename instead of cascading deletion so other shared fixture rows survive.
	if _, err := pg.Exec(`UPDATE agents SET key='reporter_migration_fixture' WHERE id=$1`, reporter.ID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pg.Exec(`UPDATE agents SET key='reporter' WHERE id=$1`, reporter.ID); err != nil {
			t.Error(err)
		}
	})
	if _, err := pg.Exec(`DELETE FROM settings WHERE key=$1`, reporterCapabilityFlag); err != nil {
		t.Fatal(err)
	}
	legacySchema := `{"type":"object","properties":{"finding_id":{"type":"integer"},"report":{"type":"string"}},"required":["finding_id","report"]}`
	if _, err := pg.Exec(`UPDATE tools SET schema=$1::jsonb WHERE key='update_finding_report'`, legacySchema); err != nil {
		t.Fatal(err)
	}
	if err := s.upgradeReporterCapabilities(); err != nil {
		t.Fatal(err)
	}
	tool, err := pg.GetTool("update_finding_report")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]json.RawMessage
		Required   []string
	}
	if err := json.Unmarshal(tool.Schema, &schema); err != nil {
		t.Fatal(err)
	}
	if len(schema.Properties["finding_record_id"]) == 0 || len(schema.Properties["evidence_version"]) == 0 || contains(schema.Required, "finding_id") || !contains(schema.Required, "evidence_version") {
		t.Fatalf("global report schema not upgraded without reporter: %s", tool.Schema)
	}
	if ag, err := pg.GetAgentByKey("reporter"); err != nil || ag != nil {
		t.Fatal("deleted reporter was recreated", err)
	}
	if flag, ok, err := pg.GetSetting(reporterCapabilityFlag); err != nil || !ok || flag != "true" {
		t.Fatal("schema migration not completed", err)
	}
}
