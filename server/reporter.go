package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
	actool "github.com/Autumn-27/norma/tool"
)

type findingReportContext struct {
	FindingID       int64              `json:"finding_id,string"`
	FindingNodeID   *int64             `json:"finding_node_id,string,omitempty"`
	EvidenceVersion int64              `json:"evidence_version"`
	Finding         FindingDTO         `json:"finding"`
	Node            *db.Node           `json:"node,omitempty"`
	Traffic         *db.FindingTraffic `json:"traffic"`
	Task            *reportTaskContext `json:"task,omitempty"`
	IntentIDs       []string           `json:"intent_ids"`
	Warnings        []string           `json:"warnings"`
}

type reportTaskContext struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Goal        string          `json:"goal"`
	Constraints []db.Constraint `json:"constraints"`
}

func (s *Server) toolGetFindingReportContext() actool.CoreTool {
	return roTool("get_finding_report_context", "读取一个漏洞的完整报告上下文：独立 finding_id、finding_node_id、摘要/证据/已有报告、影响资产、来源任务与约束、相关 intent_ids、当前 evidence_version 与有序流量清单。finding_id 与 finding_node_id 二选一，不猜测编号。正文仍须用 get_finding_traffic 分段读取；本工具不重新探测。",
		objSchema(map[string]any{"finding_id": strParam("独立漏洞记录 ID，优先使用"), "finding_node_id": strParam("仅知道探索节点编号时使用，与 finding_id 二选一")}),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var input struct {
				FindingID json.RawMessage `json:"finding_id"`
				NodeID    json.RawMessage `json:"finding_node_id"`
			}
			if err := json.Unmarshal(raw, &input); err != nil {
				return actool.Errorf("无效 JSON: " + err.Error()), nil
			}
			if (len(input.FindingID) == 0) == (len(input.NodeID) == 0) {
				return actool.Errorf("finding_id 与 finding_node_id 必须且只能提供一个"), nil
			}
			id := parseProfileID(input.FindingID)
			if len(input.NodeID) > 0 {
				nodeID := parseProfileID(input.NodeID)
				if nodeID <= 0 {
					return actool.Errorf("finding_node_id 无效"), nil
				}
				var err error
				id, err = s.m.pg.FindingIDByNodeID(nodeID)
				if errors.Is(err, sql.ErrNoRows) {
					return actool.Errorf("找不到该探索节点对应的漏洞；不要猜测其他编号"), nil
				}
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
			}
			if err := s.agentFindingTrafficAccess(ctx, id, false); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, err := s.findingReportContext(ctx, id)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(out)
		})
}

func (s *Server) findingReportContext(ctx context.Context, id int64) (*findingReportContext, error) {
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, db.ErrFindingNotFound
	}
	// Freeze report and binding versions together using the existing export
	// snapshot path; bodies are deliberately read later via get_finding_traffic.
	if err := s.evidenceStore().StageFindingsExport(ctx, []*db.DBFinding{f}, "", false); err != nil {
		return nil, err
	}
	assets, err := s.m.Assets().GetByIDs(f.AssetIDs)
	if err != nil {
		return nil, err
	}
	assetMap := make(map[int64]*db.Asset, len(assets))
	for _, asset := range assets {
		assetMap[asset.ID] = asset
	}
	traffic := trafficSummary(&db.FindingTraffic{FindingID: id, Version: f.EvidenceVersion, ReportVersion: f.ReportEvidenceVersion, Bindings: f.TrafficBindings})
	f.TrafficBindings = nil
	out := &findingReportContext{FindingID: id, FindingNodeID: f.NodeID, EvidenceVersion: f.EvidenceVersion, Finding: findingFromDB(f, assetMap), Traffic: traffic, IntentIDs: []string{}, Warnings: []string{}}
	out.Finding.Report = report.AgentReportText(out.Finding.Report)
	if len(traffic.Bindings) == 0 {
		out.Warnings = append(out.Warnings, "未绑定 HTTP 流量；依据真实文字/命令证据撰写，不补造报文。")
	}
	if f.TaskID == nil {
		out.Warnings = append(out.Warnings, "来源任务不可用，无法补读执行过程。")
		return out, nil
	}
	task, err := s.m.pg.GetTask(*f.TaskID)
	if err != nil {
		return nil, err
	}
	if task == nil {
		out.Warnings = append(out.Warnings, "来源任务不可用，无法补读执行过程。")
		return out, nil
	}
	store := s.m.pg.Exploration(task.ExplorationID)
	constraints, err := store.ListConstraints()
	if err != nil {
		return nil, err
	}
	out.Task = &reportTaskContext{ID: strconv.FormatInt(task.ID, 10), Name: task.Name, Description: task.Description, Goal: task.Goal, Constraints: constraints}
	if f.NodeID == nil {
		out.Warnings = append(out.Warnings, "探索节点不可用，使用独立漏洞记录中的保留证据。")
		return out, nil
	}
	if ri := agent.RunInfoFrom(ctx); ri.TaskID > 0 && ri.TaskID != task.ID {
		// Retained findings are readable in a child task; live source Worker
		// traces and nodes must not be exposed through this convenience tool.
		out.Warnings = append(out.Warnings, "继承漏洞只读；到来源任务读取执行过程并保存报告。")
		return out, nil
	}
	out.Node, err = store.GetNode(*f.NodeID)
	if err != nil {
		return nil, err
	}
	rows, err := s.m.pg.QueryContext(ctx, `SELECT e.src_id FROM exploration_edges e JOIN exploration_nodes n ON n.id=e.src_id WHERE e.exploration_id=$1 AND e.dst_id=$2 AND e.rel=$3 AND n.kind='intent' ORDER BY e.src_id`, task.ExplorationID, *f.NodeID, db.RelYields)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var intentID int64
		if err := rows.Scan(&intentID); err != nil {
			return nil, err
		}
		out.IntentIDs = append(out.IntentIDs, strconv.FormatInt(intentID, 10))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

const reporterCapabilityFlag = "reporter_reproduction_v1"
const reporterImageSchemaFlag = "reporter_image_schema_v1"

// Add screenshot inputs once for already-deployed databases. Existing property
// definitions remain untouched so user-edited tool schemas survive upgrades.
func (s *Server) upgradeReporterImageSchemaTx(tx *sql.Tx) error {
	if _, err := tx.Exec(`UPDATE agent_triggers SET tool_call_message=$1 WHERE agent_key='reporter' AND on_tool_call AND tool_call_message=$2`, reporterToolCallMessage, reporterToolCallMessageV3); err != nil {
		return err
	}
	var value string
	err := tx.QueryRow(`SELECT value FROM settings WHERE key=$1`, reporterImageSchemaFlag).Scan(&value)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if value == "true" {
		return nil
	}
	var raw json.RawMessage
	if err = tx.QueryRow(`SELECT schema FROM tools WHERE key='update_finding_report' AND system FOR UPDATE`).Scan(&raw); err != nil {
		return err
	}
	var schema map[string]any
	if err = json.Unmarshal(raw, &schema); err != nil {
		return err
	}
	if schema == nil {
		return fmt.Errorf("update_finding_report schema is empty")
	}
	var defaults map[string]any
	encoded, err := json.Marshal(s.toolUpdateFindingReport().InputSchema())
	if err != nil {
		return err
	}
	if err = json.Unmarshal(encoded, &defaults); err != nil {
		return err
	}
	defaultProperties := objectProperty(defaults, "properties")
	properties := objectProperty(schema, "properties")
	changed := false
	for _, key := range []string{"with_images", "report_steps"} {
		if _, exists := properties[key]; !exists {
			properties[key] = defaultProperties[key]
			changed = true
		}
	}
	if changed {
		raw, err = json.Marshal(schema)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`UPDATE tools SET schema=$1::jsonb,updated_at=now() WHERE key='update_finding_report' AND system`, string(raw)); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`INSERT INTO settings(key,value) VALUES($1,'true') ON CONFLICT(key) DO UPDATE SET value='true'`, reporterImageSchemaFlag)
	return err
}

// Upgrade only untouched defaults. A transaction serializes the flag, binding,
// schema and prompt changes; failed upgrades retry at the next startup.
func (s *Server) upgradeReporterCapabilities() error {
	tx, err := s.m.pg.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SELECT pg_advisory_xact_lock($1)`, int64(7337741010)); err != nil {
		return err
	}
	if err = s.upgradeReporterImageSchemaTx(tx); err != nil {
		return err
	}
	var value string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key=$1`, reporterCapabilityFlag).Scan(&value)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if value == "true" {
		return tx.Commit()
	}
	if _, err = tx.Exec(`UPDATE agent_triggers SET tool_call_message=$1 WHERE agent_key='reporter' AND on_tool_call AND tool_call_message IN ($2,$3,$4)`, reporterToolCallMessage, reporterToolCallMessageV1, reporterToolCallMessageV2, reporterToolCallMessageV3); err != nil {
		return err
	}
	var raw json.RawMessage
	if err = tx.QueryRow(`SELECT schema FROM tools WHERE key='update_finding_report' AND system FOR UPDATE`).Scan(&raw); err != nil {
		return err
	}
	var schema map[string]any
	if err = json.Unmarshal(raw, &schema); err != nil {
		return err
	}
	if schema == nil {
		return fmt.Errorf("update_finding_report schema is empty")
	}
	properties := objectProperty(schema, "properties")
	if _, exists := properties["finding_record_id"]; !exists {
		properties["finding_record_id"] = strParam("独立漏洞记录 ID，优先使用；与旧 finding_id（探索节点 ID）二选一")
	}
	if _, exists := properties["evidence_version"]; !exists {
		properties["evidence_version"] = map[string]any{"type": "integer", "description": "实际读取的证据版本；无流量时为 0"}
	}
	kept := []any{}
	requiredFields := map[string]bool{}
	if required, ok := schema["required"].([]any); ok {
		for _, field := range required {
			name, ok := field.(string)
			if !ok {
				return fmt.Errorf("update_finding_report required fields must be strings")
			}
			if name != "finding_id" {
				kept = append(kept, name)
				requiredFields[name] = true
			}
		}
	}
	for _, name := range []string{"report", "evidence_version"} {
		if !requiredFields[name] {
			kept = append(kept, name)
		}
	}
	schema["required"] = kept
	raw, err = json.Marshal(schema)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE tools SET schema=$1::jsonb,updated_at=now() WHERE key='update_finding_report' AND system`, string(raw)); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO settings(key,value) VALUES($1,'true') ON CONFLICT(key) DO UPDATE SET value='true'`, reporterCapabilityFlag); err != nil {
		return err
	}
	// Reporter-specific defaults are optional: a user may have removed the
	// built-in agent, while the global save-tool schema still needs upgrading.
	var agentID int64
	var promptID *int64
	err = tx.QueryRow(`SELECT id,current_prompt_id FROM agents WHERE key='reporter' FOR UPDATE`).Scan(&agentID, &promptID)
	if errors.Is(err, sql.ErrNoRows) {
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE tools SET agents=agents || '["reporter"]'::jsonb WHERE key='get_finding_report_context' AND NOT agents @> '["reporter"]'::jsonb`); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO agent_skill_visibility(agent_id,skill_name,enabled) VALUES($1,'vuln-report-writer',true) ON CONFLICT DO NOTHING`, agentID); err != nil {
		return err
	}
	if promptID != nil {
		var current string
		if err = tx.QueryRow(`SELECT template_text FROM agent_prompts WHERE id=$1`, *promptID).Scan(&current); err != nil {
			return err
		}
		if current == agent.ReporterLegacyPrompt {
			var version int
			if err = tx.QueryRow(`SELECT COALESCE(max(version),0)+1 FROM agent_prompts WHERE agent_id=$1`, agentID).Scan(&version); err != nil {
				return err
			}
			var newID int64
			if err = tx.QueryRow(`INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by) VALUES($1,$2,$3,'复现报告规范升级','system') RETURNING id`, agentID, version, agent.ReporterDefaultPrompt).Scan(&newID); err != nil {
				return err
			}
			if _, err = tx.Exec(`UPDATE agents SET current_prompt_id=$1 WHERE id=$2`, newID, agentID); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
