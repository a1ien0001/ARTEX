package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// This file holds the function-graph (业务功能图) write/read tools used by the
// `modeler` agent to build the third graph: the business-semantic model that maps
// the frontend's "给人看的业务缩影" into module→feature→action nodes, role
// reachability, maps_to bridges to the asset graph, and invariants (the "本不该如此"
// oracle). The tools mirror record_fact / insert_assets conventions: batch items,
// {ids, errors} return shape, writeExpTool/readExpTool nil-store guard. The handler
// dereferences t.fs, which is derived from t.ts (so the needExploration guard, which
// checks t.ts, gates these correctly).

// ---- add_function_node ----

type funcNodeItem struct {
	Kind       string          `json:"kind"`
	Name       string          `json:"name"`
	Path       string          `json:"path"`
	ParentID   json.RawMessage `json:"parent_id"`
	AppID      json.RawMessage `json:"app_id"`
	StatePre   string          `json:"state_pre"`
	RoleSeen   string          `json:"role_seen"`
	Confidence string          `json:"confidence"`
	Evidence   string          `json:"evidence"`
	Props      map[string]any  `json:"props"`
}

func (t *ToolSet) addOneFunctionNode(it funcNodeItem) (int64, error) {
	payload := map[string]any{}
	for k, v := range it.Props {
		payload[k] = v
	}
	if e := strings.TrimSpace(it.Evidence); e != "" {
		payload["evidence"] = e
	}
	id, err := t.fs.AddFunctionNode(db.AddFunctionNodeReq{
		AppID:      pid(it.AppID),
		Kind:       it.Kind,
		Name:       it.Name,
		Path:       it.Path,
		StatePre:   it.StatePre,
		RoleSeen:   it.RoleSeen,
		Confidence: it.Confidence,
		Payload:    payload,
	})
	if err != nil {
		return 0, err
	}
	// parent_id (if given) → contains edge (module→feature→action hierarchy).
	if parent := pid(it.ParentID); parent > 0 {
		_ = t.fs.LinkFunction(parent, db.RelContains, id, "")
	}
	t.writes.FuncNodes++
	return id, nil
}

func (t *ToolSet) addFunctionNode() actool.CoreTool {
	return t.writeExpTool("add_function_node",
		"把一个【业务功能节点】写入功能图：module(一级模块)→feature(二级功能)→action(原子动作)。"+
			"这里只登记【业务结构】(这个系统能干什么、谁能看到),不登记漏洞、不登记技术资产(接口本身用 insert_assets,再用 map_function_to_endpoint 挂上来)。"+
			"写前先 list_function_nodes 去重；只写增量,别把已登记节点换措辞重记。返回 {ids,errors},ids 与 nodes 等长同序。",
		obj(map[string]any{
			"nodes":      map[string]any{"type": "array", "description": "【优先批量】功能节点数组,元素字段同下方顶层字段。", "items": map[string]any{"type": "object"}},
			"kind":       str("[单条] module|feature|action"),
			"name":       str("业务名,如 订单模块 / 退款 / 提交退款申请"),
			"path":       str("UI 路由或面包屑,如 /order/:id/refund(可选)"),
			"parent_id":  idp("父节点 id(自动建 contains 层级边);顶层模块留空"),
			"app_id":     idp("所属应用根(资产图 type=app/subdomain 的 id,可选)"),
			"state_pre":  str("进入该动作要求的业务状态,如 已支付(仅 action,可选)"),
			"role_seen":  str("本次是以哪个角色看到/到达它的(建角色可达性用,可选)"),
			"confidence": str("observed(菜单/UI直接看到) | inferred(路由推断,未实际到达)。默认 observed。"),
			"evidence":   str("一行来源证据,如 '/api/menu 返回含此项'"),
			"props":      map[string]any{"type": "object", "description": "其它结构化属性(可选),写入节点 payload"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.fs == nil {
				return actool.Errorf("add_function_node 需要任务上下文(功能图)"), nil
			}
			var a struct {
				Nodes []funcNodeItem `json:"nodes"`
				funcNodeItem
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Nodes) > 0
			items := a.Nodes
			if !batch {
				items = []funcNodeItem{a.funcNodeItem}
			}
			ids := make([]int64, len(items))
			errs := map[string]string{}
			for i, it := range items {
				id, err := t.addOneFunctionNode(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
			}
			if !batch {
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("function node: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

// ---- map_function_to_endpoint ----

type funcMapItem struct {
	FunctionNodeID  json.RawMessage `json:"function_node_id"`
	EndpointAssetID json.RawMessage `json:"endpoint_asset_id"`
	Evidence        string          `json:"evidence"`
}

func (t *ToolSet) mapFunctionToEndpoint() actool.CoreTool {
	return t.writeExpTool("map_function_to_endpoint",
		"把一个【动作】连到它实际触发的资产图 endpoint(maps_to 桥)。只引用 endpoint 的 id,不拷贝接口数据。"+
			"endpoint 不在资产图时先用 insert_assets 登记拿到 id。返回 {ok,errors}。",
		obj(map[string]any{
			"links":             map[string]any{"type": "array", "description": "【优先批量】映射数组,元素字段同下方顶层字段。", "items": map[string]any{"type": "object"}},
			"function_node_id":  idp("[单条] 动作节点 id(add_function_node 返回的 id)"),
			"endpoint_asset_id": idp("资产图 type=endpoint 的 id"),
			"evidence":          str("一行证据,如 '点退款按钮触发 POST /order/refund'"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.fs == nil {
				return actool.Errorf("map_function_to_endpoint 需要任务上下文(功能图)"), nil
			}
			var a struct {
				Links []funcMapItem `json:"links"`
				funcMapItem
			}
			_ = json.Unmarshal(in, &a)
			items := a.Links
			if len(items) == 0 {
				items = []funcMapItem{a.funcMapItem}
			}
			ok := 0
			errs := map[string]string{}
			for i, it := range items {
				fn, ep := pid(it.FunctionNodeID), pid(it.EndpointAssetID)
				if fn <= 0 || ep <= 0 {
					errs[strconv.Itoa(i)] = "function_node_id 和 endpoint_asset_id 都必须是正整数"
					continue
				}
				if err := t.fs.MapToEndpoint(fn, ep, it.Evidence); err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ok++
			}
			out := map[string]any{"ok": ok}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

// ---- add_invariant ----

type invariantItem struct {
	Kind       string          `json:"kind"`
	Statement  string          `json:"statement"`
	TargetNode json.RawMessage `json:"target_node"`
	AppID      json.RawMessage `json:"app_id"`
	Source     string          `json:"source"`
	Evidence   string          `json:"evidence"`
}

func (t *ToolSet) addInvariant() actool.CoreTool {
	return t.writeExpTool("add_invariant",
		"登记一条【业务不变量】(规范性约束:本不该如此),作为后续攻击的判据(oracle)。"+
			"来自角色diff(admin有/merchant无→merchant不得到达X)、旅程diff(退款不得从cart触发)或人工输入。返回 {ids,errors}。",
		obj(map[string]any{
			"invariants":  map[string]any{"type": "array", "description": "【优先批量】不变量数组,元素字段同下方顶层字段。", "items": map[string]any{"type": "object"}},
			"kind":        str("[单条] authz(越权)|ownership(归属·IDOR)|state(非法迁移)|resource(资源·额度)"),
			"statement":   str("人话陈述,如 'merchant 不得到达 强制退款'"),
			"target_node": idp("关联的功能节点 id(可选)"),
			"app_id":      idp("所属应用根 id(可选)"),
			"source":      str("role_diff|journey|hint|doc —— 这条不变量怎么得出的"),
			"evidence":    str("一行证据,如 'admin菜单有此项,merchant菜单无'"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.fs == nil {
				return actool.Errorf("add_invariant 需要任务上下文(功能图)"), nil
			}
			var a struct {
				Invariants []invariantItem `json:"invariants"`
				invariantItem
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Invariants) > 0
			items := a.Invariants
			if !batch {
				items = []invariantItem{a.invariantItem}
			}
			ids := make([]int64, len(items))
			errs := map[string]string{}
			for i, it := range items {
				id, err := t.fs.AddInvariant(db.AddInvariantReq{
					AppID:      pid(it.AppID),
					Kind:       it.Kind,
					Statement:  it.Statement,
					TargetNode: pid(it.TargetNode),
					Source:     it.Source,
					Evidence:   it.Evidence,
				})
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
			}
			if !batch {
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("invariant: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

// ---- record_function_access ----

func (t *ToolSet) recordFunctionAccess() actool.CoreTool {
	return t.writeExpTool("record_function_access",
		"记录【某角色实测某动作】的结果,填进本任务的授权矩阵格子。result: allowed(能访问)|denied(被拦)|unknown(测不了)。"+
			"命中越权(不变量说该 denied、实测 allowed)时,另外用 report_finding 上报漏洞——本工具只记'测过了、结果是什么'。",
		obj(map[string]any{
			"function_node_id": idp("动作节点 id"),
			"role":             str("测试所用角色"),
			"result":           str("allowed|denied|unknown"),
			"evidence_id":      idp("关联的证据/流量 id(可选)"),
		}, "function_node_id", "role", "result"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.fs == nil {
				return actool.Errorf("record_function_access 需要任务上下文(功能图)"), nil
			}
			var a struct {
				FunctionNodeID json.RawMessage `json:"function_node_id"`
				Role           string          `json:"role"`
				Result         string          `json:"result"`
				EvidenceID     json.RawMessage `json:"evidence_id"`
			}
			_ = json.Unmarshal(in, &a)
			if err := t.fs.RecordFunctionAccess(t.taskID, pid(a.FunctionNodeID), a.Role, a.Result, pid(a.EvidenceID)); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("access recorded"), nil
		})
}

// ---- list_function_nodes ----

func (t *ToolSet) listFunctionNodes() actool.CoreTool {
	return t.readExpTool("list_function_nodes",
		"列本任务功能图的节点(紧凑:id+kind+name+path+seen_roles+confidence)。写 add_function_node 前先调它去重。"+
			"可按 kind(module|feature|action)或 role(seen_roles 成员)过滤,分页 limit/offset。",
		obj(map[string]any{
			"kind":   str("按层级过滤:module|feature|action(可选)"),
			"role":   str("按角色可达性过滤:只返回 seen_roles 含该角色的节点(可选)"),
			"limit":  intp("返回上限,默认 50,上限 200"),
			"offset": intp("分页偏移,默认 0"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.fs == nil {
				return actool.Errorf("list_function_nodes 需要任务上下文(功能图)"), nil
			}
			var a struct {
				Kind   string `json:"kind"`
				Role   string `json:"role"`
				Limit  int    `json:"limit"`
				Offset int    `json:"offset"`
			}
			_ = json.Unmarshal(in, &a)
			nodes, err := t.fs.ListFunctionNodes(a.Kind, a.Role, a.Limit, a.Offset)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"count": len(nodes), "nodes": nodes})
		})
}

// ---- get_function_subtree ----

func (t *ToolSet) getFunctionSubtree() actool.CoreTool {
	return t.readExpTool("get_function_subtree",
		"读整张功能图(节点 + contains/precedes 边 + maps_to 挂的 endpoint + 不变量清单),给建模自检和下钻用。",
		obj(map[string]any{}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.fs == nil {
				return actool.Errorf("get_function_subtree 需要任务上下文(功能图)"), nil
			}
			g, err := t.fs.BuildFunctionGraph()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(g)
		})
}

// ---- resolve_invariant ----

func (t *ToolSet) resolveInvariant() actool.CoreTool {
	return t.writeExpTool("resolve_invariant",
		"测完一条业务不变量后更新它的状态:holds(验证后【成立】——该被拒的确实被拒,无越权) | violated(【测出洞】——该被拒的却放行了,此时另外用 report_finding 上报漏洞)。"+
			"invariant_id 来自你领到意图的 invariant_id 或 list/get 功能图。只是把判据的结论落库,证据仍走 report_finding。",
		obj(map[string]any{
			"invariant_id": idp("要更新的不变量 id"),
			"status":       str("holds(不变量成立,无洞) | violated(测出洞)"),
		}, "invariant_id", "status"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.fs == nil {
				return actool.Errorf("resolve_invariant 需要任务上下文(功能图)"), nil
			}
			var a struct {
				InvariantID json.RawMessage `json:"invariant_id"`
				Status      string          `json:"status"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.InvariantID)
			if id <= 0 {
				return actool.Errorf("invariant_id 必须是正整数"), nil
			}
			if err := t.fs.SetInvariantStatus(id, a.Status); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("invariant %d → %s", id, a.Status)), nil
		})
}

// FunctionTools is the full function-graph tool set (write + read), shared by
// ModelerTools and available for binding to other agents via the DB tools table.
func (t *ToolSet) FunctionTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.addFunctionNode(), t.mapFunctionToEndpoint(), t.addInvariant(),
		t.recordFunctionAccess(), t.listFunctionNodes(), t.getFunctionSubtree(),
	}
}

// FunctionAttackTools are the function-graph tools an ATTACK worker uses when it
// tests an invariant assigned by the planner: read the graph, record the measured
// matrix cell, and resolve the invariant. Deliberately a narrow subset — the attack
// worker builds no structure (no add_function_node / add_invariant); it only测+回写.
func (t *ToolSet) FunctionAttackTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.listFunctionNodes(), t.getFunctionSubtree(),
		t.recordFunctionAccess(), t.resolveInvariant(),
	}
}
