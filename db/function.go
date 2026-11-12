package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// FunctionStore is a handle onto one exploration's function graph: the business-
// semantic model (modules → features → actions), its maps_to bridge to the asset
// graph, invariants ("本不该如此" oracle), and the per-task access matrix. It mirrors
// ExplorationStore: a cheap value scoped to one exploration id, every query filtered
// by exploration_id=s.expID. See schema.sql section B2.
type FunctionStore struct {
	db    *DB
	expID int64
}

// Functions returns a function-graph handle bound to the same exploration as this
// ExplorationStore. The ToolSet derives it next to the AssetStore so function-graph
// tools share the task's exploration scope.
func (s *ExplorationStore) Functions() *FunctionStore {
	if s == nil {
		return nil
	}
	return &FunctionStore{db: s.db, expID: s.expID}
}

// Functions binds a function-graph handle directly from the pool (for server-side
// readers like the frontend graph builder that have an exploration id in hand).
func (d *DB) Functions(expID int64) *FunctionStore { return &FunctionStore{db: d, expID: expID} }

func (s *FunctionStore) ID() int64 { return s.expID }

// FunctionNode is one business-semantic node (module/feature/action).
type FunctionNode struct {
	ID            int64           `json:"id"`
	AppID         int64           `json:"app_id,omitempty"`
	Kind          string          `json:"kind"`
	Name          string          `json:"name"`
	Path          string          `json:"path,omitempty"`
	StatePre      string          `json:"state_pre,omitempty"`
	SeenRoles     []string        `json:"seen_roles,omitempty"`
	IntendedRoles []string        `json:"intended_roles,omitempty"`
	Confidence    string          `json:"confidence"`
	Payload       json.RawMessage `json:"payload,omitempty"`
}

// AddFunctionNodeReq is the raw agent input for one node. The dedup key
// (exploration_id, kind, COALESCE(path,”), name) is computed by the DB via the
// uq_fnode unique index; the agent submits raw info, the program merges.
type AddFunctionNodeReq struct {
	AppID      int64
	Kind       string
	Name       string
	Path       string
	StatePre   string
	RoleSeen   string // the role under which this node was seen/reached this time (merged into seen_roles)
	Confidence string
	Payload    map[string]any
}

// AddFunctionNode upserts a node on the uq_fnode dedup key. On conflict it merges
// conservatively (COALESCE: a new non-empty value wins, a missing one never erases),
// upgrades confidence inferred→observed, and unions role_seen into seen_roles — the
// same "scalars COALESCE, arrays union" discipline as assets.UpsertEndpoint.
func (s *FunctionStore) AddFunctionNode(req AddFunctionNodeReq) (int64, error) {
	if s == nil {
		return 0, fmt.Errorf("function store 未初始化")
	}
	kind := strings.TrimSpace(req.Kind)
	switch kind {
	case KindModule, KindFeature, KindAction:
	default:
		return 0, fmt.Errorf("kind 必须是 module|feature|action，收到 %q", req.Kind)
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return 0, fmt.Errorf("name 不能为空")
	}
	confidence := strings.TrimSpace(req.Confidence)
	if confidence != "inferred" {
		confidence = "observed"
	}
	// seen_roles starts as the single role seen this time (may be empty → '[]').
	seen := []string{}
	if r := strings.TrimSpace(req.RoleSeen); r != "" {
		seen = []string{r}
	}
	seenRaw, _ := json.Marshal(seen)
	payloadRaw, _ := json.Marshal(req.Payload)
	if len(payloadRaw) == 0 || string(payloadRaw) == "null" {
		payloadRaw = []byte("{}")
	}
	var appID any
	if req.AppID > 0 {
		appID = req.AppID
	}
	var statePre any
	if sp := strings.TrimSpace(req.StatePre); sp != "" {
		statePre = sp
	}
	var path any
	if p := strings.TrimSpace(req.Path); p != "" {
		path = p
	}
	var id int64
	err := s.db.QueryRow(`
INSERT INTO function_nodes(exploration_id, app_id, kind, name, path, state_pre, seen_roles, confidence, payload)
VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9::jsonb)
ON CONFLICT (exploration_id, kind, COALESCE(path,''), name) DO UPDATE SET
    app_id     = COALESCE(EXCLUDED.app_id, function_nodes.app_id),
    state_pre  = COALESCE(EXCLUDED.state_pre, function_nodes.state_pre),
    -- union seen_roles (dedup), so each role that reaches the node accumulates
    seen_roles = (SELECT COALESCE(jsonb_agg(DISTINCT e), '[]'::jsonb)
           FROM jsonb_array_elements(function_nodes.seen_roles || EXCLUDED.seen_roles) AS e),
    -- confidence only upgrades inferred→observed, never downgrades
    confidence = CASE WHEN function_nodes.confidence = 'observed' OR EXCLUDED.confidence = 'observed'
        THEN 'observed' ELSE 'inferred' END,
    payload    = function_nodes.payload || EXCLUDED.payload
RETURNING id`,
		s.expID, appID, kind, name, path, statePre, string(seenRaw), confidence, string(payloadRaw)).Scan(&id)
	return id, err
}

// MapToEndpoint writes a maps_to bridge (action ↔ asset endpoint). Idempotent on the
// (function_node_id, asset_id) PK. Reference only — never copies endpoint data.
func (s *FunctionStore) MapToEndpoint(functionNodeID, assetID int64, evidence string) error {
	if s == nil {
		return fmt.Errorf("function store 未初始化")
	}
	if functionNodeID <= 0 || assetID <= 0 {
		return nil
	}
	_, err := s.db.Exec(`
INSERT INTO function_asset_map(exploration_id, function_node_id, asset_id, evidence)
VALUES ($1,$2,$3,$4)
ON CONFLICT (function_node_id, asset_id) DO UPDATE SET
    evidence = COALESCE(NULLIF(EXCLUDED.evidence,''), function_asset_map.evidence)`,
		s.expID, functionNodeID, assetID, evidence)
	return err
}

// LinkFunction writes a contains/precedes edge between two function nodes. Idempotent.
func (s *FunctionStore) LinkFunction(from int64, rel string, to int64, guard string) error {
	if s == nil {
		return fmt.Errorf("function store 未初始化")
	}
	if from <= 0 || to <= 0 || from == to {
		return nil
	}
	switch rel {
	case RelContains, RelPrecedes:
	default:
		return fmt.Errorf("rel 必须是 contains|precedes，收到 %q", rel)
	}
	var g any
	if gg := strings.TrimSpace(guard); gg != "" {
		g = gg
	}
	_, err := s.db.Exec(`
INSERT INTO function_edges(exploration_id, src_id, dst_id, rel, guard)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (exploration_id, src_id, rel, dst_id) DO NOTHING`,
		s.expID, from, to, rel, g)
	return err
}

// AddInvariantReq is the raw agent input for one invariant.
type AddInvariantReq struct {
	AppID      int64
	Kind       string
	Statement  string
	TargetNode int64
	Source     string
	Evidence   string
}

// AddInvariant registers a "本不该如此" invariant (the oracle). status starts 'open'.
func (s *FunctionStore) AddInvariant(req AddInvariantReq) (int64, error) {
	if s == nil {
		return 0, fmt.Errorf("function store 未初始化")
	}
	switch strings.TrimSpace(req.Kind) {
	case InvAuthz, InvOwnership, InvState, InvResource:
	default:
		return 0, fmt.Errorf("kind 必须是 authz|ownership|state|resource，收到 %q", req.Kind)
	}
	switch strings.TrimSpace(req.Source) {
	case InvSrcRoleDiff, InvSrcJourney, InvSrcHint, InvSrcDoc:
	default:
		return 0, fmt.Errorf("source 必须是 role_diff|journey|hint|doc，收到 %q", req.Source)
	}
	if strings.TrimSpace(req.Statement) == "" {
		return 0, fmt.Errorf("statement 不能为空")
	}
	var appID, target any
	if req.AppID > 0 {
		appID = req.AppID
	}
	if req.TargetNode > 0 {
		target = req.TargetNode
	}
	var id int64
	err := s.db.QueryRow(`
INSERT INTO invariants(exploration_id, app_id, kind, statement, target_node, source, evidence)
VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		s.expID, appID, strings.TrimSpace(req.Kind), strings.TrimSpace(req.Statement),
		target, strings.TrimSpace(req.Source), strings.TrimSpace(req.Evidence)).Scan(&id)
	return id, err
}

// RecordFunctionAccess upserts one measured matrix cell (task × role × action → result).
func (s *FunctionStore) RecordFunctionAccess(taskID, functionNodeID int64, role, result string, evidenceID int64) error {
	if s == nil {
		return fmt.Errorf("function store 未初始化")
	}
	switch result {
	case AccessAllowed, AccessDenied, AccessUnknown:
	default:
		return fmt.Errorf("result 必须是 allowed|denied|unknown，收到 %q", result)
	}
	if strings.TrimSpace(role) == "" {
		return fmt.Errorf("role 不能为空")
	}
	var ev any
	if evidenceID > 0 {
		ev = evidenceID
	}
	_, err := s.db.Exec(`
INSERT INTO function_access(exploration_id, task_id, function_node_id, role, result, evidence_id)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (task_id, function_node_id, role) DO UPDATE SET
    result = EXCLUDED.result,
    evidence_id = COALESCE(EXCLUDED.evidence_id, function_access.evidence_id)`,
		s.expID, taskID, functionNodeID, role, result, ev)
	return err
}

// ListFunctionNodes returns nodes in this exploration, newest first, paginated.
// kind/role are optional filters; role matches membership in seen_roles.
func (s *FunctionStore) ListFunctionNodes(kind, role string, limit, offset int) ([]FunctionNode, error) {
	if s == nil {
		return nil, fmt.Errorf("function store 未初始化")
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	q := `SELECT id, COALESCE(app_id,0), kind, name, COALESCE(path,''), COALESCE(state_pre,''),
	      seen_roles, COALESCE(intended_roles,'null'::jsonb), confidence, payload
	      FROM function_nodes WHERE exploration_id=$1`
	args := []any{s.expID}
	if k := strings.TrimSpace(kind); k != "" {
		args = append(args, k)
		q += fmt.Sprintf(" AND kind=$%d", len(args))
	}
	if r := strings.TrimSpace(role); r != "" {
		args = append(args, r)
		q += fmt.Sprintf(" AND seen_roles ? $%d", len(args))
	}
	args = append(args, limit, offset)
	q += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	return s.scanNodes(q, args...)
}

func (s *FunctionStore) scanNodes(q string, args ...any) ([]FunctionNode, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FunctionNode
	for rows.Next() {
		var n FunctionNode
		var seenRaw, intendedRaw, payloadRaw []byte
		if err := rows.Scan(&n.ID, &n.AppID, &n.Kind, &n.Name, &n.Path, &n.StatePre,
			&seenRaw, &intendedRaw, &n.Confidence, &payloadRaw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(seenRaw, &n.SeenRoles)
		if len(intendedRaw) > 0 && string(intendedRaw) != "null" {
			_ = json.Unmarshal(intendedRaw, &n.IntendedRoles)
		}
		n.Payload = payloadRaw
		out = append(out, n)
	}
	return out, rows.Err()
}

// CountFunctionNodes reports how many function nodes exist in this exploration —
// used by the modeling gate to skip re-modeling an already-modeled task (idempotent).
func (s *FunctionStore) CountFunctionNodes() (int, error) {
	if s == nil {
		return 0, nil
	}
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM function_nodes WHERE exploration_id=$1`, s.expID).Scan(&n)
	return n, err
}

// FunctionGraphData is the frontend payload: nodes + edges (contains + maps_to).
type FunctionGraphData struct {
	Nodes      []FunctionGraphNode `json:"nodes"`
	Edges      []FunctionGraphEdge `json:"edges"`
	Invariants []FunctionInvariant `json:"invariants"`
}

type FunctionGraphNode struct {
	Key        string   `json:"key"`  // f:<id>
	Kind       string   `json:"kind"` // module|feature|action
	Name       string   `json:"name"`
	Path       string   `json:"path,omitempty"`
	SeenRoles  []string `json:"seen_roles,omitempty"`
	Confidence string   `json:"confidence"`
	Endpoints  []string `json:"endpoints,omitempty"` // mapped endpoint urls (for the drawer)
}

type FunctionGraphEdge struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
	Rel string `json:"rel"`
}

type FunctionInvariant struct {
	ID        int64  `json:"id"`
	Kind      string `json:"kind"`
	Statement string `json:"statement"`
	Source    string `json:"source"`
	Status    string `json:"status"`
	Target    int64  `json:"target_node,omitempty"`
}

// BuildFunctionGraph assembles the function graph for the frontend view: all nodes,
// contains edges (hierarchy), maps_to as mapped-endpoint labels on action nodes, and
// the open/holds/violated invariants. Node keys are f:<id>, matching the asset
// graph's a:<id> convention (task_scope.go BuildCoverageGraph).
func (s *FunctionStore) BuildFunctionGraph() (*FunctionGraphData, error) {
	if s == nil {
		return &FunctionGraphData{}, nil
	}
	out := &FunctionGraphData{Nodes: []FunctionGraphNode{}, Edges: []FunctionGraphEdge{}, Invariants: []FunctionInvariant{}}
	nodes, err := s.ListFunctionNodes("", "", 200, 0)
	if err != nil {
		return nil, err
	}
	// mapped endpoint urls per function node (for action drawers)
	epByNode := map[int64][]string{}
	rows, err := s.db.Query(`
SELECT m.function_node_id, a.url FROM function_asset_map m
JOIN assets a ON a.id = m.asset_id
WHERE m.exploration_id=$1`, s.expID)
	if err == nil {
		for rows.Next() {
			var fid int64
			var url sql.NullString
			if rows.Scan(&fid, &url) == nil && url.Valid {
				epByNode[fid] = append(epByNode[fid], url.String)
			}
		}
		rows.Close()
	}
	for _, n := range nodes {
		out.Nodes = append(out.Nodes, FunctionGraphNode{
			Key: fmt.Sprintf("f:%d", n.ID), Kind: n.Kind, Name: n.Name, Path: n.Path,
			SeenRoles: n.SeenRoles, Confidence: n.Confidence, Endpoints: epByNode[n.ID],
		})
	}
	erows, err := s.db.Query(`SELECT src_id, dst_id, rel FROM function_edges WHERE exploration_id=$1`, s.expID)
	if err != nil {
		return nil, err
	}
	for erows.Next() {
		var src, dst int64
		var rel string
		if err := erows.Scan(&src, &dst, &rel); err != nil {
			erows.Close()
			return nil, err
		}
		out.Edges = append(out.Edges, FunctionGraphEdge{Src: fmt.Sprintf("f:%d", src), Dst: fmt.Sprintf("f:%d", dst), Rel: rel})
	}
	erows.Close()
	irows, err := s.db.Query(`SELECT id, kind, statement, source, status, COALESCE(target_node,0) FROM invariants WHERE exploration_id=$1 ORDER BY id`, s.expID)
	if err != nil {
		return nil, err
	}
	defer irows.Close()
	for irows.Next() {
		var inv FunctionInvariant
		if err := irows.Scan(&inv.ID, &inv.Kind, &inv.Statement, &inv.Source, &inv.Status, &inv.Target); err != nil {
			return nil, err
		}
		out.Invariants = append(out.Invariants, inv)
	}
	return out, nil
}
