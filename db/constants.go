package db

// Exploration node kinds (exploration_nodes.kind).
const (
	KindBegin   = "begin"   // DEPRECATED: legacy task root; new tasks seed an origin fact (KindFact + StateOrigin) instead
	KindGoal    = "goal"    // a task objective
	KindIntent  = "intent"  // an exploration direction (planner-generated)
	KindFact    = "fact"    // a worker's exploration result/conclusion (incl. negative results), tied to its intent
	KindFinding = "finding" // a confirmed vulnerability (report_finding), distinct from a fact
	KindHint    = "hint"
	KindDigest  = "digest" // a compressed fold of cold intents/facts (cold-digest-spec §1); lossless — members kept, restorable by id
)

// Digest node states (kind='digest'). A digest is 'active' while it renders in
// graph_overview; major compaction retires a merged-away segment to 'superseded'
// (its covers edges repointed to the new digest) — cold-digest-spec §5.1.
const (
	StateDigestActive     = "active"
	StateDigestSuperseded = "superseded"
)

// StateOrigin marks the task root fact (KindFact) seeded at task creation — the
// exploration graph's origin. Every intent traces back to it, so "an intent must
// connect to a fact" holds uniformly from the very first intent. Worker-produced
// facts use state 'confirmed', so this never collides.
const StateOrigin = "origin"

// StateIntentDeleted marks an intent the user假删除(soft delete): it drops out of
// the frontier and graph_overview like other terminal states, but keeps its node
// and full lineage. The delete reason lives in exploration_nodes.delete_reason.
const StateIntentDeleted = "deleted"

// Exploration edge relations (exploration_edges.rel).
const (
	RelSpawns      = "spawns"
	RelDerivedFrom = "derived_from"
	RelYields      = "yields"
	RelProves      = "proves"
	RelCovers      = "covers" // digest --covers--> member (cold-digest-spec §1); source of truth for "which digest folds node X"
)

// Function-graph node kinds (function_nodes.kind) — the business-semantic model:
// module(一级模块)→feature(二级功能)→action(原子动作). See schema.sql section B2.
const (
	KindModule  = "module"
	KindFeature = "feature"
	KindAction  = "action"
)

// Function-graph edge relations (function_edges.rel). Both ends are function_nodes.
// maps_to(action→asset endpoint) lives in function_asset_map; guarded_by(action→
// invariant) is expressed via invariants.target_node — neither is a function_edge row.
const (
	RelContains = "contains" // module→feature→action 层级
	RelPrecedes = "precedes" // action→action 旅程顺序 (P3)
)

// Invariant kinds (invariants.kind) — the "本不该如此" oracle categories.
const (
	InvAuthz     = "authz"     // 越权:角色不得到达某动作
	InvOwnership = "ownership" // 归属/IDOR:非 owner 不得访问对象
	InvState     = "state"     // 非法状态迁移
	InvResource  = "resource"  // 资源/额度/金额守恒
)

// Invariant sources (invariants.source) — how the invariant was derived.
const (
	InvSrcRoleDiff = "role_diff" // 角色间菜单差分(白送 oracle)
	InvSrcJourney  = "journey"   // 旅程/状态机差分
	InvSrcHint     = "hint"      // 人工注入
	InvSrcDoc      = "doc"       // 文档/规范
)

// Invariant status (invariants.status).
const (
	InvStatusOpen     = "open"     // 待验
	InvStatusHolds    = "holds"    // 验过成立
	InvStatusViolated = "violated" // 测出洞
)

// Function access results (function_access.result) — a measured matrix cell.
const (
	AccessAllowed = "allowed"
	AccessDenied  = "denied"
	AccessUnknown = "unknown"
)
