"use client";

import * as React from "react";

import type { Graph as G6Graph } from "@antv/g6";
import { RefreshCw, ShieldAlert } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { api } from "@/lib/api";
import type { FunctionGraphData, FunctionGraphNode, FunctionInvariant } from "@/lib/types";
import { cn } from "@/lib/utils";

// 功能图是业务语义图,规模远小于资产覆盖图(几十个模块/功能/动作),无需折叠。
type Kind = FunctionGraphNode["kind"];

const kindMeta: Record<Kind, { label: string; hex: string; size: number }> = {
  module: { label: "模块", hex: "#6366f1", size: 40 },
  feature: { label: "功能", hex: "#3b82f6", size: 30 },
  action: { label: "动作", hex: "#f43f5e", size: 22 },
};

function svgUri(inner: string): string {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;
  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

const KIND_ICON: Record<Kind, string> = {
  module: svgUri(
    '<path d="M2.97 12.92A2 2 0 0 0 2 14.63v3.24a2 2 0 0 0 .97 1.71l3 1.8a2 2 0 0 0 2.06 0L12 19v-5.5l-5-3-4.03 2.42Z"/><path d="m7 16.5-4.74-2.85"/><path d="m7 16.5 5-3"/><path d="M7 16.5v5.17"/><path d="M12 13.5V19l3.97 2.38a2 2 0 0 0 2.06 0l3-1.8a2 2 0 0 0 .97-1.71v-3.24a2 2 0 0 0-.97-1.71L17 10.5l-5 3Z"/><path d="m17 16.5-5-3"/><path d="m17 16.5 4.74-2.85"/><path d="M17 16.5v5.17"/><path d="M7.97 4.42A2 2 0 0 0 7 6.13v4.37l5 3 5-3V6.13a2 2 0 0 0-.97-1.71l-3-1.8a2 2 0 0 0-2.06 0l-3 1.8Z"/><path d="M12 8 7.26 5.15"/><path d="m12 8 4.74-2.85"/><path d="M12 13.5V8"/>',
  ),
  feature: svgUri(
    '<path d="M12 2v20"/><path d="M2 5h20"/><path d="M3 3v2"/><path d="M7 3v2"/><path d="M17 3v2"/><path d="M21 3v2"/>',
  ),
  action: svgUri('<path d="M9 9h.01"/><path d="M15 9h.01"/><path d="m9 15 3 3 3-3"/><circle cx="12" cy="12" r="10"/>'),
};

const invMeta: Record<FunctionInvariant["kind"], { label: string; cls: string }> = {
  authz: { label: "越权", cls: "border-rose-400 text-rose-600 dark:text-rose-400" },
  ownership: { label: "归属/IDOR", cls: "border-amber-400 text-amber-600 dark:text-amber-400" },
  state: { label: "非法迁移", cls: "border-violet-400 text-violet-600 dark:text-violet-400" },
  resource: { label: "资源/额度", cls: "border-cyan-400 text-cyan-600 dark:text-cyan-400" },
};

type G6NodeDatum = { id: string; kind: Kind; size: number; lbl: string; inferred: boolean };
const nd = (d: unknown) => d as G6NodeDatum;

function nodeFill(d: G6NodeDatum): string {
  // inferred(路由推断、未实际到达)用浅灰,observed 用本类型实色。
  return d.inferred ? "#cbd5e1" : kindMeta[d.kind].hex;
}

function graphLabel(n: FunctionGraphNode): string {
  const base = n.name || n.path || n.key;
  return base.length > 18 ? `${base.slice(0, 17)}…` : base;
}

// 动作抽屉:名称 + 路径 + 角色可达性 + maps_to 挂的真实接口。
function NodeSheet({ node, onOpenChange }: { node: FunctionGraphNode | null; onOpenChange: (open: boolean) => void }) {
  return (
    <Sheet open={!!node} onOpenChange={onOpenChange}>
      <SheetContent className="w-[380px] sm:max-w-[380px]">
        {node && (
          <>
            <SheetHeader>
              <SheetTitle className="flex items-center gap-2 text-base">
                <Badge variant="outline">{kindMeta[node.kind].label}</Badge>
                {node.name}
              </SheetTitle>
            </SheetHeader>
            <ScrollArea className="mt-4 h-[calc(100vh-7rem)] pr-3">
              <div className="space-y-4 text-sm">
                {node.path && (
                  <div>
                    <div className="mb-1 text-muted-foreground text-xs">路径</div>
                    <code className="break-all rounded bg-muted px-1.5 py-0.5 text-xs">{node.path}</code>
                  </div>
                )}
                <div>
                  <div className="mb-1 text-muted-foreground text-xs">置信度</div>
                  <Badge variant={node.confidence === "observed" ? "default" : "secondary"}>
                    {node.confidence === "observed" ? "已观测" : "推断(未到达)"}
                  </Badge>
                </div>
                <div>
                  <div className="mb-1 text-muted-foreground text-xs">角色可达性</div>
                  {node.seen_roles && node.seen_roles.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {node.seen_roles.map((r) => (
                        <Badge key={r} variant="outline">
                          {r}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-muted-foreground text-xs">—</span>
                  )}
                </div>
                {node.endpoints && node.endpoints.length > 0 && (
                  <div>
                    <div className="mb-1 text-muted-foreground text-xs">映射接口 (maps_to)</div>
                    <div className="space-y-1">
                      {node.endpoints.map((ep) => (
                        <code key={ep} className="block break-all rounded bg-muted px-1.5 py-0.5 text-xs">
                          {ep}
                        </code>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </ScrollArea>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

function GraphInner({ taskId }: { taskId: string }) {
  const [data, setData] = React.useState<FunctionGraphData | null>(null);
  const [selected, setSelected] = React.useState<FunctionGraphNode | null>(null);
  const [loading, setLoading] = React.useState(true);

  const containerRef = React.useRef<HTMLDivElement>(null);
  const graphRef = React.useRef<G6Graph | null>(null);
  const nodeMapRef = React.useRef<Map<string, FunctionGraphNode>>(new Map());
  const gDataRef = React.useRef<{ nodes: G6NodeDatum[]; edges: { source: string; target: string }[] }>({
    nodes: [],
    edges: [],
  });

  const fetchGraph = React.useCallback(() => {
    setLoading(true);
    api
      .taskFunctionGraph(taskId)
      .then((g) => setData({ nodes: g.nodes ?? [], edges: g.edges ?? [], invariants: g.invariants ?? [] }))
      .catch(() => {
        /* 保留上一次数据 */
      })
      .finally(() => setLoading(false));
  }, [taskId]);

  React.useEffect(() => {
    fetchGraph();
  }, [fetchGraph]);

  // 维护 G6 数据 + key→node 映射(事件回调闭包外读 ref)。
  const nodes = data?.nodes ?? [];
  const edges = data?.edges ?? [];
  const sig = `${nodes
    .map((n) => `${n.key}:${n.confidence}`)
    .sort()
    .join(",")}|${edges.length}`;
  gDataRef.current = {
    nodes: nodes.map((n) => ({
      id: n.key,
      kind: n.kind,
      size: kindMeta[n.kind].size,
      lbl: graphLabel(n),
      inferred: n.confidence === "inferred",
    })),
    edges: edges.map((e) => ({ source: e.src, target: e.dst })),
  };
  const nmap = new Map<string, FunctionGraphNode>();
  for (const n of nodes) nmap.set(n.key, n);
  nodeMapRef.current = nmap;

  const applyData = React.useCallback(() => {
    const graph = graphRef.current;
    if (!graph || graph.destroyed) return;
    graph.setData(gDataRef.current);
    void graph.render().catch((err) => {
      if (!graph.destroyed) console.error("[function-graph] render:", err);
    });
  }, []);

  React.useEffect(() => {
    let destroyed = false;
    let graph: G6Graph | null = null;
    void (async () => {
      const { Graph } = await import("@antv/g6");
      if (destroyed || !containerRef.current) return;
      graph = new Graph({
        container: containerRef.current,
        autoResize: true,
        autoFit: "view",
        background: "#f0f2f7",
        node: {
          style: {
            size: (d: unknown) => nd(d).size,
            fill: (d: unknown) => nodeFill(nd(d)),
            stroke: (d: unknown) => (nd(d).inferred ? "#94a3b8" : "#ffffff"),
            lineWidth: (d: unknown) => (nd(d).inferred ? 1 : 1.5),
            lineDash: (d: unknown) => (nd(d).inferred ? [3, 3] : [0]),
            iconSrc: (d: unknown) => KIND_ICON[nd(d).kind],
            iconWidth: (d: unknown) => Math.max(12, nd(d).size * 0.55),
            iconHeight: (d: unknown) => Math.max(12, nd(d).size * 0.55),
            labelText: (d: unknown) => nd(d).lbl,
            labelFontSize: 10,
            labelPlacement: "bottom",
            labelFill: "#475569",
            labelBackground: true,
            labelBackgroundFill: "rgba(255,255,255,0.75)",
            labelBackgroundRadius: 3,
            labelPadding: [1, 3],
          },
        },
        edge: { style: { stroke: "#cbd5e1", lineWidth: 1, endArrow: false } },
        layout: {
          type: "d3-force",
          collide: { radius: (d: unknown) => (nd(d).size ? nd(d).size : 20) + 8 },
          link: {
            distance: (edge: unknown) => {
              const s = (edge as { source: string | { id?: string } }).source;
              const srcId = typeof s === "string" ? s : (s?.id ?? "");
              const src = nodeMapRef.current.get(srcId);
              return src?.kind === "module" ? 120 : 60;
            },
          },
          manyBody: { strength: (d: unknown) => (nd(d).kind === "action" ? -80 : -220) },
        },
        behaviors: ["drag-element-force", "drag-canvas", "zoom-canvas"],
      });
      graph.on("node:click", (evt: unknown) => {
        const id = (evt as { target?: { id?: string } }).target?.id;
        if (!id) return;
        const n = nodeMapRef.current.get(id);
        if (n) setSelected(n);
      });
      graphRef.current = graph;
      applyData();
    })();
    return () => {
      destroyed = true;
      try {
        graph?.stopLayout();
      } catch {
        /* 图可能尚未建成 */
      }
      graph?.destroy();
      graphRef.current = null;
    };
  }, [applyData]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: sig 是刻意的重排触发依赖
  React.useEffect(() => {
    applyData();
  }, [sig, applyData]);

  const invariants = data?.invariants ?? [];
  const byKind = (k: Kind) => nodes.filter((n) => n.kind === k).length;

  return (
    <div className="relative h-full w-full">
      <div ref={containerRef} className="h-full w-full" />

      {/* 图例 + 统计 + 刷新 */}
      <div className="pointer-events-auto absolute top-3 left-3 flex max-w-[320px] flex-col gap-2.5 rounded-lg border bg-card/95 p-3 text-xs shadow-sm backdrop-blur">
        <div className="flex items-center justify-between gap-3">
          {nodes.length > 0 ? (
            <span className="text-muted-foreground">
              模块 <span className="font-semibold text-foreground tabular-nums">{byKind("module")}</span> · 功能{" "}
              <span className="font-semibold text-foreground tabular-nums">{byKind("feature")}</span> · 动作{" "}
              <span className="font-semibold text-foreground tabular-nums">{byKind("action")}</span>
            </span>
          ) : (
            <span className="text-muted-foreground">{loading ? "加载中…" : "暂无功能图（建模 agent 尚未建树）"}</span>
          )}
          <Button variant="ghost" size="icon" className="size-6" onClick={fetchGraph} title="刷新">
            <RefreshCw className={cn("size-3.5", loading && "animate-spin")} />
          </Button>
        </div>
        <div className="flex flex-wrap gap-x-3 gap-y-1.5">
          {(Object.keys(kindMeta) as Kind[]).map((k) => (
            <span key={k} className="inline-flex items-center gap-1.5 text-foreground">
              <span className="size-3 rounded-full" style={{ backgroundColor: kindMeta[k].hex }} /> {kindMeta[k].label}
            </span>
          ))}
          <span className="inline-flex items-center gap-1.5 text-foreground">
            <span className="size-3 rounded-full border border-neutral-400 border-dashed bg-neutral-300" /> 推断(未到达)
          </span>
        </div>
        <p className="border-border/60 border-t pt-2 text-muted-foreground/80 leading-relaxed">
          力导向布局，可拖拽节点、滚轮缩放；点节点看角色可达性与映射接口。
        </p>
      </div>

      {/* 不变量清单(本不该如此 → 规划者的越权/逻辑测试靶子) */}
      {invariants.length > 0 && (
        <div className="pointer-events-auto absolute top-3 right-3 flex max-h-[80%] w-[300px] flex-col gap-2 rounded-lg border bg-card/95 p-3 text-xs shadow-sm backdrop-blur">
          <div className="flex items-center gap-1.5 font-medium">
            <ShieldAlert className="size-3.5 text-rose-500" /> 不变量 · {invariants.length}
          </div>
          <ScrollArea className="max-h-[60vh] pr-2">
            <div className="space-y-2">
              {invariants.map((inv) => (
                <div key={inv.id} className="rounded border border-border/60 p-2">
                  <div className="mb-1 flex items-center gap-1.5">
                    <Badge variant="outline" className={cn("h-4 px-1 text-[10px]", invMeta[inv.kind].cls)}>
                      {invMeta[inv.kind].label}
                    </Badge>
                    {inv.status === "violated" && (
                      <Badge variant="destructive" className="h-4 px-1 text-[10px]">
                        已命中
                      </Badge>
                    )}
                  </div>
                  <p className="text-foreground leading-snug">{inv.statement}</p>
                </div>
              ))}
            </div>
          </ScrollArea>
        </div>
      )}

      <NodeSheet node={selected} onOpenChange={(o) => !o && setSelected(null)} />
    </div>
  );
}

export function FunctionGraphTab({ taskId }: { taskId: string }) {
  return (
    <Card>
      <CardContent className="p-0">
        <div className="h-[72vh] w-full overflow-hidden rounded-xl">
          <GraphInner taskId={taskId} />
        </div>
      </CardContent>
    </Card>
  );
}
