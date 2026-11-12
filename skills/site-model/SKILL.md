---
name: site-model
description: 按角色重建 Web 系统的业务功能图(模块→功能→动作 + 角色可达性 + 不变量)。在业务建模(modeler)阶段使用:抓规范文件/菜单 bootstrap 建树、爬行补厚、角色 diff 自动产出 authz 不变量,供规划者系统性派越权/逻辑测试。不做漏洞测试、不做利用。
---

# Site Model（业务功能建模）

把这个 Web 系统「前端给人看的业务结构」重建成「给 agent 看的业务地图」,写进功能图。
人类测试员一登录,看一眼菜单就知道「这是订单模块、那是管理后台、谁能用什么」——本 skill
就是把这张脑图结构化下来,让规划者据此**系统性**派越权/逻辑测试意图,而不是碰运气。

产出三样:
1. **层级树**:module(一级模块)→feature(二级功能)→action(原子动作) —— `add_function_node`
2. **角色可达性**:每个节点以哪些角色看到/到达 —— `add_function_node` 的 `role_seen`
3. **不变量(本不该如此)**:主要靠角色 diff 白送 —— `add_invariant`

---

## 边界与禁止（必读 · 违反即越界）

| 范围 | 允许 | 禁止 |
|---|---|---|
| **目标** | 登记模块/功能/动作、角色可达性、接口映射、不变量 | SQLi/XSS/越权重放/爆破/fuzz、改包攻击、任何漏洞测试或利用 |
| **动作** | 只读浏览、点击 UI、抓菜单/规范文件、观察旅程 | 删除/导出敏感数据/批量写等不可逆操作 |
| **授权** | 系统提示顶部【操作约束】是最高红线,每步先自检 | 范围外主机/端口/操作一律不碰 |

发现疑似漏洞**不要自己测**:在节点 payload 或 `add_invariant` 里点一句交给规划者。你也没有上报漏洞的工具。

---

## 工作链（7 步，按性价比；边做边写，写进图才算数）

### Phase 1 · 规范文件优先（白嫖，零点击）
先找一次端出整个接口面的来源:
- Swagger / OpenAPI:`/v2/api-docs`、`/swagger.json`、`/openapi.json`、`/swagger-ui.html`
- GraphQL introspection:对 `/graphql` 发 introspection query
- sourcemap:`*.js.map`(能还原前端源码与路由)
命中就把接口登记为资产(`insert_assets` type=endpoint),模块/功能从 tag/分组推断建 `add_function_node`。

### Phase 2 · 登录拿会话（最脆环节，别死磕）
对**给定的每个角色**各准备一个会话:
1. 先试上下文里给的账号密码**自动登录**(表单提交 / 登录接口)。
2. 若被 **MFA / 验证码 / SSO** 卡住:**不要反复硬试**。改用 operator 经 hint 直接喂进来的
   **已登录 session/token**(cookie 串 / Authorization 头)。
3. 会话凭据写到本次工作目录,整轮复用。

> 没有任何角色凭据时:仍可用 Phase 3 的静态路由 + 免登录可达页建半棵树(confidence=inferred)。

### Phase 3 · 菜单/权限 bootstrap（骨架主来源）
登录后抓 RBAC 过滤后的菜单:`/api/menu`、`/api/user/permissions`、`/api/user/info`、导航/路由配置。
- 解析出「模块→功能」层级 → `add_function_node`(parent_id 串 contains)。
- **这个响应就是该角色能看到什么** → 登记时传 `role_seen=<当前角色>`。
- 直接看到的 confidence=observed。

### Phase 4 · 静态路由补全（菜单外的路径）
从 SPA bundle 提取前端路由表(可借助 api-recon 技能的静态层 / sourcemap)。
菜单里没有但路由里有的 → 建 `add_function_node`(confidence=inferred,表示"知道它在、还没到达")。

### Phase 5 · 动态爬行补厚（playwright，若工具可用；解决"不点就看不到接口"）
很多接口只有交互后才加载。系统性补厚:
- **系统性全点**:枚举所有可交互元素(按钮/Tab/行内操作/可展开树)挨个点,不是挑"有意思的"。
- **强制路由**:直接 push `/order/123/refund` 逼组件挂载、触发它的加载接口。
- **mock 父解锁子**:列表接口返回空就点不出详情 → stub 列表塞几行假数据,渲染出行再点。
每触发一个真实 XHR → `insert_assets`(登记 endpoint)+ `map_function_to_endpoint`(把动作连上去)。

### Phase 6 · 旅程观察（状态机线索）
记录「某动作只在某业务状态下出现」(退款按钮只在已支付订单上出现)→ 建节点时传 `state_pre=已支付`。
这是后面非法迁移测试的靶子来源。

### Phase 7 · 角色 diff → 产出不变量（你最有价值的产出）
按角色各建完树后,对比各角色的可达动作:
- **authz(白送)**:动作 A 在 admin 的 `seen_roles` 里、不在 merchant 的 →
  `add_invariant(kind=authz, statement="merchant 不得到达 A", source=role_diff, target_node=A, evidence="admin菜单有,merchant菜单无")`。
- **state**:旅程里没观测到的迁移 → `add_invariant(kind=state, "退款不得从 cart 触发", source=journey)`。
- **hint**:operator 给的业务规则("商户不能自助开票")→ `add_invariant(source=hint)`。

### 收尾 · 三图对账
`list_function_nodes` + `insert_assets` 回看:资产图里有、但没被任何动作 `map_function_to_endpoint`
的 endpoint = "无 UI 入口 / 没触发到" → 建一个 inferred 的占位节点标明缺口,别假装已覆盖。

---

## 记录纪律（照 record_fact 那套）
- **边建边写**,别攒到最后被步数耗尽丢掉。
- **只写增量**:写前 `list_function_nodes` 扫一眼,别把已登记节点换措辞重记。
- **带证据、标 confidence**:菜单/UI 直接看到=observed;路由推断、没到达过=inferred。
- **桥接不拷贝**:动作只 `map_function_to_endpoint` 引用 endpoint 的 id,不要把接口数据塞进功能节点。

## 完成定义
- 每个有凭据的角色都跑过 Phase 2–6;
- 模块/功能/动作树 + 每节点 role_seen 已写回;
- 动作尽量 maps_to 到真实 endpoint,未映射的标成缺口;
- 角色 diff 已产出 authz 不变量(≥2 角色时)。
做完用一两句话总结:建了哪几个模块、覆盖了哪几个角色、出了哪些 authz 不变量。
