# 防御加固 Checklist（反向使用即漏洞判据）

> 双向用途：给厂商写修复建议时直接引用条目编号；测试时反向核对——未满足条目 ≈ 对应层缺陷。

## E · 入口层（Entry）

> 审计口径：只有"浏览器一次点击可拉起"或"App 功能内 XSS 能在注入 JSB 的容器执行"的入口才计入本作业法的交付入口（SKILL.md Gate 0）。E1–E5 仍是加固项，但"仅本地 App 显式 Intent 可拉起"单独不构成我们的漏洞结论。

- [ ] E0 所有浏览器可拉起的入口（`CATEGORY_BROWSABLE` / App Links / `intent://`）与 App 内用户内容/反射参数都按不可信输入处理，统一走 URL 网关
- [ ] E1 WebView 容器 Activity 一律 `exported="false"`；确需导出时 extra 白名单 + 调用方签名校验
- [ ] E2 所有 URL 入口（BROWSABLE DeepLink / App Links / `intent://` / 剪贴板 / 推送 / 富文本 / NFC）统一收口到单一 URL 网关函数，禁止各 Activity 自行 loadUrl
- [ ] E3 禁止 Intent extras 透传二次解析（anti intent-redirection）；嵌套 Intent 一律拒绝
- [ ] E4 PendingIntent 使用 `FLAG_IMMUTABLE`
- [ ] E5 拒绝来自外部的 `file://` / `content://` URL 进入 WebView

## D · 域名校验层（Domain）

- [ ] D1 用 `Uri.getHost()` 与白名单**精确全等**（`equals`）比对；绝不用 `contains()` / `endsWith()` / 正则 `find()`
- [ ] D2 后缀匹配必须带前导点且锚定两端（`.target.com` 仅匹配子域，`target.com` 精确匹配裸域）
- [ ] D3 只允许 `https`；显式拒绝 `intent:`、`javascript:`、`file:`、`content:`、自定义 scheme（白名单外的全部拒绝）
- [ ] D4 校验点覆盖**每一次导航**：`shouldOverrideUrlLoading` + `onPageStarted` + `onPageFinished` + 服务端重定向后复检
- [ ] D5 全链路使用同一官方解析器（`android.net.Uri`），禁止 `java.net.URL`/`URI`/手写 split 混用（防解析器差分）
- [ ] D6 校验最终 `getHost()`，而非 `getUrl()`/`getAuthority()`/extra 原文（防 userinfo@ 混淆与检查对象错位）
- [ ] D7 白名单域自身治理：关闭开重定向、富文本 XSS 过滤、SPA 路由参数禁止二次 loadUrl
- [ ] D8 白名单 DNS 记录巡检，及时清理 dangling CNAME（防子域接管）
- [ ] D9 规范化 host 后再比对：去 trailing dot、统一小写、拒绝 punycode 同形域
- [ ] D10 App 内用户可控内容（昵称/签名/评论/弹幕/私信/公告/个人主页/富文本/搜索回显/活动页参数）统一输出编码；富文本走标签/属性/协议白名单；禁止 `innerHTML` / `document.write` 直插

## P · 接口权限层（Permission）

- [ ] P1 JSB **按域分组注册**：非自家域仅注入 public 子集——按需注入，而非运行时判断后放行
- [ ] P2 敏感接口三重校验：域名校验 + 用户手势 + 服务端下发短时效 nonce（secret 不落前端）
- [ ] P3 禁用通用反射分发器（`call(method, params)` 类）；接口名静态注册
- [ ] P4 权限判定不信任 H5 传参（禁止客户端自报 permission 字段）
- [ ] P5 JSB 调用全量审计日志（域 + 接口 + 参数摘要 + 时间）
- [ ] P6 WebView 硬化：`setAllowFileAccess(false)`、`setAllowUniversalAccessFromFileURLs(false)`、外部域用独立 WebView 进程并隔离 Cookie 域
- [ ] P7 移除历史灰度/降级通道；旧版弱校验接口下线

---

## 反向判据速查（测试用）

| 未满足条目 | 对应攻击面（见 jsb-playbook.md） |
|---|---|
| E0 | A 浏览器 1-click 入口（入口 2）/ B App 功能内 XSS（入口 8；SKILL.md Gate 0） |
| E1–E5 | Phase 1 入口层 1–7 号入口（其中入口 1 仅在浏览器可达时计入） |
| D1/D2 | 2.1 contains / 2.2 endsWith / 2.3 正则锚点 |
| D5/D6 | 2.4 userinfo 混淆 / 2.5 解析器差分 / 2.6 反斜杠 / 2.7 检查错位 |
| D3 | 2.10 scheme 逃逸 |
| D4 | 1.1 二段跳 / 1.4 TOCTOU / 2.11 时序缺陷 |
| D7 | 1.5 开重定向 / 1.6 路由可控 / 入口 8 白名单域 XSS |
| D8 | 2.9 子域接管 |
| D9 | 2.8 trailing dot / IDN 同形 |
| D10 | B 入口（App 功能内 XSS：存储型/反射型） |
| P1/P3/P4 | 3.1 分发器反射 / 3.2 参数自报 |
| P2 | 3.3 前端硬编码密钥 |
| P5/P6/P7 | 3.6 降级通道 / Phase 4 影响放大 |
