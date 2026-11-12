# JSBridge 攻击面完整挖掘手册

> 攻击链总览：**入口（A 浏览器一次点击 / B App 功能内 XSS）→ 攻击者可控 URL/JS 进入 WebView 容器 → 同进程加载/执行（共享 Cookie/Token、私有沙箱、系统权限）→ 调用注入的 JSBridge → 特权接口可达**
>
> 入口口径：只收 A 浏览器一次点击 / B App 功能内 XSS；`am start`、另一个本地 App、Frida 直调只算开发调试（详见 SKILL.md Gate 0）。
>
> 来源：GeekCon 议题实录 + 公开安全研究方法论（OWASP MASTG 等）补全。仅限授权测试。

---

## Phase 0 · 资产测绘

**目标：画出"入口—容器—桥—特权接口"四层地图。**

### 0.1 样本获取

- 应用市场 APK；`adb shell pm path <pkg>` + pull 拿全量 split APK（base + splits）
- 历史版本（旧版防御更弱、白名单更松）
- 快应用/小程序容器（同源 JSB 风险，常被忽略）

### 0.2 静态分析关键词清单（jadx / JEB / MobSF / apktool）

Manifest 审计：
- `exported="true"` 且读 `intent.getStringExtra("url"/"link"/"jumpUrl"/"target")` 的 Activity
- 含 `<intent-filter>` 的隐式导出（exported 默认 true），重点看是否带 `CATEGORY_BROWSABLE`
- `scheme="http/https/*"` 通配 DeepLink
- App Links：`android:autoVerify="true"` + `android:host` 的 https filter

JSB 注入点搜索：
```
addJavascriptInterface(
@JavascriptInterface
shouldOverrideUrlLoading(
onJsPrompt( / onJsAlert( / onJsConfirm(
shouldInterceptRequest(
WebMessagePort / createWebMessageChannel(
```

白名单实现类搜索：
```
checkDomain / isTrustUrl / WhiteList / DomainUtils / UrlCheck / host(
```

XSS 落点搜索（B 类入口）：
```
innerHTML / document.write / v-html / dangerouslySetInnerHTML / insertAdjacentHTML / eval(
```

### 0.3 动态分析

用 references/frida-hooks.md 的现成脚本：hook `loadUrl` 记录全部加载点与调用栈、hook `setJavaScriptEnabled/setAllowFileAccess/setAllowUniversalAccessFromFileURLs`、运行时 dump JSB 方法表。

---

## Phase 1 · 入口层挖掘（A 浏览器一次点击 / B App 功能内 XSS）

**硬口径**：只收两类入口——A 浏览器一次点击（web → app）；B App 功能内 XSS（攻击者 JS 在 App 自有 WebView 里执行）。`am start`、另一个本地 App、Frida 直调只算开发调试，不算入口验证。

### A · 浏览器一次点击

- `CATEGORY_BROWSABLE` 自定义 scheme：`victimscheme://web?url=https://evil.com/`
- `intent://`：`intent://web?url=...#Intent;scheme=victimscheme;package=com.victim.app;end`
- App Links / Verified Links：`https://target.com/...` + `autoVerify`
- http(s) 中转页：攻击页 302/JS 跳深链，首跳仍是浏览器点击

**计数口径**：点击链接本身算一次；系统"用哪个应用打开/是否打开"的选择器与确认框属于同一次点击的解析过程，不额外计。要无弹窗直开，优先 App Links（`autoVerify`）或系统里唯一处理该 scheme 的应用。

### B · App 功能内 XSS

**本质**：攻击者控制的内容/参数在 App 自己的 H5 里被当作 HTML/JS 执行，执行域与 JSB 相同。

| 类型 | 落点 | 触发 |
|---|---|---|
| 存储型 | 昵称、签名、头像描述、评论、弹幕、私信、群公告、个人主页、动态/帖子富文本、收货备注 | 受害者打开功能页/查看内容，无需点链接 |
| 反射型 | 搜索词回显、活动页参数、分享落地页 query、H5 路由参数、邀请码/推广位 | 受害者打开构造 URL；可经站内消息/推送/分享卡片/浏览器点击送达 |
| 二阶 | 白名单域上的存储/反射 XSS（原入口 8） | 执行后直接调 JSB |

**挖法**：

1. 枚举可写字段（抓包 + 表单 + 接口文档），写入最小探测串 `xsstest<>"'`，看回显编码。
2. 枚举反射参数（活动页/分享页/搜索/路由），确认是否进入 `innerHTML`、`document.write`、`v-html`、`dangerouslySetInnerHTML`、模板字符串、`eval`。
3. 最小验证 `<img src=x onerror=console.log(document.domain)>`；确认上下文后再升级到 `window.<JSB>.getToken()`。
4. 有过滤按 Phase 3 思路绕：标签/属性/协议白名单、HTML 实体、JS 字符串转义、URL 编码、CSP。
5. 确认执行域在 App 白名单内；不在白名单的 XSS 只能当普通 Web XSS（转 `web-vulnhunt-methodology`），或先做 Phase 3 域名校验绕过。

**B 的合格条件（全部满足）**：攻击者可写入/可构造且不依赖本地 App/adb；执行在注入 JSB 的容器；域在白名单内或已绕过；有真实用户路径。

### 入口清单与分类

| # | 入口 | 分类 | 说明 |
|---|---|---|---|
| 1 | 本地导出组件唤起 | 辅助* | WebView Activity `exported="true"`；仅当同一组件同时带 browsable filter / 可被 `intent://` 命中时才算 A |
| 2 | 外部 DeepLink 唤起 | A | `CATEGORY_BROWSABLE` / App Links；浏览器点击、http(s) 中转页 302 均可 |
| 3 | 站内富文本链接跳转 | 辅助（内容有 XSS 时归 B） | 私信/评论 URL 绑 `ClickableSpan`；普通跳转无代码执行 |
| 4 | Intent 重定向 / Bundle 透传 | 辅助 | 恶意 App 嵌套 Intent；需先有 A/B 把你送进那个转发组件 |
| 5 | PendingIntent `FLAG_MUTABLE` | 辅助 | 通知/小组件二次填充 URL；同样不能自己当入口 |
| 6 | 剪贴板 / 二维码 / NFC / 推送 URL | 辅助（送达通道） | 通道本身不算入口；送达页面有 XSS 时入口归 B |
| 7 | `file://` / `content://` 本地 Scheme | 辅助 | 需任意文件写前置；不能替代 A/B |
| 8 | 白名单域 XSS（二阶） | B | 浏览器点击或站内功能触达白名单域注入点 → 合法调 JSB；最被低估 |

\* 入口 1 的合格变体：浏览器不能直接发显式 Intent，但可以点 `intent://...#Intent;package=com.victim;end` 命中带 browsable filter 的组件；组件完全没 filter 时只能是辅助入口。

**判定标准（满足即记候选）**：

- A：浏览器一次点击可拉起 → 攻击者可控 URL → 未经拦截 → 进入同一 WebView 容器。
- B：攻击者可写入/构造 → 在注入 JSB 的容器内执行 → 白名单内或已绕过 → 真实用户路径。

缺对应条件 → `residual[非合格入口]`，不交付。

### 不合格入口的处置

只用于攻击面测绘与辅助证据，不写入 PoC 起点。继续在同一特权面上找 A/B 变体，优先检查：

1. 该组件/Activity 是否同时挂了 `BROWSABLE` 的 `intent-filter`；
2. 是否能被 `intent://...#Intent;package=...;end` 命中（即使 `exported` 未显式声明）；
3. 是否有 https App Link 或 http(s) 中转页可把浏览器流量送进来；
4. 入口 URL 是否只是被放进"另一个 extra"，能否换成浏览器可控的那个 extra；
5. 该功能里用户可控字段/反射参数是否在 App 内 WebView 回显（有则转为 B 类 XSS 测试）。

---

## Phase 2 · JSBridge 通道发现与全量枚举

### 五类通道

| 通道 | 特征 | 枚举方法 |
|---|---|---|
| ① addJavascriptInterface | 同步调用 `window.X.method()` | dump 注入对象 + 反射方法表；Android ≥4.2 仅暴露 `@JavascriptInterface` 方法 |
| ② URL Scheme 拦截 | `shouldOverrideUrlLoading` 拦 `jsbridge://`、`wvjbscheme://`、`app://` | Hook 拦截器，伪造 scheme 遍历 method 名 |
| ③ onJsPrompt / onJsAlert | `prompt("bridge://...")` 隧道 | 构造 prompt 载荷探测回包 |
| ④ shouldInterceptRequest | 拦 fetch/XHR 伪协议 | 伪造请求观察 native 响应 |
| ⑤ WebMessage / postMessage | `createWebMessageChannel` 端口通信 | Hook port message |

### 枚举技巧

- **官方 H5 文档反查**：App 内嵌 H5 的 JSBridge 文档常在公开 CDN / 前端仓库 / 小程序 SDK 泄露全量接口签名。
- **H5 bundle 爬取**：APK assets、缓存目录、线上 H5 站点抓 JS，grep `bridge.call(` 提取真实调用样例与敏感接口名（`getUserInfo / getToken / contact / sms / pay / install / screencast`）。
- **方法表爆破**：部分 JSB 暴露 `$invoke(method, params)` 通用分发器 → 直接传敏感 method 名提权调用。
- **错误信息回显**：调用不存在方法时的报错常泄露完整方法列表。

---

## Phase 3 · 防御识别与逐层绕过

### Layer 1 · 调用来源校验绕过

实现常见为"最后加载的 URL 是否自家域名"或"Referer/首包域名"。

| # | 手法 | 原理 |
|---|---|---|
| 1.1 | meta refresh / JS location 二段跳 | 校验在 `shouldOverrideUrlLoading`（仅主 frame 导航触发），页面内 iframe/location 二次跳转不经过 |
| 1.2 | iframe 嵌套 | 校验 top frame，payload 跑在白名单 iframe 的 evil 子 frame（或反向） |
| 1.3 | onload 后注入 | 先加载白名单页通过校验，setTimeout 后 `document.write` 载荷 |
| 1.4 | WebView 内 302 重定向 | 校验在请求前，重定向后不复检（TOCTOU） |
| 1.5 | 白名单域开重定向 | `target.com/redirect?url=evil.com` → 白名单域亲自送流量去 evil |
| 1.6 | 白名单域前端路由可控 | `target.com/#/webview?url=` SPA 路由参数被当作二次 loadUrl 目标 |

### Layer 2 · 域名合法性校验绕过（12 种）

议题原始 3 种：

| # | 实现 | 绕过 |
|---|---|---|
| 2.1 | `host.contains("target.com")` | `target.com.evil.com` |
| 2.2 | `host.endsWith("target.com")` 缺前导点 | 注册 `eviltarget.com` |
| 2.3 | 正则含 `[.]target[.]com` 且 `find()` 缺尾部 `$` | 前缀拼接种子串命中 |

专家补充 9 种（真实工程最致命）：

| # | 手法 | 示例 |
|---|---|---|
| 2.4 | **userinfo 混淆** | `https://target.com@evil.com/` — `URL.getAuthority()` 含 target.com，实际 host 是 evil.com |
| 2.5 | **解析器差分** | `java.net.URI` vs `android.net.Uri` vs Blink 内核对 `\`、`%2F`、`%00`、`\t\n` 解析不一致 → 校验器看到的 host ≠ 内核实际请求的 host |
| 2.6 | **反斜杠与协议混淆** | `https://target.com\@evil.com`、`https:/\evil.com`、`target.com\\.evil.com` |
| 2.7 | **检查对象错位** | 校验 `getUrl()` 而非最终 `getHost()`；或校验 Intent extra A 却 load 了 extra B |
| 2.8 | **trailing dot / 大小写 / IDN 同形** | `target.com.`、`TARGET.com`、punycode 同形域（西里尔 а） |
| 2.9 | **子域接管** | 白名单里的 dangling DNS（`dev.target.com` CNAME 失效）→ 注册接管 |
| 2.10 | **Scheme 逃逸** | 域名校验仅针对 http(s)，`intent://`、`javascript:`、`file://`、`content://` 跳过校验分支 |
| 2.11 | **校验时序缺陷** | 只在 `onPageStarted` 校验首跳；`onPageFinished` / 内部 redirect / SPA pushState 不复检 |
| 2.12 | **Service Worker 缓存投毒** | 白名单页 SW 缓存被投毒后离线加载载荷 |

> 实战命中率排序：**2.4 与 2.5 最高**（所有手写 URL 解析几乎都死于解析器差分）> 2.10 scheme 逃逸 > 2.1/2.2 实现缺陷。

### Layer 3 · 接口权限分级绕过（6 种）

| # | 手法 | 说明 |
|---|---|---|
| 3.1 | **通用分发器反射** | 低权接口暴露 `call(method, json)` → 越级传敏感 method |
| 3.2 | **参数驱动的权限判定** | 权限由 H5 传参决定（`{"permission":"sensitive"}` 客户端自报） |
| 3.3 | **JS 侧硬编码密钥** | 敏感接口签名 secret 写在前端 JS → 逆向 bundle 提取后伪造签名 |
| 3.4 | **间接调用链** | 敏感接口不可直达，但可经 `openUrl`/`execJs`/`loadData` 类接口二跳触达 |
| 3.5 | **竞态窗口** | 校验与执行之间 post 到主线程的间隙替换 state |
| 3.6 | **降级与灰度** | 旧版本接口 / region 参数切换到弱校验通道 |

---

## Phase 4 · 特权接口利用与影响放大

### 六类基础影响（议题）

1. 红包/优惠券窃取、批量拉新注册
2. 窃取登录态：Cookie、Token
3. 窃通讯录、短信、相册、定位（需用户授权场景）
4. 远程投屏，同屏展示钓鱼内容
5. 调用系统 API：下载安装指定 App
6. 申请高危权限

### 放大链（专家补充）

- **Cookie/Token 全量提取**：`CookieManager.getCookie(url)` 一次拉全部子域 Cookie；注入 JS 读 localStorage 里 long-lived token
- **蠕虫化传播**：JSB `sendMsg(contactList)` + 富文本入口 = 站内私信自我复制（"站内链接"入口的反向利用）
- **无感操作**：`requestPermissions` 配合伪造系统弹窗时序实现"已授权"假象
- **支付链路**：静默领取/转移红包券 + `getPaymentSignature` 类接口伪造支付回调
- **持久化**：`downloadAndInstall` / `writeFile` 写启动路径
- **同屏钓鱼**：悬浮窗/WebOverlay 类接口展示假登录页收割二次凭据

---

## Phase 5 · PoC 构建规范

1. **最小复现链**：
   - A 类：攻击页 HTML 落在攻击域 → 受害者在浏览器点击链接（`intent://` / 自定义 scheme / App Link）→ 进容器 → 过校验 → 调 JSB。
   - B 类：攻击者投放/构造 payload → 受害者打开功能页/链接 → 容器内执行 → 调 JSB。
2. **演示证据**：
   - A：录屏含浏览器地址栏攻击页 URL、浏览器→App 拉起瞬间、宿主包名、敏感接口回包（真实数据打码）。
   - B：录屏含 payload 投放（攻击者视角）、受害者打开功能页后的执行、宿主包名、敏感接口回包。
3. **入口合规**：PoC 中不得用 `am start`、另一个本地 App、Frida 直调作为触发；它们只能用于开发期定位。A/B 都复现不了的，判定为 `residual[非合格入口]`，不作为漏洞交付。
4. **危害定量**：可达 JSB 接口全集 + 分级（隐私级 / 资产级 / 系统级）。
5. **边界条件**：是否需要用户交互、是否需要前台、Android 版本适配、浏览器类型（Chrome / 系统浏览器 / 第三方）。
6. **修复建议**：按 Layer 1/2/3 逐层给出，引用 references/defense-checklist.md 条目编号。
