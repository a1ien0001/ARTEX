---
name: apk-vulnhunt
description: APK/Android 应用漏洞挖掘作业法（入口→容器→JSBridge→特权接口全链路）。入口口径固定为**浏览器一次点击**或**App 功能内 XSS**（拒绝任意本地 App/adb 直调）。以 WebView JSBridge 攻击面为核心，覆盖 Browsable DeepLink、域名白名单绕过、JSB 通道枚举、三层防御突破与特权利用。当要求「挖 APK」「测安卓 App」「APK 漏洞挖掘」「测 WebView」「JSB/JSBridge 绕过」「域名白名单绕过」「addJavascriptInterface」「exported 组件」「DeepLink 安全」「安卓静态分析」「H5 容器安全」，或拿到一个 APK 要找漏洞、复测安卓客户端、写移动端安全报告时使用。
---

# APK 漏洞挖掘作业法（JSBridge 核心链路）

授权安全测试作业法。核心洞察：入口只有两类——**浏览器一次点击**或 **App 功能内 XSS**——之后都是同一条链：**攻击者可控的 URL/JS 在未拦截的 WebView 容器内执行 → 与宿主 App 同进程 → 调用注入的 JSBridge 获得宿主特权**。所有挖掘工作围绕这条链的四个环节展开。

## 前提

- 仅用于授权测试（自有 App / 已签授权 / 公开 SRC 项目）。未授权不开展。
- 证据优先：每个结论附 APK 版本、代码位置（类名/方法）、可复现步骤。只读优先，涉及设备用模拟器或测试机。

## 入口硬约束（Gate 0，全程不放松）

本 skill 只承认两类入口，终点相同：**攻击者可控的 URL/JS 在注入了 JSB 的 WebView 容器内执行**。

### A · 浏览器一次点击（web → app）

```
攻击者页面(http/https) --浏览器点击--> 系统 browsable intent 解析 --拉起--> 目标 App
```

合格载体（满足任一）：

- `CATEGORY_BROWSABLE` 自定义 scheme：浏览器点 `victimscheme://web?url=...`
- `intent://` 包装：`intent://host/path#Intent;scheme=victimscheme;package=com.victim;end`
- App Links / Verified Links：`https://target.com/...` + `autoVerify`
- http(s) 中转页：攻击页 302/JS 跳到上述深链（首跳仍是浏览器点击）

一次点击的计数口径：点击链接本身；系统"用哪个应用打开/是否打开"的选择器与确认框属于同一次点击的解析过程，不额外计用户交互。需要无弹窗直开时，用 App Links（`autoVerify`）或系统里唯一处理该 scheme 的应用。

### B · App 功能内 XSS（app 内执行）

攻击者把 payload 植入 App 自有功能/内容（存储型），或构造 App 内打开的 URL（反射型）；受害者在正常使用 App 时，payload 在已注入 JSB 的 WebView 里执行。

典型落点：

- 昵称 / 签名 / 头像描述 / 评论 / 弹幕 / 私信 / 群公告 / 个人主页 / 动态富文本
- 搜索词回显、活动页 / 分享页 / H5 路由参数被拼进 `innerHTML` / `document.write`
- 站内消息、推送、分享卡片送达的 H5 页面（送达通道本身不算入口，XSS 才算）
- 小程序 / 快应用容器内的同源页面

B 的合格条件（全部满足）：

1. 攻击者可写入（存储型）或可构造 URL（反射型），且不依赖本地 App / adb；
2. 执行发生在注入了 JSB 的容器（同一 WebView / 同进程），或执行后能经容器触达 JSB；
3. 执行域在白名单内，或已用 Phase 3 手法绕过域名校验；
4. 有真实用户路径触发（受害者打开功能页 / 查看该内容 / 点开该链接），不是 Frida 或测试工具直调。

边界：B 不是"App 内随便点个链接"。普通站内跳转没有代码执行，只能做二次放大；只有当该功能/页面存在 XSS 时才算入口。

### 不合格入口（不得作为 PoC 起点，也不得作为漏洞交付）

- 另一个本地 App 构造显式 Intent 拉起导出组件（"任意本地 App"模型）
- `adb shell am start` / `am broadcast` / 测试 APK / Frida 直接调用
- 仅扫码、NFC、剪贴板、推送本身（它们只是送达通道；送达页面存在 App 功能内 XSS 时，入口归 B）
- App 内普通链接跳转（无 XSS）

处置：不合格入口只作为攻击面测绘与辅助证据，记为 `residual[非合格入口]`，不计入漏洞结论；继续在同一特权面上找 A 或 B 的变体。

验证闸门：

- A：真机/模拟器浏览器完成真实点击，地址栏为攻击者 URL，录屏含"浏览器 → App"切换；
- B：录屏含 payload 投放（攻击者视角）与受害者打开功能页后执行、JSB 回包（受害者视角）；
- `am start` / Frida 直调仅限开发调试，不能作为最终复现证据。

## 流水线总览

```
Phase 0 资产测绘 → Phase 1 入口发现（A 浏览器 1-click / B App 功能内 XSS）→ Phase 2 JSB 通道枚举
→ Phase 3 防御识别与绕过 → Phase 4 特权利用与影响放大 → Phase 5 PoC/报告
```

每个 Phase 的判定不通过就记录为 residual（残留问题），不阻塞下一 Phase——真实目标往往某一层完全裸奔。

## Phase 0 · 资产测绘

拿到 APK 先画"入口—容器—桥—特权接口"四层地图：

1. `apktool d` / `aapt dump xmltree` 取 Manifest；`jadx`/JEB 反编译（大 APK 用 `--deobf`）。
2. Manifest 审计关键词：`exported="true"`、含 `intent-filter` 的隐式导出、读 `url/link/jumpUrl/target` extra 的 Activity、`http/https/*` 通配 scheme。重点标记带 `CATEGORY_BROWSABLE` / `autoVerify` 的入口——它们才可能被浏览器点击拉起；其余导出组件只作辅助面。
3. 定位 WebView 容器类（`H5Activity/BaseWebActivity/WebViewActivity`）。
4. grep 五类 JSB 注入点与白名单实现类（关键词清单见 references/jsb-playbook.md §Phase 0）。
5. 动态起手式（Frida hook `loadUrl` 全量记录加载点与调用栈）：直接取 references/frida-hooks.md 里的现成脚本，不要每次重写。
6. XSS 面（B 类入口候选池）：抓 H5 bundle grep `innerHTML|document.write|v-html|dangerouslySetInnerHTML|eval`，同时枚举用户可控字段（昵称/评论/私信/个人主页）与反射参数（搜索/活动页/分享页/路由 query），标记其执行域是否在白名单、是否同容器。

### ASC 快查层（已安装：`droidasc`，大型 APK 静态分析首选）

已装载 [MG1937/ASC](https://github.com/MG1937/ASC)（pipx 安装，命令 `droidasc`）：把 APK 当数据库按需查询，352MB APK 全局交叉引用秒级返回——远快于 jadx 全量反编译。Phase 0–3 的定位类工作先走 ASC，只有需要全量源码审计或资源解包时才上 jadx/apktool。

| JSB 挖掘动作 | ASC 命令 |
|---|---|
| Manifest 审计（Phase 0.2） | `droidasc getmanifest app.apk` |
| 定位全部 WebView 加载点（静态版 loadUrl hook） | `droidasc findrefs app.apk method loadUrl` |
| 定位 JSB 注入点（五通道之一） | `droidasc findrefs app.apk method addJavascriptInterface` |
| 定位白名单实现类 | `droidasc findrefs app.apk string checkDomain`（换任意关键词） |
| 反编译校验实现看 Layer 2 缺陷 | `droidasc getclass app.apk Lcom/x/util/DomainUtils;` |
| 类清单 / 包内速览 | `droidasc listclass app.apk --prefix com.x.web` |
| 敏感接口名检索 | `droidasc findrefs app.apk string getToken` |

类名两种写法均接受：`com.x.Main` 或 `Lcom/x/Main;`。加了固的 APK 先脱壳（见 reverse-engineer-anything）。

## Phase 1 · 入口发现（A 浏览器一次点击 / B App 功能内 XSS）

先过 Gate 0 再谈利用。两类入口可叠加（例如浏览器点击把受害者送进一个有存储型 XSS 的功能页）。

### A 类 · 浏览器一次点击

| 优先级 | 入口 | 浏览器点击载体 |
|---|---|---|
| 1 | Browsable DeepLink / 自定义 scheme | `CATEGORY_BROWSABLE`，点 `victimscheme://...` |
| 2 | `intent://` 包装 | 浏览器点 `intent://...#Intent;scheme=...;package=...;end` |
| 3 | App Links / Verified Links | `https://target.com/...` + `autoVerify` |
| 4 | http(s) 中转页 | 攻击页 302/JS 跳到上述深链（首跳仍是浏览器点击） |

### B 类 · App 功能内 XSS

在 App 自有 H5 / 富文本功能里找可写入或可反射的注入点：

- **存储型**：昵称、签名、评论、弹幕、私信、群公告、个人主页、动态/帖子富文本 → 受害者查看即执行
- **反射型**：搜索词、活动页参数、分享落地页 query、H5 路由参数 → 构造 URL 让受害者打开
- **二阶**：白名单域 XSS（原入口 8）→ 执行后直接调 JSB
- **送达**：存储型靠用户打开功能页；反射型可经站内消息/推送/分享卡片/浏览器点击送达

合格四条件见 Gate 0，核心是"攻击者可植入/可构造 + 执行在注入 JSB 的容器 + 域在白名单内或已绕过 + 真实用户路径"。

### 辅助入口（单独不合格）

本地导出组件显式 Intent、Intent 重定向透传、`FLAG_MUTABLE` PendingIntent、`file://`·`content://`、扫码/NFC/剪贴板/推送通道本身。它们回答"进容器后能做什么"，不回答"怎么进容器"；必须与 A 或 B 串联。

判定标准：

- A：**浏览器一次点击可拉起 + 攻击者可控 URL + 未经拦截 + 进入同一 WebView 容器**
- B：**攻击者可写入/构造 + 在注入 JSB 的容器内执行 + 白名单内或已绕过 + 真实用户路径**

缺对应条件 → `residual[非合格入口]`，不交付。完整判定标准与利用细节读 references/jsb-playbook.md §Phase 1。

## Phase 2 · JSB 通道枚举

JSB 不止 addJavascriptInterface——五类通道逐一排查（addJavascriptInterface 同步调用 / shouldOverrideUrlLoading Scheme 拦截 / onJsPrompt 隧道 / shouldInterceptRequest / WebMessage）。枚举技巧：H5 官方文档反查、前端 bundle grep 真实调用、错误回显爆破方法表、通用分发器 `$invoke(method)` 提权。详见 references/jsb-playbook.md §Phase 2。

## Phase 3 · 防御识别与绕过（核心）

三层防御逐层突破，每层有独立手法表：

| 层 | 常见实现 | 绕过要点 |
|---|---|---|
| 01 来源校验 | 仅校验首跳/主 frame | 二段跳、iframe、onload 后注入、TOCTOU |
| 02 域名白名单 | contains/endsWith/正则 | 议题 3 种 + userinfo@ 混淆 + 解析器差分 + scheme 逃逸等 12 种 |
| 03 权限分级 | 运行时判断域 | 分发器反射、参数自报、前端硬编码密钥、二跳触达 |

**命中率排序**：解析器差分与 userinfo 混淆 > scheme 逃逸 > contains/endsWith 实现缺陷。完整手法表（12 种域名校验绕过 + 6 种权限提权）必须读 references/jsb-playbook.md §Phase 3 后再动手，避免漏测。

## Phase 4 · 特权利用与影响放大

六类基础影响（登录态/资产/隐私/投屏钓鱼/静默安装/高危权限）+ 放大链（CookieManager 全量 Cookie、私信蠕虫化、支付回调伪造、写启动路径持久化）。按可达接口分级定危害：隐私级 < 资产级 < 系统级。细节见 references/jsb-playbook.md §Phase 4。

## Phase 5 · PoC 与报告

- 最小复现链：
  - A 类：浏览器点击攻击页链接 → 拉起 App 进容器 → 过校验 → 调 JSB。
  - B 类：攻击者投放/构造 payload → 受害者打开功能页/链接 → 容器内执行 → 调 JSB。
- 录屏要素：
  - A：浏览器地址栏攻击页 URL、浏览器→App 拉起瞬间、宿主包名、敏感接口回包（真实数据打码）。
  - B：payload 投放过程（攻击者视角）、受害者打开功能页后的执行、宿主包名、敏感接口回包。
- 入口合规自查：复现步骤中不得出现 `am start`、另一个本地 App、Frida 直调作为触发；开发期用过 adb 的，交付前必须补 A/B 的真实版本。
- 危害定量：列出可达 JSB 接口全集 + 分级；注明交互条件与版本适配。
- 修复建议按 Layer 1/2/3 逐层给出，直接引用 references/defense-checklist.md 的条目编号，厂商沟通效率高。

## 输出格式

漏洞记录固定结构：`[层级][入口:A-浏览器点击 / B-App功能内XSS][载体][绕过手法] 标题 + 复现步骤 + 代码证据(类:方法:行) + 影响分级 + 修复建议(checklist 编号)`。A 写真实深链载体（如 `intent://` + package），B 写 XSS 落点与触发路径，不写"本地 App 可拉起"。

## 与其他 skill 协同

- 逆向 App 本体（native/加固脱壳/协议分析）→ `reverse-engineer-anything`
- 整体渗透流程编排、入库去重 → `pentest-ops`
- 打包报告/PoC/演示视频交付 → `vuln-deliverables`
- 服务端接口漏洞（JSB 之外）→ `web-vulnhunt-methodology`

## 参考文档路由

| 场景 | 读哪个 |
|---|---|
| 动手前完整过一遍手法表 / 任一 Phase 细节 | references/jsb-playbook.md |
| 需要 Frida hook 脚本（loadUrl 记录、JSB dump、白名单 trace） | references/frida-hooks.md |
| 写修复建议 / 判定是否构成漏洞 | references/defense-checklist.md |
