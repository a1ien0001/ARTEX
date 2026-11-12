package report

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"strings"
	"testing"
)

func TestEvidencePagesKeepRequestAndResponseComplete(t *testing.T) {
	request := "GET /object/314 HTTP/1.1\nHost: example.test\nCookie: secret-cookie\n\n" + strings.Repeat("参数id=314&", 320)
	response := "HTTP/1.1 200 OK\n\n" + strings.Repeat("result-row\n", 260) + "LAST_RESPONSE_ROW"
	pages, err := EvidencePages("对象越权验证", "binding_id=71", "完整请求报文", request, "完整响应报文", response)
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) < 2 {
		t.Fatalf("long exchange was not split across paired pages: %d", len(pages))
	}
	var all strings.Builder
	for _, p := range pages {
		if !strings.Contains(p.SVG, "完整请求报文") || !strings.Contains(p.SVG, "完整响应报文") || !strings.Contains(p.SVG, "binding_id=71") {
			t.Fatal("request and response were separated or source citation was lost")
		}
		all.WriteString(p.SVG)
	}
	if !strings.Contains(all.String(), "LAST_RESPONSE_ROW") {
		t.Fatal("last response line was cropped")
	}
	if strings.Contains(all.String(), "secret-cookie") {
		t.Fatal("cookie was not redacted")
	}
	if !strings.Contains(all.String(), "GET /object/314") {
		t.Fatal("vulnerability-defining parameter was removed")
	}
}

func TestEvidencePagesEscapeUntrustedMarkup(t *testing.T) {
	pages, err := EvidencePages("Step 3", "intent=5 · step=8", "操作", `{"id":314,"token":"hidden-value"}`, "执行结果", "<script>alert(1)</script>")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pages[0].SVG, "<script>") || strings.Contains(pages[0].SVG, "hidden-value") {
		t.Fatal("untrusted markup or credential reached image")
	}
	if !strings.Contains(pages[0].SVG, "&lt;script&gt;") || !strings.Contains(pages[0].SVG, "314") {
		t.Fatal("escaped content or relevant evidence is missing")
	}
}

func TestTerminalPagesKeepCommandAndResult(t *testing.T) {
	command := `curl -i -X POST https://example.test/object -H 'Authorization: secret' -d '{"id":314}'`
	result := "HTTP/1.1 200 OK\n\n" + strings.Repeat("result-row\n", 150) + "LAST_TERMINAL_RESULT"
	pages, err := TerminalPages("步骤 1：curl 验证", "intent_id=5 · step_id=8", command, result)
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) < 2 {
		t.Fatalf("terminal result was not paginated: %d", len(pages))
	}
	var all strings.Builder
	for _, page := range pages {
		all.WriteString(page.SVG)
	}
	text := all.String()
	for _, want := range []string{"#0b1220", "真实 CLI 命令记录", "curl -i -X POST", "LAST_TERMINAL_RESULT", "intent_id=5"} {
		if !strings.Contains(text, want) {
			t.Fatalf("terminal evidence missing %q", want)
		}
	}
	if strings.Contains(text, "Authorization: secret") {
		t.Fatal("terminal screenshot did not redact credentials")
	}
}

func TestTerminalExchangePagesKeepPair(t *testing.T) {
	pages, err := TerminalExchangePages("对象越权", "binding_id=71 · 完整配对流量", "curl -i https://example.test/object/314", "GET /object/314 HTTP/1.1\nHost: example.test", "HTTP/1.1 200 OK\n\nLAST_RESPONSE")
	if err != nil || len(pages) == 0 {
		t.Fatal("terminal exchange image was not generated", err)
	}
	text := pages[0].SVG
	for _, want := range []string{"binding_id=71", "完整请求报文", "完整响应报文", "GET /object/314", "LAST_RESPONSE"} {
		if !strings.Contains(text, want) {
			t.Fatalf("terminal exchange missing %q", want)
		}
	}
}

func TestTerminalToolPagesDoNotRenderToolJSONAsShellCommand(t *testing.T) {
	pages, err := TerminalToolPages("步骤 2：打开页面", "intent_id=5 · step_id=9", "browser_navigate", `{"url":"https://example.test/"}`, "页面已打开")
	if err != nil || len(pages) != 1 {
		t.Fatal("tool transcript image was not generated", err)
	}
	text := pages[0].SVG
	if !strings.Contains(text, "真实工具调用记录") || !strings.Contains(text, "调用工具: browser_navigate") || strings.Contains(text, "$ {\"url\"") {
		t.Fatal("non-shell tool input was presented as a CLI command")
	}
}

func TestPortableImagesForOfflineExport(t *testing.T) {
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 20, 20))); err != nil {
		t.Fatal(err)
	}
	uri := "data:image/png;base64," + base64.StdEncoding.EncodeToString(b.Bytes())
	md := "## Step 1\n\n![step](" + uri + ")\n![other](" + uri + ")\n"
	portable, files, err := PortableImages(md, "evidence/12/screenshots")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(portable, "evidence/12/screenshots/") || strings.Contains(portable, "data:image") || len(files) != 1 || !bytes.Equal(files[0].Data, b.Bytes()) {
		t.Fatalf("bad portable report refs or attachments: %q, %d", portable, len(files))
	}
}
