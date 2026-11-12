package report

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"path"
	"regexp"
	"strings"
	"unicode"
)

type EvidencePage struct {
	SVG    string `json:"svg"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

const MaxEvidencePages = 160

var secretHeaders = regexp.MustCompile(`(?im)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)([ \t]*:[ \t]*)[^\r\n]*`)
var secretCLIHeaders = regexp.MustCompile(`(?i)((?:-H|--header)[ \t]+['"]?(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)[ \t]*:[ \t]*)[^'"\r\n]+`)
var secretJSON = regexp.MustCompile(`(?i)("(?:password|passwd|access_token|refresh_token|token|api_key|secret|cookie|authorization)"\s*:\s*)"(?:[^"\\]|\\.)*"`)
var secretParams = regexp.MustCompile(`(?i)((?:^|[?&\s])(?:password|passwd|access_token|refresh_token|token|api_key|secret)=)[^&\s]*`)

// RedactImageText changes the deliverable copy only; original evidence is retained.
func RedactImageText(s string) string {
	s = secretHeaders.ReplaceAllString(s, "$1$2<REDACTED>")
	s = secretCLIHeaders.ReplaceAllString(s, "$1<REDACTED>")
	s = secretJSON.ReplaceAllString(s, "$1\"<REDACTED>\"")
	return secretParams.ReplaceAllString(s, "$1<REDACTED>")
}

func imageLines(s string, width int) []string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	var out []string
	for _, line := range strings.Split(s, "\n") {
		var b strings.Builder
		n := 0
		for _, r := range line {
			w := 1
			if unicode.Is(unicode.Han, r) || r >= 0x3000 && r <= 0xffef {
				w = 2
			}
			if r == '\t' || r < 32 {
				w = 4
			}
			if n+w > width {
				out = append(out, b.String())
				b.Reset()
				n = 0
			}
			if r == '\t' {
				b.WriteString("    ")
			} else if r < 32 {
				fmt.Fprintf(&b, "\\x%02x", r)
			} else {
				b.WriteRune(r)
			}
			n += w
		}
		out = append(out, b.String())
	}
	return out
}

// EvidencePages paginates the two complete sources together. Every page retains
// request/response or operation/result labels and stable evidence citations.
func EvidencePages(title, source, leftTitle, left, rightTitle, right string) ([]EvidencePage, error) {
	l, r := imageLines(RedactImageText(left), 82), imageLines(RedactImageText(right), 82)
	const rows = 45
	count := (max(len(l), len(r)) + rows - 1) / rows
	if count > MaxEvidencePages {
		return nil, fmt.Errorf("证据需要 %d 页，超过 %d 页上限；未生成截断图片，请拆分报告", count, MaxEvidencePages)
	}
	pages := make([]EvidencePage, 0, count)
	for page := 0; page < count; page++ {
		var b strings.Builder
		b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" width="1800" height="1240" viewBox="0 0 1800 1240"><rect width="1800" height="1240" fill="#f1f5f9"/><style>text{font-family:Consolas,'Noto Sans Mono CJK SC','Noto Sans CJK SC',monospace;fill:#172033;font-size:16px;white-space:pre}.heading{font-size:23px;font-weight:600}.muted{fill:#52647a;font-size:15px}</style>`)
		text := func(x, y int, class, value string) {
			fmt.Fprintf(&b, `<text x="%d" y="%d" class="%s">%s</text>`, x, y, class, html.EscapeString(value))
		}
		for i, line := range imageLines(RedactImageText(title), 130) {
			if i == 2 {
				break
			}
			text(32, 39+i*27, "heading", line)
		}
		text(32, 104, "muted", fmt.Sprintf("ARTEX 保存证据 · %s · 第 %d / %d 页", source, page+1, count))
		for side, lines := range [][]string{l, r} {
			x := 28 + side*886
			fmt.Fprintf(&b, `<rect x="%d" y="126" width="858" height="1058" rx="10" fill="white" stroke="#d4dde8"/>`, x)
			label := leftTitle
			if side == 1 {
				label = rightTitle
			}
			text(x+18, 163, "heading", label)
			start, end := page*rows, min((page+1)*rows, len(lines))
			if start >= len(lines) {
				text(x+18, 207, "muted", "本侧内容已在前页完整展示")
			}
			for i := start; i < end; i++ {
				text(x+18, 207+(i-start)*21, "", lines[i])
			}
		}
		text(32, 1220, "muted", "由保存的原始证据生成；凭据已自动脱敏。网页截图另列，原始报文随 ZIP 保留。")
		b.WriteString(`</svg>`)
		pages = append(pages, EvidencePage{SVG: b.String(), Width: 1800, Height: 1240})
	}
	return pages, nil
}

// TerminalPages renders a real command input and its saved result as a
// terminal-style evidence image. The command and output are only formatted for
// display; their content comes from the recorded tool_use/tool_result pair.
// Long output is paginated without dropping lines.
func TerminalPages(title, source, command, output string) ([]EvidencePage, error) {
	commandLines := imageLines(RedactImageText(command), 142)
	if len(commandLines) == 0 {
		commandLines = []string{"[未保存命令输入]"}
	}
	outputLines := imageLines(RedactImageText(output), 142)
	if len(outputLines) == 0 {
		outputLines = []string{"[命令未返回文本结果]"}
	}
	lines := make([]string, 0, len(commandLines)+len(outputLines)+4)
	lines = append(lines, "$ "+commandLines[0])
	if len(commandLines) > 1 {
		lines = append(lines, commandLines[1:]...)
	}
	lines = append(lines, "", "--- 真实执行结果 ---")
	lines = append(lines, outputLines...)
	return terminalPages(title, source, "真实 CLI 命令记录", lines)
}

// TerminalToolPages keeps non-shell actions honest while using the same visual
// transcript style: it labels the real tool call and input instead of rendering
// browser/API tool JSON as a shell command.
func TerminalToolPages(title, source, tool, input, output string) ([]EvidencePage, error) {
	inputLines := imageLines(RedactImageText(input), 142)
	outputLines := imageLines(RedactImageText(output), 142)
	if len(inputLines) == 0 {
		inputLines = []string{"[未保存输入参数]"}
	}
	if len(outputLines) == 0 {
		outputLines = []string{"[工具未返回文本结果]"}
	}
	lines := []string{"调用工具: " + tool, "输入参数:"}
	lines = append(lines, inputLines...)
	lines = append(lines, "", "--- 真实执行结果 ---")
	lines = append(lines, outputLines...)
	return terminalPages(title, source, "真实工具调用记录", lines)
}

// TerminalExchangePages renders a saved request/response pair as a terminal
// transcript. A command is included when the same worker step recorded one;
// otherwise the image explicitly marks that only the saved exchange is shown.
func TerminalExchangePages(title, source, command, request, response string) ([]EvidencePage, error) {
	commandLines := imageLines(RedactImageText(command), 142)
	requestLines := imageLines(RedactImageText(request), 142)
	responseLines := imageLines(RedactImageText(response), 142)
	if len(requestLines) == 0 {
		requestLines = []string{"[空请求报文]"}
	}
	if len(responseLines) == 0 {
		responseLines = []string{"[空响应报文]"}
	}
	lines := make([]string, 0, len(commandLines)+len(requestLines)+len(responseLines)+8)
	if len(commandLines) > 0 {
		lines = append(lines, "$ "+commandLines[0])
		if len(commandLines) > 1 {
			lines = append(lines, commandLines[1:]...)
		}
		lines = append(lines, "")
	} else {
		lines = append(lines, "$ [未保存 CLI 命令；以下为已保存的真实流量]", "")
	}
	lines = append(lines, ">>> 完整请求报文 <<<")
	lines = append(lines, requestLines...)
	lines = append(lines, "", "<<< 完整响应报文 >>>")
	lines = append(lines, responseLines...)
	return terminalPages(title, source, "真实 HTTP 流量记录", lines)
}

func terminalPages(title, source, chromeTitle string, lines []string) ([]EvidencePage, error) {
	const rows = 52
	count := (len(lines) + rows - 1) / rows
	if count > MaxEvidencePages {
		return nil, fmt.Errorf("终端证据需要 %d 页，超过 %d 页上限；未生成截断图片", count, MaxEvidencePages)
	}
	pages := make([]EvidencePage, 0, count)
	for page := 0; page < count; page++ {
		var b strings.Builder
		b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" width="1800" height="1240" viewBox="0 0 1800 1240"><rect width="1800" height="1240" fill="#0b1220"/><style>text{font-family:Consolas,'Noto Sans Mono CJK SC','Noto Sans CJK SC',monospace;fill:#dbe7f5;font-size:17px;white-space:pre}.heading{font-family:Consolas,'Noto Sans CJK SC',monospace;font-size:23px;font-weight:600;fill:#f8fafc}.muted{fill:#8da2bd;font-size:15px}.prompt{fill:#8be28b}.marker{fill:#7dd3fc;font-weight:600}</style>`)
		text := func(x, y int, class, value string) {
			fmt.Fprintf(&b, `<text x="%d" y="%d" class="%s">%s</text>`, x, y, class, html.EscapeString(value))
		}
		for i, line := range imageLines(RedactImageText(title), 132) {
			if i == 2 {
				break
			}
			text(32, 40+i*27, "heading", line)
		}
		text(32, 105, "muted", fmt.Sprintf("ARTEX 终端证据 · %s · 第 %d / %d 页", source, page+1, count))
		// Terminal chrome and a single full-width transcript preserve the visual
		// relationship between the command, request and response.
		b.WriteString(`<rect x="26" y="126" width="1748" height="1058" rx="10" fill="#111827" stroke="#334155"/><circle cx="54" cy="157" r="7" fill="#fb7185"/><circle cx="78" cy="157" r="7" fill="#fbbf24"/><circle cx="102" cy="157" r="7" fill="#4ade80"/>`)
		text(130, 163, "muted", chromeTitle)
		start, end := page*rows, min((page+1)*rows, len(lines))
		for i := start; i < end; i++ {
			class := ""
			if strings.HasPrefix(lines[i], "$ ") {
				class = "prompt"
			} else if strings.HasPrefix(lines[i], "--- ") || strings.HasPrefix(lines[i], ">>> ") || strings.HasPrefix(lines[i], "<<< ") {
				class = "marker"
			}
			text(48, 205+(i-start)*19, class, lines[i])
		}
		text(32, 1220, "muted", "由保存的真实工具输入与输出生成；凭据已自动脱敏。原始报文随证据 ZIP 保留。")
		b.WriteString(`</svg>`)
		pages = append(pages, EvidencePage{SVG: b.String(), Width: 1800, Height: 1240})
	}
	return pages, nil
}

type PortableImage struct {
	Name string
	Data []byte
}

var embeddedPNG = regexp.MustCompile(`!\[([^\]\r\n]*)\]\((data:image/png;base64,([A-Za-z0-9+/=]+))\)`)

// PortableImages extracts report PNGs into ZIP-relative files, deduplicated by hash.
func PortableImages(markdown, prefix string) (string, []PortableImage, error) {
	var images []PortableImage
	seen := map[string]bool{}
	var decodeErr error
	out := embeddedPNG.ReplaceAllStringFunc(markdown, func(match string) string {
		m := embeddedPNG.FindStringSubmatch(match)
		data, err := base64.StdEncoding.DecodeString(m[3])
		if err != nil {
			decodeErr = err
			return match
		}
		hash := sha256.Sum256(data)
		name := path.Join(prefix, fmt.Sprintf("%x.png", hash))
		if !seen[name] {
			images = append(images, PortableImage{Name: name, Data: data})
			seen[name] = true
		}
		return fmt.Sprintf("![%s](%s)", m[1], name)
	})
	return out, images, decodeErr
}

// AgentReportText avoids sending megabytes of encoded image pixels to an LLM.
func AgentReportText(markdown string) string {
	return embeddedPNG.ReplaceAllString(markdown, "[已保存报告图片：$1]")
}
