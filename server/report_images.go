package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
	"github.com/Autumn-27/artex/report"
)

const (
	maxReportScreenshotBytes = 20 << 20
	maxReportImageBytes      = 24 << 20
)

type reportImageStepInput struct {
	Title          string    `json:"title"`
	IntentID       jsonRawID `json:"intent_id"`
	StepID         jsonRawID `json:"step_id"`
	BindingID      jsonRawID `json:"binding_id"`
	ScreenshotPath string    `json:"screenshot_path"`
}

// jsonRawID accepts IDs returned as either JSON numbers or numeric strings.
type jsonRawID = json.RawMessage

type stepImageSource struct {
	tool           string
	operation      string
	result         string
	toolUseID      string
	request        string
	response       string
	screenshot     []byte
	operationPages int
	trafficPages   int
}

// reportTerminalCommand extracts the real shell command from a Bash tool input
// without inventing one when the step used another tool or stored a different
// input shape. The raw tool input remains available as a fallback in the image.
func reportTerminalCommand(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var input struct {
		Command string `json:"command"`
	}
	if json.Unmarshal([]byte(raw), &input) == nil && strings.TrimSpace(input.Command) != "" {
		return input.Command
	}
	return raw
}

func reportShellCommand(tool, raw string) string {
	if !strings.EqualFold(strings.TrimSpace(tool), "bash") && !strings.EqualFold(strings.TrimSpace(tool), "shell") {
		return ""
	}
	return reportTerminalCommand(raw)
}

func (s *Server) addFindingReportImages(ctx context.Context, findingID int64, markdown string, version int64, steps []reportImageStepInput) (string, error) {
	if len(steps) == 0 {
		return "", errors.New("with_images=true 时至少提供一个真实 report_steps 来源")
	}
	f, err := s.m.pg.GetFinding(findingID)
	if err != nil {
		return "", err
	}
	if f == nil {
		return "", db.ErrFindingNotFound
	}
	if f.EvidenceVersion != version {
		return "", db.ErrEvidenceConflict
	}

	traffic, err := s.m.pg.GetFindingTraffic(ctx, findingID)
	if err != nil {
		return "", err
	}
	if traffic.Version != version {
		return "", db.ErrEvidenceConflict
	}
	bindings := make(map[int64]db.FindingTrafficBinding, len(traffic.Bindings))
	for _, binding := range traffic.Bindings {
		bindings[binding.ID] = binding
	}

	var store *db.ExplorationStore
	if f.TaskID != nil {
		task, err := s.m.pg.GetTask(*f.TaskID)
		if err != nil {
			return "", err
		}
		if task != nil {
			store = s.m.pg.Exploration(task.ExplorationID)
		}
	}

	sources := make([]stepImageSource, 0, len(steps))
	for i, input := range steps {
		title := strings.TrimSpace(input.Title)
		if title == "" {
			title = fmt.Sprintf("复现步骤 %d", i+1)
		}
		intentID, stepID, bindingID := parseProfileID(input.IntentID), parseProfileID(input.StepID), parseProfileID(input.BindingID)
		source := stepImageSource{}
		if stepID > 0 {
			if intentID <= 0 || store == nil {
				return "", fmt.Errorf("%s: step_id 必须对应来源任务内的 intent_id", title)
			}
			if err := s.validateFindingIntent(store, f, intentID); err != nil {
				return "", fmt.Errorf("%s: %w", title, err)
			}
			activity, err := store.ActivityEvidence(stepID, intentID)
			if err != nil {
				return "", fmt.Errorf("%s: 无法读取指定的真实执行步骤: %w", title, err)
			}
			if activity.Kind != "tool_result" && activity.Kind != "result" {
				return "", fmt.Errorf("%s: step_id 必须指向真实的步骤结果", title)
			}
			source.tool = activity.Tool
			source.result = activity.Detail
			source.toolUseID = activity.ToolUseID
			if activity.Kind == "tool_result" && activity.ToolUseID != "" {
				operation, err := store.ActivityToolUse(intentID, activity.ToolUseID, activity.ID)
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					return "", fmt.Errorf("%s: 读取对应操作失败: %w", title, err)
				}
				if operation != nil {
					source.operation = operation.Detail
				}
			}
			if strings.TrimSpace(source.result) == "" {
				source.result = activity.Summary
			}
			if strings.TrimSpace(source.operation) == "" {
				source.operation = "执行记录未单独保存操作输入；以下展示真实步骤结果。"
			}
		}
		if bindingID > 0 {
			binding, ok := bindings[bindingID]
			if !ok {
				return "", fmt.Errorf("%s: binding_id=%d 不属于当前漏洞", title, bindingID)
			}
			source.request, err = trafficSideText(s.evidenceStore(), binding.Snapshot, "request")
			if err != nil {
				return "", fmt.Errorf("%s: 读取完整请求失败: %w", title, err)
			}
			source.response, err = trafficSideText(s.evidenceStore(), binding.Snapshot, "response")
			if err != nil {
				return "", fmt.Errorf("%s: 读取完整响应失败: %w", title, err)
			}
		}
		if strings.TrimSpace(input.ScreenshotPath) != "" {
			if f.TaskID == nil {
				return "", fmt.Errorf("%s: 漏洞没有来源任务，不能读取任务截图", title)
			}
			source.screenshot, err = s.readReportScreenshot(*f.TaskID, input.ScreenshotPath)
			if err != nil {
				return "", fmt.Errorf("%s: %w", title, err)
			}
		}
		if stepID == 0 && bindingID == 0 && len(source.screenshot) == 0 {
			return "", fmt.Errorf("%s: 至少指定真实 step_id、binding_id 或 screenshot_path", title)
		}
		sources = append(sources, source)
	}

	pages := make([]report.EvidencePage, 0, len(sources)*2)
	for i := range sources {
		source := &sources[i]
		title := strings.TrimSpace(steps[i].Title)
		if title == "" {
			title = fmt.Sprintf("复现步骤 %d", i+1)
		}
		intentID, stepID, bindingID := parseProfileID(steps[i].IntentID), parseProfileID(steps[i].StepID), parseProfileID(steps[i].BindingID)
		if stepID > 0 {
			citation := fmt.Sprintf("intent_id=%d · step_id=%d", intentID, stepID)
			if source.toolUseID != "" {
				citation += " · tool_use_id=" + source.toolUseID
			}
			var p []report.EvidencePage
			var err error
			if strings.EqualFold(source.tool, "bash") || strings.EqualFold(source.tool, "shell") {
				p, err = report.TerminalPages(title, citation, reportTerminalCommand(source.operation), source.result)
			} else {
				p, err = report.TerminalToolPages(title, citation, source.tool, source.operation, source.result)
			}
			if err != nil {
				return "", err
			}
			source.operationPages = len(p)
			pages = append(pages, p...)
		}
		if bindingID > 0 {
			p, err := report.TerminalExchangePages(title, fmt.Sprintf("binding_id=%d · 完整配对流量", bindingID), reportShellCommand(source.tool, source.operation), source.request, source.response)
			if err != nil {
				return "", err
			}
			source.trafficPages = len(p)
			pages = append(pages, p...)
		}
	}
	if len(pages) > report.MaxEvidencePages {
		return "", fmt.Errorf("报告截图需要 %d 页，超过 %d 页上限；未截断证据", len(pages), report.MaxEvidencePages)
	}
	renderer := s.reportImageRenderer
	if renderer == nil {
		renderer = report.RenderEvidencePNGs
	}
	images, err := renderer(ctx, pages)
	if err != nil {
		return "", err
	}
	if len(images) != len(pages) {
		return "", fmt.Errorf("截图渲染页数不完整：预期 %d，实际 %d", len(pages), len(images))
	}
	totalBytes := 0
	for _, image := range images {
		totalBytes += len(image)
		if len(image) == 0 || len(image) > maxReportImageBytes || totalBytes > maxReportImageBytes {
			return "", fmt.Errorf("生成的截图超出 %d MiB 保存上限", maxReportImageBytes>>20)
		}
		config, err := png.DecodeConfig(bytes.NewReader(image))
		if err != nil || config.Width <= 0 || config.Height <= 0 || config.Width > 2000 || config.Height > 1400 || int64(config.Width)*int64(config.Height) > 2_800_000 {
			if err != nil {
				return "", fmt.Errorf("截图渲染结果不是有效 PNG: %w", err)
			}
			return "", errors.New("截图渲染结果尺寸超限")
		}
		if _, err := png.Decode(bytes.NewReader(image)); err != nil {
			return "", fmt.Errorf("截图 PNG 数据不完整: %w", err)
		}
	}
	for _, source := range sources {
		totalBytes += len(source.screenshot)
		if totalBytes > maxReportImageBytes {
			return "", fmt.Errorf("报告截图超过 %d MiB 保存上限", maxReportImageBytes>>20)
		}
	}

	var out strings.Builder
	out.WriteString(strings.TrimRight(markdown, "\r\n"))
	out.WriteString("\n\n## 复现过程截图\n")
	pageIndex := 0
	for i, source := range sources {
		title := strings.TrimSpace(steps[i].Title)
		if title == "" {
			title = fmt.Sprintf("复现步骤 %d", i+1)
		}
		out.WriteString("\n### " + markdownHeading(title) + "\n")
		if stepID := parseProfileID(steps[i].StepID); stepID > 0 {
			count := source.operationPages
			for n := 0; n < count; n++ {
				fmt.Fprintf(&out, "\n![%s：终端命令与结果（第 %d/%d 页）](data:image/png;base64,%s)\n", markdownAlt(title), n+1, count, base64.StdEncoding.EncodeToString(images[pageIndex]))
				pageIndex++
			}
		}
		if bindingID := parseProfileID(steps[i].BindingID); bindingID > 0 {
			count := source.trafficPages
			for n := 0; n < count; n++ {
				fmt.Fprintf(&out, "\n![%s：完整请求与响应（第 %d/%d 页）](data:image/png;base64,%s)\n", markdownAlt(title), n+1, count, base64.StdEncoding.EncodeToString(images[pageIndex]))
				pageIndex++
			}
		}
		if len(source.screenshot) > 0 {
			fmt.Fprintf(&out, "\n![%s：真实浏览器页面截图](data:image/png;base64,%s)\n", markdownAlt(title), base64.StdEncoding.EncodeToString(source.screenshot))
		}
	}
	if pageIndex != len(images) {
		return "", errors.New("报告截图索引不完整")
	}
	return out.String(), nil
}

func markdownHeading(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "#", "＃")
	return s
}

func markdownAlt(s string) string {
	s = strings.NewReplacer("[", " ", "]", " ", "(", " ", ")", " ", "\\", " ", "\r", " ", "\n", " ").Replace(s)
	return strings.TrimSpace(s)
}

func (s *Server) validateFindingIntent(store *db.ExplorationStore, finding *db.DBFinding, intentID int64) error {
	if finding.NodeID == nil {
		return errors.New("漏洞来源节点不可用，不能校验意图归属")
	}
	node, err := store.GetNode(intentID)
	if err != nil {
		return err
	}
	if node == nil || node.Kind != "intent" {
		return errors.New("intent_id 不属于当前漏洞的来源任务")
	}
	var linked bool
	err = s.m.pg.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_edges WHERE exploration_id=$1 AND src_id=$2 AND dst_id=$3 AND rel=$4)`, store.ID(), intentID, *finding.NodeID, db.RelYields).Scan(&linked)
	if err != nil {
		return err
	}
	if !linked {
		return errors.New("intent_id 与当前漏洞没有保存的验证关系")
	}
	return nil
}

func trafficSideText(store *evidence.Store, snapshot db.TrafficEvidenceSnapshot, side string) (string, error) {
	head := snapshot.ReqHead
	if side == "response" {
		head = snapshot.RespHead
	}
	f, length, err := store.OpenBody(snapshot, side)
	if err != nil {
		return "", err
	}
	defer f.Close()
	const maxEvidenceBytes = 1 << 20
	if length > maxEvidenceBytes {
		return "", fmt.Errorf("正文为 %d 字节，超出完整图片证据上限 %d 字节；正文未截断，请拆分报告", length, maxEvidenceBytes)
	}
	body, err := io.ReadAll(io.LimitReader(f, maxEvidenceBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(body)) != length {
		return "", errors.New("流量正文长度校验失败")
	}
	content := string(body)
	if !utf8.Valid(body) || strings.ContainsRune(content, '\x00') {
		content = "[正文采用 Base64 表示，保留全部原始字节]\n" + base64.StdEncoding.EncodeToString(body)
	}
	if strings.TrimSpace(head) == "" {
		return content, nil
	}
	if content == "" {
		return strings.TrimRight(head, "\r\n") + "\r\n", nil
	}
	return strings.TrimRight(head, "\r\n") + "\r\n\r\n" + content, nil
}

func (s *Server) readReportScreenshot(taskID int64, relative string) ([]byte, error) {
	if taskID <= 0 || strings.TrimSpace(relative) == "" {
		return nil, errors.New("截图路径无效")
	}
	root := filepath.Join(s.m.dir, "tasks", strconv.FormatInt(taskID, 10))
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if filepath.IsAbs(relative) || filepath.VolumeName(relative) != "" || !filepath.IsLocal(relative) {
		return nil, errors.New("截图路径必须是任务工作目录内的相对路径")
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, errors.New("截图路径不能离开任务工作目录")
	}
	rootResolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("任务工作目录不存在: %w", err)
	}
	candidate := filepath.Join(rootResolved, clean)
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return nil, fmt.Errorf("无法读取截图: %w", err)
	}
	rel, err := filepath.Rel(rootResolved, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, errors.New("截图路径解析后超出任务工作目录")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxReportScreenshotBytes {
		return nil, fmt.Errorf("截图必须是 1..%d MiB 的普通文件", maxReportScreenshotBytes>>20)
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, err
	}
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil || config.Width <= 0 || config.Height <= 0 || config.Width > 12000 || config.Height > 12000 || int64(config.Width)*int64(config.Height) > 40_000_000 {
		return nil, errors.New("截图必须是有效 PNG，尺寸不得超过 12000×12000 或 4000 万像素")
	}
	decoded, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("PNG 数据不完整: %w", err)
	}
	var normalized bytes.Buffer
	if err := png.Encode(&normalized, decoded); err != nil {
		return nil, err
	}
	if normalized.Len() > maxReportScreenshotBytes {
		return nil, fmt.Errorf("PNG 解码后超过 %d MiB 保存上限", maxReportScreenshotBytes>>20)
	}
	return normalized.Bytes(), nil
}
