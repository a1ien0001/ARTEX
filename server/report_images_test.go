package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
)

func TestReportImageSaveUsesFullPacketsAndRealStepResults(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	stored, _ := s.m.pg.GetFinding(f.FindingID)
	task, _ := s.m.pg.GetTask(*stored.TaskID)
	es := s.m.pg.Exploration(task.ExplorationID)
	intent, err := es.AddIntent(map[string]any{"summary": "verify object"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err = es.Link(intent, db.RelYields, f.NodeID); err != nil {
		t.Fatal(err)
	}
	_, err = es.AppendActivity(db.Activity{NodeID: &intent, Kind: "tool_use", Tool: "Bash", ToolUseID: "actual-call", Detail: `{"command":"curl http://example.test/object/314"}`})
	if err != nil {
		t.Fatal(err)
	}
	step, err := es.AppendActivity(db.Activity{NodeID: &intent, Kind: "tool_result", Tool: "Bash", ToolUseID: "actual-call", Detail: strings.Repeat("observed output\n", 120) + "FINAL_STEP_OUTPUT"})
	if err != nil {
		t.Fatal(err)
	}
	seedServerEvidenceFlow(t, s, "image-proof", []byte(strings.Repeat("response\n", 180)+"FINAL_RESPONSE"))
	bindings, err := s.evidenceStore().Bind(context.Background(), f.FindingID, []db.TrafficRef{{TrafficID: "image-proof", Role: "proof"}})
	if err != nil {
		t.Fatal(err)
	}
	var captured []report.EvidencePage
	s.reportImageRenderer = func(_ context.Context, pages []report.EvidencePage) ([][]byte, error) {
		captured = pages
		var b bytes.Buffer
		_ = png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 1800, 1240)))
		out := make([][]byte, len(pages))
		for i := range out {
			out[i] = b.Bytes()
		}
		return out, nil
	}
	pageDir := filepath.Join(s.m.dir, "tasks", fmt.Sprint(task.ID), fmt.Sprintf("i%d", intent), "screenshots")
	if err := os.MkdirAll(pageDir, 0700); err != nil {
		t.Fatal(err)
	}
	var realPage bytes.Buffer
	if err := png.Encode(&realPage, image.NewRGBA(image.Rect(0, 0, 32, 48))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pageDir, "step-01.png"), realPage.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	input := map[string]any{"finding_record_id": f.FindingID, "evidence_version": bindings.Version, "report": "## 三、复现步骤\n\n1. 请求对象 314", "with_images": true, "report_steps": []map[string]any{{"title": "步骤 1：请求对象 314", "intent_id": intent, "step_id": step, "binding_id": bindings.Bindings[0].ID, "screenshot_path": fmt.Sprintf("i%d/screenshots/step-01.png", intent)}}}
	workflowCall(t, ctx, s.toolUpdateFindingReport(), input, false)
	var source strings.Builder
	for _, p := range captured {
		source.WriteString(p.SVG)
	}
	for _, want := range []string{"FINAL_RESPONSE", "FINAL_STEP_OUTPUT", "actual-call", "$ curl http://example.test/object/314", "完整请求报文", "完整响应报文"} {
		if !strings.Contains(source.String(), want) {
			t.Fatalf("missing complete source: %s", want)
		}
	}
	updated, _ := s.m.pg.GetFinding(f.FindingID)
	if !strings.Contains(updated.Report, "data:image/png;base64,") || !strings.Contains(updated.Report, "真实浏览器页面截图") {
		t.Fatal("images not saved with report")
	}
	before := updated.Report
	s.reportImageRenderer = func(context.Context, []report.EvidencePage) ([][]byte, error) {
		return nil, errors.New("renderer unavailable")
	}
	workflowCall(t, ctx, s.toolUpdateFindingReport(), input, true)
	updated, _ = s.m.pg.GetFinding(f.FindingID)
	if updated.Report != before {
		t.Fatal("failed image rendering replaced report")
	}
}

func TestReportScreenshotRejectsEscapeAndMissingFiles(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	stored, _ := s.m.pg.GetFinding(f.FindingID)
	base := filepath.Join(s.m.dir, "tasks", fmt.Sprint(*stored.TaskID))
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	_ = png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 32, 48)))
	if err := os.WriteFile(filepath.Join(base, "real.png"), b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"../outside.png", "missing.png"} {
		if _, err := s.readReportScreenshot(*stored.TaskID, p); err == nil {
			t.Fatalf("accepted invalid screenshot %s", p)
		}
	}
	got, err := s.readReportScreenshot(*stored.TaskID, "real.png")
	if err != nil || len(got) == 0 {
		t.Fatal("existing screenshot could not be imported", err)
	}
}

func TestReportImageToolSchema(t *testing.T) {
	s := &Server{}
	raw, _ := json.Marshal(s.toolUpdateFindingReport().InputSchema())
	for _, name := range []string{"with_images", "report_steps", "screenshot_path", "binding_id", "step_id"} {
		if !bytes.Contains(raw, []byte(name)) {
			t.Fatalf("missing schema %s", name)
		}
	}
}

func TestFindingReportZipCarriesPNGAttachments(t *testing.T) {
	var imageBytes bytes.Buffer
	if err := png.Encode(&imageBytes, image.NewRGBA(image.Rect(0, 0, 18, 12))); err != nil {
		t.Fatal(err)
	}
	markdown := "## 复现截图\n\n![步骤](data:image/png;base64," + base64.StdEncoding.EncodeToString(imageBytes.Bytes()) + ")\n"
	finding := &db.DBFinding{ID: 9917, Severity: "high", Name: "ZIP 图片验证", Report: markdown}
	var archive bytes.Buffer
	if err := writeFindingsEvidenceZip(&archive, []*db.DBFinding{finding}, t.TempDir(), time.Now()); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var exportedMarkdown string
	var exportedPNG []byte
	for _, file := range zr.File {
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(file.Name, ".md") {
			exportedMarkdown = string(data)
		}
		if strings.HasPrefix(file.Name, "evidence/9917/images/") && strings.HasSuffix(file.Name, ".png") {
			exportedPNG = data
		}
	}
	if strings.Contains(exportedMarkdown, "data:image") || !strings.Contains(exportedMarkdown, "evidence/9917/images/") || !bytes.Equal(exportedPNG, imageBytes.Bytes()) {
		t.Fatalf("offline report image attachment missing or incorrect: markdown=%q png=%d", exportedMarkdown, len(exportedPNG))
	}
}
