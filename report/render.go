package report

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

//go:embed render.cjs
var rendererScript string

// RenderEvidencePNGs captures only escaped local evidence cards. No target URL
// is visited. Node, Playwright and Chromium are included in the Docker image.
func RenderEvidencePNGs(ctx context.Context, pages []EvidencePage) ([][]byte, error) {
	if len(pages) == 0 {
		return nil, nil
	}
	if len(pages) > MaxEvidencePages {
		return nil, fmt.Errorf("证据图片超过 %d 页，未截断保存", MaxEvidencePages)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	in, err := json.Marshal(pages)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "node", "-e", rendererScript)
	cmd.Stdin = bytes.NewReader(in)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("生成报告截图失败：%w（需要 Node、Playwright 与 Chromium；Docker 版已内置）。%s", err, stderr.String())
	}
	var encoded []string
	if err = json.Unmarshal(out, &encoded); err != nil {
		return nil, fmt.Errorf("截图工具返回无效数据：%w", err)
	}
	if len(encoded) != len(pages) {
		return nil, fmt.Errorf("截图页数不完整：预期 %d，实际 %d", len(pages), len(encoded))
	}
	images := make([][]byte, len(encoded))
	for i, s := range encoded {
		images[i], err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
	}
	return images, nil
}
