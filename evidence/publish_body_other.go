//go:build !windows

package evidence

import (
	"os"
	"path/filepath"
)

func publishBody(stage, dest string) error {
	if err := os.Rename(stage, dest); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(dest))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
