package evidence

import "golang.org/x/sys/windows"

// Windows cannot fsync an opened directory. The staged file has already been
// flushed; request a write-through move before publishing its database reference.
func publishBody(stage, dest string) error {
	from, err := windows.UTF16PtrFromString(stage)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(dest)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
