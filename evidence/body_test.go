package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

func TestWriteBodyPersistsVerifiedContent(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	body := []byte("reproduction evidence\x00\r\n")
	digest := sha256.Sum256(body)
	expected := hex.EncodeToString(digest[:])
	for i := 0; i < 2; i++ {
		hash, err := s.writeBody(bytes.NewReader(body), int64(len(body)), expected)
		if err != nil {
			t.Fatal(err)
		}
		if hash != expected {
			t.Fatalf("unexpected hash: %s", hash)
		}
		path, err := hashPath(s.Dir, hash)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("persisted body mismatch: %q, %v", got, err)
		}
	}
}
