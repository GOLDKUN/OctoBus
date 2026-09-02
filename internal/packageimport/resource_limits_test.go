package packageimport

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCopyWithByteLimitRejectsOversizedContent(t *testing.T) {
	var dst bytes.Buffer
	err := copyWithByteLimit(&dst, strings.NewReader("oversized"), 4)
	if err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("copy limit error = %v", err)
	}
}

func TestTarExtractionEnforcesExpandedSizeLimit(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "package.tgz")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gz)
	body := []byte("0123456789")
	if err := tarWriter.WriteHeader(&tar.Header{Name: "package/data", Mode: 0o600, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	err = untarGzWithLimits(archivePath, t.TempDir(), archiveExtractionLimits{
		MaxFiles:      10,
		MaxEntryBytes: 5,
		MaxTotalBytes: 5,
	})
	if err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("tar limit error = %v", err)
	}
}

func TestZipExtractionEnforcesFileCountLimit(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "package.zip")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	zipWriter := zip.NewWriter(file)
	for _, name := range []string{"package/a", "package/b"} {
		entry, err := zipWriter.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(bytes.Repeat([]byte{'x'}, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	err = unzipWithLimits(archivePath, t.TempDir(), archiveExtractionLimits{
		MaxFiles:      1,
		MaxEntryBytes: 10,
		MaxTotalBytes: 10,
	})
	if err == nil || !strings.Contains(err.Error(), "file limit") {
		t.Fatalf("zip limit error = %v", err)
	}
}
