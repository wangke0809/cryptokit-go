package kit

import (
	"bytes"
	"container/list"
	"io"
	"os"
	"path/filepath"
)

func SaveFile(path string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, bytes.NewReader(data))
	if err != nil {
		return err
	}
	return nil
}

func ValidateFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}
	return true
}

func ScanFile(path string) (*list.List, error) {
	files := list.New()
	err := filepath.Walk(path, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return err
		}
		if f.IsDir() {
			return nil
		}
		files.PushBack(path)
		return nil
	})
	return files, err
}
