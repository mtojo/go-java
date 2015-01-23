package java

import (
	"archive/zip"
	"path/filepath"
)

const (
	javaClassExt = ".class"
)

func ReadJarFile(fname string, fn func(string, *ClassFile)) error {
	r, err := zip.OpenReader(fname)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if filepath.Ext(f.Name) != javaClassExt {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		c, err := ReadClassFile(rc)
		if err != nil {
			return err
		}
		fn(f.Name, c)
	}

	return nil
}
