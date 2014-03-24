package utils

import (
    "os"
    "path/filepath"
)

func RChmod(path string, mode os.FileMode) error {
    walker := func(p string, fi os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        errPerm := os.Chmod(p, mode)
        if errPerm != nil {
            return errPerm
        }
        return nil
    }
    if err := filepath.Walk(path, walker); err != nil {
        return err
    }
    return nil
}