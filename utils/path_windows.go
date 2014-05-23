/*
Go does not have Symlink support, hence, this module
*/
package utils

import (
    "fmt"
    "os"
    "syscall"
    "unsafe"
    "errors"
)

func fileOrFolder(target string) (dwFlag int, err error){
	f, err := os.Open(target)
    if err != nil {
        return
    }
    defer f.Close()
    fi, err := f.Stat()
    if err != nil {
        return
    }
    switch mode := fi.Mode(); {
    case mode.IsDir():
    	dwFlag = 1
    case mode.IsRegular():
    	dwFlag = 0
    }
    return dwFlag, err
}

func CreateSymLink(link, target string) error{
	dwFlag, err := fileOrFolder(target)
	if err != nil {
        return err
    }
	var (
        kernel32, _ = syscall.LoadLibrary("kernel32.dll")
        CreateSymbolicLinkW, _ = syscall.GetProcAddress(kernel32, "CreateSymbolicLinkW")
	)
	var nargs uintptr = 3
	_, _, callErr := syscall.Syscall(uintptr(CreateSymbolicLinkW), nargs, 
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(link))), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(target))), uintptr(dwFlag))
	if callErr != 0 {
            return errors.New(fmt.Sprintf("CreateSymbolicLinkW Error: %v", callErr))
        }
	defer syscall.FreeLibrary(kernel32)
    return nil
}

func Readlink(link string) (string, error){
    var (kernel32 = syscall.NewLazyDLL("kernel32.dll")
         GetFinalPathNameByHandleW = kernel32.NewProc("GetFinalPathNameByHandleW")

         nargs uint32 = 4
         buf_size int = 512
         buf [512]byte
         target string
         )

    handle, Err := syscall.Open(link, 0, 2)
    if Err != nil {
        return "", errors.New(fmt.Sprintf("CreateFileW Error: %v", Err))
    }

    _, _, callErr := syscall.Syscall6(GetFinalPathNameByHandleW.Addr(),
                                        uintptr(unsafe.Pointer(&nargs)),
                                        uintptr(unsafe.Pointer(handle)),
                                        uintptr(unsafe.Pointer(&buf)),
                                        uintptr(buf_size), 0, 0, 0)
    if callErr != 0 {
        return "", errors.New(fmt.Sprintf("GetFinalPathNameByHandleW Error: %v", callErr))
    }

    defer syscall.CloseHandle(handle)
    for i, _ := range buf {
        if buf[i] != 0{
            target += string(buf[i])
       }
    }
    if target[:4] == `\\?\` {
        target = target[4:]
    }
    return target, nil
}

func Symlink(oldname, newname string) error {
    return CreateSymLink(newname, oldname)
}
