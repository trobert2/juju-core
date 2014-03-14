package utils

import (
    "fmt"
    "os"
    "syscall"
    "unsafe"
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

func CreateSymLink(link, target string){
	dwFlag, err := fileOrFolder(target)
	if err != nil {
        fmt.Println(err)
        return
    }
	var (
        kernel32, _ = syscall.LoadLibrary("kernel32.dll")
        CreateSymbolicLinkW, _ = syscall.GetProcAddress(kernel32, "CreateSymbolicLinkW")
	)
	var nargs uintptr = 3
	_, _, callErr := syscall.Syscall(uintptr(CreateSymbolicLinkW), nargs, 
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(link))), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(target))), uintptr(dwFlag))
	if callErr != 0 {
            fmt.Println("CreateSymbolicLinkW Error:", callErr)
        }
	defer syscall.FreeLibrary(kernel32)
}
