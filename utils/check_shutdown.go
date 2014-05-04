package utils

import (
    "fmt"
    "syscall"
)

func CheckPendingShutdown()(result bool) {
    var (
            user32, _ = syscall.LoadLibrary("user32.dll")
            GetSystemMetrics, _ = syscall.GetProcAddress(user32, "GetSystemMetrics")
    )

    const (
        SM_SHUTTINGDOWN = 0x2000
    )

    var nargs uintptr = 1
    var index uintptr = SM_SHUTTINGDOWN

    ret, _, callErr := syscall.Syscall(uintptr(GetSystemMetrics), nargs, index, 0, 0)
    if callErr != 0 {
        panic(fmt.Sprintf("Call GetSystemMetrics failed with error: %v", callErr))
    } else {
        return ret != 0
    }
}
