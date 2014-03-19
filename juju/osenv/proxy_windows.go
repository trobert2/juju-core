package osenv

import (
        "fmt"
        "syscall"
        "unsafe"
		)

const(
	//registry keys to modify for 32 bit and 64 bit
	key = `Software\Microsoft\Windows\CurrentVersion\Internet Settings\`
	key_WOW6432Node = `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings`

	REG_NONE      uint64 = 0 // No value type
	REG_SZ               = 1 // Unicode nul terminated string
	REG_EXPAND_SZ        = 2 // Unicode nul terminated string
	// (with environment variable references)
	REG_BINARY                     = 3 // Free form binary
	REG_DWORD                      = 4 // 32-bit number
	REG_DWORD_LITTLE_ENDIAN        = 4 // 32-bit number (same as REG_DWORD)
	REG_DWORD_BIG_ENDIAN           = 5 // 32-bit number
	REG_LINK                       = 6 // Symbolic Link (unicode)
	REG_MULTI_SZ                   = 7 // Multiple Unicode strings
	REG_RESOURCE_LIST              = 8 // Resource list in the resource map
	REG_FULL_RESOURCE_DESCRIPTOR   = 9 // Resource list in the hardware description
	REG_RESOURCE_REQUIREMENTS_LIST = 10
	REG_QWORD                      = 11 // 64-bit number
	REG_QWORD_LITTLE_ENDIAN        = 11 // 64-bit number (same as REG_QWORD)
)

func getValueFromKey(key, value_name string) (value_data string, err error) {
	var h syscall.Handle
	err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, syscall.StringToUTF16Ptr(key), 0, syscall.KEY_READ, &h)
	if err != nil {
		return
	}
	defer syscall.RegCloseKey(h)
	var count uint32
	var buf [124]uint16
	n := uint32(len(buf))
	err = syscall.RegQueryValueEx(h, syscall.StringToUTF16Ptr(value_name), nil, &count, (*byte)(unsafe.Pointer(&buf[0])), &n)
	if err != nil {
		return
	}
	value_data = syscall.UTF16ToString(buf[:])
	return
}

func writeToKey(key, value_name string, size, value_data, value_data_type uintptr) (err error) {
		var (
        advapi32, _ = syscall.LoadLibrary("advapi32.dll")
        RegSetValueEx, _ = syscall.GetProcAddress(advapi32, "RegSetValueExW")
	)
	var h syscall.Handle
	err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, syscall.StringToUTF16Ptr(key), 0, syscall.KEY_ALL_ACCESS, &h)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer syscall.RegCloseKey(h)
	ret, _, Callerr := syscall.Syscall6(RegSetValueEx, 6,
		uintptr(h),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(value_name))),
		0,
		value_data_type,
		value_data,
		size)
	fmt.Println(ret, Callerr)

	defer syscall.FreeLibrary(advapi32)
	return
}

func EnableProxyServer(key, ProxyServer string) (){
	var (enabled 	uint32 = 1
		 disabled	uint32 = 0)
	ProxyOverride := "<local>"
	writeToKey(key, "ProxyServer", uintptr(len(ProxyServer)*2), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(ProxyServer))),  REG_SZ)
	writeToKey(key, "ProxyHttp1.1", 4, uintptr(unsafe.Pointer(&disabled)),  REG_DWORD)
	writeToKey(key, "ProxyEnable", 4, uintptr(unsafe.Pointer(&enabled)),  REG_DWORD)
	writeToKey(key, "MigrateProxy", 4, uintptr(unsafe.Pointer(&enabled)),  REG_DWORD)
	writeToKey(key, "ProxyOverride", uintptr(len(ProxyOverride)*2), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(ProxyOverride))), REG_SZ)
}


// SetEnvironmentValues updates the registry keys with the
// proxy values stored in the settings object.  Both the lower-case
// and upper-case variants are set.
//
// http_proxy, HTTP_PROXY
// https_proxy, HTTPS_PROXY
// ftp_proxy, FTP_PROXY
func (s *ProxySettings) SetEnvironmentValues() {
	// this replaces the setenv part
	EnableProxyServer(key, s.Http)
}

// getProxySetting returns the current value of the proxy url, if it exists,
// otherwise, the value returned is "" (aka empty string)
// warning: get proxy setting (old juju version uses a string parameter, the 
// key name, we don't need that)

func getProxySetting() string {
	value, err := getProxySetting(key, "ProxyServer");
	if err != nil {
		if value == "" {
			return ""
		}
		else {
			return value
		}
	}
	return value
}