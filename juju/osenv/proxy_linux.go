package osenv

import (
    "os"
    "strings"
)

func getProxySetting(key string) string {
    value := os.Getenv(key)
    if value == "" {
        value = os.Getenv(strings.ToUpper(key))
    }
    return value
}

// SetEnvironmentValues updates the process environment with the
// proxy values stored in the settings object.  Both the lower-case
// and upper-case variants are set.
//
// http_proxy, HTTP_PROXY
// https_proxy, HTTPS_PROXY
// ftp_proxy, FTP_PROXY
func (s *ProxySettings) SetEnvironmentValues() {
    setenv := func(proxy, value string) {
        os.Setenv(proxy, value)
        os.Setenv(strings.ToUpper(proxy), value)
    }
    setenv(http_proxy, s.Http)
    setenv(https_proxy, s.Https)
    setenv(ftp_proxy, s.Ftp)
    setenv(no_proxy, s.NoProxy)
}