package version

import (
    "io/ioutil"
    "strings"
    // "runtime"
)


func readSeries(releaseFile string) string {
    data, err := ioutil.ReadFile(releaseFile)
    if err != nil {
        return "unknown"
    }
    for _, line := range strings.Split(string(data), "\n") {
        const prefix = "DISTRIB_CODENAME="
        if strings.HasPrefix(line, prefix) {
            return strings.Trim(line[len(prefix):], "\t '\"")
        }
    }
    return "unknown"
}

// ReleaseVersion looks for the value of DISTRIB_RELEASE in the content of
// the lsbReleaseFile.  If the value is not found, the file is not found, or
// an error occurs reading the file, an empty string is returned.
func ReleaseVersion() string {
    content, err := ioutil.ReadFile(lsbReleaseFile)
    if err != nil {
        return ""
    }
    const prefix = "DISTRIB_RELEASE="
    for _, line := range strings.Split(string(content), "\n") {
        if strings.HasPrefix(line, prefix) {
            return strings.Trim(line[len(prefix):], "\t '\"")
        }
    }
    return ""
}