package windows

import (
	// "bufio"
	"fmt"
	// "io"
	// "os"
	// "strings"
	"sync"

	"github.com/juju/loggo"
)

var logger = loggo.GetLogger("juju.ubuntu")

var (
	seriesVersionsMutex   sync.Mutex
	// updatedseriesVersions bool
)

// seriesVersions provides a mapping between Ubuntu series names and version numbers.
// The values here are current as of the time of writing. On Ubuntu systems, we update
// these values from /usr/share/distro-info/ubuntu.csv to ensure we have the latest values.
// On non-Ubuntu systems, these values provide a nice fallback option.
// Exported so tests can change the values to ensure the distro-info lookup works.
var seriesVersions = map[string]string{
	"win2012hv": "win2012hv",
	"win2012hvr2": "win2012hvr2",
	"win2012": "win2012",
	"win2012r2": "win2012r2",
}

// SeriesVersion returns the version number for the specified Ubuntu series.
func SeriesVersion(series string) (string, error) {
	if series == "" {
		panic("cannot pass empty series to SeriesVersion()")
	}
	seriesVersionsMutex.Lock()
	defer seriesVersionsMutex.Unlock()
	if vers, ok := seriesVersions[series]; ok {
		return vers, nil
	}
	return "", fmt.Errorf("invalid series %q", series)
}

// SupportedSeries returns the Ubuntu series on which we can run Juju workloads.
func SupportedSeries() []string {
	seriesVersionsMutex.Lock()
	defer seriesVersionsMutex.Unlock()
	var series []string
	for s := range seriesVersions {
		series = append(series, s)
	}
	return series
}