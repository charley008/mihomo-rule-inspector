//go:build !windows

package mihomo

import (
	"fmt"
	"net/http"
	"time"
)

func newPipeHTTPClient(pipeName string, timeout time.Duration) (*http.Client, dialContextFunc, error) {
	return nil, nil, fmt.Errorf("windows pipe controller %s is not supported on this platform", pipeName)
}
