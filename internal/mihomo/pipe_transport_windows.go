//go:build windows

package mihomo

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/Microsoft/go-winio"
)

func newPipeHTTPClient(pipeName string, timeout time.Duration) (*http.Client, dialContextFunc, error) {
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return winio.DialPipeContext(ctx, pipeName)
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: dial,
		},
	}, dial, nil
}
