package warp

import (
	"fmt"
	"net/http"
)

// ProxyHandler creates an HTTP handler that forwards requests through WARP exits.
func ProxyHandler(pool *Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		exit, err := pool.Acquire(ctx)
		if err != nil {
			http.Error(w, fmt.Sprintf("WARP unavailable: %v", err), http.StatusServiceUnavailable)
			return
		}
		defer pool.Release(exit)

		http.Error(w, "WARP proxy not implemented", http.StatusNotImplemented)
	}
}
