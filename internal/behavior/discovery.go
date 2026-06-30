package behavior

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/scottbass3/oidc-test-idp/internal/storage"
)

// discoveryOverrideSetting is the settings key holding the JSON object merged
// into the generated discovery document (kept in sync with admin.DiscoveryOverrideKey).
const discoveryOverrideSetting = "discovery_override"

const discoveryPath = "/.well-known/openid-configuration"

// DiscoveryOverride wraps the discovery endpoint and shallow-merges the operator's
// stored JSON overrides into the generated document, so a developer can make the
// IdP advertise the same discovery fields as a target real IdP.
func DiscoveryOverride(store *storage.Storage) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != discoveryPath {
				next.ServeHTTP(w, r)
				return
			}
			raw := store.DB().GetSetting(discoveryOverrideSetting, "")
			if raw == "" || raw == "{}" {
				next.ServeHTTP(w, r)
				return
			}
			var override map[string]any
			if err := json.Unmarshal([]byte(raw), &override); err != nil || len(override) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Capture the downstream discovery response.
			rec := &bufferWriter{header: http.Header{}, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			var doc map[string]any
			if err := json.Unmarshal(rec.body.Bytes(), &doc); err != nil {
				// Not JSON (error path) — replay verbatim.
				copyHeader(w.Header(), rec.header)
				w.WriteHeader(rec.status)
				_, _ = w.Write(rec.body.Bytes())
				return
			}
			for k, v := range override {
				doc[k] = v
			}
			out, _ := json.Marshal(doc)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(rec.status)
			_, _ = w.Write(out)
		})
	}
}

// bufferWriter buffers a handler's response for post-processing.
type bufferWriter struct {
	header      http.Header
	body        bytes.Buffer
	status      int
	wroteHeader bool
}

func (b *bufferWriter) Header() http.Header { return b.header }
func (b *bufferWriter) WriteHeader(status int) {
	if !b.wroteHeader {
		b.status = status
		b.wroteHeader = true
	}
}
func (b *bufferWriter) Write(p []byte) (int, error) {
	b.wroteHeader = true
	return b.body.Write(p)
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
