package reqlog

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRingBufferRecordsNewestFirst(t *testing.T) {
	l := New(2)
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	for _, p := range []string{"/a", "/b", "/c"} {
		req := httptest.NewRequest("GET", "http://x"+p+"?client_id=cli", nil)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	entries := l.Entries()
	if len(entries) != 2 { // max=2, oldest dropped
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Path != "/c" || entries[1].Path != "/b" {
		t.Fatalf("expected newest-first [/c /b], got [%s %s]", entries[0].Path, entries[1].Path)
	}
	if entries[0].Status != http.StatusTeapot {
		t.Fatalf("expected captured status 418, got %d", entries[0].Status)
	}
	if entries[0].ClientID != "cli" {
		t.Fatalf("expected client_id cli, got %q", entries[0].ClientID)
	}
}
