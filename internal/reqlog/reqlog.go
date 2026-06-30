// Package reqlog keeps an in-memory ring buffer of recent protocol requests for
// the admin "Logs" page, so a developer can see what their app sent to the IdP.
package reqlog

import (
	"net/http"
	"sync"
	"time"
)

// Entry is one recorded request.
type Entry struct {
	Time       time.Time
	Method     string
	Path       string
	ClientID   string
	Status     int
	DurationMS int64
}

// Log is a fixed-size ring buffer of entries, safe for concurrent use.
type Log struct {
	mu  sync.Mutex
	buf []Entry
	max int
}

// New creates a ring buffer holding at most max entries.
func New(max int) *Log {
	if max <= 0 {
		max = 200
	}
	return &Log{max: max}
}

func (l *Log) add(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, e)
	if len(l.buf) > l.max {
		l.buf = l.buf[len(l.buf)-l.max:]
	}
}

// Entries returns a copy of the recorded entries, newest first.
func (l *Log) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, len(l.buf))
	for i, e := range l.buf {
		out[len(l.buf)-1-i] = e
	}
	return out
}

// Middleware records each request's method, path, client and response status.
func (l *Log) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		l.add(Entry{
			Time:       start,
			Method:     r.Method,
			Path:       r.URL.Path,
			ClientID:   clientID(r),
			Status:     rec.status,
			DurationMS: time.Since(start).Milliseconds(),
		})
	})
}

// clientID extracts the client without consuming the request body (query or
// HTTP basic only), so it does not interfere with downstream form parsing.
func clientID(r *http.Request) string {
	if v := r.URL.Query().Get("client_id"); v != "" {
		return v
	}
	if id, _, ok := r.BasicAuth(); ok {
		return id
	}
	return ""
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}
