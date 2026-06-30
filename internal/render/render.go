// Package render loads the embedded HTML templates and renders them by name.
package render

import (
	"html/template"
	"net/http"

	"github.com/scottbass3/oidc-test-idp/web"
)

// Renderer holds the parsed template set.
type Renderer struct {
	tpl *template.Template
}

// New parses every embedded template file.
func New() (*Renderer, error) {
	tpl, err := template.New("").ParseFS(web.Templates, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Renderer{tpl: tpl}, nil
}

// HTML renders the named template with data. Errors yield a 500.
func (r *Renderer) HTML(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := r.tpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
