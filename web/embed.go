// Package web embeds the HTML templates and static assets served by the IdP.
package web

import "embed"

// Templates holds the HTML templates for the login, consent, device and admin UIs.
//
//go:embed templates/*.html
var Templates embed.FS

// Static holds CSS/JS assets served under /static.
//
//go:embed static/*
var Static embed.FS
