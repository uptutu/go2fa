package web

import (
	"embed"
	"io/fs"
)

//go:embed static/*
var staticFSRaw embed.FS

// staticFS exposes the embedded "static" directory as an fs.FS suitable for
// http.FileServer. The /api/* routes take precedence over /, so index.html
// is served only on exact "/" or non-API subpaths.
var staticFS fs.FS

func init() {
	sub, err := fs.Sub(staticFSRaw, "static")
	if err != nil {
		panic(err)
	}
	staticFS = sub
}
