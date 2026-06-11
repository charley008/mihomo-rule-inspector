package web

import "embed"

//go:embed index.html app.js style.css favicon.ico
var Files embed.FS
