// Package ui holds the Vault OS templ views; handlers live in gateway.
package ui

import (
	"embed"
	"fmt"
	"net/url"
	"path"
	"strings"
)

//go:embed htmx.min.js wallpaper-light.svg wallpaper-dark.svg logo.svg
var Static embed.FS

type Node struct {
	ID    string
	Alive bool
}

type Raft struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Leader string `json:"leader"`
	Term   uint64 `json:"term"`
	Index  uint64 `json:"index"`
	Up     bool   `json:"up"`
}

// Cluster is what the menu-bar pulse needs.
type Cluster struct {
	Err, Healing string
	Nodes        []Node
	Lost         int64
}

// Health is the one-line summary shown in the top bar and Stats.
func (c Cluster) Health() (label, class string) {
	switch {
	case c.Err != "":
		return "metadata unavailable", "bad"
	case c.Lost > 0:
		return fmt.Sprintf("%d chunks lost", c.Lost), "bad"
	case c.Healing != "":
		return "repairing · " + c.Healing, "warn"
	}
	return "fully redundant", "ok"
}

func (c Cluster) AliveNodes() string {
	alive := 0
	for _, n := range c.Nodes {
		if n.Alive {
			alive++
		}
	}
	return fmt.Sprintf("%d/%d nodes", alive, len(c.Nodes))
}

type Bucket struct {
	Name, Policy, Created string
}

// Files is one directory listing: the bucket list when Bucket is empty.
type Files struct {
	Bucket, Prefix, Policy, Err string
	Buckets                     []Bucket
	Folders                     []string // full prefixes, e.g. "docs/"
	Objects                     []Object
}

func (f Files) URL() string { return FilesURL(f.Bucket, f.Prefix) }

func FilesURL(bucket, prefix string) string {
	if bucket == "" {
		return "/app/files"
	}
	return "/app/files?bucket=" + url.QueryEscape(bucket) + "&prefix=" + url.QueryEscape(prefix)
}

// Crumb is one step of the Files breadcrumb.
type Crumb struct{ Name, URL string }

func (f Files) Crumbs() []Crumb {
	out := []Crumb{{"buckets", FilesURL("", "")}}
	if f.Bucket == "" {
		return out
	}
	out = append(out, Crumb{f.Bucket, FilesURL(f.Bucket, "")})
	acc := ""
	for _, part := range strings.Split(strings.TrimSuffix(f.Prefix, "/"), "/") {
		if part == "" {
			continue
		}
		acc += part + "/"
		out = append(out, Crumb{part, FilesURL(f.Bucket, acc)})
	}
	return out
}

func FolderName(prefix string) string { return path.Base(strings.TrimSuffix(prefix, "/")) }

type Object struct {
	Bucket, Key, Name, Size, Modified, Type string
}

func (o Object) URL() string { return ObjectURL(o.Bucket, o.Key) }
func (o Object) ViewURL() string {
	return "/app/view?bucket=" + url.QueryEscape(o.Bucket) + "&key=" + url.QueryEscape(o.Key)
}
func (o Object) Kind() string { return Kind(o.Type) }

// Ext is the short badge shown on a file tile.
func (o Object) Ext() string {
	e := strings.TrimPrefix(path.Ext(o.Name), ".")
	if e == "" || len(e) > 4 {
		return "file"
	}
	return strings.ToLower(e)
}

func ObjectURL(bucket, key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return "/obj/" + url.PathEscape(bucket) + "/" + strings.Join(parts, "/")
}

// Kind picks how the viewer previews a content type.
func Kind(contentType string) string {
	ct, _, _ := strings.Cut(contentType, ";")
	switch {
	case strings.HasPrefix(ct, "image/"):
		return "image"
	case strings.HasPrefix(ct, "video/"):
		return "video"
	case strings.HasPrefix(ct, "audio/"):
		return "audio"
	case strings.HasPrefix(ct, "text/"), ct == "application/json", ct == "application/pdf", ct == "application/xml":
		return "doc"
	}
	return ""
}

// Viewer is one opened object: preview plus where its bytes live.
type Viewer struct {
	Object
	ETag   string
	Chunks []ChunkInfo
}

type ChunkInfo struct {
	N       int
	SHA     string
	Size    string
	Holders []Holder
}

type Holder struct {
	ID    string
	Alive bool
}

func Bytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func urlq(s string) string { return url.QueryEscape(s) }
