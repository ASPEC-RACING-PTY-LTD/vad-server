// Package inspect checks uploaded content. Every upload is treated as
// unknown, whoever sent it (administrators included): programs, scripts and
// other content that can run are flagged, content disguised as something
// harmless (a program named .mp4) and anything an antivirus engine (ClamAV,
// when configured) reports is quarantined.
package inspect

import (
	"bytes"
	"io"
	"path"
	"strings"
)

// Verdicts.
const (
	Clean       = "clean"
	Flagged     = "flagged"     // can run on a computer; kept, always downloaded as a file
	Quarantined = "quarantined" // disguised or detected; not served, shared or processed
)

// Result is an inspection outcome.
type Result struct {
	Verdict string `json:"verdict"`
	Kind    string `json:"kind,omitempty"`   // program, script, shortcut, package, ..., disguised, malware
	Detail  string `json:"detail,omitempty"` // human-readable reason
	Engine  string `json:"engine,omitempty"` // "vaultdock", or the antivirus engine that answered
}

// HeadSize is how much of a file Static needs.
const HeadSize = 4096

// riskyExt are file types Windows, macOS or Linux can run, install, mount
// or open with macros.
var riskyExt = map[string]string{
	"exe": "program", "dll": "program", "scr": "program", "com": "program", "cpl": "program", "sys": "program",
	"msi": "installer", "msp": "installer", "msix": "installer", "appx": "installer", "appxbundle": "installer",
	"bat": "script", "cmd": "script", "ps1": "script", "psm1": "script", "vbs": "script", "vbe": "script",
	"js": "script", "jse": "script", "wsf": "script", "wsh": "script", "hta": "script", "sh": "script", "reg": "script",
	"lnk": "shortcut", "url": "shortcut", "scf": "shortcut",
	"jar": "package", "apk": "package", "xpi": "package", "crx": "package",
	"docm": "macro document", "xlsm": "macro document", "pptm": "macro document", "dotm": "macro document", "xltm": "macro document",
	"iso": "disk image", "img": "disk image", "vhd": "disk image", "vhdx": "disk image",
}

// harmlessExt are types people expect to open safely (media, pictures,
// documents, text): runnable content behind one of them is disguised.
var harmlessExt = map[string]bool{
	"mp4": true, "mov": true, "mkv": true, "webm": true, "avi": true, "m4v": true, "wmv": true, "flv": true, "ts": true,
	"mp3": true, "wav": true, "flac": true, "m4a": true, "aac": true, "ogg": true, "opus": true,
	"jpg": true, "jpeg": true, "png": true, "gif": true, "webp": true, "heic": true, "bmp": true, "tif": true, "tiff": true,
	"pdf": true, "txt": true, "csv": true, "md": true, "json": true, "docx": true, "xlsx": true, "pptx": true, "doc": true, "xls": true,
}

// contentKind recognises runnable content from its first bytes.
func contentKind(head []byte) (kind, detail string) {
	switch {
	case bytes.HasPrefix(head, []byte("MZ")) && len(head) >= 64:
		return "program", "Windows program"
	case bytes.HasPrefix(head, []byte("\x7fELF")):
		return "program", "Linux program"
	case bytes.HasPrefix(head, []byte{0xfe, 0xed, 0xfa, 0xce}), bytes.HasPrefix(head, []byte{0xfe, 0xed, 0xfa, 0xcf}),
		bytes.HasPrefix(head, []byte{0xce, 0xfa, 0xed, 0xfe}), bytes.HasPrefix(head, []byte{0xcf, 0xfa, 0xed, 0xfe}):
		return "program", "macOS program"
	case bytes.HasPrefix(head, []byte("#!")):
		return "script", "script"
	case bytes.HasPrefix(head, []byte{0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00}):
		return "shortcut", "Windows shortcut"
	}
	return "", ""
}

// Static inspects a file from its name and first HeadSize bytes.
func Static(name string, head []byte) Result {
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(name), "."))
	kind, detail := contentKind(head)
	switch {
	case kind != "" && harmlessExt[ext]:
		return Result{Verdict: Quarantined, Kind: "disguised", Detail: detail + " named as a ." + ext + " file", Engine: "vaultdock"}
	case kind != "":
		return Result{Verdict: Flagged, Kind: kind, Detail: detail, Engine: "vaultdock"}
	case riskyExt[ext] != "":
		return Result{Verdict: Flagged, Kind: riskyExt[ext], Detail: "." + ext + " file (" + riskyExt[ext] + ")", Engine: "vaultdock"}
	}
	return Result{Verdict: Clean, Engine: "vaultdock"}
}

// ReadHead reads up to HeadSize bytes.
func ReadHead(r io.Reader) []byte {
	head := make([]byte, HeadSize)
	n, _ := io.ReadFull(r, head)
	return head[:n]
}
