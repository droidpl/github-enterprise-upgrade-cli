package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/schollz/progressbar/v3"
)

func appendOnFile(file, text string) {
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("%v", err)
	}

	defer f.Close()

	if _, err = f.WriteString(text); err != nil {
		log.Fatalf("%v", err)
	}
}

func splitHostPort(mHost string) (host, port string) {
	h, p, err := net.SplitHostPort(mHost)
	// No port is specified, default is 22
	if err != nil {
		h = mHost
		p = DefaultPort
	}
	return h, p
}

func concatCmds(cmds ...string) string {
	return strings.Join(cmds, " && ")
}

func exist(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func getAbsPathFromTilde(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}
	return os.Getenv("HOME") + path[1:]
}

func absPath(path string) string {
	if path == "" {
		return ""
	}
	path = getAbsPathFromTilde(path)
	path, _ = filepath.Abs(path)
	return path
}

func downloadPkgToHost(url, pkgName string) {
	fullPath := savePath + pkgName
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("An error happened while trying to prepare download request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("An error happened while trying to get HTTP client: %v", err)
	}
	defer resp.Body.Close()

	var out io.Writer
	f, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("Cannot open file %s: %v", fullPath, err)
	}
	defer f.Close()
	log.Printf("Downloading package %s", pkgName)
	bar := progressbar.NewOptions(
		int(resp.ContentLength),
		progressbar.OptionShowBytes(true),
		progressbar.OptionClearOnFinish(),
	)
	out = io.MultiWriter(f, bar)
	io.Copy(out, resp.Body)
}
