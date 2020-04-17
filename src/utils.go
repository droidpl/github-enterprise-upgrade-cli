package main

import (
	"log"
	"net"
	"os"
	"strings"
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

func getHostPort(mHost string) (host, port string) {
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
