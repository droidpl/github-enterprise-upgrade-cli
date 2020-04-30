package main

import (
	"io"
	"log"
	"os"

	"github.com/pkg/sftp"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/crypto/ssh"
)

const (
	savePath = "/tmp/"
)

func copyFile(client *ssh.Client, pkgName string) {
	// create new SFTP client
	fullPath := savePath + pkgName
	sftp, err := sftp.NewClient(client)
	if err != nil {
		log.Fatal("Cannot create SFTP client")
	}
	defer sftp.Close()
	// create destination file
	dstFile, err := sftp.Create(fullPath)
	if err != nil {
		log.Fatalf("Cannot creates the named file %s in server", fullPath)
	}
	defer dstFile.Close()

	// create source file
	srcFile, err := os.Open(fullPath)
	if err != nil {
		log.Fatalf("Cannot read the named file %s in host: %v", fullPath, err)
	}
	// get file size
	srcFStat, err := srcFile.Stat()
	if err != nil {
		log.Fatalf("Cannot read FileInfo describing file %s: %v", fullPath, err)
	}
	progress := progressbar.NewOptions(
		int(srcFStat.Size()),
		progressbar.OptionShowBytes(true),
		progressbar.OptionClearOnFinish(),
	)
	// copy source file to destination file
	_, err = io.Copy(io.MultiWriter(dstFile, progress), srcFile)
	if err != nil {
		log.Fatalf("Cannot copy file %s to remote server: %v", fullPath, err)
	}

}

func isExist(client *ssh.Client, filename string) bool {
	// create new SFTP client
	fullPath := savePath + filename
	sftp, err := sftp.NewClient(client)
	if err != nil {
		log.Fatal("Cannot create SFTP client")
	}
	defer sftp.Close()
	// create source file
	srcFile, err := os.Open(fullPath)
	if err != nil {
		return false
	}
	if _, err := srcFile.Stat(); err == nil {
		return true
	}

	return false
}
