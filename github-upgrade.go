package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/go-version"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

// YamlConfig is exported.
type YamlConfig struct {
	Primary struct {
		Host      string `yaml:"host"`
		IsReplica bool   `yaml:"replication_enabled"`
	} `yaml:"primary"`
	Replicas []struct {
		Host       string `yaml:"host"`
		IsActive   bool   `yaml:"active"`
		Datacenter string `yaml:"datacenter"`
	} `yaml:"replicas"`
}

// Constants
const (
	Port = "22"
	User = "admin"
	// ghr commands
	GTHVersion = "ghe-version"
)

func main() {
	// Commands
	configPath := flag.String("config", "config.yml", "Configuration file")
	userversion := flag.String("v", "", "GHE version")

	flag.Parse()

	targetVersion, err := version.NewVersion(*userversion)

	// Parse config file
	f, err := os.Open(*configPath)
	if err != nil {
		fmt.Printf("Unable to Open Config file %v", err)
	}
	defer f.Close()
	var cfg YamlConfig
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		fmt.Printf("Something happened while reading the config file: %v", err)
	}
	// Connect to remote host
	mHost := cfg.Primary.Host
	host, port := getHostPort(mHost)
	client, err := connectToHost(User, host, port)
	if err != nil {
		log.Fatalf("An error happened while trying to connect to host: %v", err)
	}
	defer closeConnection(client)
	// Run commands
	currentVersion, err := version.NewVersion(getVersion(client))
	if currentVersion.GreaterThanOrEqual(targetVersion) {
		fmt.Printf("Target Version %s is less than Current installed version %s", targetVersion, currentVersion)
	} else {
		currentVersionSegment := currentVersion.Segments()
		targetVersionSegment := targetVersion.Segments()

		if (targetVersionSegment[0] > currentVersionSegment[0]) || (targetVersionSegment[1] > currentVersionSegment[1]) {
			fmt.Print("This is a major update")
		} else {
			performHotPath(client, targetVersionSegment)
		}

	}

}

func connectToHost(user, host, port string) (*ssh.Client, error) {
	// A public key may be used to authenticate against the remote
	// server by using an un-encrypted PEM-encoded private key file.
	//
	// If you have an encrypted private key, the crypto/x509 package
	// can be used to decrypt it.
	key, err := ioutil.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"))
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %v", err)
	}

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %v", err)
	}

	fmt.Printf("Connecting to host %s, port %s", host, port)
	hostKey, err := getHostKey(host)
	if err != nil {
		return nil, err
	}

	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			// Use the PublicKeys method for remote authentication.
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(host, port), sshConfig)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func getHostKey(host string) (ssh.PublicKey, error) {
	file, err := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var hostKey ssh.PublicKey
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue
		}
		if strings.Contains(fields[0], host) {
			var err error
			hostKey, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				return nil, fmt.Errorf("error parsing %q: %v", fields[2], err)
			}
			break
		}
	}

	if hostKey == nil {
		return nil, fmt.Errorf("no hostkey for %s", host)
	}
	return hostKey, nil
}
func executeCmd(client *ssh.Client, cmd string) error {
	// Create session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("Failed to open SSH Session: %v", err)
	}
	defer session.Close()
	// Once a Session is created, you can execute a single command on
	// the remote side using the Run method.
	// var b bytes.Buffer
	// session.Stdout = &b
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("Unable to setup stdin for session: %v", err)
	}
	go io.Copy(stdin, os.Stdin)

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("Unable to setup stdout for session: %v", err)
	}
	go io.Copy(os.Stdout, stdout)

	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("Unable to setup stderr for session: %v", err)
	}
	go io.Copy(os.Stderr, stderr)

	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("Failed to run: %v", err)
	}
	return nil
}

func closeConnection(client *ssh.Client) {
	client.Close()
}

func getHostPort(mHost string) (host, port string) {
	h, p, err := net.SplitHostPort(mHost)
	// No port is specified
	if err != nil {
		h = mHost
		p = Port
	}
	return h, p
}

func getVersion(client *ssh.Client) string {
	const (
		GTHVersion  = "ghe-version"
		semverRegex = "([0-9]+)(\\.[0-9]+)?(\\.[0-9]+)"
	)

	// Create session
	session, err := client.NewSession()
	if err != nil {
		fmt.Printf("Failed to open SSH Session: %v", err)
	}
	var b bytes.Buffer
	session.Stdout = &b

	if err := session.Run(GTHVersion); err != nil {
		fmt.Printf("Failed to run: %v", err)
	}
	re := regexp.MustCompile(semverRegex)
	return re.FindString(b.String())

}

func downloadPatchURL(version []int) string {
	githubPatchURL := "https://github-enterprise.s3.amazonaws.com/hotpatch/"
	githubPatchURL += strconv.Itoa(version[0]) + "." + strconv.Itoa(version[1])
	githubPatchURL += "/github-enterprise-" + strconv.Itoa(version[0]) + "." + strconv.Itoa(version[1]) + "." + strconv.Itoa(version[2])
	githubPatchURL += ".hpkg"

	return githubPatchURL
}

func performHotPath(client *ssh.Client, version []int) {
	pkgName := "github-enterprise-" + strconv.Itoa(version[0]) + "." + strconv.Itoa(version[1]) + "." + strconv.Itoa(version[2]) + ".hpkg"
	downloadPkgCmd := "cd /tmp && curl -L -O " + downloadPatchURL(version)
	updateCmd := "cd /tmp && ghe-upgrade -y " + pkgName

	fmt.Print("downloading  " + downloadPatchURL(version))
	fmt.Print("downloading package " + pkgName)
	executeCmd(client, downloadPkgCmd)
	fmt.Print("Install the package" + pkgName)
	executeCmd(client, updateCmd)
}

func performUpgrade(client *ssh.Client, version []int) {
	pkgName := "github-enterprise-" + strconv.Itoa(version[0]) + "." + strconv.Itoa(version[1]) + "." + strconv.Itoa(version[2]) + ".hpkg"
	downloadPkgCmd := "cd /tmp && curl -L -O " + downloadPatchURL(version)
	maintenanceCmd := "ghe-maintenance -s"
	stopReplicationCmd := "ghe-repl-stop"
	removeMaintenanceCmd := "ghe-maintenance -u"
	updateCmd := "cd /tmp && ghe-upgrade -y " + pkgName

	fmt.Print("downloading package " + pkgName)
	executeCmd(client, downloadPkgCmd)
	fmt.Print("Set maintenance mode")
	executeCmd(client, maintenanceCmd)
	fmt.Print("Stop the replication")
	executeCmd(client, stopReplicationCmd)
	fmt.Print("Install the package" + pkgName)
	executeCmd(client, updateCmd)
	fmt.Print("Remove the maintenance mode")
	executeCmd(client, removeMaintenanceCmd)
}
