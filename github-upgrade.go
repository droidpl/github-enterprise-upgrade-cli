package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"

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
		User      string `yaml:"user"`
		IsReplica bool   `yaml:"replication_enabled"`
		Client    *ssh.Client
	} `yaml:"primary"`
	Replicas []struct {
		Host       string `yaml:"host"`
		User       string `yaml:"user"`
		IsActive   bool   `yaml:"active"`
		Datacenter string `yaml:"datacenter"`
		Client     *ssh.Client
	} `yaml:"replicas"`
}

// Constants
const (
	Port       = "22"
	User       = "root"
	GTHVersion = "ghe-version"
)

var sshConfigPath *string

func main() {
	// read the options
	configPath := flag.String("config", "config.yml", "Configuration file")
	userversion := flag.String("v", "", "GHE version")
	platform := flag.String("p", "esx", "Platform your Github Entreprise is running on")
	sshConfigPath = flag.String("ssh-config", filepath.Join(os.Getenv("HOME"), ".ssh"), "SSH keys folder path")
	dryRun := flag.Bool("dry-run", false, "If true, only print how teh execution looks like, without running it.")
	flag.Parse()

	// Cast the new version
	targetVersion, err := version.NewVersion(*userversion)
	if err != nil {
		fmt.Printf("An error happened while casting GHE specified version %v : %v", *userversion, err)
		os.Exit(1)
	}
	// Check the selected platform
	supportedPlatforms := getSupportedPlatforms()
	if !exist(supportedPlatforms, *platform) {
		fmt.Printf("Unrecognized platforms %v, valid options are: %v", *platform, strings.Join(supportedPlatforms, ", "))
		os.Exit(1)
	}
	// Parse config file
	f, err := os.Open(*configPath)
	if err != nil {
		fmt.Printf("Unable to Open Config file %v \n", err)
	}
	defer f.Close()
	var cfg YamlConfig
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		fmt.Printf("Something happened while reading the config file: %v \n", err)
		os.Exit(1)

	}
	// Verify user input and fill default options
	verifyConfigOption(cfg)
	// check connectivity and get clients
	cfg = setupSSHClient(cfg)
	defer closeConnection(cfg)
	// get GHE version installed on server & verify it's the same on Primary and replicas
	currentVersion, _ := version.NewVersion(gerInstalledVersion(cfg.Primary.Client))
	if cfg.Primary.IsReplica {
		checkPrimaryReplicasVersion(cfg, currentVersion)
	}
	// Verify Target version with the current installed version
	if currentVersion.GreaterThanOrEqual(targetVersion) {
		fmt.Printf("Target Version %s is less than Current installed version %s", targetVersion, currentVersion)
		os.Exit(1)
	}
	currentVersionSegment := currentVersion.Segments()
	targetVersionSegment := targetVersion.Segments()

	if (targetVersionSegment[0] > currentVersionSegment[0]) || (targetVersionSegment[1] > currentVersionSegment[1]) {
		// TODO: upgrade here
	} else {
		// TODO: Patch here
	}

}

func connectToHost(user, host, port string) (*ssh.Client, error) {
	// A public key may be used to authenticate against the remote
	// server by using an un-encrypted PEM-encoded private key file.
	//
	// If you have an encrypted private key, the crypto/x509 package
	// can be used to decrypt it.
	key, err := ioutil.ReadFile(filepath.Join(*sshConfigPath, "id_rsa"))
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %v", err)
	}

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %v", err)
	}
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
	file, err := os.Open(filepath.Join(*sshConfigPath, "known_hosts"))
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

func closeConnection(config YamlConfig) {
	config.Primary.Client.Close()
	for _, replica := range config.Replicas {
		replica.Client.Close()
	}
}

// Since we need to read version from output, we separate it from the general method
// by using a Buffer to capture generated output from the method and parse it to get
// the installed version
func gerInstalledVersion(client *ssh.Client) string {
	const (
		GTHVersionCmd = "ghe-version"
		semverRegex   = "([0-9]+)(\\.[0-9]+)?(\\.[0-9]+)"
	)
	// Create session
	session, err := client.NewSession()
	if err != nil {
		fmt.Printf("Failed to open SSH Session: %v", err)
	}
	var buffer bytes.Buffer
	session.Stdout = &buffer

	if err := session.Run(GTHVersionCmd); err != nil {
		fmt.Printf("Failed to run: %v", err)
	}
	re := regexp.MustCompile(semverRegex)
	return re.FindString(buffer.String())
}

func downloadPatchURL(version []int) string {
	githubPatchURL := "https://github-enterprise.s3.amazonaws.com/hotpatch/"
	githubPatchURL += strconv.Itoa(version[0]) + "." + strconv.Itoa(version[1])
	githubPatchURL += "/" + getPackageName(version)

	return githubPatchURL
}

func downloadUpgradeURL(version []int, platform string) string {
	githubUpgradeURL := "https://github-enterprise.s3.amazonaws.com/"
	githubUpgradeURL += "/" + platform
	githubUpgradeURL += "/updates/github-enterprise" + platform
	githubUpgradeURL += strconv.Itoa(version[0]) + "." + strconv.Itoa(version[1])
	githubUpgradeURL += "/" + getPackageName(version)

	return githubUpgradeURL
}

func performHotPath(client *ssh.Client, version []int, dryRun bool) {
	pkgName := getPackageName(version)
	patchURL := downloadPatchURL(version)
	downloadPkgCmd := "cd /tmp && curl -L -O " + patchURL
	updateCmd := "cd /tmp && ghe-upgrade -y " + pkgName

	fmt.Println("downloading package " + pkgName)
	if !dryRun {
		executeCmd(client, downloadPkgCmd)
	}
	fmt.Println("Install the package" + pkgName)
	if !dryRun {
		executeCmd(client, updateCmd)
	}
}

func performUpgrade(client *ssh.Client, version []int, platform string, dryRun bool) {
	pkgName := getPackageName(version)
	patchURL := downloadUpgradeURL(version, platform)
	downloadPkgCmd := "cd /tmp && curl -L -O " + patchURL
	maintenanceCmd := "ghe-maintenance -s"
	stopReplicationCmd := "ghe-repl-stop"
	removeMaintenanceCmd := "ghe-maintenance -u"
	updateCmd := "cd /tmp && ghe-upgrade -y " + pkgName

	fmt.Println("downloading package " + pkgName)
	if !dryRun {
		executeCmd(client, downloadPkgCmd)
	}
	fmt.Println("Set maintenance mode")
	if !dryRun {
		executeCmd(client, maintenanceCmd)
	}
	fmt.Println("Stop the replication")
	if !dryRun {
		executeCmd(client, stopReplicationCmd)
	}
	fmt.Println("Install the package" + pkgName)
	if !dryRun {
		executeCmd(client, updateCmd)
	}
	fmt.Println("Remove the maintenance mode")
	if !dryRun {
		executeCmd(client, removeMaintenanceCmd)
	}
}

func getPackageName(versionArray []int) string {
	version := strings.Trim(strings.Replace(fmt.Sprint(versionArray), " ", ".", -1), "[]")
	var pkgName = "github-enterprise-"
	pkgName += version
	pkgName += ".hpkg"
	return pkgName
}

func setupSSHClient(config YamlConfig) YamlConfig {
	pHost := config.Primary.Host
	pUser := config.Primary.User
	// if no user specified, use default used
	if pUser == "" {
		pUser = User
	}
	fmt.Printf("Checking Connectivity of the primary %s ...", pHost)
	host, port := getHostPort(pHost)
	client, err := connectToHost(pUser, host, port)
	if err != nil {
		fmt.Printf("failed to connect to primary %s: %s", host, err)
		os.Exit(1)
	}
	config.Primary.Client = client
	fmt.Println("Success")
	if config.Primary.IsReplica {
		for _, replica := range config.Replicas {
			rHost := replica.Host
			rUser := replica.User
			// if no user specified, use default used
			if rUser == "" {
				rUser = User
			}
			fmt.Printf("Checking Connectivity of the replica %s ...", rHost)
			host, port := getHostPort(rHost)
			client, err := connectToHost(rUser, host, port)
			if err != nil {
				fmt.Printf("failed to connect to replica %s ", host)
				os.Exit(1)
			}
			replica.Client = client
			fmt.Println("Success")
		}
	}
	return config
}

func checkPrimaryReplicasVersion(config YamlConfig, currentVersion *version.Version) {
	fmt.Println("Comparing Replicas GHE version to primary. Current version is " + currentVersion.String())
	for _, replica := range config.Replicas {
		rHost := replica.Host
		replicaVersion, _ := version.NewVersion(gerInstalledVersion(replica.Client))
		if !currentVersion.Equal(currentVersion) {
			// fail and exit
			fmt.Printf("Replica %v does not have the same version as primary! Current version is %v", rHost, replicaVersion.String())
			os.Exit(1)
		}
	}
	fmt.Println("Success! Primary and replicas have the same version")
}

func getSupportedPlatforms() []string {
	return []string{"hyperv", "kvm", "esx", "xen", "ami", "azure", "gce"}
}

func verifyConfigOption(config YamlConfig) YamlConfig {
	// Set up default options for Prirmary
	if config.Primary.Host == "" {
		fmt.Printf("Primary host shouldn't be empty")
		os.Exit(1)
	}
	// If user not specified, switch to default user
	if config.Primary.User == "" {
		config.Primary.User = User
	}
	if config.Primary.IsReplica {
		for i, replica := range config.Replicas {
			if replica.Host == "" {
				fmt.Printf("Replica with indice %d host shouldn't be empty", i)
				os.Exit(1)
			}
			if replica.User == "" {
				replica.User = User
			}
		}
	}
	return config
}

func getHostPort(mHost string) (host, port string) {
	h, p, err := net.SplitHostPort(mHost)
	// No port is specified, default is 22
	if err != nil {
		h = mHost
		p = Port
	}
	return h, p
}

func exist(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}
