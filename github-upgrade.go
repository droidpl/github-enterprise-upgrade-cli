package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	kh "golang.org/x/crypto/ssh/knownhosts"

	"github.com/hashicorp/go-version"
	"golang.org/x/crypto/ssh"

	"gopkg.in/yaml.v2"
)

// YamlConfig is exported.
type YamlConfig struct {
	Primary struct {
		Host           string `yaml:"host"`
		User           string `yaml:"user"`
		ReplicaEnabled bool   `yaml:"replication_enabled"`
		Client         *ssh.Client
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
	DefaultPort     = "22"
	DefaultUser     = "root"
	GTHVersion      = "ghe-version"
	RebootWaitTime  = 60 // should be in seconds
	retriesWaitTime = 15 // Time to wait before checking if the config finished
)

var sshConfigPath *string

func main() {
	// read the options
	configPath := flag.String("config", "config.yml", "Configuration file")
	userversion := flag.String("v", "", "GHE version")
	platform := flag.String("p", "esx", "Platform your Github Entreprise is running on")
	sshConfigPath = flag.String("ssh-config", filepath.Join(os.Getenv("HOME"), ".ssh"), "SSH keys folder path")
	dryRun := flag.Bool("dry-run", false, "If true, only print how teh execution looks like, without running it.")
	refreshHostSSHKeys := flag.Bool("update-host-keys", false, "Grep new SSH host keys from the machine after rebooting the server, especially for upgrade")
	flag.Parse()

	// Cast the new version
	targetVersion, err := version.NewVersion(*userversion)
	if err != nil {
		log.Fatalf("An error happened while casting GHE specified version %v : %v", *userversion, err)
	}
	// Check the selected platform
	supportedPlatforms := getSupportedPlatforms()
	if !exist(supportedPlatforms, *platform) {
		log.Fatalf("Unrecognized platforms %v, valid options are: %v", *platform, strings.Join(supportedPlatforms, ", "))
	}
	// Parse config file
	f, err := os.Open(*configPath)
	if err != nil {
		log.Printf("Unable to Open Config file %v \n", err)
	}
	defer f.Close()
	var cfg YamlConfig
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		log.Fatalf("Something happened while reading the config file: %v \n", err)

	}
	// Verify user input and fill default options
	verifyConfigOption(cfg)
	// check connectivity and get clients
	cfg = setupSSHClient(cfg)
	defer closeConnection(cfg)
	// get GHE version installed on server & verify it's the same on Primary and replicas
	currentVersion, _ := version.NewVersion(getInstalledVersion(cfg.Primary.Client))
	if cfg.Primary.ReplicaEnabled {
		checkPrimaryReplicasVersion(cfg, currentVersion)
	}
	// Verify Target version with the current installed version
	if currentVersion.GreaterThanOrEqual(targetVersion) {
		log.Fatalf("Target Version (%s) should be greater than the Current installed version (%s)", targetVersion, currentVersion)
	}
	currentVersionSegment := currentVersion.Segments()
	targetVersionSegment := targetVersion.Segments()

	if (targetVersionSegment[0] > currentVersionSegment[0]) || (targetVersionSegment[1] > currentVersionSegment[1]) {
		applyMaintenanceMode(cfg.Primary.Client, *dryRun)
		stopReplication(cfg, *dryRun)
		log.Println("--> Upgrading Primary server " + cfg.Primary.Host)
		performUpgrade(cfg.Primary.Client, targetVersionSegment, *platform, *dryRun)
		// server reboot, we need to open new connection to disable maintenance mode
		cfg.Primary.Client = refreshSSHClients(cfg.Primary.Host, cfg.Primary.User, *refreshHostSSHKeys)
		waitCfgToFinish(cfg.Primary.Client, *dryRun)
		// check if replica and perform individual upgrades on them
		if cfg.Primary.ReplicaEnabled {
			for i, replica := range cfg.Replicas {
				log.Println("--> Upgrading Replica server " + replica.Host)
				performUpgrade(replica.Client, targetVersionSegment, *platform, *dryRun)
				// server reboot, we need to open new connection to disable maintenance mode
				cfg.Replicas[i].Client = refreshSSHClients(replica.Host, replica.User, *refreshHostSSHKeys)
				waitCfgToFinish(cfg.Replicas[i].Client, *dryRun)
			}
			// Enabling again replication
			enableRreplication(cfg, *dryRun)
		}
		removeMaintenanceMode(cfg.Primary.Client, *dryRun)
	} else {
		log.Println("--> Upgrading Primary server " + cfg.Primary.Host)
		performHotPath(cfg.Primary.Client, targetVersionSegment, *dryRun)
		// check if replica and perform individual patchs on them
		if cfg.Primary.ReplicaEnabled {
			for _, replica := range cfg.Replicas {
				if replica.IsActive {
					log.Println("--> Upgrading Replica server " + replica.Host)
					performHotPath(replica.Client, targetVersionSegment, *dryRun)
				}
			}
		}
	}
	log.Println("--> The current installed version of Github Entreprise is " + getInstalledVersion(cfg.Primary.Client))
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

	hostKeyCallback, err := kh.New(filepath.Join(*sshConfigPath, "known_hosts"))
	if err != nil {
		return nil, fmt.Errorf("could not create hostkeycallback function: %v", err)
	}
	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			// Use the PublicKeys method for remote authentication.
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(host, port), sshConfig)
	if err != nil {
		return nil, err
	}
	return client, nil
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
	if config.Primary.ReplicaEnabled {
		for _, replica := range config.Replicas {
			if replica.IsActive {
				replica.Client.Close()
			}
		}
	}
}

// Since we need to read version from output, we separate it from the general method
// by using a Buffer to capture generated output from the method and parse it to get
// the installed version
func getInstalledVersion(client *ssh.Client) string {
	const (
		GTHVersionCmd = "ghe-version"
		semverRegex   = "([0-9]+)(\\.[0-9]+)?(\\.[0-9]+)"
	)
	// Don't ignore connad errors
	output := executeCmdAndReturnBuffer(client, GTHVersionCmd, false)
	re := regexp.MustCompile(semverRegex)
	return re.FindString(output)
}

func downloadPatchURL(version []int) string {
	githubPatchURL := "https://github-enterprise.s3.amazonaws.com/hotpatch/"
	githubPatchURL += strconv.Itoa(version[0]) + "." + strconv.Itoa(version[1])
	githubPatchURL += "/" + getPackageName(version, "")
	return githubPatchURL
}

func downloadUpgradeURL(version []int, platform string) string {
	githubUpgradeURL := "https://github-enterprise.s3.amazonaws.com/"
	githubUpgradeURL += platform
	githubUpgradeURL += "/updates/"
	githubUpgradeURL += getPackageName(version, platform)

	return githubUpgradeURL
}

func performHotPath(client *ssh.Client, version []int, dryRun bool) {
	pkgName := getPackageName(version, "")
	patchURL := downloadPatchURL(version)
	downloadPkgCmd := "cd /tmp && curl -L -O " + patchURL
	updateCmd := "cd /tmp && ghe-upgrade -y " + pkgName

	log.Println("--> Downloading package " + pkgName)
	if !dryRun {
		executeCmdFailOnError(client, downloadPkgCmd)
	}
	log.Println("--> Installing the package " + pkgName)
	if !dryRun {
		executeCmdFailOnError(client, updateCmd)
	}
}

func performUpgrade(client *ssh.Client, version []int, platform string, dryRun bool) {
	pkgName := getPackageName(version, platform)
	patchURL := downloadUpgradeURL(version, platform)
	downloadPkgCmd := "cd /tmp && curl -L -O " + patchURL
	updateCmd := "cd /tmp && ghe-upgrade -y " + pkgName

	log.Println("--> Downloading package " + pkgName)
	if !dryRun {
		executeCmdFailOnError(client, downloadPkgCmd)
	}

	log.Println("--> Installing the package" + pkgName)
	if !dryRun {
		executeCmd(client, updateCmd)
	}
}

func getPackageName(versionArray []int, platform string) string {
	version := strings.Trim(strings.Replace(fmt.Sprint(versionArray), " ", ".", -1), "[]")
	var pkgName = "github-enterprise-"
	if platform != "" {
		pkgName += platform + "-"
	}
	pkgName += version
	if platform != "" {
		pkgName += ".pkg"
	} else {
		pkgName += ".hpkg"
	}
	return pkgName
}

func setupSSHClient(config YamlConfig) YamlConfig {
	config.Primary.Client = getSSHClient(config.Primary.Host, config.Primary.User)
	log.Println("Success")
	if config.Primary.ReplicaEnabled {
		for i, replica := range config.Replicas {
			if replica.IsActive {
				config.Replicas[i].Client = getSSHClient(replica.Host, replica.User)
				log.Println("Success")
			}
		}
	}
	return config
}

func checkPrimaryReplicasVersion(config YamlConfig, currentVersion *version.Version) {
	log.Println("--> Comparing Replicas GHE version to primary. Current version is " + currentVersion.String())
	for _, replica := range config.Replicas {
		if replica.IsActive {
			rHost := replica.Host
			replicaVersion, _ := version.NewVersion(getInstalledVersion(replica.Client))
			if !currentVersion.Equal(currentVersion) {
				// fail and exit
				log.Fatalf("Replica %v does not have the same version as primary! Current version is %v", rHost, replicaVersion.String())
			}
		}
	}
	log.Println("--> Success! Primary and replicas have the same version")
}

func getSupportedPlatforms() []string {
	return []string{"hyperv", "kvm", "esx", "xen", "ami", "azure", "gce"}
}

func verifyConfigOption(config YamlConfig) YamlConfig {
	// Set up default options for Primary
	if config.Primary.Host == "" {
		log.Fatal("Primary host shouldn't be empty")
	}
	// If user not specified, switch to default user
	if config.Primary.User == "" {
		config.Primary.User = DefaultUser
	}
	if config.Primary.ReplicaEnabled {
		for i, replica := range config.Replicas {
			if replica.Host == "" {
				log.Fatalf("Replica with indice %d host shouldn't be empty", i)
			}
			if replica.User == "" {
				replica.User = DefaultUser
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
		p = DefaultPort
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

func applyMaintenanceMode(client *ssh.Client, dryRun bool) {
	maintenanceCmd := "ghe-maintenance -s"
	log.Println("--> Setting maintenance mode")
	if !dryRun {
		executeCmdFailOnError(client, maintenanceCmd)
	}
}
func removeMaintenanceMode(client *ssh.Client, dryRun bool) {
	removeMaintenanceCmd := "ghe-maintenance -u"
	log.Println("--> Disabling maintenance mode")
	executeCmd(client, removeMaintenanceCmd)
	log.Println("-->  Maintenance mode disabled!")
}

func waitCfgToFinish(client *ssh.Client, dryRun bool) {
	if !dryRun {
		ticker := time.NewTicker(retriesWaitTime * time.Second)
		for range ticker.C {
			isRunning, _ := isConfigInProgress(client)
			if isRunning {
				log.Printf("Configuration is still running... Retrying in %ds", retriesWaitTime)
			} else {
				break
			}
		}
	}
}

func getSSHClient(fullHost, user string) *ssh.Client {
	log.Printf("--> Checking Connectivity of the server %s ...", fullHost)
	host, port := getHostPort(fullHost)
	client, err := connectToHost(user, host, port)
	if err != nil {
		log.Fatalf("failed to connect to server %s: %s", host, err)
	}
	return client
}

func refreshSSHClients(host, user string, updateSSHHostKeys bool) *ssh.Client {
	log.Println("--> Server is rebooting! Sleeping for 60s")
	time.Sleep(RebootWaitTime * time.Second)
	if updateSSHHostKeys {
		sshKeyScan(host)
	}
	return getSSHClient(host, user)
}

func executeCmdFailOnError(client *ssh.Client, cmd string) {
	err := executeCmd(client, cmd)
	if err != nil {
		log.Fatalf("An error happened while executing command %v", err)
	}
}

func enableRreplication(config YamlConfig, dryRun bool) {
	primary, _ := getHostPort(config.Primary.Host)
	firstReplSetupCmd := fmt.Sprintf("echo y | ghe-repl-setup %s", primary)
	replSetupCmd := fmt.Sprintf("echo y | ghe-repl-setup --add %s", primary)
	startReplCmd := "ghe-repl-start"
	replStatusCmd := "ghe-repl-status"
	applyConfigCmd := "ghe-config-apply"

	for i, replica := range config.Replicas {
		log.Println("--> Configuring the replica ")
		if !dryRun {
			// Check if its the first replica or not, to decide which command to run
			// If the replica has been already configured, the method execution fail saying "Already configured as cluster node"
			// we ignore the error and proceed
			if i == 0 {
				executeCmd(replica.Client, firstReplSetupCmd)
			} else {
				executeCmd(replica.Client, replSetupCmd)
			}
		}
		log.Println("--> Starting the replica ")
		if !dryRun {
			executeCmdFailOnError(replica.Client, startReplCmd)
		}
		if !dryRun {
			executeCmdFailOnError(replica.Client, replStatusCmd)
		}
		if replica.Datacenter != "" {
			log.Println("-->  Configuring the replica for the specified datacenter: " + replica.Datacenter)
			if !dryRun {
				var datacenterCmd string
				if replica.IsActive {
					datacenterCmd = fmt.Sprintf("ghe-repl-node --active --datacenter %s", primary)
				} else {
					datacenterCmd = fmt.Sprintf("ghe-repl-node --inactive --datacenter %s", primary)
				}
				executeCmdFailOnError(replica.Client, datacenterCmd)
			}
		}

	}

	log.Println("--> Applying the configuration")
	if !dryRun {
		executeCmdFailOnError(config.Primary.Client, applyConfigCmd)
	}
}

func stopReplication(config YamlConfig, dryRun bool) {
	if config.Primary.ReplicaEnabled {
		stopReplCmd := "ghe-repl-stop"
		for _, replica := range config.Replicas {
			log.Printf("--> Stopping the replica %s", replica.Host)
			if !dryRun {
				executeCmdFailOnError(replica.Client, stopReplCmd)
			}
		}
	}
}

// Execute command on the remote host using the provide client!
// You can choose to ignore the errors of a command execution,
// if ignored, the method will return the result of the execution, if not the script will fail and exit
func executeCmdAndReturnBuffer(client *ssh.Client, cmd string, ignore bool) string {
	// Create session
	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("Failed to open SSH Session: %v", err)
	}
	var buffer bytes.Buffer
	session.Stdout = &buffer

	if err := session.Run(cmd); err != nil && !ignore {
		log.Fatalf("Failed to run %v", err)
	}
	return buffer.String()
}

func isConfigInProgress(client *ssh.Client) (bool, error) {
	CheckCfgScript := "/usr/local/share/enterprise/ghe-config-in-progress"
	// the script exit(3) and return false if no config are running, We ignore that and continue
	isRunningStr := executeCmdAndReturnBuffer(client, CheckCfgScript, true)
	return strconv.ParseBool(strings.TrimSuffix(isRunningStr, "\n"))
}

/**
 When the server reboot after an upgrade, the host ke changes and thus cannot open an SSH connection
 My approach was to run `ssh-keygen -R -p <port> <host> -f <known_hosts_file>` to remove current host entry
 and then run `ssh-keyscan -t ecdsa -p <port> <host>` ti get the new ssh keys
 and then, and only then append the new entry on the known_hosts file
**/
func sshKeyScan(host string) {
	sshKH := filepath.Join(*sshConfigPath, "known_hosts")
	h, p := getHostPort(host)
	log.Println("--> Refreshing host keys for host " + h)
	execCmdHost("ssh-keygen", "-R", fmt.Sprintf("[%s]:%s", h, p), "-f", sshKH)
	hk := execCmdHost("ssh-keyscan", "-t", "ecdsa", "-p", p, h)
	appendOnFile(sshKH, hk)
}

func execCmdHost(scmd string, arg ...string) string {
	cmd := exec.Command(scmd, arg...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Connot execute Command On host: %v", err)
	}
	return out.String()
}

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
