package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-version"
	"golang.org/x/crypto/ssh"
)

// Constants
const (
	RetriesWaitTime = 15 // Time to wait before checking if the config finished
	SemverRegex     = "([0-9]+)(\\.[0-9]+)?(\\.[0-9]+)"
)

var (
	// GHEVersion to get current GHE version
	GHEVersion = newCmd("ghe-version")
)

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
	// Read config file and verify input
	cfg := mapConfig(*configPath)
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

// Since we need to read version from output, we separate it from the general method
// by using a Buffer to capture generated output from the method and parse it to get
// the installed version
func getInstalledVersion(client *ssh.Client) string {
	// Don't ignore connad errors
	output := executeCmdAndReturnBuffer(client, GHEVersion.String(), false)
	re := regexp.MustCompile(SemverRegex)
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
	packageURL := downloadPatchURL(version)
	upgradeCmd := newCmdArgs("ghe-upgrade", "-y", pkgName)
	downloadPkgCmd := newCmdArgs("curl", "-L", "-O", packageURL)
	cdCmd := newCmdArgs("cd", "/tmp")

	log.Println("--> Downloading package " + pkgName)
	if !dryRun {
		executeCmdFailOnError(client, concatCmds(cdCmd.String(), downloadPkgCmd.String()))
	}
	log.Println("--> Installing the package " + pkgName)
	if !dryRun {
		executeCmdFailOnError(client, concatCmds(cdCmd.String(), upgradeCmd.String()))
	}
}

func performUpgrade(client *ssh.Client, version []int, platform string, dryRun bool) {
	pkgName := getPackageName(version, platform)
	packageURL := downloadUpgradeURL(version, platform)
	upgradeCmd := newCmdArgs("ghe-upgrade", "-y", pkgName)
	downloadPkgCmd := newCmdArgs("curl", "-L", "-O", packageURL)
	cdCmd := newCmdArgs("cd", "/tmp")

	log.Println("--> Downloading package " + pkgName)
	if !dryRun {
		executeCmdFailOnError(client, concatCmds(cdCmd.String(), downloadPkgCmd.String()))
	}

	log.Println("--> Installing the package" + pkgName)
	if !dryRun {
		executeCmd(client, concatCmds(cdCmd.String(), upgradeCmd.String()))
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

func applyMaintenanceMode(client *ssh.Client, dryRun bool) {
	maintenanceCmd := newCmdArgs("ghe-maintenance", "-s")
	log.Println("--> Setting maintenance mode")
	if !dryRun {
		executeCmdFailOnError(client, maintenanceCmd.String())
	}
}
func removeMaintenanceMode(client *ssh.Client, dryRun bool) {
	removeMaintenanceCmd := newCmdArgs("ghe-maintenance", "-u")
	log.Println("--> Disabling maintenance mode")
	executeCmd(client, removeMaintenanceCmd.String())
	log.Println("-->  Maintenance mode disabled!")
}

func waitCfgToFinish(client *ssh.Client, dryRun bool) {
	if !dryRun {
		ticker := time.NewTicker(RetriesWaitTime * time.Second)
		for range ticker.C {
			isRunning, _ := isConfigInProgress(client)
			if isRunning {
				log.Printf("Configuration is still running... Retrying in %ds", RetriesWaitTime)
			} else {
				break
			}
		}
	}
}

func executeCmdFailOnError(client *ssh.Client, cmd string) {
	err := executeCmd(client, cmd)
	if err != nil {
		log.Fatalf("An error happened while executing command %v", err)
	}
}

func enableRreplication(config YamlConfig, dryRun bool) {
	primary, _ := getHostPort(config.Primary.Host)
	replSetupCmd := newCmd("ghe-repl-setup")
	startReplCmd := newCmd("ghe-repl-start")
	replStatusCmd := newCmd("ghe-repl-status")
	applyConfigCmd := newCmd("ghe-config-apply")
	replDCNodeCmd := newCmd("ghe-repl-node")

	for i, replica := range config.Replicas {
		log.Println("--> Configuring the replica ")
		if !dryRun {
			// Check if its the first replica or not, to decide which command to run
			// If the replica has been already configured, the method execution fail saying "Already configured as cluster node"
			// we ignore the error and proceed
			if i == 0 {
				replSetupCmd.addArg("--add")
			}
			replSetupCmd.addArg(primary)
			replSetupCmd.assumeYes()
			executeCmd(replica.Client, replSetupCmd.String())

		}
		log.Println("--> Starting the replica ")
		if !dryRun {
			executeCmdFailOnError(replica.Client, startReplCmd.String())
		}
		if !dryRun {
			executeCmdFailOnError(replica.Client, replStatusCmd.String())
		}
		if replica.Datacenter != "" {
			log.Println("-->  Configuring the replica for the specified datacenter: " + replica.Datacenter)
			if !dryRun {
				if replica.IsActive {
					replDCNodeCmd.addArg("--active")
				} else {
					replDCNodeCmd.addArg("--inactive")
				}
				replDCNodeCmd.addArgs("--datacenter", primary)
				executeCmdFailOnError(replica.Client, replDCNodeCmd.String())
			}
		}

	}

	log.Println("--> Applying the configuration")
	if !dryRun {
		executeCmdFailOnError(config.Primary.Client, applyConfigCmd.String())
	}
}

func stopReplication(config YamlConfig, dryRun bool) {
	if config.Primary.ReplicaEnabled {
		stopReplCmd := newCmd("ghe-repl-stop")
		for _, replica := range config.Replicas {
			log.Printf("--> Stopping the replica %s", replica.Host)
			if !dryRun {
				executeCmdFailOnError(replica.Client, stopReplCmd.String())
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
