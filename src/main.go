package main

import (
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
	configFile := flag.String("config", "config.yml", "Configuration file")
	userversion := flag.String("v", "", "GHE version")
	platform := flag.String("p", "esx", "Platform your Github Entreprise is running on")
	sshConfigPath = flag.String("ssh-config", filepath.Join(os.Getenv("HOME"), ".ssh"), "SSH keys folder path")
	dryRun := flag.Bool("dry-run", false, "If true, only print how teh execution looks like, without running it.")
	local := flag.Bool("l", false, "Download the package locally, and then upload it to servers using sftp")
	assumeYes := flag.Bool("y", false, "Automatic yes to confirmation prompt and run non-interactively")
	refreshHostSSHKeys := flag.Bool("update-host-keys", false, "Grep new SSH host keys from the machine after rebooting the server, especially for upgrade")
	useConfigFile := flag.Bool("use-ssh-config", false, "Complete missing details of config file from user-specific ssh configuration file")
	flag.Parse()

	// Make paths Absolute
	*sshConfigPath = absPath(*sshConfigPath)
	*configFile = absPath(*configFile)

	// Cast the new version
	targetVersion, err := version.NewVersion(*userversion)
	if err != nil {
		log.Fatalf("Incorrect version %v, Please provide a valid version. check https://enterprise.github.com/releases. error details: %v", *userversion, err)
	}
	// Check the selected platform
	if !exist(getSupportedPlatforms(), *platform) {
		log.Fatalf("Unrecognized platforms %s, valid options are: %s", *platform, strings.Join(getSupportedPlatforms(), ", "))
	}
	// Read config file and verify input
	cfg := mapConfig(*configFile, *sshConfigPath, *useConfigFile)
	// check connectivity and get clients
	cfg.setupSSHClient()
	defer closeConnection(cfg)
	// get GHE version installed on server & verify it's the same on Primary and replicas
	currentVersion, _ := version.NewVersion(getInstalledVersion(cfg.Primary.Client))
	if cfg.Primary.ReplicaEnabled {
		checkPrimaryReplicasVersion(cfg, currentVersion)
		checkAllReplStatus(cfg)
	}
	// Verify Target version with the current installed version
	if currentVersion.GreaterThanOrEqual(targetVersion) {
		log.Fatalf("Target Version (%s) should be greater than the Current installed version (%s)", targetVersion, currentVersion)
	}
	currentVersionSegment := currentVersion.Segments()
	targetVersionSegment := targetVersion.Segments()
	// ask user for final confirmation
	cfg.bringFacts(currentVersion.String(), targetVersion.String(), *assumeYes, *dryRun)
	if (targetVersionSegment[0] > currentVersionSegment[0]) || (targetVersionSegment[1] > currentVersionSegment[1]) {
		// If user chosen to local option, we upload the files to server first
		if *local {
			cfg.uploadFromHost(getPackageName(targetVersionSegment, *platform), downloadUpgradeURL(targetVersionSegment, *platform))
		}
		applyMaintenanceMode(cfg.Primary.Client, *dryRun)
		stopReplication(cfg, *dryRun)
		log.Println("--> Updating Primary server " + cfg.Primary.Host)
		performUpgrade(cfg.Primary.Client, targetVersionSegment, *platform, *local, *dryRun)
		// server reboot, we need to open new connection to disable maintenance mode
		cfg.Primary.Client = refreshSSHClients(cfg.Primary.Host, cfg.Primary.User, cfg.Primary.SSHKey, *refreshHostSSHKeys)
		waitCfgToFinish(cfg.Primary.Client, *dryRun)
		// check if replica and perform individual upgrades on them
		if cfg.Primary.ReplicaEnabled {
			for i, replica := range cfg.Replicas {

				log.Println("--> Updating Replica server " + replica.Host)
				performUpgrade(replica.Client, targetVersionSegment, *platform, *local, *dryRun)
				// server reboot, we need to open new connection to disable maintenance mode
				cfg.Replicas[i].Client = refreshSSHClients(replica.Host, replica.User, replica.SSHKey, *refreshHostSSHKeys)
				waitCfgToFinish(cfg.Replicas[i].Client, *dryRun)

			}
			// Enabling again replication
			enableRreplication(cfg, *dryRun)
		}
		removeMaintenanceMode(cfg.Primary.Client, *dryRun)
	} else {
		// If user chosen to local option, we upload the files to server first
		if *local {
			cfg.uploadFromHost(getPackageName(targetVersionSegment, *platform), downloadPatchURL(targetVersionSegment))
		}
		log.Println("--> Updating Primary server " + cfg.Primary.Host)
		performHotPatch(cfg.Primary.Client, targetVersionSegment, *local, *dryRun)
		// check if replica and perform individual patchs on them
		if cfg.Primary.ReplicaEnabled {
			for _, replica := range cfg.Replicas {

				log.Println("--> Updating Replica server " + replica.Host)
				performHotPatch(replica.Client, targetVersionSegment, *local, *dryRun)

			}
		}
	}
	if *dryRun {
		log.Println("--> You're running the script in dry-run mode. Nothing changed in the server(s)")
	} else {
		log.Println("--> The current installed version of Github Entreprise is " + getInstalledVersion(cfg.Primary.Client))
	}
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

func performHotPatch(client *ssh.Client, version []int, local, dryRun bool) {
	pkgName := getPackageName(version, "")
	packageURL := downloadPatchURL(version)
	upgradeCmd := newCmdArgs("ghe-upgrade", "-y", pkgName)
	downloadPkgCmd := newCmdArgs("curl", "-L", "-O", packageURL)
	cdCmd := newCmdArgs("cd", savePath)
	// do not download the file locally, it has been already uploaded to the server
	if !local {
		if pkgExist := fileExist(client, pkgName); pkgExist {
			log.Printf("--> Package %s already exist, skipping download", pkgName)
		} else {
			log.Println("--> Downloading package " + pkgName)
			if !dryRun {
				executeCmdFailOnError(client, concatCmds(cdCmd.String(), downloadPkgCmd.String()))
			}
		}
	}

	log.Println("--> Installing package " + pkgName)
	if !dryRun {
		executeCmdFailOnError(client, concatCmds(cdCmd.String(), upgradeCmd.String()))
	}
}

func performUpgrade(client *ssh.Client, version []int, platform string, local, dryRun bool) {
	pkgName := getPackageName(version, platform)
	packageURL := downloadUpgradeURL(version, platform)
	upgradeCmd := newCmdArgs("ghe-upgrade", "-y", pkgName)
	downloadPkgCmd := newCmdArgs("curl", "-L", "-O", packageURL)
	cdCmd := newCmdArgs("cd", savePath)
	// do not download the file locally, it has been already uploaded to the server
	if !local {
		if pkgExist := fileExist(client, pkgName); pkgExist {
			log.Println("--> Package %s already exist, skipping download" + pkgName)
		} else {
			log.Println("--> Downloading package " + pkgName)
			if !dryRun {
				executeCmdFailOnError(client, concatCmds(cdCmd.String(), downloadPkgCmd.String()))
			}
		}

	}

	log.Println("--> Installing package " + pkgName)
	if !dryRun {
		executeCmd(client, concatCmds(cdCmd.String(), upgradeCmd.String()))
	}
}

// Return package name and handle the differences for both hotpatch and upgrade naming
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
	log.Println("--> Comparing Replica(s) GHE version to primary. Current version is " + currentVersion.String())
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
	log.Println("--> Maintenance mode disabled!")
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

// Check status of given replica and ask  user if he wants to continue upgrade even with reported errors
func checkReplStatus(client *ssh.Client) bool {
	replStatusCmd := newCmd("ghe-repl-status")
	err := executeCmd(client, replStatusCmd.String())
	if err == nil {
		return true
	}
	log.Printf("Something went wrong while executing `ghe-repl-status`. Check details above (Trace: %v)", err)
	return userConfirm()

}

// Check all replicas status
func checkAllReplStatus(config YamlConfig) {
	for _, replica := range config.Replicas {
		log.Printf("--> Checking replica %s status", replica.Host)
		if !checkReplStatus(replica.Client) {
			os.Exit(1)
		}
	}

}

func enableRreplication(config YamlConfig, dryRun bool) {
	primary, _ := splitHostPort(config.Primary.Host)
	replSetupCmd := newCmd("ghe-repl-setup")
	startReplCmd := newCmd("ghe-repl-start")
	replStatusCmd := newCmd("ghe-repl-status")
	applyConfigCmd := newCmd("ghe-config-apply")
	replDCNodeCmd := newCmd("ghe-repl-node")

	for i, replica := range config.Replicas {
		log.Println("--> Configuring replication ")
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
		log.Println("--> Starting replication ")
		if !dryRun {
			executeCmdFailOnError(replica.Client, startReplCmd.String())
		}
		if !dryRun {
			executeCmd(replica.Client, replStatusCmd.String())
		}
		if replica.Datacenter != "" {
			log.Println("-->  Configuring replication for datacenter: " + replica.Datacenter)
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

	log.Println("--> Applying replication configuration")
	if !dryRun {
		executeCmdFailOnError(config.Primary.Client, applyConfigCmd.String())
	}
}

func stopReplication(config YamlConfig, dryRun bool) {
	if config.Primary.ReplicaEnabled {
		stopReplCmd := newCmd("ghe-repl-stop")
		for _, replica := range config.Replicas {
			log.Printf("--> Stopping replication %s", replica.Host)
			if !dryRun {
				executeCmdFailOnError(replica.Client, stopReplCmd.String())
			}
		}
	}
}

func isConfigInProgress(client *ssh.Client) (bool, error) {
	CheckCfgScript := "/usr/local/share/enterprise/ghe-config-in-progress"
	// the script exit(3) and return false if no config are running, We ignore that and continue
	isRunningStr := executeCmdAndReturnBuffer(client, CheckCfgScript, true)
	return strconv.ParseBool(strings.TrimSuffix(isRunningStr, "\n"))
}

func (config YamlConfig) uploadFromHost(pkgName, pkgURL string) {
	log.Printf("local option selected...Downloading the package %s locally", pkgName)
	downloadPkgToHost(pkgURL, pkgName)
	if pkgExist := fileExist(config.Primary.Client, pkgName); pkgExist {
		log.Printf("--> Package %s already exist, skipping upload", pkgName)
	} else {
		log.Printf("Uploading package to primary %s", config.Primary.Host)
		copyFile(config.Primary.Client, pkgName)
	}

	if config.Primary.ReplicaEnabled {
		for _, replica := range config.Replicas {
			if pkgExist := fileExist(replica.Client, pkgName); pkgExist {
				log.Printf("--> Package %s already exist, skipping upload", pkgName)
			} else {
				log.Printf("Uploading package to replica %s", replica.Host)
				copyFile(replica.Client, pkgName)
			}
		}
	}

}
