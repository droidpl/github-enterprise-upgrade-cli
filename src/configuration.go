package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/olekukonko/tablewriter"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

// YamlConfig holds configuration of the ghe hosts.
type YamlConfig struct {
	Primary struct {
		Host           string `yaml:"host"`
		User           string `yaml:"user"`
		ReplicaEnabled bool   `yaml:"replication_enabled"`
		Client         *ssh.Client
		SSHKey         string `yaml:"authkey"`
	} `yaml:"primary"`
	Replicas []struct {
		Host       string `yaml:"host"`
		User       string `yaml:"user"`
		IsActive   bool   `yaml:"active"`
		Datacenter string `yaml:"datacenter"`
		Client     *ssh.Client
		SSHKey     string `yaml:"authkey"`
	} `yaml:"replicas"`
}

func mapConfig(configFile, sshConfigPath string, useConfigFile bool) YamlConfig {
	// Parse config file
	f, err := os.Open(configFile)
	if err != nil {
		log.Fatalf("Unable to Open Config file %v", err)
	}
	defer f.Close()
	var cfg YamlConfig
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		log.Fatalf("Something happened while reading the config file: %v \n", err)

	}
	// get config from ssh config file if wanted
	if useConfigFile {
		cfg.replaceWithSSHConfig(sshConfigPath)
	}

	cfg.configureIdentityKeys(sshConfigPath)
	// Verify user input and fill default options
	cfg.verifyConfigOption()
	return cfg
}

func (config *YamlConfig) verifyConfigOption() {
	// Set up default options for Primary
	if strings.Trim(config.Primary.Host, " ") == "" {
		log.Fatal("Primary host shouldn't be empty")
	}
	// If user not specified, switch to default user
	if strings.Trim(config.Primary.User, " ") == "" {
		config.Primary.User = DefaultUser
	}
	if config.Primary.ReplicaEnabled {
		for i, replica := range config.Replicas {
			if strings.Trim(replica.Host, " ") == "" {
				log.Fatalf("Replica with indice %d host shouldn't be empty", i)
			}
			if strings.Trim(replica.User, " ") == "" {
				config.Replicas[i].User = DefaultUser
			}
		}
	}
}

func (config *YamlConfig) askForConfirmation(currentVer, targetVer string, assumeYes, dryRun bool) {
	log.Println("Welcome to SGT GHE upgrade tool")
	fmt.Println("=====================================")
	fmt.Println("Please find below Upgrade details:")
	data := [][]string{
		{"Primary Node", ""},
		{"Replica Node(s)", ""},
		{"Update replicas", ""},
		{"Current GHE version", ""},
		{"Target GHE version", ""},
	}
	data[0][1] = config.Primary.Host
	data[2][1] = strconv.FormatBool(config.Primary.ReplicaEnabled)
	data[3][1] = currentVer
	data[4][1] = targetVer
	var replicas []string
	for _, r := range config.Replicas {
		replicas = append(replicas, r.Host)
	}
	data[1][1] = strings.Join(replicas, ", ")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetBorder(false)
	table.SetTablePadding("\t") // pad with tabs
	table.SetNoWhiteSpace(true)
	table.AppendBulk(data) // Add Bulk Data
	table.Render()
	if dryRun {
		fmt.Println("Script is running in dry-run mode. Nothing will change in server(s)")
	} else {
		fmt.Println("This will update the primary and all replica nodes (if any)")
	}
	fmt.Println("=====================================")
	if !assumeYes {
		var str string
		for {
			fmt.Print("Are you sure you want to proceed (y/n)?")
			fmt.Scanf("%s", &str)
			if strings.ToLower(str) == "y" {
				break
			}
			if strings.ToLower(str) == "n" {
				log.Println("Upgrade Aborted")
				os.Exit(0)
			}
		}
	}

}
