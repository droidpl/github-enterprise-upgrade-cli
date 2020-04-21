package main

import (
	"log"
	"os"

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
		log.Printf("Unable to Open Config file %v \n", err)
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
		cfg.getSSHConfig(sshConfigPath)
	}

	cfg.configureIdentityKeys(sshConfigPath)
	log.Printf("******** %v %s %s *******", cfg, sshConfigPath, configFile)
	// Verify user input and fill default options
	cfg.verifyConfigOption()
	return cfg
}

func (config *YamlConfig) verifyConfigOption() {
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
				config.Replicas[i].User = DefaultUser
			}
		}
	}
}
