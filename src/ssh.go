package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/kevinburke/ssh_config"
	kh "golang.org/x/crypto/ssh/knownhosts"

	"golang.org/x/crypto/ssh"
)

// Constants
const (
	DefaultUser    = "root"
	DefaultPort    = "22"
	RebootWaitTime = 60 // should be in seconds
	SSHKeyFile     = "id_rsa"
	SSHConfigFile  = "config"
)

// SSH files path. This variable is initiated from the
var sshConfigPath *string

func connectToHost(user, host, port, sshkeyPath string) (*ssh.Client, error) {
	// A public key may be used to authenticate against the remote
	// server by using an un-encrypted PEM-encoded private key file.
	//
	// If you have an encrypted private key, the crypto/x509 package
	// can be used to decrypt it.
	key, err := ioutil.ReadFile(sshkeyPath)
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
		return nil, fmt.Errorf("could not dial host: %v", err)
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
func getSSHClient(fullHost, user, sshkeyPath string) *ssh.Client {
	log.Printf("--> Checking Connectivity of the server %s ...", fullHost)
	host, port := splitHostPort(fullHost)
	client, err := connectToHost(user, host, port, sshkeyPath)
	if err != nil {
		log.Fatalf("failed to connect to server %s: %s", host, err)
	}
	return client
}

func (config *YamlConfig) setupSSHClient() {
	config.Primary.Client = getSSHClient(config.Primary.Host, config.Primary.User, config.Primary.SSHKey)
	log.Println("Success")
	if config.Primary.ReplicaEnabled {
		for i, replica := range config.Replicas {
			if replica.IsActive {
				config.Replicas[i].Client = getSSHClient(replica.Host, replica.User, replica.SSHKey)
				log.Println("Success")
			}
		}
	}
}
func refreshSSHClients(host, user, sshkeyPath string, updateSSHHostKeys bool) *ssh.Client {
	log.Println("--> Server is rebooting! Sleeping for 60s")
	time.Sleep(RebootWaitTime * time.Second)
	if updateSSHHostKeys {
		sshKeyScan(host)
	}
	return getSSHClient(host, user, sshkeyPath)
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

/**
 When the server reboot after an upgrade, the host ke changes and thus cannot open an SSH connection
 My approach was to run `ssh-keygen -R -p <port> <host> -f <known_hosts_file>` to remove current host entry
 and then run `ssh-keyscan -t ecdsa -p <port> <host>` ti get the new ssh keys
 and then, and only then append the new entry on the known_hosts file
**/
func sshKeyScan(host string) {
	sshKH := filepath.Join(*sshConfigPath, "known_hosts")
	h, p := splitHostPort(host)
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

//
func (config *YamlConfig) replaceWithSSHConfig(configPath string) {
	f, err := os.Open(filepath.Join(configPath, SSHConfigFile))
	if err != nil {
		log.Fatalf("An error happened while reading ssh config file: %v", err)
	}
	cfg, err := ssh_config.Decode(f)
	if err != nil {
		log.Fatalf("Unable to parse ssh config file: %v", err)
	}
	alias := config.Primary.Host
	// Get ssh config values and replace in Yaml config Struct if not empty
	host, user, key := getHostWithKeyFromSSHConfig(alias, *cfg)
	if host != "" {
		config.Primary.Host = host
	}

	if user != "" {
		config.Primary.User = user
	}

	if key != "" {
		config.Primary.SSHKey = key
	}

	for i := range config.Replicas {
		alias := config.Replicas[i].Host
		config.Replicas[i].Host, config.Replicas[i].User, config.Replicas[i].SSHKey = getHostWithKeyFromSSHConfig(alias, *cfg)
	}
}

// Given an alias and a config, this function return addr, user and ssh keys
func getHostWithKeyFromSSHConfig(alias string, c ssh_config.Config) (addr, user, authkey string) {
	host, _ := c.Get(alias, "Hostname")
	port, _ := c.Get(alias, "Port")
	user, _ = c.Get(alias, "User")
	authkey, _ = c.Get(alias, "IdentityFile")
	authkey = absPath(authkey)
	addr = fmt.Sprintf("%s:%s", host, port)

	return
}

// Add Default SSH IdentityKey if it is empty
func (config *YamlConfig) configureIdentityKeys(sshCfgPath string) {
	if config.Primary.SSHKey == "" {
		config.Primary.SSHKey = filepath.Join(sshCfgPath, SSHKeyFile)
	}
	for i := range config.Replicas {
		if config.Replicas[i].SSHKey == "" {
			config.Replicas[i].SSHKey = filepath.Join(sshCfgPath, SSHKeyFile)
		}
	}
}
