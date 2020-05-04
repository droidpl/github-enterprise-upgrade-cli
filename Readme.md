# Github Enterprise upgrade command line tool

Command line tool, built with golang for automatic upgrade/patch of Github Entreprise. It support both single instance and multi replicas. 

Script options are:
```
  -config string
        Configuration file (default "config.yml")
  -p string
        Platform your Github Enterprise is running on (default "esx")
        supported platforms are: "hyperv", "kvm", "esx", "xen", "ami", "azure", "gce"
  -ssh-config string
        SSH keys folder path (default "~/.ssh")
  -v string
        GHE version
  -y boolean
        Automatic yes to confirmation prompt and run non-interactively (default false)
  -l boolean
        Download the upgrade package locally (from where you're running the tool) and upload it to servers, instead of downloading it from the servers. This is useful in case of servers have no/slow internet (default false)
  -dry-run boolean
        If true, only print how teh execution looks like, without running it.
  -use-ssh-config boolean
        Read host config values from ssh config file. the host in config.yml would be the alias to get the host, port, user and ssh keys from
  -update-host-keys boolean
        Grep new SSH host keys from the machine after rebooting the server, especially for upgrade

```

The configuration file, is a yaml file that describe how to connect to the instances:
```yaml
primary:
   host: host:port               // IP and ssh port to connect to (port is default to 22)
   user: user                    // ssh user to connect with (default to root)
   authkey: "some auth keys"     // SSH auth keys for the primary (default to ~/.ssh/id_rsa)
   replication_enabled: false    // is replica enables (default to false)
replicas:                        // list of replicas
   - host: host:port             // IP and ssh port to connect to (port is default to 22)
     user: user                  // user to connect with default to root
     authkey: "some auth keys"   // SSH auth keys for the replica (default to ~/.ssh/id_rsa)
     active: false               // is the replica active or not (default to false)
     datacenter: "somedata"      // datacenter namegit  for geo-replication (optional)
```

The app can read config from ssh config files. To enable this use the `-use-ssh-config` option. the app expect a `config` under the configured ssh folder (the one you mentioned under `-ssh-config`). The config file should look something like below:
```
Host primary
    HostName XX.XX.XX.XX
    User admin
    Port 122
    IdentityFile ~/.ssh/some_id.key
```

### Build app locally
The source files are under `src` directory. An example of configuration file is available in `config.yml`. To build the application simply run `go build -o update-cli ./src`.