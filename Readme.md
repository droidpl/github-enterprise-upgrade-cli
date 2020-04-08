# Github Enterprise upgrade command line tool

Command line tool, built with golang for automatic upgrade/patch of Github Entreprise. It support both single instance and multi replicas

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
  -dry-run boolean
        If true, only print how teh execution looks like, without running it.
  -update-host-keys boolean
        Grep new SSH host keys from the machine after rebooting the server, especially for upgrade
```

The configuration file, is a yaml file that describe how to connect to the instances:
```yaml
primary:
   host: host:port               // IP and ssh port to connect to (port is default to 22)
   user: user                    // ssh user to connect with (default to root)
   replication_enabled: false    // is replica enables (default to false)
replicas:                        // list of replicas
   - host: host:port             // IP and ssh port to connect to (port is default to 22)
     user: user                  // user to connect with default to root
     active: false               // is the replica active or not (default to false)
     datacenter: "somedata"      // datacenter name for georeplication (optional)
```
