# Flaway
Flaway is a Custom kernel setup configuration menu that is coded in python that automated some default setup configrations in order to have as least amount of downtime as possible.

What operating systems is this used for?   
  Debian | Ubuntu | Some Features Like the netfilter install may be different depending on your OS
All code was tested & debugged through the python3.9.0 Shell.


Configure Your machine to your likeing by editing 'settings'.

Options:
```
Install antivirus software       : False
~ Custom Made antivirus Software For logging foreighn IP Connections
```

```
make software a startup service  : False
~ Using the information given in Install antivurs software Create a Startup Service
```

```
Change Default Kernal to FISH    : False / Highly Reccomending For root users.
~ Change your current users Default shell, This will effect basic FTP UIs.
```

```
Disable Port Scanning on machine : False 
~ Using IP-Tables Block port Scanning on other machines
```

```
Secure your machines ports       : False
~ Secure Yourself Against Basic Denial of service attacks & basic overflows & attacks on port 0
Also Blocks connections from Private IP addresses on Servers Network.
```

```
install firewall(Netfilter)      : False
~  Install a public NetFilter-That is easy to use, very migratable.
```

```
Update & Upgrade your Kernel     : False
~ Runs 'apt-get update -y' & 'apt-get upgrade -y'
```

```
Change Default SSH port          : 22
~ Change your current SSH Port (will default any configurations)
```

