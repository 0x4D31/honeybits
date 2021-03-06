# Honeybits
A simple PoC tool designed to enhance the effectiveness of your traps by spreading breadcrumbs & honeytokens across your production servers and workstations to lure the attacker toward your honeypots.

_Author: Adel "0x4D31" Karimi._

The Windows version of this project: [honeybits-win](https://github.com/0x4D31/honeybits-win)

## Background

Although honeypots are used by security researchers to study the attackers’ tools, techniques and motives for many years, they still have not been widely accepted and deployed in production environments. One reason is that the traditional implementation of honeypots is static and success is based on an attacker discovering it (which usually requires network scanning)!

Taking a look at the [Mitre ATT&CK Matrix](https://attack.mitre.org/wiki/Main_Page), you will see that 'Network Service Scanning' is only one of the many different Post-compromise activities. **The more you plant false or misleading information in response to the post-compromise techniques** (specially the techniques under ‘credential access’, ‘Discovery’, and ‘Lateral movement’ tactics in ATT&CK matrix), **the greater the chance of catching the attackers**. _Honeybits_ helps you automate the creation of breadcrumbs/honeytokens on your production Servers and Workstations. These honeytokens or breadcrumbs include:
* Fake bash_history commands (such as ssh, ftp, rsync, scp, mysql, wget, awscli)
* Fake AWS credentials and config files (you required to create fake AWS IAM users with no permissions and generate access keys for them)
* Configuration, backup and connection files such as RDP and VPN
* Fake entries in hosts, ARP table, etc.
* Fake browser history, bookmarks and saved passwords
* Injected fake credentials into LSASS
* Fake registry keys

![Honeybits](https://github.com/0x4D31/honeybits/blob/master/docs/honeybits.png)

## Features
* Creating honeyfiles and monitoring the access to these traps using go-audit or auditd 
* Template based content generator for honeyfiles
* Insert honeybits into AWS config and credentials file
* Insert honeybits into /etc/hosts
* Reading config from a Remote Key/Value Store such as Consul or etcd
* Insert different honeybits into "bash_history", including the following sample commands:
  + ssh
```(sshpass -p '123456' ssh -p 2222 root@192.168.1.66)```
  + ftp
```(ftp ftp://backup:b123@192.168.1.66:2121)```
  + rsync
```(rsync -avz -e 'ssh -p 2222' root@192.168.1.66:/var/db/backup.tar.gz /tmp/backup.tar.gz)```
  + scp
```(scp -P 2222 root@192.168.1.66:/var/db/backup.tar.gz /tmp/backup.tar.gz)```
  + mysql
```(mysql -h 192.168.1.66 -P 3306 -u dbadmin -p12345 -e "show databases")```
  + wget
```(wget http://192.168.1.66:8080/backup.zip)```
  + any custom commands:
```(nano /tmp/backup/credentials.txt)```
  + aws:
```
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws ec2 describe-instances --profile devops --region us-east-2
```

## Requirements
* [Go Lang 1.7+](https://golang.org/dl/)
* Viper (```go get github.com/spf13/viper```)
* crypt (```go get github.com/xordataexchange/crypt/config```)
* [go-audit](https://github.com/slackhq/go-audit) or auditd (if you want to monitor the honeyfiles)

## Usage:
```
$ go build
$ sudo ./honeybits 

Failed reading remote config. Reading the local config file...
Local config file loaded.

[failed] honeyfile already exists at this path: /tmp/secret.txt
[done] go-audit rule for /home/test/secret.txt is added
[done] honeyfile is created (/home/test/secret.txt)
[done] go-audit rule for /opt/secret.txt is added
[done] sshpass honeybit is inserted
[done] wget honeybit is inserted
[done] ftp honeybit is inserted
[done] rsync honeybit is inserted
[done] scp honeybit is inserted
[done] mysql honeybit is inserted
[failed] aws honeybit already exists
[done] hostsconf honeybit is inserted
[done] awsconf honeybit is inserted
[done] awscred honeybit is inserted
[done] custom honeybit is inserted
```

## TODO:
- [ ] Rewrite the whole code. Current code is crap (just a PoC)!
- [ ] Improve the Content generator
- [ ] More traps, including:
  - [ ] Beacon documents
  - [ ] KeePass file with entries (.kdbx)
  - [ ] Database files/backups: SQLite, MySQL
  - [ ] Fake security scan results such as Nmap output
  - [ ] Binary files with hardcoded IP / credentials
- [ ] More network traps
  - [ ] Fake PCAP / network traffic containing credentials and etc.
  - [ ] Fake ARP Table entries
  - [ ] Monitoring network traps using go-audit
- [ ] Complete the Windows version (honeybits-win)
- [ ] Documentation
