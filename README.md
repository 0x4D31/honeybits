# honeybits
A simple tool to create and place breadcrumbs, honeytoken/traps or as I call it "honeybits", to lead the attackers to your decoys/honeypots! #cyber_deception #honeytoken

The problem with the traditional implementation of honeypots in production environments is that the bad guys can ONLY discover the honeypots by network scanning which is noisy! The only exception I can think of is [Beeswarm](https://github.com/honeynet/beeswarm) (it intentionally leaks credentials in the network traffic and then looks for the unexpected reuse of these honey credentials).

If you take a look at the [Mitre ATT&CK Matrix](https://attack.mitre.org/wiki/Main_Page), you will see that 'Network Service Scanning' is only one of the many different Post-breach activities of attackers. The more you plant false or misleading information in response to the post-compromise techniques (specially the techniques under ‘credential access’, ‘Discovery’, and ‘Lateral movement’ tactics in ATT&CK matrix), the greater the chance of catching the attackers. "Honeybits" helps you automate the creation of breadcrumbs/honeytokens on your production Servers and Workstations. These honeytokens or breadcrumbs can include:
* Fake bash_history commands (such as ssh, ftp, rsync, scp, mysql, wget, awscli)
* Fake AWS credentials and config files (you required to create fake AWS IAM users with no permissions and generate access keys for them)
* Configuration, backup and connection files such as RDP and VPN
* Fake entries in hosts, ARP table, etc.
* Fake browser history, bookmarks and saved passwords
* Injected fake credentials into LSASS
* Fake registry keys

This is a small but crusial component of your deception system which should also include honeypots (ideally high-interaction ones), Log collection and analysis system, alerting, and so on. 

![Honeybits](https://github.com/0x4D31/honeybits/blob/master/docs/honeybits.png)

###Current features:
* Creating honeyfiles and monitoring the access to these traps using go-audit or auditd 
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
  + aws


###Installation:
Following are the list of prerequisite that you need to fulfill to 
run the test smoothly.
(Note: This is tested on ubuntu 16.04)
* GO_LANG 
  + Install GO_LANG 
```$ sudo apt-get install golang-go```
  + Set the GOPATH
```$ export GOPATH="/usr/share/go"```
  + Add Go path in environment
```$ sudo nano /etc/environment``` and add the GOPATH="/usr/share/go/" at the end.
  + Update the source
```$ source /etc/environment```
  + Install Viper dependency for honeybits
```$ sudo go get github.com/spf13/viper```
  + Install crypt dependency
```$ sudo go get github.com/xordataexchange/crypt/config```

* Audit 
    + Install the Audit package that will monitor the honeyfile that will be created after the build
```$ sudo apt-get install auditd audispd-plugins```

* AWS
    + Install the AWS that will used for AWS honeybits configuration
```$ sudo apt install awscli```

You are done here with prerequisites the important file you have to play with is *hbconf.yaml*, 
here you can specify the following things
* Path where you want to create the honeybits bashhistory file 
* IP Address of an honeypot where you want to redirect the attacker
* file which you want to monitor named as *traps* in configurations
* Fake credentials and configurations for honeybits and honeyfiles

If you want to test with the default configurations you have to create the following directories 
*/home/test*
*/home/test/.aws/

    export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    aws ec2 describe-instance --profile devops --region us-east-2
```
* Insert honeybits into AWS config and credentials file
* Insert honeybits into /etc/hosts
* Reading config from a Remote Key/Value Store such as Consul or etcd
  
```


###Test:
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

###Reading the audit results###
To view the audit rules you have to run use the *auditctl* `$ sudo auditctl -l`
To view the adversiry activity on the file we want to monitor `$ sudo ausearch -f /opt/secret.txt`

    time->Tue Mar 14 11:07:28 2017
        type=PROCTITLE msg=audit(1489471648.788:1562): proctitle=6E616E6F002F6F70742F7365637265742E747874
        type=PATH msg=audit(1489471648.788:1562): item=1 *name="/opt/secret.txt"* inode=22806636 dev=fc:00 mode=0100644 ouid=0 ogid=0 rdev=00:00      nametype=NORMAL
        type=PATH msg=audit(1489471648.788:1562): item=0 name="/opt/" inode=22806529 dev=fc:00 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT
        type=CWD msg=audit(1489471648.788:1562):  *cwd="/home/waseem/honeybits"*
        type=SYSCALL msg=audit(1489471648.788:1562): arch=c000003e *syscall=2* success=no exit=-13 a0=18f2f70 a1=441 a2=1b6 a3=7f0751a1ab78 items=2 ppid=2147 pid=18616 *auid=1000* uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="nano" *exe="/bin/nano"* key="honeyfile"
 ```
Some highlights of this output are:

The *time* of the event and the name of the object, the current working path (*cwd*), related *syscall*, audit user ID (*auid*) and the binary (*exe*) performing the action upon the file. Please note that the auid defines the original user during log-in. The other user ID fields might indicate a different user, depending on the effective user being used while triggering an event.

You can use *ausyscall* to understand/converting the System call 
     
    $ ausyscall x86_64 2
    open

```
###TODO:
* Content generator for honeyfiles and file honeybits
  + note: honeyfiles are fake monitored files with random content (doesn't matter), but file honeybits are like connection, config, or backup files that may contain credentials and point the attackers to our honeypots/decoys
* Add more Credential Traps
  + Configuration, connection and backup files (file honeybit)
* Add more Network Traps
  + Monitoring some network traps using go-audit
* Add Application Traps
* Add Windows support (current version supports Linux and Mac OS X)
  + New traps including CMD/PowerShell commands history, Browser history, Saved passwords, Registry keys, Credentials, Connection and configuration files such as .rdp and etc.
* Documentation

