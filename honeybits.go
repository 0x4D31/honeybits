package main

import (
	"fmt"
	"github.com/spf13/viper"
	_ "github.com/spf13/viper/remote"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"github.com/0x4D31/honeybits/contentgen"
)

func check(e error) {
	if e != nil {
		os.Stderr.WriteString(fmt.Sprintf("Error: %s\n", e.Error()))
	}
}

func loadCon() (*viper.Viper, error) {
	// Reading config values from environment variables and then getting
	// the remote config (remote Key/Value store such as etcd or Consul)
	// e.g. $ export HBITS_KVSPROVIDER="consul"
	// 		$ export HBITS_KVSADDR="127.0.0.1:32775"
	//		$ export HBITS_KVSDIR="/config/hbconf.yaml"
	// 		$ export HBITS_KVSKEY="/etc/secrets/mykeyring.gpg"
	conf := viper.New()
	conf.SetEnvPrefix("hbits")
	conf.AutomaticEnv()

	conf.SetDefault("kvsprovider", "consul")
	conf.SetDefault("kvsdir", "/config/hbconf.yaml")
	conf.SetDefault("path.bashhistory", "~/.bash_history")
	conf.SetDefault("path.hosts", "/etc/hosts")
	conf.SetDefault("path.awsconf", "~/.aws/config")
	conf.SetDefault("path.awscred", "~/.aws/credentials")

	kvsaddr := conf.GetString("kvsaddr")
	kvsprovider := conf.GetString("kvsprovider")
	kvsdir := conf.GetString("kvsdir")

	// If HBITS_KVSKEY is set, use encryption for the remote Key/Value Store
	if conf.IsSet("kvskey") {
		kvskey := conf.GetString("kvskey")
		conf.AddSecureRemoteProvider(kvsprovider, kvsaddr, kvsdir, kvskey)
	} else {
		conf.AddRemoteProvider(kvsprovider, kvsaddr, kvsdir)
	}
	conf.SetConfigType("yaml")
	if err := conf.ReadRemoteConfig(); err != nil {

		// Reading local config file
		fmt.Print("Failed reading remote config. Reading the local config file...\n")
		conf.SetConfigName("hbconf")
		conf.AddConfigPath("/etc/hbits/")
		conf.AddConfigPath(".")
		if err := conf.ReadInConfig(); err != nil {
			return nil, err
		}
		fmt.Print("Local config file loaded.\n\n")
		return conf, nil
	}
	fmt.Print("Remote config file loaded\n\n")
	return conf, nil
}

func rndline(l []string) int {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	rl := r1.Intn(len(l))
	return rl
}

func contains(s []string, b string) bool {
	for _, a := range s {
		if a == b {
			return true
		}
	}
	return false
}

func linefinder(l []string, k string) int {
	linenum := 0
	for i := range l {
		if l[i] == k {
			linenum = i
		}
	}
	return linenum + 1
}

func honeybit_creator(conf *viper.Viper, htype string, hpath string, rnd string) {

	switch htype {
	case "ssh":
		sshserver := conf.GetString("honeypot.addr")
		if p := &sshserver; conf.IsSet("honeybits.ssh.server") {
			*p = conf.GetString("honeybits.ssh.server")
		}
		honeybit := fmt.Sprintf("ssh -p %s %s@%s",
			conf.GetString("honeybits.ssh.port"),
			conf.GetString("honeybits.ssh.user"),
			sshserver)
		insertbits(htype, hpath, honeybit, rnd)
	case "sshpass":
		sshserver := conf.GetString("honeypot.addr")
		if p := &sshserver; conf.IsSet("honeybits.ssh.server") {
			*p = conf.GetString("honeybits.ssh.server")
		}
		honeybit := fmt.Sprintf("sshpass -p '%s' ssh -p %s %s@%s",
			conf.GetString("honeybits.ssh.pass"),
			conf.GetString("honeybits.ssh.port"),
			conf.GetString("honeybits.ssh.user"),
			sshserver)
		insertbits(htype, hpath, honeybit, rnd)
	case "wget":
		honeybit := fmt.Sprintf("wget %s",
			conf.GetString("honeybits.wget.url"))
		insertbits(htype, hpath, honeybit, rnd)
	case "ftp":
		ftpserver := conf.GetString("honeypot.addr")
		if p := &ftpserver; conf.IsSet("honeybits.ftp.server") {
			*p = conf.GetString("honeybits.ftp.server")
		}
		honeybit := fmt.Sprintf("ftp ftp://%s:%s@%s:%s",
			conf.GetString("honeybits.ftp.user"),
			conf.GetString("honeybits.ftp.pass"),
			ftpserver,
			conf.GetString("honeybits.ftp.port"))
		insertbits(htype, hpath, honeybit, rnd)
	case "rsync":
		rsyncserver := conf.GetString("honeypot.addr")
		if p := &rsyncserver; conf.IsSet("honeybits.rsync.server") {
			*p = conf.GetString("honeybits.rsync.server")
		}
		honeybit := fmt.Sprintf("rsync -avz -e 'ssh -p %s' %s@%s:%s %s",
			conf.GetString("honeybits.rsync.port"),
			conf.GetString("honeybits.rsync.user"),
			rsyncserver,
			conf.GetString("honeybits.rsync.remotepath"),
			conf.GetString("honeybits.rsync.localpath"))
		insertbits(htype, hpath, honeybit, rnd)
	case "rsyncpass":
		honeybit := fmt.Sprintf("rsync -rsh=\"sshpass -p '%s' ssh -l %s -p %s\" %s:%s %s",
			conf.GetString("honeybits.rsync.pass"),
			conf.GetString("honeybits.rsync.user"),
			conf.GetString("honeybits.rsync.port"),
			conf.GetString("honeybits.rsync.server"),
			conf.GetString("honeybits.rsync.remotepath"),
			conf.GetString("honeybits.rsync.localpath"))
		insertbits(htype, hpath, honeybit, rnd)
	case "scp":
		scpserver := conf.GetString("honeypot.addr")
		if p := &scpserver; conf.IsSet("honeybits.scp.server") {
			*p = conf.GetString("honeybits.scp.server")
		}
		honeybit := fmt.Sprintf("scp -P %s %s@%s:%s %s",
			conf.GetString("honeybits.scp.port"),
			conf.GetString("honeybits.scp.user"),
			scpserver,
			conf.GetString("honeybits.scp.remotepath"),
			conf.GetString("honeybits.scp.localpath"))
		insertbits(htype, hpath, honeybit, rnd)
	case "mysql":
		mysqlserver := conf.GetString("honeypot.addr")
		if p := &mysqlserver; conf.IsSet("honeybits.mysql.server") {
			*p = conf.GetString("honeybits.mysql.server")
		}
		honeybit := fmt.Sprintf("mysql -h %s -P %s -u %s -p%s -e \"%s\"",
			mysqlserver,
			conf.GetString("honeybits.mysql.port"),
			conf.GetString("honeybits.mysql.user"),
			conf.GetString("honeybits.mysql.pass"),
			conf.GetString("honeybits.mysql.command"))
		insertbits(htype, hpath, honeybit, rnd)
	case "mysqldb":
		mysqlserver := conf.GetString("honeypot.addr")
		if p := &mysqlserver; conf.IsSet("honeybits.mysql.server") {
			*p = conf.GetString("honeybits.mysql.server")
		}
		honeybit := fmt.Sprintf("mysql -h %s -u %s -p%s -D %s -e \"%s\"",
			conf.GetString("honeybits.mysql.server"),
			conf.GetString("honeybits.mysql.user"),
			conf.GetString("honeybits.mysql.pass"),
			conf.GetString("honeybits.mysql.dbname"),
			conf.GetString("honeybits.mysql.command"))
		insertbits(htype, hpath, honeybit, rnd)
	case "aws":
		honeybit := fmt.Sprintf("export AWS_ACCESS_KEY_ID=%s\nexport AWS_SECRET_ACCESS_KEY=%s\naws %s --profile %s --region %s",
			conf.GetString("honeybits.aws.accesskeyid"),
			conf.GetString("honeybits.aws.secretaccesskey"),
			conf.GetString("honeybits.aws.command"),
			conf.GetString("honeybits.aws.profile"),
			conf.GetString("honeybits.aws.region"))
		insertbits(htype, hpath, honeybit, rnd)
	case "hostsconf":
		hostip := conf.GetString("honeypot.addr")
		if p := &hostip; conf.IsSet("honeybits.hostsconf.ip") {
			*p = conf.GetString("honeybits.hostsconf.ip")
		}
		honeybit := fmt.Sprintf("%s	%s",
			hostip,
			conf.GetString("honeybits.hostsconf.name"))
		insertbits(htype, hpath, honeybit, rnd)
	case "awsconf":
		honeybit := fmt.Sprintf("[profile %s]\noutput=json\nregion=%s",
			conf.GetString("honeybits.awsconf.profile"),
			conf.GetString("honeybits.awsconf.region"))
		insertbits(htype, hpath, honeybit, rnd)
	case "awscred":
		honeybit := fmt.Sprintf("[%s]\naws_access_key_id=%s\naws_secret_access_key=%s",
			conf.GetString("honeybits.awsconf.profile"),
			conf.GetString("honeybits.awsconf.accesskeyid"),
			conf.GetString("honeybits.awsconf.secretaccesskey"))
		insertbits(htype, hpath, honeybit, rnd)
		//default:
		//custom
	}
}

func insertbits(ht string, fp string, hb string, rnd string) {
	if _, err := os.Stat(fp); os.IsNotExist(err) {
		_, err := os.Create(fp)
		check(err)
	}
	fi, err := ioutil.ReadFile(fp)
	check(err)
	var lines []string = strings.Split(string(fi), "\n")
	var hb_lines []string = strings.Split(string(hb), "\n")
	if iscontain := contains(lines, hb_lines[0]); iscontain == false {
		if rnd == "true" {
			rl := (rndline(lines))
			lines = append(lines[:rl], append([]string{hb}, lines[rl:]...)...)
		} else if rnd == "false" {
			lines = append(lines, hb)
		}
		output := strings.Join(lines, "\n")
		err = ioutil.WriteFile(fp, []byte(output), 0644)
		if err != nil {
			fmt.Printf("[failed] Can't insert %s honeybit, error: \"%s\"\n", ht, err)
		} else {
			fmt.Printf("[done] %s honeybit is inserted\n", ht)
		}
	} else {
		fmt.Printf("[failed] %s honeybit already exists\n", ht)
	}
}

func honeyfile_creator(conf *viper.Viper, fp string, ft string) {
	if _, err := os.Stat(fp); err == nil {
		fmt.Printf("[failed] honeyfile already exists at this path: %s\n", fp)
	} else {
		data := contentgen.Textgen(conf, ft)
		/*switch ft {
		case "test":
			p := &data
			*p = fmt.Sprintf(testtext, "adel")	
		case "initial":
			p := &data
			*p = "hello world!"
		case "credential":
			p := &data
			*p = "admin:@123!"
		} */
		err := ioutil.WriteFile(fp, []byte(data), 0644)
		if err != nil {
			fmt.Printf("[failed] Can't create honeyfile, error: \"%s\"\n", err)
		} else {
			fmt.Printf("[done] honeyfile is created (%s)\n", fp)
		}
	}
}

func honeyfile_monitor(fp string, cf string, m string) {
	switch m {
	case "auditd":
		if runtime.GOOS == "linux" {
			searchString := fmt.Sprintf("-w %s -p rwa -k honeyfile", fp)
			out, err := exec.Command("auditctl", "-l").Output()
			check(err)
			outString := string(out[:])
			if strings.Contains(outString, searchString) == false {
				//pathArg := fmt.Sprintf("path=%s", fp)
				//err := exec.Command("auditctl", "-a", "exit,always", "-F", pathArg, "-F", "perm=wra", "-k", "honeyfile").Run()
				err := exec.Command("auditctl", "-w", fp, "-p", "wra", "-k", "honeyfile").Run()
				check(err)
				fmt.Printf("[done] auditd rule for %s is added\n", fp)
			} else {
				fmt.Print("[failed] auditd rule already exists\n")
			}
		} else {
			fmt.Print("[failed] honeybits auditd monitoring only works on Linux. Use go-audit for Mac OS\n")
		}

	case "go-audit":
		if _, err := os.Stat(cf); err == nil {
			fi, err := ioutil.ReadFile(cf)
			check(err)
			var lines []string = strings.Split(string(fi), "\n")
			rule := fmt.Sprintf("  - -a exit,always -F path=%s -F perm=wra -k honeyfile", fp)
			if iscontain := contains(lines, rule); iscontain == false {
				ruleline := linefinder(lines, "rules:")
				lines = append(lines[:ruleline], append([]string{rule}, lines[ruleline:]...)...)
				output := strings.Join(lines, "\n")
				err = ioutil.WriteFile(cf, []byte(output), 0644)
				if err != nil {
					fmt.Printf("[failed] Can't add go-audit rule, error: \"%s\"\n", err)
				} else {
					fmt.Printf("[done] go-audit rule for %s is added\n", fp)
				}
			} else {
				fmt.Print("[failed] go-audit rule already exists\n")
			}
		} else {
			check(err)
		}
	}
}

func main() {

	conf, err := loadCon()
	check(err)

	var (
		bhrnd       = conf.GetString("randomline.bashhistory")
		cfrnd       = conf.GetString("randomline.confile")
		bhpath      = conf.GetString("path.bashhistory")
		hostspath   = conf.GetString("path.hosts")
		awsconfpath = conf.GetString("path.awsconf")
		awscredpath = conf.GetString("path.awscred")
	)

	// Insert honeybits
	// [File]
	if conf.GetString("honeyfile.enabled") == "true" {
		switch conf.GetString("honeyfile.monitor") {
		case "go-audit":
			configfile := conf.GetString("honeyfile.goaudit-conf")
			if traps := conf.GetStringSlice("honeyfile.traps"); len(traps) != 0 {
				for _, t := range traps {
					tconf := strings.Split(t, ":")
					honeyfile_creator(conf, tconf[0], tconf[1])
					honeyfile_monitor(tconf[0], configfile, "go-audit")
				}
			}
		case "auditd":
			if traps := conf.GetStringSlice("honeyfile.traps"); len(traps) != 0 {
				for _, t := range traps {
					tconf := strings.Split(t, ":")
					honeyfile_creator(conf, tconf[0], tconf[1])
					honeyfile_monitor(tconf[0], "", "auditd")
				}
			}
		case "none":
			if traps := conf.GetStringSlice("honeyfile.traps"); len(traps) != 0 {
				for _, t := range traps {
					tconf := strings.Split(t, ":")
					honeyfile_creator(conf, tconf[0], tconf[1])
				}
			}
		default:
			fmt.Print("Error: you must specify one of these options for honeyfile.monitor: go-audit, auditd, none\n")
		}
	}
	// [Bash_history]
	//// SSH
	if conf.GetString("honeybits.ssh.enabled") == "true" {
		if conf.GetString("honeybits.ssh.sshpass") == "true" {
			honeybit_creator(conf, "sshpass", bhpath, bhrnd)
		} else {
			honeybit_creator(conf, "ssh", bhpath, bhrnd)
		}
	}
	//// WGET
	if conf.GetString("honeybits.wget.enabled") == "true" {
		honeybit_creator(conf, "wget", bhpath, bhrnd)
	}
	//// FTP
	if conf.GetString("honeybits.ftp.enabled") == "true" {
		honeybit_creator(conf, "ftp", bhpath, bhrnd)
	}
	//// RSYNC
	if conf.GetString("honeybits.rsync.enabled") == "true" {
		if conf.GetString("rsync.sshpass") == "true" {
			honeybit_creator(conf, "rsyncpass", bhpath, bhrnd)
		} else {
			honeybit_creator(conf, "rsync", bhpath, bhrnd)
		}
	}
	//// SCP
	if conf.GetString("honeybits.scp.enabled") == "true" {
		honeybit_creator(conf, "scp", bhpath, bhrnd)
	}
	//// MYSQL
	if conf.GetString("honeybits.mysql.enabled") == "true" {
		if conf.IsSet("mysql.dbname") {
			honeybit_creator(conf, "mysqldb", bhpath, bhrnd)
		} else {
			honeybit_creator(conf, "mysql", bhpath, bhrnd)
		}
	}
	//// AWS
	if conf.GetString("honeybits.aws.enabled") == "true" {
		honeybit_creator(conf, "aws", bhpath, bhrnd)
	}
	// [Hosts Conf]
	if conf.GetString("honeybits.hostsconf.enabled") == "true" {
		honeybit_creator(conf, "hostsconf", hostspath, cfrnd)
	}
	// [AWS Conf]
	if conf.GetString("honeybits.awsconf.enabled") == "true" {
		honeybit_creator(conf, "awsconf", awsconfpath, cfrnd)
		honeybit_creator(conf, "awscred", awscredpath, cfrnd)
	}
	// Custom bits in bash_history
	if cb := conf.GetStringSlice("honeybits.custom"); len(cb) != 0 {
		for _, v := range cb {
			insertbits("custom", bhpath, v, bhrnd)
		}
	}
}

