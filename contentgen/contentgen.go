package contentgen

import (
	"fmt"
	"github.com/spf13/viper"
	"io/ioutil"
	"os"
)


func readtemplate(tp *string, fp string) {
	if fi, err := ioutil.ReadFile(fp); err != nil {
			os.Stderr.WriteString(fmt.Sprintf("Error: %s\n", err.Error()))
		} else {
			*tp = string(fi)
		}
}

func Textgen(conf *viper.Viper, ctype string, ctemp string) string {
	addr := conf.GetString("honeypot.addr")
	data := ""
	template := ""
	t := &template

	switch ctype {
		case "rdpconn":
			if ctemp == "config" {
				*t = conf.GetString("contentgen.rdpconn.template")
			} else {
				readtemplate(t, ctemp)
			}
			if ap := &addr; conf.IsSet("contentgen.rdpconn.server") {
				*ap = conf.GetString("contentgen.rdpconn.server")
			}
			p := &data
			*p = fmt.Sprintf(template, addr, conf.GetString("contentgen.rdpconn.user"), conf.GetString("contentgen.rdpconn.domain"), conf.GetString("contentgen.rdpconn.pass"))	
		case "txtemail":
			if ctemp == "config" {
				*t = conf.GetString("contentgen.txtemail.template")
			} else {
				readtemplate(t, ctemp)
			}
			if ap := &addr; conf.IsSet("contentgen.txtemail.server") {
				*ap = conf.GetString("contentgen.txtemail.server")
			}
			p := &data
			*p = fmt.Sprintf(template, addr, conf.GetString("contentgen.txtemail.user"), conf.GetString("contentgen.txtemail.pass"))
		default:
			p := &data
			*p = "Hello World!"
		}
	return data
}