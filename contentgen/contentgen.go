package contentgen

import (
	"fmt"
	"github.com/spf13/viper"
)


var rdpConn string = `screen mode id:i:2
desktopwidth:i:1024
desktopheight:i:768
use multimon:i:1
session bpp:i:24
full address:s:%s
compression:i:1
audiomode:i:2
username:s:%s
domain:s:%s
authentication level:i:0
clear password:s:%s
disable wallpaper:i:0
disable full window drag:i:0
disable menu anims:i:0
disable themes:i:0
alternate shell:s:
shell working directory:s:
authentication level:i:2
connect to console:i:0
gatewayusagemethod:i:0
disable cursor setting:i:0
allow font smoothing:i:1
allow desktop composition:i:1
redirectprinters:i:0
prompt for credentials on client:i:1
use redirection server name:i:0`


var txtEmail string = `From: Adel 0x <adel@trapbits.com>
Subject: Re: Monitoring system
Date: March 22, 2017 at 21:59:15 GMT+11
To: Dave Cohen <dave.cohen@trapbits.com>
Cc: security <security@trapbits.com>

Hi,

Ah, sorry I forgot to send you the new address: http://%s/login
I also reset your password to the default pass: %s (user: %s)

Please set the MFA (multi-factor authentication) ASAP.

Cheers,
Adel

On 22 Mar 2017, at 9:57 pm, Dave Cohen <dave.cohen@trapbits.com> wrote:

Hi Adel,

I just wanted to login to the Monitoring system, but I get 404 error. Could you please have a look at it?

Thanks
Dave

The information contained in this email and any attachments is confidential and/or privileged. This email and any attachments are intended to be read only by the person named above. If the reader of this email, and any attachments, is not the intended recipient, you are hereby notified that any review, dissemination or copying of this email and any attachments is prohibited. If you have received this email and any attachments in error, please notify the sender by email or telephone and delete it from your email client.`


func Textgen(conf *viper.Viper, ct string) string {
	addr := conf.GetString("honeypot.addr")
	data := ""
	switch ct {
		case "rdpconn":
			if ap := &addr; conf.IsSet("contentgen.rdpconn.server") {
				*ap = conf.GetString("contentgen.rdpconn.server")
			}
			p := &data
			*p = fmt.Sprintf(rdpConn, addr, conf.GetString("contentgen.rdpconn.user"), conf.GetString("contentgen.rdpconn.domain"), conf.GetString("contentgen.rdpconn.pass"))	
		case "txtemail":
			if ap := &addr; conf.IsSet("contentgen.txtemail.server") {
				*ap = conf.GetString("contentgen.txtemail.server")
			}
			p := &data
			*p = fmt.Sprintf(txtEmail, addr, conf.GetString("contentgen.txtemail.pass"), conf.GetString("contentgen.txtemail.user"))
		default:
			p := &data
			*p = "Hello World!"
		}
	return data
}