'''definitely need to rewrite the wrapper for this'''

import securitycenter
import subprocess
import time
import os
import sys
import re
from smtplib import SMTP  
from email.mime.text import MIMEText

def get_info(sc):
    SMTPserver = #smtpServer you are going to use to send the mail  
    sender =  #who you are sending from
    destination = []
    text_subtype = 'plain'
    subject="Scanner Error"

    print (time.strftime('%Y/%m/%d %H:%M:%S'))
    stats = 0
    resp = sc.get('scanner', params={'fields': 'ip,status,name'})
    for scan in resp.json()['response']:
        scannerstatus = int(scan['status'])
        if scannerstatus != 1:
            if scannerstatus != 16384:
                content = str(scan['name']) + " is down"
                name = str(scan["name"])
                try:
                    msg = MIMEText(content, text_subtype)
                    msg['Subject']=       subject
                    msg['From']   = sender # some SMTP servers will do this automatically, not all

                    conn = SMTP(SMTPserver)
                    conn.set_debuglevel(False)
                    try:
                        conn.sendmail(sender, destination, msg.as_string())
                    finally:
                        conn.quit()
                except Exception, exc:
                    sys.exit( "mail failed; %s" % str(exc) ) # give a error message

    
    
if __name__ == '__main__':
    print time.strftime("%c")
    host = raw_input('SecurityCenter Server : ') #hard code these 3 params or conf file them if you want to run on cron
    username = raw_input('SecurityCenter Username : ')
    password = raw_input('SecurityCenter Password : ')
    sc = securitycenter.SecurityCenter5(host)
    sc.login(username, password)
    "Login Successful"
    scanners = get_info(sc)
