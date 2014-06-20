#!/usr/bin/env python
#
import os, sys, glob, optparse
import re, json, netaddr
import time, socket
import subprocess
import smtplib
import syslog
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

try:
    import cStringIO as StringIO
except ImportError:
    import StringIO
import ndiff
from spongebob import getconfig


def run_ndiff(filea, fileb):
    """Run ndiff, return diff as string.
    
    :param: filea, fileb: pathnames
    :returns: diff as string, '' if no diff
    """
    try:
        scan_a = ndiff.Scan()
        scan_a.load_from_file(filea)
        scan_b = ndiff.Scan()
        scan_b.load_from_file(fileb)
    except IOError, e:
        print >> sys.stderr, u"Can't open file: %s" % str(e)
        sys.exit(2)
    
    # not sure why returning a StringIO filehandle won't work, but that's why
    # we're reading it here and returning a string.
    fh = StringIO.StringIO()
    #diff = ndiff.ScanDiffXML(scan_a, scan_b, f=fh)
    diff = ndiff.ScanDiffText(scan_a, scan_b, f=fh)
    cost = diff.output()
    if cost: # there is a diff
        fh.flush()
        out = fh.getvalue()
        fh.close()
        return out
    else:
        return ''


def parse_report(thediff):
    """Parses an ndiff text report. 

    :param: thediff: string
    :returns: dict of hostaddress: [list, of, port, changes]
    """
    # this RE pulls IP address preceded by [ +-] tag
    # line can be:
    # +123.123.123.4: or -1.2.3.4 (host.example.com):
    ippat = re.compile('([ \+-]).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?:$')

    report = re.split('\n\n', thediff)
    hosts = {}
    # stuff nmap headers into hosts dict
    hosts['header'] = report[0]
    for record in report:
        ports = []
        lines = record.split('\n')
        m = re.search(ippat, lines[0])
        if m:
            hostaddr = m.groups()[0] + m.groups()[1]
            for line in lines[1:]:
                # match port spec lines: +22/tcp, -53/udp, etc
                if re.match('([ +-])(\d+)/(tcp|udp)', line):
                    ports.append(line)
            hosts[hostaddr] = ports
        else:
            continue             
    return hosts


def html_wrapper(content):
    """Quick and dirty way to try getting around some webmail client's inconsistent
    display of multipart messages that have plain and html content.
    """
    htmldecl = '<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">'
    return """%s<html><head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>Nmap diff report</title>
    </head><body><pre>%s</pre></body></html>
    """ % (htmldecl, content)

    
def print_report(networks, hosts, showfiltered):
    """Produce the report, sorted by 'network' (description or AWS account name)

    :param: networks
    :param: hosts
    """
    header = hosts.pop('header', '')
    output = ''
    for net, ips in networks.items():
        hasinfo = False # does this network have information it it
        out = "** {}\n".format(net)
        for host in hosts:
            if netaddr.IPAddress(host[1:]) in netaddr.IPSet(ips):
                try:
                    hname = '(%s)' % socket.gethostbyaddr(host[1:])[0]
                except:
                    hname = ''
                out = out + "\n{} {}\n".format(host, hname)
                hasinfo = True
                for port in hosts[host]:
                    portinfo = port.split(None, 3)
                    for i in range(len(portinfo), 4):
                        portinfo.insert(i, '')
                    status = portinfo[1]
                    if (showfiltered == False) and (status == 'filtered'):
                        pass
                    else:
                        out = out + "  {}\n".format(port)
                continue
        if hasinfo:
            output = output + out + '\n\n'
    header = header + '\n' + \
        'Run from: %s\n%s\n\n' % (socket.getfqdn(), '=' * 72)
    return html_wrapper(header + output)


def get_saved_scans(sdir, scantime):
    """Given timespec of previous, day, week, find the appropriate 'scan_a'
    (older) file.
   
    :param: sdir, savedirectory
    :param: scantime, string: 'previous', 'day', 'week'
    :returns: filename string
    """
    # create a list of nmaprun files, sort latest first
    files = filter(os.path.isfile, glob.glob(sdir  + 'nmaprun*.xml'))
    filedatelist = [(f, os.path.getmtime(f)) for f in files]
    filedatelist.sort(reverse=True, key=lambda x: x[1])
    now = time.time()

    scanb = filedatelist[0][0]   # newest file

    if scantime == 'previous':
        scana = filedatelist[1][0]
    elif scantime == 'day':
        for f in filedatelist:
            if f[1] <= now - (23 * 60 * 60):
                scana = f[0]
                break
    elif scantime == 'week':
        for f in filedatelist:
            if f[1] <= now - (7 * 24 * 60 * 60):
                scana = f[0]
                break
        else: # else-for!
            scana = filedatelist[len(filedatelist)][0]
    return (scana, scanb)


def main():
    global options
    opt = optparse.OptionParser()
    opt.add_option('-c', '--config', dest='configfile', type='string', 
        default='config.json', action='store',
        metavar='FILE', help='Specify configuration FILE path. Default ./config.json')
    opt.add_option('-d', '--diff', action='store', type='string', dest='difftime',
         default='previous', 
         help='Diff timescale, either "day", "week", or "previous" (default)')
    opt.add_option('--showfiltered', dest='showfiltered', action='store_false',
            default='False', help='Show ports in "filtered" state')
    (options, args) = opt.parse_args()

    conf = getconfig(options.configfile)
    sdir = conf['spongebob']['savedirectory'] + '/'


    # load networks info from cache (created by spongebob.py)
    with open(sdir + conf['spongebob']['cachefile']) as cf:
        networks = json.load(cf)

    syslog.openlog('SpongeBob reporter')
    syslog.syslog('starting.')

    try:       
        scana, scanb = get_saved_scans(sdir, options.difftime)
	syslog.syslog('scan files: %s, %s' % (scana, scanb))
        mydiff = run_ndiff(scana, scanb)
	
        hosts = parse_report(mydiff)
        if len(hosts.keys()) <= 1:
            # no results (1 is header)
            syslog.syslog('NO DIFFS: Have a nice day.')
            sys.exit(0)
	else:
            syslog.syslog('{} hosts changed'.format(len(hosts.keys())))

        ndiffreport = print_report(networks, hosts, options.showfiltered)
        nmapdetails = subprocess.check_output(['xsltproc', 
            '/usr/local/share/nmap/nmap.xsl', scanb])

        msg = MIMEMultipart()
        msg['Subject'] = 'Spongebob report'
        msg['From'] = conf['spongebob']['emailfrom']
        msg['To'] = conf['spongebob']['emailto']
        part1 = MIMEText(ndiffreport, 'html')
        part2 = MIMEText(nmapdetails, 'html')
        part2.add_header('Content-Disposition', 'attachment', filename = scanb + '.html')
        msg.attach(part1)
        msg.attach(part2)
        s = smtplib.SMTP(conf['spongebob']['emailserver'])
        r = s.sendmail(conf['spongebob']['emailfrom'], 
            conf['spongebob']['emailto'], 
            msg.as_string())
        if r:
            syslog.syslog('Error sending mail: %s' % (r,))
        s.quit()
    
    except Exception as e:
        msg = MIMEText('Spongebob reporter.py ran into an error as follows.\n\n%s'
                % repr(e), 'plain')
        msg['Subject'] = 'Spongebob Error report'
        msg['From'] = conf['spongebob']['emailfrom']
        msg['To'] = conf['spongebob']['errorsto']
        s = smtplib.SMTP(conf['spongebob']['emailserver'])
        r = s.sendmail(conf['spongebob']['emailfrom'],
            conf['spongebob']['errorsto'],
            msg.as_string())
        if r:
            syslog.syslog('IN EXCEPTION: message sending failed.')
        s.quit()



if __name__ == "__main__":
    main() 
