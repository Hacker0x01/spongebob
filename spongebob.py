#!/usr/bin/env python
# 
"""
Spongebob - produce open ports change reports.
"""
import time, datetime
import re
import optparse
import syslog
import itertools
import json
import cStringIO
import xml.etree.cElementTree as ET
import subprocess
import multiprocessing
import netaddr
import boto.ec2

def getconfig(configfile):
    """Read a JSON format configuration file and export it as a dict."""
    with open(configfile) as cfd:
        config = json.load(cfd)
        return config


def getNetblocks(conf):
    """Generate lists of netblocks with description from config file."""
    networks = {}
    for net in conf['target_networks']:
        description = conf['target_networks'][net]
        networks[description] = [net]
    return networks


def getAWSregions(aws_key, aws_secret):
    """Returns a list of current AWS regions. Some regions are blacklisted.

    :param aws_key:    AWS access key id
    :type aws_key:     string
    :param aws_secret: AWS secret access key
    :type aws_secret:  string
    :returns:          list of regions
    """
    # these are failing 4/29/14
    blacklist = ['us-gov-west-1', 'cn-north-1']
    regions = boto.ec2.regions(aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret)
    return [r.name for r in regions if r.name not in blacklist]


def make_cache(obj, fname):
    """Create a JSON cache of obj into fname.
    
    :param obj: object to cache
    :param fname: file to write to
    """
    with open(fname, 'w') as cache:
        json.dump(obj, cache)


def getAWShosts(conf):
    """Generate list of AWS hosts with public ip addresses.
    
    :param conf: configuration dict
    :returns: networks dict
    
    First get a list of all regions, then connect with all accounts
    to each in turn and pull all instances. Filter out instances without 
    assigned IP address.
    """
    # use the first credentials to get list of AWS regions
    u = conf['aws_credentials'].keys()[0]
    regions = getAWSregions(conf['aws_credentials'][u]['aws_access_key_id'], 
        conf['aws_credentials'][u]['aws_secret_access_key'])
    # go through all credentials we have and find hosts in all regions
    networks = {}
    for account, creds in conf['aws_credentials'].iteritems():
        myid = creds['aws_access_key_id']
        mykey = creds['aws_secret_access_key']
        iplist = []
        for region in regions:
            allinstances = instances = []
            conn = boto.ec2.connect_to_region(region, aws_access_key_id=myid,
                    aws_secret_access_key=mykey)
            instances = [i for i in conn.get_only_instances() if i.ip_address is not None]
            conn.close()
            if len(instances):
                for i in instances:
                    iplist.append(i.ip_address)
        if len(iplist):
            networks[account] = iplist        
    return networks


def nmap_command(target):
    """Construct a nmap command line and run it in a subprocess.

    :param target: currently a single IP (v4 or v6) address
    :returns: string of XML gibberish
    """
    nmap = conf['nmap_profile']['nmap_bin']
    args = conf['nmap_profile']['nmap_args']
    if netaddr.IPNetwork(target).version == 6:
        args = '-6 ' + args
    
    command = "{0} {1} {2}".format(nmap, args, target)
    t0 = time.time()
    result = subprocess.check_output(command.split())
    t1 = time.time()
    syslog.syslog('target {0} scanned in {1:.2f} seconds'.format(target, t1 - t0))
    return result


def run_nmap(targets):
    """Run nmap scans using the multiprocessing module.

    Input: dict of "network: [ip, ip, network], ..."
    Output: list of strings
    XXX: see if chunking targets and using nmap threads would be good.
    XXX: use Queue instead (current is ok with tcp scans)
    """
    my4targets = []
    my6targets = []
    results4 = []
    results6 = []
    for ip in list(itertools.chain.from_iterable(targets.values())):
        i = netaddr.IPNetwork(ip)
        if i.version == 4:
            if i.prefixlen == 32:
                my4targets.append(str(i.ip))
            else:
                # valid host addresses from CIDR spec
                for a in netaddr.IPNetwork.iter_hosts(i):
                    my4targets.append(str(a))
        elif i.version == 6:
            if i.prefixlen == 128:
                my6targets.append(str(i.ip))
            else:
                for a in netaddr.IPNetwork.iter_hosts(i):
                    my6targets.append(str(a))

    syslog.syslog("Got {} IPv4 and {} IPv6 target addresses.".format(len(my4targets), len(my6targets)))
    procs = multiprocessing.cpu_count() * 8
    syslog.syslog('starting pool with {} workers'.format(procs))
    pool = multiprocessing.Pool(processes = procs)
    if len(my4targets):
        results4 = pool.map(nmap_command, my4targets)
    if len(my6targets):
        results6 = pool.map(nmap_command, my6targets)
    pool.close()
    pool.join()

    return results4 + results6
    


def combine_report(reports, savefile):
    """Generate a combined report from multiple nmap scans' XML reports (-oX).
    
    This allows us to use stock ndiff (either command or library) to parse the
    differences. Should be more robust that way.

    Input: list of strings
    Output: none, saves result in file named based on current time.
    """
    # ElementTree needs to be created from a file-like object
    dummy = '<nmaprun></nmaprun>'
    combinedreport = ET.ElementTree(file=cStringIO.StringIO(dummy))
    combinedreportroot = combinedreport.getroot()
    # copy the nmaprun attributes from the first report to squelch parsing
    # errors. Remove IP address from 'args' attribute (it refers to a single
    # run).
    report0 = ET.fromstring(reports[0])
    for k, v in report0.items():
        if k == 'args':
            noip = re.sub('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', v, '')
            v = noip
        combinedreportroot.set(k, v)
    
    for report in reports:
        scan = ET.fromstring(report)
        for host in scan.iter('host'):
            combinedreportroot.append(host)
    combinedreport.write(savefile)
    

def main():
    global conf
    opt = optparse.OptionParser()
    opt.add_option('-c', '--config', dest='configfile', type='string', 
            default = 'config.json', metavar='FILE', 
            help='Specify configuration FILE path. Default is ./config.json')
    (options, args) = opt.parse_args()
    conf = getconfig(options.configfile)

    syslog.openlog('SpongeBob', logoption=syslog.LOG_PID)
    syslog.syslog('starting')

    networks = {}
    t0 = time.time()
    networks.update(getNetblocks(conf))
    networks.update(getAWShosts(conf))
    t1 = time.time()
    syslog.syslog('{} networks/tags discovered in {} seconds.'.format(len(networks), t1 - t0))
    
    make_cache(networks, conf['spongebob']['savedirectory'] + '/networks.json')
    
    t0 = time.time()
    reports = run_nmap(networks)
    t1 = time.time()
    syslog.syslog('{} hosts scanned in {} seconds.'.format(len(reports), t1 - t0))

    savefile = '{0}/{1}'.format(conf['spongebob']['savedirectory'], 
            datetime.datetime.now().strftime(conf['spongebob']['savepattern']))
    combine_report(reports, savefile)
    syslog.syslog('report written to {}'.format(savefile))

if __name__ == "__main__":
    main()
