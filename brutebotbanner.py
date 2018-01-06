#!/usr/bin/env python2

from os import geteuid, devnull
import logging
# shut up scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb=0
from sys import exit
import argparse
from subprocess import Popen, PIPE
from collections import OrderedDict
import datetime
##########################
# built from net-creds.py
# https://github.com/DanMcInerney/net-creds/blob/master/net-creds.py
#########################

DN = open(devnull, 'w')
pkt_frag_loads = OrderedDict()
creds= set()
ips=set()

# Regexs
authenticate_re = '(www-|proxy-)?authenticate'
authorization_re = '(www-|proxy-)?authorization'

#Console colors
W = '\033[0m'  # white (normal)
T = '\033[93m'  # tan

def parse_args():
   """Create the arguments"""
   parser = argparse.ArgumentParser()
   parser.add_argument("-i", "--interface", help="Choose an interface")
   parser.add_argument("-p", "--pcap", help="Parse info from a pcap file; -p <pcapfilename>")
   parser.add_argument("-f", "--filterip", help="Do not sniff packets from this IP address; -f 192.168.0.4")
   return parser.parse_args()

def iface_finder():
    try:
        ipr = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
        for line in ipr.communicate()[0].splitlines():
            if 'default' in line:
                l = line.split()
                iface = l[4]
                return iface
    except IOError:
        exit('[-] Could not find an internet active interface; please specify one with -i <interface>')

def frag_remover(ack, load):
    '''
    Keep the FILO OrderedDict of frag loads from getting too large
    3 points of limit:
        Number of ip_ports < 50
        Number of acks per ip:port < 25
        Number of chars in load < 5000
    '''
    global pkt_frag_loads

    # Keep the number of IP:port mappings below 50
    # last=False pops the oldest item rather than the latest
    while len(pkt_frag_loads) > 50:
        pkt_frag_loads.popitem(last=False)

    # Loop through a deep copy dict but modify the original dict
    copy_pkt_frag_loads = copy.deepcopy(pkt_frag_loads)
    for ip_port in copy_pkt_frag_loads:
        if len(copy_pkt_frag_loads[ip_port]) > 0:
            # Keep 25 ack:load's per ip:port
            while len(copy_pkt_frag_loads[ip_port]) > 25:
                pkt_frag_loads[ip_port].popitem(last=False)

    # Recopy the new dict to prevent KeyErrors for modifying dict in loop
    copy_pkt_frag_loads = copy.deepcopy(pkt_frag_loads)
    for ip_port in copy_pkt_frag_loads:
        # Keep the load less than 75,000 chars
        for ack in copy_pkt_frag_loads[ip_port]:
            # If load > 5000 chars, just keep the last 200 chars
            if len(copy_pkt_frag_loads[ip_port][ack]) > 5000:
                pkt_frag_loads[ip_port][ack] = pkt_frag_loads[ip_port][ack][-200:]

def frag_joiner(ack, src_ip_port, load):
    '''
    Keep a store of previous fragments in an OrderedDict named pkt_frag_loads
    '''
    for ip_port in pkt_frag_loads:
        if src_ip_port == ip_port:
            if ack in pkt_frag_loads[src_ip_port]:
                # Make pkt_frag_loads[src_ip_port][ack] = full load
                old_load = pkt_frag_loads[src_ip_port][ack]
                concat_load = old_load + load
                return OrderedDict([(ack, concat_load)])

    return OrderedDict([(ack, load)])

def pkt_parser(pkt):
    global pkt_frag_loads

    # Get rid of Ethernet pkts with just a raw load cuz these are usually network controls like flow control
    if pkt.haslayer(Ether) and pkt.haslayer(Raw) and not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
        return

    if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):

        ack = str(pkt[TCP].ack)
        seq = str(pkt[TCP].seq)
        src_ip_port = str(pkt[IP].src) + ':' + str(pkt[TCP].sport)
        dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[TCP].dport)

	#create full load from load fragments	
	load = pkt[Raw].load
        frag_remover(ack, load)
        pkt_frag_loads[src_ip_port] = frag_joiner(ack, src_ip_port, load)
        full_load = pkt_frag_loads[src_ip_port][ack]

        #Pull out pertinent info from the parsed HTTP packet data
        user_passwd = None
        url = ''
        method = None
        path = None
        http_methods = ['GET ', 'POST ', 'CONNECT ', 'TRACE ', 'TRACK ', 'PUT ', 'DELETE ', 'HEAD ']
        http_line, header_lines, body = parse_http_load(full_load, http_methods)
        headers = headers_to_dict(header_lines)
        if 'host' in headers:
            host = headers['host']
        else:
            host = ''

        if http_line != None:
            method, path = parse_http_line(http_line, http_methods)
            url = get_http_url(method, host, path, headers)

        # Get user/pwds
        if body != '':
            user_passwd = get_login_pass(body)
            ts= datetime.datetime.utcnow()
            if user_passwd != None:
                try:
                    http_user = user_passwd[0].decode('utf8')
                    http_pass = user_passwd[1].decode('utf8')
                    # Set a limit on how long they can be prevent false+
                    if len(http_user) > 75 or len(http_pass) > 75:
                        return
                    if len(url)>80: url=url[:80]
	            print '%s:[%s] %s%s%s %s' % (ts, str(pkt[IP].src), T, http_user+":"+http_pass, W, url)
                    #add creds to global sets
		    creds.add(str(pkt[IP].src)+":"+http_user+":"+http_pass)
                    ips.add(str(pkt[IP].src))
	        except UnicodeDecodeError:
                    pass

def get_http_url(method, host, path, headers):
    '''
    Get the HTTP method + URL from requests
    '''
    if method != None and path != None:

        # Make sure the path doesn't repeat the host header
        if host != '' and not re.match('(http(s)?://)?'+host, path):
            http_url_req = method + ' ' + host + path
        else:
            http_url_req = method + ' ' + path

        http_url_req = url_filter(http_url_req)

        return http_url_req

def headers_to_dict(header_lines):
    '''
    Convert the list of header lines into a dictionary
    '''
    headers = {}
    for line in header_lines:
        lineList=line.split(': ', 1)
        key=lineList[0].lower()
        if len(lineList)>1:
                headers[key]=lineList[1]
        else:
                headers[key]=""
    return headers

def parse_http_line(http_line, http_methods):
    '''
    Parse the header with the HTTP method in it
    '''
    http_line_split = http_line.split()
    method = ''
    path = ''

    # Accounts for pcap files that might start with a fragment
    # so the first line might be just text data
    if len(http_line_split) > 1:
        method = http_line_split[0]
        path = http_line_split[1]

    # This check exists because responses are much different than requests e.g.:
    #     HTTP/1.1 407 Proxy Authentication Required ( Access is denied.  )
    # Add a space to method because there's a space in http_methods items
    # to avoid false+
    if method+' ' not in http_methods:
        method = None
        path = None

    return method, path

def parse_http_load(full_load, http_methods):
    '''
    Split the raw load into list of headers and body string
    '''
    try:
        headers, body = full_load.split("\r\n\r\n", 1)
    except ValueError:
        headers = full_load
        body = ''
    header_lines = headers.split("\r\n")

    # Pkts may just contain hex data and no headers in which case we'll
    # still want to parse them for usernames and password
    http_line = get_http_line(header_lines, http_methods)
    if not http_line:
        headers = ''
        body = full_load

    header_lines = [line for line in header_lines if line != http_line]

    return http_line, header_lines, body

def get_http_line(header_lines, http_methods):
    '''
    Get the header with the http command
    '''
    for header in header_lines:
        for method in http_methods:
            # / is the only char I can think of that's in every http_line
            # Shortest valid: "GET /", add check for "/"?
            if header.startswith(method):
                http_line = header
                return http_line

def url_filter(http_url_req):
    '''
    Filter out the common but uninteresting URLs
    '''
    if http_url_req:
        d = ['.jpg', '.jpeg', '.gif', '.png', '.css', '.ico', '.js', '.svg', '.woff']
        if any(http_url_req.endswith(i) for i in d):
            return

    return http_url_req

def get_login_pass(body):
    '''
    Regex out logins and passwords from a string
    '''
    user = None
    passwd = None
    userfields = ['log','login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                  'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                  'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                  'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                  'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']
    passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword', 
                  'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword', 'login_password'
                  'passwort', 'passwrd', 'wppassword', 'upasswd','senha','contrasena']
    for login in userfields:
        login_re = re.search('%s=([^&]+)' % login, body, re.IGNORECASE)
        if login_re:
            user = login_re.group(1)
	    break
    for passfield in passfields:
        pass_re = re.search('%s=([^&]+)' % passfield, body, re.IGNORECASE)
        if pass_re:
            passwd = pass_re.group(1)
	    break
    if user and passwd:
        return (user, passwd)

def main(args):
    # Read packets from either pcap or interface
    if args.pcap:
        try:
            for pkt in PcapReader(args.pcap):
                pkt_parser(pkt)
        except IOError:
            exit('[-] Could not open %s' % args.pcap)

    else:
        # Check for root
        if geteuid():
            exit('[-] Please run as root')

        #Find the active interface
        if args.interface:
            conf.iface = args.interface
        else:
            conf.iface = iface_finder()
        print '[*] Using interface:', conf.iface
	
	#sniff for 5 minutes
        if args.filterip:
            sniff(iface=conf.iface, prn=pkt_parser, filter="not src %s" % args.filterip, store=0, timeout=300)
        else:
            sniff(iface=conf.iface, prn=pkt_parser, store=0, timeout=300)

	#find folks who have sent a bunch of different credentials
	print "\ncount\tsource_ip"
	print "-----\t---------"
	for i in ips:
	    count = 0
	    for c in creds:
		addr, user, passwd = c.split(":")
		if addr == i: count +=1
	    print "%d\t%s" %(count, i)
	    if count > 10: 
		subprocess.call('/usr/local/bin/ip_banner.sh %s' %i, shell=True)
		print "Banned %s for %d password attempts!" %(i,count)
		

if __name__ == "__main__":
   main(parse_args())
