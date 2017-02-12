"""
Following DNSBLs list is additional / fallback
Checker trying to get fresh DNSBLs list from:

    http://www.dnsbl.info/dnsbl-list.php

But if you want to add specific DNSBLs or to avoid
site unavailability, you may add some DNSBLs here.
"""
BASE_LISTS = [
              'zen.spamhaus.org',
              'bl.spamcop.net',
              'combined.abuse.ch',
              'dnsbl.sorbs.net',
              'b.barracudacentral.org',
              'bl.spamcannibal.org',
              'spam.abuse.ch',
              'spam.dnsbl.sorbs.net',
              'spam.spamrats.com'
              ]
"""
You may also want to change following settings
"""
max_workers = 60
verbose = False
log_file = 'dnsbl.log'
skip_slow = True
"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from datetime import timedelta
import dns.resolver
from netaddr import IPNetwork
import re
import sys
from urllib.request import Request, urlopen


parser = argparse.ArgumentParser(description='Black-List IP Checker')
parser.add_argument('-i', dest='inventory', type=str, nargs='+', required=True,
                   help='hosts-file or comma separated IP list. CIDR allowed.')

parser.add_argument('-o', dest='output', type=str, nargs=1, required=False,
                   help='output file')


def log(msg):
    if verbose:
        timestamp = datetime.now().strftime('%d.%m.%Y %H:%M')
        log_file.write('\n%s  %s\n' % (timestamp, msg))


def get_hosts(inventory):
    hosts = set()
    network = re.compile('(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/\d{1,2})?')
    if network.search(inventory[0]):
        inventory = ' '.join(inventory)
        networks = set(network.findall(inventory))
    else:
        try:
            inventory_file = open(inventory[0], 'r').read()
            networks = set(network.findall(inventory_file))
        except Exception as exception:
            print('Fail! %s' % exception)
            sys.exit(0)
    for network in networks:
        hosts.update(str(ip) for ip in IPNetwork(network))
    return hosts


def fetch_dnsbl_lists():
    url = 'http://www.dnsbl.info/dnsbl-list.php'
    regexp = 'dnsbl=([A-Za-z0-9-\.]+)'
    headers = {'User-Agent': 'Mozilla/5.0'}
    req = Request(url, headers=headers)
    local_lists = set(BASE_LISTS)
    fresh_lists = set()
    try:
        page_html = str(urlopen(req).read())
        fresh_lists.update(re.findall(regexp, page_html))
    except Exception as exception:
        msg = 'Failed to fetch dnsbl lists from web source: %s' % exception
        log(msg)
        pass
    return fresh_lists | local_lists


def dnsbl_query(ip, bl):
    answer = None
    start = datetime.now()
    try:
        resolver = dns.resolver.Resolver()
        query = '.'.join(reversed(str(ip).split("."))) + "." + bl
        A = str(resolver.query(query, "A")[0])
        try:
            TXT = str(resolver.query(query, "TXT")[0])
        except dns.resolver.NoAnswer:
            TXT = '-'
        answer = (ip, bl, A, TXT)
    except dns.resolver.NXDOMAIN:
        pass
    except Exception as exception:
        msg = '%s %s %s' % (bl, ip, exception)
        log(msg)
        pass
    finish = datetime.now()
    delta = finish - start
    if skip_slow and delta > timedelta(seconds=15):
        dnsbl_lists.discard(bl)
    return answer


def check_answer(answer):
    result = answer.result()
    if result:
        ip = result[0]
        bl = result[1]
        if ip in black_list:
            black_list[ip][bl] = result[2:]
        else:
            black_list[ip] = {bl: result[2:]}


black_list = {}
counter = 0
if verbose:
    log_file = open(log_file, 'a')
args = parser.parse_args()
inventory = args.inventory
if args.output:
    output_file = open(args.output[0], 'w')
hosts = get_hosts(inventory)
dnsbl_lists = fetch_dnsbl_lists()
total_hosts = len(hosts)
for ip in hosts:
    counter += 1
    ip_result = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for bl in dnsbl_lists:
            worker = executor.submit(dnsbl_query, ip, bl)
            worker.add_done_callback(check_answer)
    sys.stdout.write("Progress: %s of %s  \r" % (counter, total_hosts))
    sys.stdout.flush()
sorted_hosts = sorted(black_list.keys(),
                      key=lambda ip: len(black_list[ip]), reverse=True)

for ip in sorted_hosts:
    for bl in black_list[ip]:
        answer = black_list[ip][bl]
        msg = '\n{} {} {} {}'.format(ip, bl, answer[0], answer[1])
        if args.output:
            output_file.write(msg)
        else:
            print(msg)
