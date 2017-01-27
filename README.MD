
DNSBL Checker
----

##### Simple multi-threading tool for checking IP-addresses
##### or CIDR-networks against known black-lists.

----

#### Performance:
120-160 IP-addresses per minute without significant server load

(checking each against 58 DNSBLs; max_workers = 60)

#### Used Lists :
The script is trying to fetch active DNSBLs from following resource:

http://www.dnsbl.info/dnsbl-list.php

You can specify additional / fallback set of DNSBLs in the top of script.

#### Usage
####
```sh
$ python dnsbl.py -i /path/to/hosts_file

$ python dnsbl.py -i 192.30.253.112 192.30.253.113

$ python dnsbl.py -i 192.30.253.0/24, 192.30.253.0/23 -o output.txt
```

#### Options
####
```sh
BASE_LISTS = [...]       ------->      additional / fallback DNSBLs list
max_workers = 60         ------->      max threads
verbose = False          ------->      logging
log_file = 'dnsbl.log'   ------->      log file
```
