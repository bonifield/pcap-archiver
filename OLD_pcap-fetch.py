#!/usr/bin/python3


#
# last updated: 2020-09-23
# example usage:
#   fetch-pcap.py 192.168.99.100 8.8.8.8
#   fetch-pcap.py 8.8.8.8 53
#   fetch-pcap.py 192.168.99.100 ipv4
#
# TO DO:
#	- time range selector (argparse)
#	- option of using an output directory
#


import json, logging, requests, sys, time
# suppress warning when accessing self-signed TLS certs
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# disable the Scapy IPv6 warning, must go above Scapy import
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# all Scapy features
from scapy.all import *


#============
# put the address of your elasticsearch cluster and index
#============
host = "https://YOUR-IP-HERE:9200"
uri = '/pcap-singles/_search?pretty' # leave the ?pretty argument if you edit the script to see results
#============
# put your base64 READ id:api_key combo here (use echo -n so you do not get a newline in your b64 output)
#============
api = 'YOUR-B64-READ-KEY-HERE=='


url = host+uri
args = sys.argv
# join any command line args if more than one is given
query_args_joined = ') ('.join(args[1:])
query_args = "(" + query_args_joined + ")"
epoch = str(int(time.time()))
outStuff = '-'.join(args[1:])
outputFile = "out."+epoch+"."+outStuff+".pcap"


heady = {
	'Authorization': 'ApiKey {}'.format(api),
	'Content-Type': 'application/json'
}


# returns up to 10k packets, the maximum supported by Elasticsearch
q = {
	"from": 0,
	"size": 10000,
	"query": {
		"query_string": {
			"query": "{}".format(query_args),
			"default_operator": "AND"
		}
	},
	"_source": {
		"includes": ["packet.encoded"]
	}
}


# wrap up for the request package
dataz = json.loads(json.dumps(q))


# make the request
r = requests.get(url, headers=heady, verify=False, json=dataz)
#print(r.text)


# load the resulting data as a dict
j = json.loads(r.text)


# write pcap file
for x in j["hits"]["hits"]:
	z = x["_source"]["packet"]["encoded"]
	hh = base64_bytes(z.lstrip("b'").rstrip("'"))
	try:
		PcapWriter(outputFile, append=True, sync=False).write(hh)
	except Exception as e:
		print(str(e))
		sys.exit(1)


print("made {}".format(outputFile))
