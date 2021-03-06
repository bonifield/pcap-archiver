#!/usr/bin/python3


#
# last updated: 2020-10-14
#
# example usage:
#  *** THE FLAG --and "args go here" IS REQUIRED ***
#  *** if using more than one argument for --and / --or switches, wrap in double-quotes and separate using spaces
#  *** earliest time defaults to epoch ***
#  *** latest time defaults to "now" ***
#  *** only use --or if using more than one value, otherwise just put the value inside --and ***
#
#   pcap-fetch.py --and 173.194.191.104
#   pcap-fetch.py --and "192.168.99.100 173.194.191.104"
#   pcap-fetch.py --and "192.168.99.100 173.194.191.104 ipv4"
#   pcap-fetch.py --and "192.168.99.100 173.194.191.104" --or "57530 57711"
#   pcap-fetch.py --and "192.168.99.100 173.194.191.104" --or "57530 57711" --earliest 2020-01-01T00:00:00 --latest 2020-02-02T23:59:59
#   pcap-fetch.py --string "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0"
#   pcap-fetch.py --string "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0" --and 57784
#
# TO DO:
#	- option of using an output directory
#	- optimize using "fields" inside query_string
#


import argparse, json, logging, requests, sys, time
from datetime import datetime as dt
from random import randint
# suppress warning when accessing self-signed TLS certs
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# disable the Scapy IPv6 warning, must go above Scapy import
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# all Scapy features
from scapy.all import *


#=======================================================
#
# put the address of your elasticsearch cluster and index
host = "https://YOUR-IP-HERE:9200"
# if using an index name other than "pcap-singles", put it here
# put your base64 READ id:api_key combo here (use echo -n so you do not get a newline in your b64 output)
api = 'YOUR-B64-READ-KEY-HERE=='
#
#
#
#
# leave the ?pretty argument if you edit the script to see the response JSON from Elasticsearch
uri = '/pcap-singles/_search?pretty' # leave the ?pretty argument if you edit the script to see results
#
#=======================================================


begin = "1970-01-01T00:00:00"
now = "T".join(str(dt.now()).split()).split(".")[0]


# instantiate parser
parser = argparse.ArgumentParser(description="arguments for Elasticsearch ")


# optional switches
# short arg, long arg, variable name to be used (accessed as dict), a default value (optional), variable type, help message when using -h
# "and" arguments
parser.add_argument("-a", "--and", dest="andArgs", default="", type=str, help="space-delimited arguments to be used in an 'and' statement (wrap in double-quotes)")
# "or" arguments
parser.add_argument("-r", "--or", dest="orArgs", default="", type=str, help="all arguments to be used in an 'or' statement (wrap in double-quotes)")
# string argument, for user agents and such (will be merged with "and" arguments during the query)
parser.add_argument("-s", "--string", dest="stringArg", default="", type=str, help="a string to query, wrap in double-quotes")
# earliest time defaults to epoch
parser.add_argument("-e", "--earliest", dest="earliest", default=begin, type=str, help="earliest GMT/Zulu time to start searching, format YYYY-MM-DDThh:mm:ss (note the middle T)")
# latest time defaults to "now"
parser.add_argument("-l", "--latest", dest="latest", default=now, type=str, help="latest GMT/Zulu time to start searching, format YYYY-MM-DDThh:mm:ss (note the middle T)")


# mandatory switches
# make a new argument group then set it to required
# "and" arguments
#requiredArgs = parser.add_argument_group("required arguments")
#requiredArgs.add_argument("-a", "--and", dest="andArgs", default="", type=str, help="space-delimited arguments to be used in an 'and' statement (wrap in double-quotes)", required=True)


# treat args as a dictionarty
args = vars(parser.parse_args())


# create variables from the args object, and string representations of the arguments for Elasticsearch queries
aArgs = args["andArgs"]
andArgs = "(" + ') ('.join(aArgs.split()) + ")"
oArgs = args["orArgs"]
orArgs = "(" + ') ('.join(oArgs.split()) + ")"
stringArg = '"' + args["stringArg"] + '"'
earliest = args["earliest"]
latest = args["latest"]
if len(stringArg) > 2:
	if len(andArgs) == 2:
		andArgs = stringArg
	elif len(andArgs) > 2:
		andArgs = andArgs +" "+ stringArg


# variables for the output filename
epoch = str(int(time.time()))
randomNumber = str(randint(100000000, 999999999))
outputFile = "out."+epoch+"."+randomNumber+".pcap"


# variables for the web request
url = host+uri
heady = {
	'Authorization': 'ApiKey {}'.format(api),
	'Content-Type': 'application/json'
}


# returns up to 10k packets, the maximum supported by Elasticsearch
# assemble "or" query if there is one present
if len(oArgs) > 0:
	q = {
	"from": 0,
	"size": 10000,
	"query": {
		"bool": {
			"must": [
				{
					"query_string": {
						"query": "{}".format(andArgs),
						"default_operator": "AND"
					}
				},
				{
					"query_string": {
						"query": "{}".format(orArgs),
						"default_operator": "OR"
					}
				}
			],
			"filter": {
				"range":{
					"packet.time": {
						"gte": "{}".format(earliest),
						"lte": "{}".format(latest)
					}
				}
			}
		}
	},
	"_source": {
		"includes": ["packet.encoded"]
	}
}
else:
	q = {
	"from": 0,
	"size": 10000,
	"query": {
		"bool": {
			"must": [
				{
					"query_string": {
						"query": "{}".format(andArgs),
						"default_operator": "AND"
					}
				}
			],
			"filter": {
				"range":{
					"packet.time": {
						"gte": "{}".format(earliest),
						"lte": "{}".format(latest)
					}
				}
			}
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
# troubleshooting here - uncomment to view request and response JSON
#print("="*21 + " REQUEST " + "="*21)
#print(json.dumps(dataz, indent=4))
#print("="*21 + " RESPONSE " + "="*21)
#print(r.text)


# load the resulting data as a dict
j = json.loads(r.text)


# write pcap file
try:
	for x in j["hits"]["hits"]:
		z = x["_source"]["packet"]["encoded"]
		hh = base64_bytes(z.lstrip("b'").rstrip("'"))
		try:
			PcapWriter(outputFile, append=True, sync=False).write(hh)
		except Exception as e:
			print("error")
			print(str(e))
			sys.exit(1)
	print("made {}".format(outputFile))
except Exception as e:
	print("error")
	print(str(e))
	sys.exit(1)
