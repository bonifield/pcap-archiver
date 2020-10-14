#!/usr/bin/python3


#
# last updated: 2020-10-13
# example usage:
#	pcap-uploader.py file.pcap
#	- ideally use with a cronjob that looks for new pcaps and invokes this script
#
# TO DO:
#	- option to see results from the upload
#


import base64, json, logging, os, requests, sys, time
# suppress warning when accessing self-signed TLS certs
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# disable the Scapy IPv6 warning, must go above Scapy import
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# all Scapy features
from scapy.all import *
load_layer("http")
load_layer("tls")


#============
# put the address of your elasticsearch cluster and index
#============
host = "https://YOUR-IP-HERE:9200"
uri = "/pcap-singles/_bulk?pretty"
#============
# put your base64 PUBLISH id:api_key combo here (use echo -n so you do not get a newline in your b64 output)
#============
api = 'YOUR-B64-PUBLISH-KEY-HERE=='


url = host+uri
inputFile = sys.argv[1]
epoch = str(int(time.time()))
outputFile = "pcapindex.out."+epoch+".log"
# from pkt[Ether].get_field('type').i2s
etherTypeNames = {4: 'n_8023', 512: 'PUPAT', 1536: 'NS', 1537: 'NSAT', 1632: 'DLOG1', 1633: 'DLOG2', 2048: 'IPv4', 2049: 'X75', 2050: 'NBS', 2051: 'ECMA', 2052: 'CHAOS', 2053: 'X25', 2054: 'ARP', 2056: 'FRARP', 2989: 'VINES', 4096: 'TRAIL', 4660: 'DCA', 5632: 'VALID', 6549: 'RCL', 15364: 'NBPCC', 15367: 'NBPDG', 16962: 'PCS', 19522: 'IMLBL', 24577: 'MOPDL', 24578: 'MOPRC', 24580: 'LAT', 24583: 'SCA', 24584: 'AMBER', 25945: 'RAWFR', 28672: 'UBDL', 28673: 'UBNIU', 28675: 'UBNMC', 28677: 'UBBST', 28679: 'OS9', 28720: 'RACAL', 32773: 'HP', 32815: 'TIGAN', 32840: 'DECAM', 32859: 'VEXP', 32860: 'VPROD', 32861: 'ES', 32871: 'VEECO', 32873: 'ATT', 32890: 'MATRA', 32891: 'DDE', 32892: 'MERIT', 32923: 'ATALK', 32966: 'PACER', 32981: 'SNA', 33010: 'RETIX', 33011: 'AARP', 33024: 'VLAN', 33026: 'BOFL', 33072: 'HAYES', 33073: 'VGLAB', 33079: 'IPX', 33087: 'MUMPS', 33094: 'FLIP', 33097: 'NCD', 33098: 'ALPHA', 33100: 'SNMP', 33149: 'XTP', 33150: 'SGITW', 33153: 'STP', 34525: 'IPv6', 34617: 'RDP', 34618: 'MICP', 34668: 'IPAS', 34825: 'SLOW', 34827: 'PPP', 34887: 'MPLS', 34902: 'AXIS', 34916: 'PPPOE', 34958: 'PAE', 34978: 'AOE', 34984: 'n_802_AD', 35020: 'LLDP', 35047: 'PBB', 36865: 'XNSSM', 36866: 'TCPSM', 43690: 'DEBNI', 64245: 'SONIX', 65280: 'VITAL', 65535: 'MAX', 35045: 'n_802_1AE'}


heady = {
        'Authorization': 'ApiKey {}'.format(api),
        'Content-Type': 'application/x-ndjson'
}


def processPacket(pkt):
	d = {
		"destination":{
			"address":"",
			"domain":"",
			"ip":"",
			"port":"",
			"mac":""
		},
		"file":{
			"name":""
		},
		"http":{
			"header":{
				"content_type":"",
				"forwarded":"",
				"location":"",
				"status_code_phrase":"",
				"server":"",
				"via":"",
				"x-forwarded-for":"",
				"x-forwarded-host":"",
				"x-forwarded-proto":"",
				"x-powered-by":""
			},
			"request": {
				"method": "",
				"referrer": ""
			},
			"response": {
				"status_code":""
			}
		},
		"icmp":{
			"code":"",
			"type":""
		},
		"is_http": "",
		"is_icmp": "",
		"is_tls": "",
		"is_vlan": "",
		"network":{
			"transport":"",
			"type":"",
			"version":"",
			"vlan":{
				"id":""
			}
		},
		"packet":{
			"encoded":"",
			"time":""
		},
		"source":{
			"address":"",
			"ip":"",
			"port":"",
			"mac":""
		},
		"tls":{
			"client":{
				"server_name":""
			}
		},
		"url":{
			"domain":"",
			"path":""
		},
		"user_agent":{
			"original":""
		}
	}
	d['file']['name'] = inputFile
	d['packet']['time'] = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.localtime(pkt.time))
	# nest everything under Ether statement to trim down captured data
	if Ether in pkt:
		d['source']['mac'] = str(pkt.src)
		d['destination']['mac'] = str(pkt.dst)
		try:
			nt = pkt[Ether].type
			d['network']['type'] = str(etherTypeNames[nt]).lower()
		except Exception as e:
			print(str(e))
			pass
		if IP in pkt:
			d['source']['address'] = str(pkt[IP].src)
			d['source']['ip'] = str(pkt[IP].src)
			d['destination']['address'] = str(pkt[IP].dst)
			d['destination']['ip'] = str(pkt[IP].dst)
			d['network']['version'] = str(pkt[IP].version)
			d['network']['transport'] = str(pkt[IP].proto)
		if Dot1Q in pkt:
			d['is_vlan'] = 'yes'
			nt = pkt[Dot1Q].type
			d['network']['type'] = str(etherTypeNames[nt]).lower()
			d['network']['vlan']['id'] = pkt[Dot1Q].vlan
		if TCP in pkt:
			d['source']['port'] = str(pkt[TCP].sport)
			d['destination']['port'] = str(pkt[TCP].dport)
		if UDP in pkt:
			d['source']['port'] = str(pkt[UDP].sport)
			d['destination']['port'] = str(pkt[UDP].dport)
		if ICMP in pkt:
			d['is_icmp'] = 'yes'
			d['icmp']['type'] = str(pkt[ICMP].type)
			d['icmp']['code'] = str(pkt[ICMP].code)
		if HTTP in pkt:
			# https://scapy.readthedocs.io/en/latest/api/scapy.layers.http.html
			d['is_http'] = 'yes'
			if HTTPRequest in pkt[HTTP]:
				hreq = pkt[HTTP][HTTPRequest]
				if hreq.Method:
					d['http']['request']['method'] = bytes(hreq.Method).decode("utf-8")
				if hreq.Host:
					d['url']['domain'] = bytes(hreq.Host).decode("utf-8")
					d['destination']['domain'] = bytes(hreq.Host).decode("utf-8")
				if hreq.Path:
					d['url']['path'] = bytes(hreq.Path).decode("utf-8")
				if hreq.Http_Version:
					d['http']['version'] = bytes(hreq.Http_Version).decode("utf-8")
				if hreq.User_Agent:
					d['user_agent']['original'] = bytes(hreq.User_Agent).decode("utf-8")
				if hreq.Content_Type:
					d['http']['header']['content_type'] = bytes(hreq.Content_Type).decode("utf-8")
				if hreq.Referer:
					d['http']['request']['referrer'] = bytes(hreq.Referer).decode("utf-8")
				if hreq.Via:
					d['http']['header']['via'] = bytes(hreq.Via).decode("utf-8")
				if hreq.Forwarded:
					d['http']['header']['forwarded'] = bytes(hreq.Forwarded).decode("utf-8")
				if hreq.X_Forwarded_For:
					d['http']['header']['x-forwarded-for'] = bytes(hreq.X-Forwarded-For).decode("utf-8")
				if hreq.X_Forwarded_Host:
					d['http']['header']['x-forwarded-host'] = bytes(hreq.X-Forwarded-Host).decode("utf-8")
				if hreq.X_Forwarded_Proto:
					d['http']['header']['x-forwarded-proto'] = bytes(hreq.X-Forwarded-Proto).decode("utf-8")
			if HTTPResponse in pkt[HTTP]:
				hres = pkt[HTTP][HTTPResponse]
				if hres.Status_Code:
					d['http']['response']['status_code'] = bytes(hres.Status_Code).decode("utf-8")
				if hres.Reason_Phrase:
					d['http']['header']['status_code_phrase'] = bytes(hres.Reason_Phrase).decode("utf-8")
				if hres.Content_Type:
					d['http']['header']['content_type'] = bytes(hres.Content_Type).decode("utf-8")
				if hres.Server:
					d['http']['header']['server'] = bytes(hres.Server).decode("utf-8")
				if hres.Http_Version:
					d['http']['version'] = bytes(hres.Http_Version).decode("utf-8")
				if hres.Via:
					d['http']['header']['via'] = bytes(hres.Via).decode("utf-8")
				if hres.X_Powered_By:
					d['http']['header']['x-powered-by'] = bytes(hres.X-Forwarded-Proto).decode("utf-8")
		if TLS in pkt:
			d['is_tls'] = 'yes'
			m = pkt[TLS].msg[0]
			try:
				snb = m[TLS_Ext_ServerName].servernames[0].servername
				sn = bytes(snb).decode("utf-8")
				d['tls']['client']['server_name'] = sn
				d['destination']['domain'] = sn
			except Exception as e:
				pass
		# reverse with base64_bytes(z.lstrip("b'").rstrip("'")) when re-combining into pcap from database retrieval
		b = str(bytes_base64(pkt))
		d['packet']['encoded'] = b
		try:
			j = json.dumps(d, sort_keys="True")
			# specify op_type when using api keys to authenticate
			return('{"index":{"_index":"pcap-singles", "op_type":"create"}}\n'+j+'\n')
			# troubleshooting here
#			pkt.show()
#			ls(pkt)
		except Exception as e:
			print(str(e))
			pass


def makeWorkingFiles(inputFile):
	with PcapReader(inputFile) as pr:
		oFileList = [] # store list of temp filenames
		c = 0 # count number of loops
		fnameCounter = 0 # counter appended to temporary log names
		oFileName = outputFile+'.'+str(fnameCounter)
		print("opening {}".format(oFileName))
		oFile = open(oFileName, 'w')
		oFileList.append(oFileName)
		for pkt in pr:
			# cap files created at 20k loops
			if c >= 20000: # this would be 40k lines created by processPacket()
				print("closing {}".format(oFileName))
				oFile.close()
				c = 0
				fnameCounter += 1
				oFileName = outputFile+'.'+str(fnameCounter)
				print("opening {}".format(oFileName))
				oFile = open(oFileName, 'w')
				oFileList.append(oFileName)
			try:
				# processPacket() only attempts to process packets with Ethernet
				oFile.write(processPacket(pkt))
			except Exception as e:
				pass
			# increment number of loops
			c += 1
		oFile.write('\n')
		print("closing {}".format(oFileName))
		oFile.close()
	pr.close()
	print("made temp files, preparing to upload")
	return(oFileList)


def uploadWorkingFiles(oFileList):
	# read list of filenames
	for o in oFileList:
		try:
			with open(o, 'rb') as f:
				print("uploading {}".format(o))
				r = requests.post(url, headers=heady, verify=False, data=f)
				# un-comment to see results, VERY loud
				#c = r.content
				#print(json.dumps(json.loads(c), indent=4))
			f.close()
			# delete the temporary log file
			print("removing {}".format(o))
			os.remove(o)
		except Exception as e:
			print("error uploading file {}".format(o))
			print(str(e))


if __name__ == '__main__':
	starttime = time.time()
	fileListToUpload = makeWorkingFiles(inputFile)
	uploadWorkingFiles(fileListToUpload)
	endtime = time.time()
	fintime = str(int(endtime-starttime))
	print("script finished in {} seconds".format(fintime))
