# pcap-archiver
store and retrieve packets using Elasticsearch

## Description
- Short Version: Stores captured network packets in Elasticsearch, which are then retrievable on-demand via script.
- Long Version: Reads PCAP files and creates a JSON representation of each raw packet, along with basic metadata about the packet, which then gets stored in an Elasticsearch database cluster. Once packets are stored, retrieve them on-demand according to various criteria via simple script.
- **Although the main scripts use APIs, setup steps 1-6 use the built-in "elastic" user; use dedicated accounts to create these APIs in production environments.**
- **Certain HTTP fields in the mapping do not align to the Elastic Common Schema. These custom fields are nested under "http.header"**

## Use Case Scenario
Your small to medium-sized business has started using a network tap or SPAN to capture PCAP files and other logs. You are using Tcpdump or Netsniff-ng to generate rotating PCAP files, but this does not make for easy access into the files for analysis. By using this tool to store the raw packets from each PCAP file in Elasticsearch, you can then purge the PCAP files as they rotate, and allow your analysts or administrators easy access to packets as they determine the need to see them. Querying Elasticsearch via this tool to retrieve packets is faster and easier than working with the rotating PCAPs directly.

## Why Elasticsearch and not Splunk?
The 500 MB ingest limit per day with the free version of Splunk is severely limiting, whereas the free version of Elasticsearch has no such limit.

## Files in this Project
- pcap-archiver-setup.sh
	- semi-automated script that walks through setting up the index and APIs, and optionally destroying the index
- pcap-upload.py
	- uploads a JSON structure containing the packet and appropriate metadata to Elasticsearch (note - creates and deletes temporary JSON files)
- pcap-fetch.py
	- retrieves PCAP from Elasticsearch using AND, OR, STRING, and time-based selectors
- OLD_pcap-fetch.py
	- retrieves PCAP from Elasticsearch in a simpler format, but only uses AND selectors
- pcap-singles.mapping
	- mapping file for the ```pcap-singles``` index

## Requirements
Scapy and Requests

## Usage
First, run the setup script, then edit each Python script with the appropriate Elasticsearch host address, index name, and API keys (read and publish, respectively).
- setup
```
pcap-archiver-setup.sh
```
- storing data (ideally via cronjob on rotating netsniff-ng or tcpdump files): **pcap-upload.py**
```
pcap-upload.py file.pcap
```
- retrieving PCAP (with the new script): **pcap-fetch.py**
	- ```--and``` and ```--or``` are split on spaces
	- ```--string``` will preserve spaces and gets rolled into an implied ```--and``` argument; wrap in double-quotes
```
pcap-fetch.py --and 173.194.191.104
pcap-fetch.py --and "192.168.99.100 173.194.191.104"
pcap-fetch.py --and "192.168.99.100 173.194.191.104 ipv4"
pcap-fetch.py --and "192.168.99.100 173.194.191.104" --or "57530 57711"
pcap-fetch.py --and "192.168.99.100 173.194.191.104" --or "57530 57711" --earliest 2020-01-01T00:00:00 --latest 2020-02-02T23:59:59
pcap-fetch.py --string "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0"
pcap-fetch.py --string "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0" --and 57784
```
- retrieving PCAP (with the old script, only supports "and" conditions where each argument is space-separated): **OLD_pcap-fetch.py**
```
pcap-fetch.py 192.168.99.100 8.8.8.8
pcap-fetch.py 192.168.99.100 53
pcap-fetch.py 192.168.99.100 8.8.8.8 34555 53
pcap-fetch.py 192.168.99.100 ipv4
pcap-fetch.py 192.168.99.100 8.8.8.8 ipv4
```

## To Do
- [x] setup script
- [x] "or" statements for fetching PCAP (added 02 October 2020)
- [x] time range selection statements for fetching PCAP (added 02 October 2020)
- [x] more metadata fields for easier searching and fetching (added many new web-related fields 14 October 2020)
- [x] ability to query for PCAP based on strings (added 14 October 2020)
- [ ] process more types of packets (just packet.Ether now)
- [ ] add cronjob and tcpdump/netsniff-ng helper notes
- [ ] output path options for PCAP fetch, vs using the present working directory
- [ ] rename processed PCAPs to flag for either deletion, compression, or other actions
- [ ] option to preserve JSON logs in compressed format, vs deleting them and keeping PCAPs
- [ ] Use the Elasticsearch libraries
- [ ] Threading and better read methods than "top-to-bottom"
- [ ] Flask front-end for PCAP retrieval, both querying and downloading the resulting file
- [ ] Dockerize the whole thing? Mount the container at your PCAP folder and relax?

## Elasticsearch Setup Steps (Configure the Index, Mapping, and APIs)
### use the [setup script](https://github.com/bonifield/pcap-archiver/blob/master/pcap-archiver-setup.sh) OR follow the steps below
1. make the ```pcap-singles``` index inside Elasticsearch
```
curl -u elastic -skX PUT "https://YOUR-IP-HERE:9200/pcap-singles?pretty"
```

2. define a mapping for the index (note you need the full path for -d, or relative paths like "./")
```
curl -u elastic -skX PUT "https://YOUR-IP-HERE:9200/pcap-singles/_mapping?pretty" -H "Content-Type: application/json" -d @/full/path/to/pcap-singles.mapping
```
_or_ via the Dev Tools in Kibana if the above command returns an error
```
PUT pcap-singles/_mapping
...contents of pcap-singles.mapping file here...
```

3. create an API key for **publishing** documents (storing data) (recommend using a dedicated account for sending data)
```
curl -u elastic -skX POST "https://YOUR-IP-HERE:9200/_security/api_key?pretty" -H 'Content-Type: application/json' -d'{"name": "pcap-singles-publish_00001", "role_descriptors": {"filebeat_writer": {"cluster": ["monitor", "read_ilm"], "index": [{"names": ["pcap-*"], "privileges": ["view_index_metadata", "create_doc"]}]}}}'
```
_or_ via the Dev Tools in Kibana
```
POST /_security/api_key
{
  "name": "pcap-singles-publish_00001", 
  "role_descriptors": {
    "filebeat_writer": { 
      "cluster": ["monitor", "read_ilm"],
      "index": [
        {
          "names": ["pcap-*"],
          "privileges": ["view_index_metadata", "create_doc"]
        }
      ]
    }
  }
}
```
both will return something like this:
```
{
  "id" : "YOUR-PUBLISH-API-ID-HERE",
  "name" : "pcap-singles-publish_00001",
  "api_key" : "YOUR-PUBLISH-API-KEY-HERE"
}
```

4. configure your **publisher** API key ("id:api_key" then base64, note they are joined with a colon)
```
echo -n "YOUR-PUBLISH-API-ID-HERE:YOUR-PUBLISH-API-KEY-HERE" | base64
YOUR-B64-PUBLISH-KEY-HERE==
```

5. test the **publisher** API
```
curl -skX GET "https://YOUR-IP-HERE:9200/pcap-singles?pretty" -H "Authorization: ApiKey YOUR-B64-PUBLISH-KEY-HERE=="
```

6. create an API key for **reading** documents (retrieving data) (recommend using a dedicated account for reading data)
```
curl -u elastic -skX POST "https://YOUR-IP-HERE:9200/_security/api_key?pretty" -H 'Content-Type: application/json' -d'{"name": "pcap-singles-read_00001", "role_descriptors": {"filebeat_writer": {"cluster": ["monitor", "read_ilm"], "index": [{"names": ["pcap-*"],"privileges": ["view_index_metadata", "read"]}]}}}'
```
_or_ via the Dev Tools in Kibana
```
POST /_security/api_key
{
  "name": "pcap-singles-read_00001", 
  "role_descriptors": {
    "filebeat_writer": { 
      "cluster": ["monitor", "read_ilm"],
      "index": [
        {
          "names": ["pcap-*"],
          "privileges": ["view_index_metadata", "read"]
        }
      ]
    }
  }
}
```
will return something like this:
```
{
  "id" : "YOUR-READ-API-ID-HERE",
  "name" : "pcap-singles-read_00001",
  "api_key" : "YOUR-READ-API-KEY-HERE"
}
```

7. configure your **read** API key ("id:api_key" then base64, note they are joined with a colon)
```
echo -n "YOUR-READ-API-ID-HERE:YOUR-READ-API-KEY-HERE" | base64
YOUR-B64-READ-KEY-HERE==
```

8. test the **read** API
```
curl -skX GET "https://YOUR-IP-HERE:9200/pcap-singles?pretty" -H "Authorization: ApiKey YOUR-B64-READ-KEY-HERE=="
```

9. edit ```pcap-upload.py``` and ```pcap-fetch.py``` with the appropriate IP and API information where indicated

## Helpful Commands
- delete all data in the ```pcap-singles``` index
```
curl -u elastic -skX POST "https://YOUR-IP-HERE:9200/pcap-singles/_delete_by_query?pretty" -H "Content-Type: application/json" -d '{"query" : {"match_all" : {}}}'
```
- delete the entire ```pcap-singles``` index
```
curl -u elastic -skX DELETE "https://YOUR-IP-HERE:9200/pcap-singles?pretty"
```
