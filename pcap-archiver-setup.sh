#!/bin/bash

#
# last updated: 2020-09-24
# example usage:
#	pcap-archiver-setup.sh
#	- then follow the menus
#

clear
date | tee -a pcap-archiver.log

echo -e "

PCAP Archiver Easy Setup

Choose an option:
\tcreate-index (sets up the index and mapping)
\tcreate-apis (obtains publish and read APIs after the index is created)
\tdestroy (remove all data in the index and then delete the index entirely)
"

read -e -p "Enter your choice:    " -i create-index option
echo
read -e -p "What is your Elasticsearch address? (no trailing slash and no quotes):    " -i https://YOUR-IP-HERE:9200 host
echo
read -e -p "What Elasticsearch user account do you want to use?:    " -i elastic user
echo

# or set these instead of answering the questions above
#host="https://YOUR-IP-HERE:9200"
#user="elastic"
#user="username:password"

printHeader() {
	echo
	echo "#==========================="
	echo -e "# $1"
	echo "#==========================="
	echo
}

createIndex() {
	read -e -p "What is the full or relative path to the pcap-singles.mapping file? (no quotes)    " -i ./pcap-singles.mapping mapping
	#mapping="/path/to/pcap-singles.mapping"
	echo

	# confirm input values
	printHeader "Provided Inputs\n#\thost: $host\n#\tuser: $user" | tee -a pcap-archiver.log

	# create the index
	printHeader "Create the Index" | tee -a pcap-archiver.log
	curl -u $user -skX PUT "$host/pcap-singles?pretty" | tee -a pcap-archiver.log

	# provide the index mapping
	printHeader "Provide the Mapping" | tee -a pcap-archiver.log
	curl -u $user -skX PUT "$host/pcap-singles/_mapping?pretty" -H "Content-Type: application/json" -d @$mapping | tee -a pcap-archiver.log

	echo
	read -e -p "Would you like to create APIs as well? (y/n)    " yesnoapis
	if [[ $yesnoapis =~ [Yy] ]]; then
		createApis
	else
		exit
	fi
}

createApis() {
	# create publish api
	printHeader 'Obtain PUBLISH (upload) API\n# note the usable key format is the output of\n#\techo -n "id:key" | base64\n#\tplace the base64 output into pcap-upload.py where indicated' | tee -a pcap-archiver.log
	# change the name inside the JSON if desired
	curl -u $user -skX POST "$host/_security/api_key?pretty" -H 'Content-Type: application/json' -d'{"name": "pcap-singles-publish_0000", "role_descriptors": {"filebeat_writer": {"cluster": ["monitor", "read_ilm"], "index": [{"names": ["pcap-*"], "privileges": ["view_index_metadata", "create_doc"]}]}}}' | tee -a pcap-archiver.log
	echo

	# create read api
	printHeader 'Obtain READ (fetch) API\n# note the usable key format is the output of\n#\techo -n "id:key" | base64\n#\tplace the base64 output into pcap-fetch.py where indicated' | tee -a pcap-archiver.log
	# change the name inside the JSON if desired
	curl -u $user -skX POST "$host/_security/api_key?pretty" -H 'Content-Type: application/json' -d'{"name": "pcap-singles-read_0000", "role_descriptors": {"filebeat_writer": {"cluster": ["monitor", "read_ilm"], "index": [{"names": ["pcap-*"],"privileges": ["view_index_metadata", "read"]}]}}}' | tee -a pcap-archiver.log
	echo
}

destroyIndex() {
	#
	# DANGER
	# DANGER
	# DANGER
	#
	# THIS IS TO CLEAR THE INDEX OF ALL DATA
	# AND THEN DELETE IT ENTIRELY
	#
	read -e -p "You have selected to destroy the index and all of its contents. Continue? (y/n)    " yesnodestroy
	if [[ $yesnodestroy =~ [Yy] ]]; then
		# confirm input values
		printHeader "Provided Inputs\n#\thost: $host\n#\tuser: $user" | tee -a pcap-archiver.log

		# DANGER
		printHeader "Delete All Data Inside the Index" | tee -a pcap-archiver.log
		curl -u $user -skX POST "$host/pcap-singles/_delete_by_query?pretty" -H "Content-Type: application/json" -d '{"query" : {"match_all" : {}}}' | tee -a pcap-archiver.log

		# DANGER
		printHeader "Delete the Entire Index" | tee -a pcap-archiver.log
		curl -u $user -skX DELETE "$host/pcap-singles?pretty" | tee -a pcap-archiver.log
	else
		echo "safely exiting without destroying anything" | tee -a pcap-archiver.log
		exit
	fi
}


if [[ $option == "create-index" ]]; then
	createIndex
elif [[ $option == "create-apis" ]]; then
	createApis
elif [[ $option == "destroy" ]]; then
	destroyIndex
else
	exit
fi

echo | tee -a pcap-archiver.log
echo "wrote output to pcap-archiver.log"
echo
