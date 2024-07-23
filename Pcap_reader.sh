#!/bin/bash

#author: chanan shenker.
#linkedin: https://www.linkedin.com/in/chanan-shenker-a00481316/
#github: https://github.com/Chananshenker/Bash-Automations
#this is a bash automation that uses IOC files that contain malicious domains/IPs, strings, import hashes and sha256 to check the pcap file for any malicious activity. 

PCAP_FILE=""
MAL_DOMAINS_FILE=""
MAL_STR_FILE=""
IMPHASH_FILE=""
MAL_SHA256_FILE=""
USAGE='usage: ./Pcap_reader.sh -f <pcap_file> [--dom  <malicious_domains_file> | --str <malicious_strings_file> | --imp <imphash_file> | --sha256 <sha256_file>]
	
options:
	-f        file                         Reads file and make a log of all domains/IPs that were interacted with and extracts all file that were downloaded in the recording.
	--dom     malicious domains/IPs file   checks if any of the domains/IPs that were interacted with are malicious
	--str     malicious dlls file          check if any of the files contain any malicious strings provided by the file
	--imp     import hash file             checks files for malicious imphashes provided by the file.
	--sha256  malicious sha256 hash file   checks for file with a malicious sha256 provided by the file.'
DIR=$(mktemp -d ./PR_results_XXX)
TIME=$(date +"%Y-%m-%d %H:%M:%S")

#sorting and cheking for flags and arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -f) PCAP_FILE="$2"; shift ;;
        --dom) MAL_DOMAINS_FILE="$2"; shift ;;
        --str) MAL_STR_FILE="$2"; shift ;;
        --imp) IMPHASH_FILE="$2"; shift ;;
        --sha256) MAL_SHA256_FILE="$2"; shift ;;
        -h|--help)echo "$USAGE";exit ;;
        *) echo "Unknown parameter passed: $1 - "$USAGE"";;
    esac
    shift
done

#checking the argument if they are valid and usable.
function ARG_CHECK(){
	PCAP_CHECK=$(file "$PCAP_FILE" | grep -oE 'pcap capture file|pcapng capture file')
	if [ "$PCAP_FILE" == '' ];then
		echo "Missing network file to run - " "$USAGE"
		exit
	elif [ "$PCAP_CHECK" == '' ];then
		echo "the file given was not a pcap/pcapng file -" "$USAGE"
		exit
	fi
	if [ "$MAL_DOMAINS_FILE" != '' ];then
		if ! [ -f "$MAL_DOMAINS_FILE" ];then
			echo "Malicious domains/IPs file does not exist - " "$USAGE"
			exit
		elif [ -z "$MAL_DOMAINS_FILE" ];then
			echo "Malicious domains/IPs file seems to be empty - " "$USAGE"
			exit
		fi
	fi
	if [ "$MAL_STR_FILE" != '' ];then
		if ! [ -f "$MAL_STR_FILE" ];then
			echo "Malicious file strings file does not exist - " "$USAGE"
			exit
		elif [ -z "$MAL_STR_FILE" ];then
			echo "Malicious file stringss file seems to be empty -" "$USAGE"
			exit
		fi
	fi
	if [ "$IMPHASH_FILE" != '' ];then
		if ! [ -f "$IMPHASH_FILE" ];then
			echo "import hashes file does not exist - " "$USAGE"
			exit
		elif [ -z "$IMPHASH_FILE" ];then
			echo "import hashes file seems to be empty - " "$USAGE"
			exit
		fi
	fi
	if [ "$MAL_SHA256_FILE" != '' ];then
		if ! [ -f "$MAL_SHA256_FILE" ];then
			echo "sha256 hashes file does not exist - " "$USAGE"
			exit
		elif [ -z "$MAL_SHA256_FILE" ];then
			echo "sha256 hashes file seems to be empty - " "$USAGE"
			exit
		fi
	fi
}

ARG_CHECK

#creating a yara rule and cheking the file that were extracted.
function MAL_STR_SCAN(){
	echo -e "\n {+} Checking files for malicious strings with yara."
	STR_YARA_RULE=$(mktemp -t XXXXX.yar)
	echo -e "rule mal_string {\n	strings:" > "$STR_YARA_RULE"
	MAL_STR_LINES=$(cat "$MAL_STR_FILE" | wc -l)
	for i in $(seq "$MAL_STR_LINES");do
		LINE_MAL_STR=$(sed -n ""$i"p" "$MAL_STR_FILE" | sed 's/\\/\\\\/g')
		echo "		\$string"$i" = \""$LINE_MAL_STR"\"" >> "$STR_YARA_RULE"
	done
	echo -e "\n	condition:\n		any of (\$string*)\n}" >> "$STR_YARA_RULE"
	MAL_STR_FOUND=$(yara "$STR_YARA_RULE" "$DIR"/Extracted_files/ | awk '{print $2}')
	if [ "$MAL_STR_FOUND" ];then
		echo " {+} files that are suspected to be malicious according to the malicious strings file:"
		echo "$MAL_STR_FOUND"
		touch "$DIR"/Malicious_file_found_strings.lst
		echo -e "runtime: "$TIME" -  IOC file: "$MAL_STR_FILE"\n\nFiles found with malicious strings:" > "$DIR"/Malicious_file_found_strings.lst
		echo "$MAL_STR_FOUND" >> "$DIR"/Malicious_file_found_strings.lst
	else
		echo " {+} No file found with malicious strings according to the file: "$MAL_STR_FILE""
	fi
}

#creating a yara rule and cheking the file that were extracted.
function IMPHASH_SCAN(){
	echo " {+} Cheking files for malicious import hashes with yara."
	IMP_YARA_RULE=$(mktemp -t XXXXX.yar)
	END=$(tail -1 "$IMPHASH_FILE")
	echo -e "import \"pe\"\n\nrule mal_import_hash {\n	condition:" > "$IMP_YARA_RULE"
	for q in $(cat "$IMPHASH_FILE");do
		if [ "$q" != "$END" ];then
			echo "		pe.imphash() == \""$q"\" or" >> "$IMP_YARA_RULE"
		else
			echo -e "		pe.imphash() == \""$q"\"\n}" >> "$IMP_YARA_RULE"
		fi
	done 
	MAL_IMP_FOUND=$(yara "$IMP_YARA_RULE" "$DIR"/Extracted_files/ | awk '{print $2}')
	if [ "$MAL_IMP_FOUND" ];then
		echo " {+} Files that were found to be malicious my their import hash:" 
		echo "$MAL_IMP_FOUND"
		touch "$DIR"/Malicious_files_found_imphash.log
		echo -e "runtime: "$TIME" -  IOC file: "$IMPHASH_FILE"\n\nFiles found with malicious import hashes:" > "$DIR"/Malicious_files_found_imphash.log
		echo "$MAL_IMP_FOUND" >> "$DIR"/Malicious_files_found_imphash.log
	else
		echo " {+} No file found with malicious import hashes according to the file: "$IMPHASH_FILE""
	fi
}

#creating a yara rule and cheking the file that were extracted.
function SHA256_SCAN(){
	echo " {+} Cheking files for malicious sha256 hashes with yara."
	SHA256_YARA_RULE=$(mktemp -t XXXXX.yar)
	END2=$(tail -1 "$MAL_SHA256_FILE")
	echo -e "import \"hash\"\n\nrule mal_import_hash {\n	condition:" > "$SHA256_YARA_RULE"
	for q in $(cat "$MAL_SHA256_FILE");do
		if [ "$q" != "$END2" ];then
			echo "		hash.sha256(0, filesize) == \""$q"\" or" >> "$SHA256_YARA_RULE"
		else
			echo -e "		hash.sha256(0, filesize) == \""$q"\"\n}" >> "$SHA256_YARA_RULE"
		fi
	done 
	
	MAL_SHA256_FOUND=$(yara "$SHA256_YARA_RULE" "$DIR"/Extracted_files | awk '{print $2}')
	if [ "$MAL_SHA256_FOUND" ];then
		echo " {+} Files that were found to be malicious my their sha256 hash:" 
		echo "$MAL_SHA256_FOUND"
		touch "$DIR"/Malicious_files_found_sha256.log
		echo -e "runtime: "$TIME" -  IOC file: "$MAL_SHA256_FILE"\n\nFiles found with malicious sha256 hashes:" > "$DIR"/Malicious_files_found_sha256.log
		echo "$MAL_SHA256_FOUND" >> "$DIR"/Malicious_files_found_sha256.log
	else
		echo " {+} No file found with malicious sha256 hashes according to the file: "$MAL_SHA256_FILE""
	fi
}

#using tshark to extract all file that were downloaded on HTTP
function FILE_EXPORTING(){
	echo -e "\n {+} if any, extracting all files downloaded on HTTP:\n"
	tshark -r "$PCAP_FILE" -q --export-objects http,"$DIR"/Extracted_files 2>/dev/null
	FILES_FOUND=$(ls "$DIR"/Extracted_files | wc -l)
	if [ "$FILES_FOUND" == '0' ];then
		echo -e "~ No files found in the file\n"
	else
		echo -e "~ files found statistics:"
		for i in "$DIR"/Extracted_files/*;do file "$i" | awk -F':' '{print $2}';done | sort | uniq -c | sort -n
	fi
	if [ "$MAL_STR_FILE" != '' ];then
		MAL_STR_SCAN
	fi
	if [ "$IMPHASH_FILE" != '' ];then
		IMPHASH_SCAN
	fi
	if [ "$MAL_SHA256_FILE" != '' ];then
		SHA256_SCAN
	fi
}

#doing a simple read and creating a log of all domains that were visited, by whom and at what time.
function NO_ARGS_READ(){
	touch "$DIR"/hosts_accessed.log
	echo -e "run time: "$TIME" \n	~/ Pcap reader - Malicious domains & files \~ \n"
	echo -e "runtime: "$TIME" - file: "PCAP_FILE"\n" > "$DIR"/hosts_accessed.log
	echo -e " {+} Hosts accsessed log:\n" | tee -a "$DIR"/hosts_accessed.log
	tshark -r "$PCAP_FILE" -Y "ssl.handshake.extensions_server_name || http.host" -Tfields -e frame.time_epoch -e ip.src -e http.host -e ssl.handshake.extensions_server_name 2>/dev/nul| while read -r LINE;do
		EPOCH_TIME=$(echo "$LINE" | awk '{print $1}')
		FRAME_TIME=$(date -d @"$EPOCH_TIME" +"%Y-%m-%d %H:%M:%S")
		IP_SRC=$(echo "$LINE" | awk '{print $2}')
		HOST=$(echo "$LINE" | awk '{print $3}')
		echo "~ $FRAME_TIME : "$IP_SRC" accessed "$HOST"" | tee -a "$DIR"/hosts_accessed.log
	done
	FILE_EXPORTING
}


#does the same as the NO_ARGS_READ but cheicks the visited domians via the IOC file
function ARGS_READ(){
	TIME=$(date +"%Y-%m-%d %H:%M:%S")
	touch "$DIR"/hosts_accessed.log
	echo -e "run time: "$TIME" \n	~/ Pcap reader - Malicious domains & files \~ \n"
	echo -e "runtime: "$TIME" - file: "$PCAP_FILE"\n" > "$DIR"/hosts_accessed.log
	echo -e " {+} Hosts accsessed log:\n" | tee -a "$DIR"/hosts_accessed.log
	touch "$DIR"/Malicious_hosts.log
	echo -e "runtime: "$TIME" -  IOC file: "$MAL_DOMAINS_FILE"\n\nmalicious hosts:" > "$DIR"/Malicious_hosts.log
	tshark -r "$PCAP_FILE" -Y "ssl.handshake.extensions_server_name || http.host" -Tfields -e frame.time_epoch -e ip.src -e http.host -e ssl.handshake.extensions_server_name 2>/dev/nul| while read -r LINE;do
		EPOCH_TIME=$(echo "$LINE" | awk '{print $1}')
		FRAME_TIME=$(date -d @"$EPOCH_TIME" +"%Y-%m-%d %H:%M:%S")
		IP_SRC=$(echo "$LINE" | awk '{print $2}')
		HOST=$(echo "$LINE" | awk '{print $3}')
		echo "~ $FRAME_TIME : "$IP_SRC" accessed "$HOST"" | tee -a "$DIR"/hosts_accessed.log
		MAL_WEB=$(grep "$HOST" "$MAL_DOMAINS_FILE")
		if [ "$MAL_WEB" ];then
			echo " ~!!!~ "$HOST" IS SUSPECTED TO BE A MALICIOUS DOMAIN/IP BY THE FILE "$MAL_DOMAINS_FILE""
			echo "~"$FRAME_TIME" - "$IP_SRC" accessed "$HOST" which is suspected to be a malicious host." >> "$DIR"/Malicious_hosts.log 
		fi
	done
	FILE_EXPORTING
}

if [ "$MAL_DOMAINS_FILE" == '' ];then
	NO_ARGS_READ
else
	ARGS_READ
fi
