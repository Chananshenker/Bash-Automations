#!/bin/bash

#Simple network pentesting automation to test weak credentials and Vulnerabilities
#made by: Chanan shenker

DATE=$(date +"%Y-%m-%d %H:%M:%S")
TEMP_FILE=$(mktemp -t XXXX.lst)

#asthetic banner
function BANNER(){
	clear
	if [ "$START_CHOICE" != '' ];then
		if [ "$NETWORK_SUBNET" != '' ];then
			echo ""$DATE" - Mode: "$MODE" - Network: "$NETWORK_SUBNET""
		else
			echo ""$DATE" - Mode: "$MODE""
		fi
	else
		echo ""$DATE""
	fi
	echo -e "\n    #/  Network analyzer - scanner, weak credentials & Vulnerabilities  \#\n"
}

#asking the user to supply a password list or using a default list which is rockyou.txt
function PASS_CREDS(){
	BANNER
	read -e -p " [+] Now please provide a password list (leave blank to use default list): " PASS_ANS
	if [ "$PASS_ANS" == '' ];then
		if [ "$START_CHOICE" == "1" ];then
			echo " [+] ok going with default list: /usr/share/wordlists/10k-most-common.txt"
			PASSLIST='/usr/share/wordlists/10k-most-common.txt'
		elif [ "$START_CHOICE" == "2" ];then
			echo " [+] Ok using default list: /usr/share/wordlists/rockyou.txt"
			PASSLIST='/usr/share/wordlists/rockyou.txt'
		fi
		sleep 1.5
	elif ! [ -f "$PASS_ANS" ];then
		echo " [/] file not found."
		sleep 1.5
		PASS_CREDS
	else 
		PASSLIST=$(echo "$PASS_ANS")
	fi
}

#asking from the user to suplly a username lsit or using a default one
function USER_CREDS(){
	BANNER
	read -e -p " [+] for weak credentials testing please provide a username list (leave blank to use default list): " USER_ANS
	if [ "$USER_ANS" == '' ];then
		echo " [+] Ok using default list: /usr/share/commix/src/txt/usernames.txt"
		USERLIST='/usr/share/commix/src/txt/usernames.txt'
		sleep 1.5
	elif ! [ -f "$USER_ANS" ];then
		echo " [/] file not found."
		sleep 1.5
		USER_CREDS
	else 
		USERLIST=$(echo "$USER_ANS")
	fi
	PASS_CREDS
}

#testing if input is an ip adress range
function TEST_IP(){
	local input="$1"
	if ! [[ $input =~ ^([0-9]{1,3}\.){3}\* ]] && ! [[ $input =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]] && ! [[ $input =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}$ ]]; then
		NETWORK_SUBNET=''
		BANNER
		echo " [+] Invalid subnet. please resubmit a valid subnet."
		sleep 1
		START2
	fi
}

#asking the user to supply a network subnet to scan 
function START2(){
	BANNER
	read -p " [+] Please provide a subnet to scan (example: 10.0.0.0/24): " NETWORK_SUBNET
	TEST_IP "$NETWORK_SUBNET"
}

#making a directory to save all the results to
function MKDIR(){
	BANNER 
	read -p " [+] Please provide a directory name to save all the results to: " DIR
	if [ -d "$DIR" ];then
		echo " [!] Directory already exists, please provide a diffrent name."
		sleep 1
		MKDIR
	elif [ -f "$DIR" ];then
		echo " [!] File exists with that name, please provide a diffrent name."
		sleep 1
		MKDIR
	else 
		mkdir "$DIR"
		echo " [+] Results will be saved to "$PWD"/"$DIR""
		sleep 1.5
	fi
}

#advanced version of the scan. scanning all ports and udp ports, testing for Vulnerabilities with nmaps vulners.nse,
#testing for common credentials with nmap brute.nse scripts and looking for OS info
function ADVANCED_SCAN(){
	BANNER
	mkdir "$PWD"/"$DIR"/Nmap_results
	echo " [+] Starting initaial scan..."
	HOST=$(hostname -I)
	fping -agq "$NETWORK_SUBNET" | grep -v $HOST > "$TEMP_FILE"
	HOSTS=$(cat "$TEMP_FILE" | wc -l)
	if [ "$HOSTS" == "0" ];then
		echo " [+] No live hosts found. exiting..."
		rm -r "$DIR"
		exit
	fi
	echo " [+] "$HOSTS" hosts found live."
	echo " [+] starting nmap scans, weak credentials testing & Vulnerabilities finding."
	for i in $(cat "$TEMP_FILE");do
		nmap "$i" -p- -sV -sC -O --script=ftp-brute.nse,ssh-brute.nse,telnet-brute.nse,smb-brute.nse,vulners.nse --script-args userdb="$USERLIST",passdb="$PASSLIST" -oN "$PWD"/"$DIR"/Nmap_results/"$i"_scan.txt >/dev/null 2>&1
		PORTS=$(cat "$PWD"/"$DIR"/Nmap_results/"$i"_scan.txt | awk '$2 == "open"' | wc -l)
		echo " [+] "$i": "$PORTS" ports found open."
		WEAK_CREDS=$(cat "$PWD"/"$DIR"/Nmap_results/"$i"_scan.txt | grep "Valid credentials" | awk '{print $2}' | sort | uniq)
		if [ "$WEAK_CREDS" ];then
			sleep 0.4
			echo " [+] Weak credentials found:"
			for q in $(echo "$WEAK_CREDS");do
				echo "   - "$q""
			done
		fi
	done
	echo " [+] Scanning for UDP ports with masscan."
	touch "$PWD"/"$DIR"/Masscan_scan.txt
	masscan -iL "$TEMP_FILE" -pU:0-65535 --rate 1000 >> "$PWD"/"$DIR"/Masscan_scan.txt 2>/dev/null
	UDP_PORTS=$(cat "$PWD"/"$DIR"/Masscan_scan.txt | wc -l)
	if [ "$UDP_PORTS" == '0' ];then
		echo " [+] No UDP ports found."
	else
		echo " [+] "$UDP_PORTS" UDP ports found."
	fi
}

#basic version of the scan. scanning 1000 default ports, getting service versions, and testing for weak credentials
function BASIC_SCAN(){
	BANNER
	mkdir "$PWD"/"$DIR"/Nmap_results
	echo " [+] Starting initaial scan..."
	HOST=$(hostname -I)
	fping -agq "$NETWORK_SUBNET" | grep -v $HOST > "$TEMP_FILE"
	HOSTS=$(cat "$TEMP_FILE" | wc -l)
	if [ "$HOSTS" == "0" ];then
		echo " [+] No live hosts found. exiting..."
		rm -r "$DIR"
		exit
	fi
	echo " [+] "$HOSTS" hosts found live."
	echo " [+] starting nmap scans and weak credentials testing."
	for i in $(cat "$TEMP_FILE");do
		nmap "$i" -sV -sC --script=ftp-brute.nse,ssh-brute.nse,telnet-brute.nse,smb-brute.nse --script-args userdb="$USERLIST",passdb="$PASSLIST" -oN "$PWD"/"$DIR"/Nmap_results/"$i"_scan.txt >/dev/null 2>&1
		PORTS=$(cat "$PWD"/"$DIR"/Nmap_results/"$i"_scan.txt | awk '$2 == "open"' | wc -l)
		echo " [+] "$i": "$PORTS" ports found open."
		WEAK_CREDS=$(cat "$PWD"/"$DIR"/Nmap_results/"$i"_scan.txt | grep "Valid credentials" | awk '{print $2}' | sort | uniq)
		if [ "$WEAK_CREDS" ];then
			sleep 0.4
			echo " [+] Weak credentials found:"
			for q in $(echo "$WEAK_CREDS");do
				echo "   - "$q""
			done
		fi
	done
	echo " [+] Basic scan done."
}

#using searchsploit to see if theres any existing exploit for the CVEs found with nmaps vulners.nse script
function SEARCHSPLOIT(){
	TEMP_FILE2=$(mktemp -t XXXXX.txt)
	echo " [+] Starting exploit searching with searchsploit."
	mkdir "$PWD"/"$DIR"/Searchsploit_results
	for p in "$PWD"/"$DIR"/Nmap_results/*;do
		if [ "cat "$p" | grep -o "CVE.*" | awk '{print $1}' | sort | uniq" ];then
			VULNERS=$(cat "$p" | grep -o "CVE.*" | awk '{print $1}' | sort | uniq | wc -l)
			IP=$(echo "$p" | awk -F'/' '{print $NF}' | awk -F'_' '{print $1}')
			cat "$p" | grep -o "CVE.*" | awk '{print $1}' | sort | uniq > "$TEMP_FILE2"
			touch "$PWD"/"$DIR"/Searchsploit_results/"$IP"_Searchsploit_result.txt
			echo -e "#searchslpoit results for all the CVEs found for - "$IP" #\n" > "$PWD"/"$DIR"/Searchsploit_results/"$IP"_Searchsploit_result.txt
			for e in $(cat "$TEMP_FILE2");do
				searchsploit --cve "$e" | grep -v "No Results" >> "$PWD"/"$DIR"/Searchsploit_results/"$IP"_Searchsploit_result.txt 2>/dev/null
			done
			EXPLOITS=$(cat "$PWD"/"$DIR"/Searchsploit_results/"$IP"_Searchsploit_result.txt | grep "Exploit Title" | wc -l)
			echo " [+] "$IP": "$VULNERS" possible vulnerabilities & "$EXPLOITS" possible exploits found"
		fi
	done
	for v in $(ls -l "$PWD"/"$DIR"/Searchsploit_results | awk '$5 == "70"' | awk '{print $NF}');do
		rm "$PWD"/"$DIR"/Searchsploit_results/"$v"
	done
	SEARCH_CHECK=$(ls "$PWD"/"$DIR"/Searchsploit_results)
	if ! [ "$SEARCH_CHECK" ];then
		rm -r "$PWD"/"$DIR"/searchsploit_results/
		echo " [+] No exploits found with searchsploit at all."
	fi
}

#asking the user to choose what mode to scan in.
function START(){
	BANNER
	echo -e " [+] options:\n   1) Basic - port scanning and service versions, weak credentials testing.\n   2) Advanced - more extensive weak credantials testing and Vulnerabilities finding."
	read -n 1 -p " [+] Choice: " START_CHOICE
	case $START_CHOICE in
	1)
		MODE='Basic'
		MKDIR
		START2
		USER_CREDS
		BASIC_SCAN
	;;
	2)
		MODE='Advanced'
		MKDIR
		START2
		USER_CREDS
		ADVANCED_SCAN
		SEARCHSPLOIT
	;;
	*)
		echo -e "\n [/] wrong input."
		sleep 1.5
		START_CHOICE=''
		START
	esac
} 

#testing to see if the user is not root, if not exiting
if [ "$UID" != '0' ];then
	BANNER
	echo " [/] You are not logged in as a root user, please log in with the needed priviliges and start again."
	exit
fi

#downloading useful pasword list for basic scan.
if ! [ -f /usr/share/wordlists/10k-most-common.txt ];then
	wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10k-most-common.txt -P /usr/share/wordlists/ >/dev/null 2>&1
fi
START
