#!/bin/bash

#Active Directory scannr by chanan shenker
#this script is a vulnerablilites tester for active directory enviroments.

DATE=$(date +"%Y-%m-%d %H:%M:%S")
TEMP_FILE1=$(mktemp -t XXXX.lst)
TEMP_FILE2=$(mktemp -t XXXX.lst)

if [ "$UID" != "0" ];then
	echo "### you do not have the relevant priviliges to run this script, please change to the root user and run the script again. ###"
	exit
fi

#a fun banner
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
	echo -e "\n    #/  Network analyzer - Active directory and network scanner \#\n"
}

#tests the input to see if its a valid adress range
function TEST_IP(){
	local input="$1"
	if [[ ! "$1" =~ ^([0-9]{1,3}.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] && [[ ! "$1" =~ ^([0-9]{1,3}.){3}[0-9]{1,3}$ ]]; then
		NETWORK_SUBNET=''
		BANNER
		echo " [+] Invalid subnet. please resubmit a valid subnet."
		sleep 1
		START2
	fi
}

#basic scan start. scans 100 ports and chekcs what ip is the AD
function BASIC_SCAN(){
	HOST_NAME=$(hostname -I)
	BANNER
	echo " [+] Staring nmap scan..."
	nmap "$NETWORK_SUBNET" -Pn | grep 'Nmap scan report for' | awk '{print $NF}' | grep -vE "254$|255$" | grep -v $HOST_NAME > "$TEMP_FILE1"
	HOSTS=$(cat "$TEMP_FILE1" | wc -l)
	if [ "$HOSTS" = '0' ] ;then
		echo -e " [/] No live hosts were found.\n [+] exiting."
		exit
	fi
	echo " [+] "$HOSTS" hosts were found live."
	mkdir "$DIR"/Nmap_results
	for ip in $(cat "$TEMP_FILE1");do
		nmap "$ip"  -Pn -sV --script=vulners.nse -oN ./"$DIR"/Nmap_results/"$ip"_scan >/dev/null 2>&1
		PORTS=$(cat ./"$DIR"/Nmap_results/"$ip"_scan | grep open | wc -l)
		DOMAIN=$(cat ./"$DIR"/Nmap_results/"$ip"_scan | grep ldap | head -1 | grep -o "Domain.*" | awk '{print $2}' | sed 's/,//g' )
		if [ "$DOMAIN" ];then
			echo " [+] "$ip": Domian controller (Domian: "$DOMAIN") - "$PORTS" open ports"
		else
			echo " [+] "$ip": "$PORTS" open ports"
		fi
	done
	echo -e " [+] Netwrok analysis done.\n [+] all results saved to "$PWD"/"$DIR""
}

#requesting a password list for the brute force attacks
function PASS_CREDS(){
	BANNER
	read -e -p " [+] Now please provide a password list (leave blank to use default list): " PASS_ANS
	if [ "$PASS_ANS" == '' ];then
		echo " [+] Ok using default list: /usr/share/wordlists/rockyou.txt"
		PASSLIST='/usr/share/wordlists/rockyou.txt '
		sleep 1.5
	elif ! [ -f "$PASS_ANS" ];then
		echo " [/] file not found."
		sleep 1.5
		PASS_CREDS
	else 
		PASSLIST=$(echo "$PASS_ANS")
	fi
}

#requesting a username list for brute force attack
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

#requesting a address range
function START2(){
	BANNER
	read -p " [+] Please provide a subnet to scan: " NETWORK_SUBNET
	TEST_IP "$NETWORK_SUBNET"
}

#requesting domain user credentials for DC enumeration
function DOMAIN_USER_CREDENTIALS(){
	BANNER
	read -p " [+] If given, please enter domain username, else leave blank: " DOMAIN_USERNAME
	if [ "$DOMAIN_USERNAME" == '' ];then
		echo " [!] Ok continuing without credentials."
		sleep 1.2
	else
		read -s -p " [+] Now the domain users password: " DOMAIN_USER_PASS
	fi
}

#enumerating SMB shares
function SMB_SHARES(){
	DOMAIN_IP=$(grep "DOMAIN_IP" "$TEMP_FILE2" | awk '{print $2}')
	DOMAIN_NAME=$(grep "DOMAIN_IP" "$TEMP_FILE2" | awk '{print $3}')
	echo " [+] Attempting to enumerate SMB shares"
	touch "$PWD"/"$DIR"/SMB_shares.txt
	if [ "$DOMAIN_USERNAME" == '' ];then
		smbclient -L //"$DOMAIN_IP" -N >> "$PWD"/"$DIR"/SMB_shares.txt 2>/dev/null
	else 
		smbclient -L //"$DOMAIN_IP" -U "$DOMAIN_NAME"/"$DOMAIN_USERNAME"%"$DOMAIN_USER_PASS" >> "$PWD"/"$DIR"/SMB_shares.txt 2>/dev/null
	fi
	SHARES_FOUND=$(sed '$d' "$PWD"/"$DIR"/SMB_shares.txt | sed '$d' | grep '\S')
	if [ "$SHARES_FOUND" ];then
		echo " [+] SMB shares found:"
		echo "$SHARES_FOUND"
	else
		echo " [+] No SMB shares found."
	fi
}

#scans with more ports and more NSE scripts
function INTERMEDIATE_SCAN(){
	HOST_NAME=$(hostname -I)
	BANNER
	echo " [+] Staring nmap scan..."
	nmap "$NETWORK_SUBNET" -Pn | grep 'Nmap scan report for' | awk '{print $NF}' | grep -vE "254$|255$" | grep -v $HOST_NAME > "$TEMP_FILE1"
	HOSTS=$(cat "$TEMP_FILE1" | wc -l)
	if [ "$HOSTS" = '0' ] ;then
		echo -e " [/] No live hosts were found.\n [+] exiting."
		exit
	fi
	echo " [+] "$HOSTS" hosts were found live."  
	mkdir "$DIR"/Nmap_results
	for ip in $(cat "$TEMP_FILE1");do
		nmap "$ip"  -Pn -p- -sV --script=vulners.nse,default,smb-os-discovery.nse,ldap-rootdse.nse  -oN ./"$DIR"/Nmap_results/"$ip"_scan >/dev/null 2>&1
		PORTS=$(cat ./"$DIR"/Nmap_results/"$ip"_scan | grep open | wc -l)
		DOMAIN=$(cat ./"$DIR"/Nmap_results/"$ip"_scan | grep "open  ldap" | head -1 | grep -o "Domain.*" | awk '{print $2}' | sed 's/,//g')
		if [ "$DOMAIN" ];then
			echo " [+] "$ip": Domian controller (Domian: "$DOMAIN") - "$PORTS" open ports"
			echo "DOMAIN_IP "$ip" "$DOMAIN"" >> "$TEMP_FILE2"
		else
			echo " [+] "$ip": "$PORTS" open ports"
		fi
	done
	echo " [+] Nmap scan done"
}

#adds UDP scan.
function ADVANCED_SCAN(){
	HOST_NAME=$(hostname -I)
	BANNER
	echo " [+] Staring nmap scan..."
	nmap "$NETWORK_SUBNET" -Pn | grep 'Nmap scan report for' | awk '{print $NF}' | grep -vE "254$|255$" | grep -v $HOST_NAME > "$TEMP_FILE1"
	HOSTS=$(cat "$TEMP_FILE1" | wc -l)
	if [ "$HOSTS" = '0' ] ;then
		echo -e " [/] No live hosts were found.\n [+] exiting."
		exit
	fi
	echo " [+] "$HOSTS" hosts were found live."  
	mkdir "$DIR"/Nmap_results
	for ip in $(cat "$TEMP_FILE1");do
		nmap "$ip"  -Pn -p- -sV --script=vulners.nse,default,smb-os-discovery.nse,ldap-rootdse.nse  -oN ./"$DIR"/Nmap_results/"$ip"_scan >/dev/null 2>&1
		PORTS=$(cat ./"$DIR"/Nmap_results/"$ip"_scan | grep open | wc -l)
		DOMAIN=$(cat ./"$DIR"/Nmap_results/"$ip"_scan | grep "open  ldap" | head -1 | grep -o "Domain.*" | awk '{print $2}' | sed 's/,//g')
		if [ "$DOMAIN" ];then
			echo " [+] "$ip": Domian controller (Domian: "$DOMAIN") - "$PORTS" open ports"
			echo "DOMAIN_IP "$ip" "$DOMAIN"" > "$TEMP_FILE2"
		else
			echo " [+] "$ip": "$PORTS" open ports"
		fi
		
	done
	echo " [+] Nmap scan done"
	echo " [+] starting UDP scan with Masscan..."
	masscan -iL "$TEMP_FILE1" -pU:0-65535 --rate 1000 >> "$PWD"/"$DIR"/Masscan_results.txt 2>/dev/null
	UDP_PORTS=$(cat "$PWD"/"$DIR"/Masscan_results.txt| wc -l)
	if [ "$UDP_PORTS" == '0' ];then
		echo " [+] No UDP ports found open"
	else 
		echo " [+] "$UDP_PORTS" UDP ports found open."
	fi
}

#using hydra to do brute force user credentials
function BRUTE_FORCE(){
	DOMAIN_IP=$(grep "DOMAIN_IP" "$TEMP_FILE2" | awk '{print $2}')
	echo " [+] Starting weak credentials testing for domain users."
	hydra -L "$USERLIST" -P "$PASSLIST" smb://"$DOMAIN_IP" -o "$PWD"/"$DIR"/Hydra_results.txt >/dev/null 2>&1
	HYDRA_RESULTS=$(cat "$PWD"/"$DIR"/Hydra_results.txt | grep -o "login.*")
	if ! [ "$HYDRA_RESULTS" ];then
		echo " [+] No credentials found with hydra."
	else
		echo " [+] Weak credentials found with hydra:"
		echo "$HYDRA_RESULTS"
	fi
}

#making a directory to save all results
function MKDIR(){
	BANNER 
	read -p " [+] Please provide a directory name to save all the results to: " DIR
	if [ -d "$DIR" ];then
		echo " [!] Directory already exists, please provide a diffrent name."
		sleep 1
		MKDIR
	elif [ "$DIR" == '' ];then
		echo " [!] Directory name cant be blank."
		sleep 1
		MKDIR
	else 
		mkdir "$DIR"
		echo " [+] Results will be saved to "$PWD"/"$DIR""
		sleep 1.5
	fi
}

#enumerating DC for user, groups . password policy etc.
function DOMAIN_ENUMERATION(){
	DOMAIN_IP=$(grep "DOMAIN_IP" "$TEMP_FILE2" | awk '{print $2}')
	DOMAIN_NAME=$(grep "DOMAIN_IP" "$TEMP_FILE2" | awk '{print $3}')
	CREDENTIALS_TESTING=$(hydra -l "$DOMAIN_USERNAME" -p "$DOMAIN_USER_PASS" smb://"$DOMAIN_IP" 2>/dev/null | grep -o "login: "$DOMAIN_USERNAME"   password: "$DOMAIN_USER_PASS"")
	echo " [+] Using the given domain user credentials, attempting to enumerate the DC."
	if [ "$CREDENTIALS_TESTING" != "login: "$DOMAIN_USERNAME"   password: "$DOMAIN_USER_PASS"" ];then
		echo -e " [+] Domain user credentials not valid.\n [+] exiting."
		exit
	fi
	echo " [+] getting all users."
	touch "$PWD"/"$DIR"/Domian_users.txt
	crackmapexec smb "$DOMAIN_IP" -u "$DOMAIN_USERNAME" -p "$DOMAIN_USER_PASS" -X "Get-ADUser -Filter *" | tail -n +4 | awk '{$1=$2=$3=$4=""; print $0}' | tee -a "$PWD"/"$DIR"/Domian_users.txt
	echo " [+] Getting all groups."
	touch "$PWD"/"$DIR"/Domain_groups.txt
	crackmapexec smb "$DOMAIN_IP" -u "$DOMAIN_USERNAME" -p "$DOMAIN_USER_PASS" --groups | tail -n +4 | awk '{$1=$2=$3=$4=""; print $0}' | tee -a "$PWD"/"$DIR"/Domain_groups.txt
	echo " [+] Gettign password policy."
	touch "$PWD"/"$DIR"/Domain_password_policy.txt
	crackmapexec smb "$DOMAIN_IP" -u "$DOMAIN_USERNAME" -p "$DOMAIN_USER_PASS" --pass-pol | tail -n +4 | awk '{$1=$2=$3=$4=""; print $0}'| tee -a "$PWD"/"$DIR"/Domain_password_policy.txt
	echo -e " [+] Netwrok analysis done.\n [+] all results saved to "$PWD"/"$DIR""
}

#start menu
function START(){
	BANNER
	echo -e " [+] Please choose the mode:\n   1 - Basic - Scanning, service version detection & Vulnerabilities detection.\n   2 - Intermediate - Weak credentials testing & SMB shares enumeration.\n   3 - Advanced - UDP scan. with valid credentials: extracting all users, groups, password policy."
	read -n 1 -p " [+] Choice: " START_CHOICE
	case $START_CHOICE in 
	1)
		MODE='Basic'
		MKDIR
		START2
		BASIC_SCAN
	;;
	2)
		MODE='Intermediate'
		MKDIR
		START2
		USER_CREDS
		DOMAIN_USER_CREDENTIALS
		INTERMEDIATE_SCAN
		SMB_SHARES
		BRUTE_FORCE
	;;
	3)
		MODE='Advanced'
		MKDIR
		START2
		USER_CREDS
		DOMAIN_USER_CREDENTIALS
		ADVANCED_SCAN
		SMB_SHARES
		BRUTE_FORCE
		DOMAIN_ENUMERATION
	;;
	*)
		echo -e "\n [/] Wrong input."
		sleep 1
		START_CHOICE=''
		START
	esac
}
START
