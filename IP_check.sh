#!/bin/bash

CYAN="\033[1;36m"
GREEN="\e[32m"
YELLOW="\e[33m"
RED="\e[31m"
RESET="\e[0m"

VIRUSTOTAL_API_KEY='<YOUR_API_KEY_HERE>'
ABUSEIPDB_API_KEY='<YOUR_API_KEY_HERE>'
GREAYNOISE_API_KEY='<YOUR_API_KEY_HERE>'
FRAUDGUARD_CREDS='<YOUR_API_KEY_HERE>'

INPUT="$1"

function IP_FILE(){
      for IP in $(cat "$INPUT");do
            echo -e "\n${CYAN}results for ${IP}:${RESET}\n"
            VT_RES_PARSED=$(curl -s --request GET \
            --url "https://www.virustotal.com/api/v3/ip_addresses/${IP}" \
            --header "x-apikey: ${VIRUSTOTAL_API_KEY}" | jq '.data.attributes.last_analysis_stats' | grep -vE '{|}' | sed 's/\,//g ; s/\"//g')
            if [ "$(echo "$VT_RES_PARSED" | grep -E 'malicious|suspicious' | awk '{print $2}' | sort | uniq)" != '0' ];then
                  echo -e "VirusTotal: ${RED}NOT CLEAN!\n${VT_RES_PARSED}${RESET}" 
            else 
                  echo -e "VirusTotal: ${GREEN}clean :)${RESET}"
            fi

            AID_RES=$(curl -s -G https://api.abuseipdb.com/api/v2/check \
            --data-urlencode "ipAddress=${IP}" \
            -H "Key: ${ABUSEIPDB_API_KEY}" \
            -H "Accept: application/json" | jq '{"clean score": .data.abuseConfidenceScore}' | grep -vE '{|}' | sed 's/\,//g ; s/\"//g')
            if [ "$(echo $AID_RES | awk '{print $3}')" -gt '50' ];then
                  echo -e "AbuseIPDB: ${RED} NOT CLEAN!\n${AID_RES}${RESET}"
            elif [ "$(echo $AID_RES | awk '{print $3}')" -gt '0' ];then
                  echo -e "AbuseIPDB: ${YELLOW} possibly not clean!\n${AID_RES}${RESET}"
            elif [ "$(echo $AID_RES | awk '{print $3}')" == '0' ];then
                  echo -e "AbuseIPDB: ${GREEN}clean :)${RESET}"
            fi

            FRAUDGUARD_RES=$(curl -s -X GET -u "${FRAUDGUARD_CREDS}" "https://@api.fraudguard.io/v2/ip/${IP}" | jq '{"risk level": .risk_level}' | grep -vE '{|}' | sed 's/\,//g ; s/\"//g')
            if [ "$(echo $FRAUDGUARD_RES | awk '{print $3}')" -gt '3' ];then
                 echo -e "Fraudguard: ${RED}NOT CLEAN!\n${FRAUDGUARD_RES}${RESET}"
            elif [ "$(echo $FRAUDGUARD_RES | awk '{print $3}')" -gt '1' ];then
                 echo -e "Fraudguard: ${YELLOW} possibly not clean!\n${FRAUDGUARD_RES}${RESET}"
            else
                  echo -e "Fraudguard: ${GREEN}clean :)${RESET}"
            fi

            GEOIPLOOKUP_RES=$(geoiplookup "$IP" | awk '{$1=$2=$3=""; print $0}')
            if ! [ -z "$(echo "$GEOIPLOOKUP_RES" | awk '{print $1}' | grep -E 'RU|CN|KP|IR|LB|YE|PS')" ];then
                  echo -e "GeoIPLookup:${RED}${GEOIPLOOKUP_RES}${RESET}"
            elif ! [ -z "$(echo "$GEOIPLOOKUP_RES" | awk '{print $1}' | grep -E 'IN|EG|UA')" ];then
                  echo -e "GeoIPLookup:${YELLOW}${GEOIPLOOKUP_RES}${RESET}"
            else
                  echo -e "GeoIPLookup:${GEOIPLOOKUP_RES}"
            fi
      done
}

function SINGLE_IP(){
      echo -e "\n${CYAN}results for ${IP}:${RESET}\n"
      VT_RES_PARSED=$(curl -s --request GET \
      --url "https://www.virustotal.com/api/v3/ip_addresses/${IP}" \
      --header "x-apikey: ${VIRUSTOTAL_API_KEY}" | jq '.data.attributes.last_analysis_stats' | grep -vE '{|}' | sed 's/\,//g ; s/\"//g')
      VT_RES_SCORE=$(echo "$VT_RES_PARSED" | grep -E 'malicious|suspicious' | awk '{print $2}' | sort | uniq)
      if [ "$VT_RES_SCORE" != '0' ];then
            echo -e "VirusTotal: ${RED}NOT CLEAN!\n${VT_RES_PARSED}${RESET}" 
      else 
            echo -e "VirusTotal: ${GREEN}clean :)${RESET}"
      fi

      AID_RES=$(curl -s -G https://api.abuseipdb.com/api/v2/check \
      --data-urlencode "ipAddress=${IP}" \
      -H "Key: ${ABUSEIPDB_API_KEY}" \
      -H "Accept: application/json" | jq '{"clean score": .data.abuseConfidenceScore}' | grep -vE '{|}' | sed 's/\,//g ; s/\"//g')
      if [ "$(echo $AID_RES | awk '{print $3}')" -gt '50' ];then
            echo -e "AbuseIPDB: ${RED}NOT CLEAN!\n${AID_RES}${RESET}"
      elif [ "$(echo $AID_RES | awk '{print $3}')" -gt '0' ];then
            echo -e "AbuseIPDB: ${YELLOW} possibly not clean!\n${AID_RES}${RESET}"
      elif [ "$(echo $AID_RES | awk '{print $3}')" == '0' ];then
            echo -e "AbuseIPDB: ${GREEN}clean :)${RESET}"
      fi
      
      FRAUDGUARD_RES=$(curl -s -X GET -u "${FRAUDGUARD_CREDS}" "https://@api.fraudguard.io/v2/ip/${IP}" | jq '{"risk level": .risk_level}' | grep -vE '{|}' | sed 's/\,//g ; s/\"//g')
      if [ "$(echo $FRAUDGUARD_RES | awk '{print $3}')" -gt '3' ];then
            echo -e "Fraudguard: ${RED}NOT CLEAN!\n${FRAUDGUARD_RES}${RESET}"
      elif [ "$(echo $FRAUDGUARD_RES | awk '{print $3}')" -gt '1' ];then
            echo -e "Fraudguard: ${YELLOW} possibly not clean!\n${FRAUDGUARD_RES}${RESET}"
      else
            echo -e "Fraudguard: ${GREEN}clean :)${RESET}"
      fi

      GEOIPLOOKUP_RES=$(geoiplookup "$IP" | awk '{$1=$2=$3=""; print $0}')
      if   [ -z "$(echo "$GEOIPLOOKUP_RES" | awk '{print $1}' | sed 's/,//g' | grep -vE 'RU|CN|KP|IR|LB|YE|PS|SY')" ];then
            echo -e "GeoIPLookup:${RED}${GEOIPLOOKUP_RES}${RESET}"
      elif ! [ -z "$(echo "$GEOIPLOOKUP_RES" | awk '{print $1}' | sed 's/,//g' | grep -E 'IN|EG|UA')" ];then
            echo -e "GeoIPLookup:${YELLOW}${GEOIPLOOKUP_RES}${RESET}"
      else
            echo -e "GeoIPLookup:${GEOIPLOOKUP_RES}"
      fi
}

if [ -f "$1" ];then
      IP_FILE
else
      IP="$1"
      SINGLE_IP
fi
