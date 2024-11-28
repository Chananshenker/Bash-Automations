#!/bin/bash

CYAN="\033[1;36m"
GREEN="\e[32m"
YELLOW="\e[33m"
RED="\e[31m"
RESET="\e[0m"

VIRUSTOTAL_API_KEY='<YOUR_API_KEY_HERE>'
ABUSEIPDB_API_KEY='<YOUR_API_KEY_HERE>'
GREAYNOISE_API_KEY='<YOUR_API_KEY_HERE>'

INPUT="$1"


function IP_FILE(){
      for IP in $(cat "$INPUT");do
            echo -e "\n${CYAN}results for ${IP}:${RESET}\n\nVirusTotal:"
            VT_SCORE=$(curl -s --request GET \
            --url "https://www.virustotal.com/api/v3/ip_addresses/${IP}" \
            --header "x-apikey: ${VIRUSTOTAL_API_KEY}" | jq '.data.attributes.last_analysis_stats' | grep -Ev '\{|\}' |sed 's/"//g ; s/,//g')
            echo -e "${VT_SCORE}"

            echo -e "\nAbuseIPDB:"
            AID_SCORE=$(curl -s -G https://api.abuseipdb.com/api/v2/check \
            --data-urlencode "ipAddress=${IP}" \
            -H "Key: ${ABUSEIPDB_API_KEY}" \
            -H "Accept: application/json" | jq '.data.abuseConfidenceScore')
            echo -e "  clean score: ${AID_SCORE}"

            echo -e "\nGreynoise:"
            GREAYNOISE_RES=$(curl -s -H "key: ${GREAYNOISE_API_KEY}" "https://api.greynoise.io/v3/community/${IP}" | grep -vE "{|}" | sed 's/"//g ; s/,//g')
            echo "$GREAYNOISE_RES"

            echo -e "\nGeoIPLookup:"
            GEOIPLOOKUP_RES=$(geoiplookup "$IP")
            echo -e " ${GEOIPLOOKUP_RES}"
      done
}

function SINGLE_IP(){
      echo -e "results for ${IP}:\n\nVirusTotal:"
      VT_SCORE=$(curl -s --request GET \
      --url "https://www.virustotal.com/api/v3/ip_addresses/${IP}" \
      --header "x-apikey: ${VIRUSTOTAL_API_KEY}" | jq '.data.attributes.last_analysis_stats' | grep -Ev '\{|\}' |sed 's/"//g ; s/,//g')
      echo -e "${VT_SCORE}"

      echo -e "\nAbuseIPDB:"
      AID_SCORE=$(curl -s -G https://api.abuseipdb.com/api/v2/check \
      --data-urlencode "ipAddress=${IP}" \
      -H "Key: ${ABUSEIPDB_API_KEY}" \
      -H "Accept: application/json" | jq '.data.abuseConfidenceScore')
      echo -e "  clean score: ${AID_SCORE}"

      echo -e "\nGreynoise:"
      GREAYNOISE_RES=$(curl -s -H "key: ${GREAYNOISE_API_KEY}" "https://api.greynoise.io/v3/community/${IP}" | grep -vE "{|}" | sed 's/"//g ; s/,//g')
      echo "$GREAYNOISE_RES"

      echo -e "\nGeoIPLookup:"
      GEOIPLOOKUP_RES=$(geoiplookup "$IP")
      echo -e " ${GEOIPLOOKUP_RES}"
}

if [ -f "$1" ];then
      IP_FILE
else
      IP="$1"
      SINGLE_IP
fi
