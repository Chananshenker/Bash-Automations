#!/bin/bash

#automatic craver, made by chanan shenker
#a quick carver for forensic use to attempt to extract all file from a HDD file or a memory file.
#NOTE: memory file carving only work with volatility_2.5_linux_x64

USER=$(whoami)
HERE=$(pwd)
REQS=( "foremost" "bulk-extractor" "binwalk" "binutils" )
file=$(echo $1)
DATE=$(date +"%d/%m/%Y")
TIME=$(date | awk '{print $4}')

#checking if the user is root and if its isnt the exiting, also alerting the user if the file that thhey provided does not exist
if [ "$USER" != "root" ]; then
	echo "[!] You are not signed in as a 'root' user."
	if ! [ -f $1 ]; then
		echo "[!] also $1 not found"
	fi
	echo "[!] Please switch users and run the script again."
	exit
fi

#alerting the user if the file does not exist then exiting
if ! [ -f $1 ]; then
	echo "[/] $1 not found, please provide an exisiting file when starting the script again. "
	exit
fi

#makign a report on the carving and compressing the dirrectory into to a zip file
function END(){
	echo "::Carving report::" | tee -a /root/Desktop/$ANS1/report.txt
	echo "---------------------------" | tee -a /root/Desktop/$ANS1/report.txt
	echo "Time: $DATE $TIME" | tee -a /root/Desktop/$ANS1/report.txt
	echo "File carved: $file" | tee -a /root/Desktop/$ANS1/report.txt
	echo "--------------------------- " | tee -a /root/Desktop/$ANS1/report.txt
	cd /root/Desktop/$ANS1
	PCAP2=$(find -iname *.pcap)
	if [ "$PCAP2" ]; then
		NUM_PCAP=$(find -iname *.pcap | wc -l)
		echo "number of network file found: $NUM_PCAP" | tee -a  /root/Desktop/$ANS1/report.txt
	fi
	EXE2=$(find -iname *.exe)
	if [ "$EXE2" ]; then
		NUM_EXE=$(find -iname *.exe | wc -l)
		echo "number of microsoft executable file found: $NUM_EXE" | tee -a  /root/Desktop/$ANS1/report.txt
	fi
	JPG2=$(find -iname *.jpg)
	if [ "$JPG2" ]; then
		NUM_JPG=$(find -iname *jpg | wc -l)
		echo "number of pictures found: $NUM_JPG" | tee -a  /root/Desktop/$ANS1/report.txt
	fi
	ZIP2=$(find -iname *.zip)
	if [ "$ZIP2" ]; then
		NUM_ZIP=$(find -iname *zip | wc -l)
		echo "number of zip files found: $NUM_ZIP" | tee -a  /root/Desktop/$ANS1/report.txt
	fi
	cd /root/Desktop
	zip -r "$ANS1".zip "$ANS1" >/dev/null 2>&1
	rm -r "$ANS1"
}

#if the file happens to be a memory file(RAM) then attempting to extract information with volatility
function VOL(){
	PROFILE=$(./volatility_2.5_linux_x64 -f $file imageinfo 2>/dev/null | grep "Suggested Profile(s)" | awk '{print $4}' | sed 's/,//g')
	echo "[!] this file seems to be a memory(RAM) file. " 
	mkdir /root/Desktop/$ANS1/vol_output
	PLUGINS=( "pslist" "connscan" "hivelist" "hashdump" "consoles" "printkey") 
	for COM in "${PLUGINS[@]}"
	do
		echo "[#] scanning the memory file using the $COM command"
		touch /root/Desktop/$ANS1/vol_output/"$COM".txt
		./volatility_2.5_linux_x64 -f "$file" --profile="$PROFILE" "$COM" 2>/dev/null >> /root/Desktop/$ANS1/vol_output/"$COM".txt
	done 
	
	END
}

#checking if the file is a memory file(RAM) if not then proceeding to the end report
function MEM_CHECK(){
	FILE_CHECK=$(echo $file | sed 's/\./ /g' | awk '{print $NF}')
	if  [ "$FILE_CHECK" == "mem" ]; then
		VOL
	else
		END
	fi
}

#checking what files where found with the carvers and telling the user where
function SCANNING(){
	cd /root/Desktop/$ANS1
	PCAP=$(find -iname *.pcap)
	if [ "$PCAP" ]; then
		echo "[!] network file found in:"
		find -iname *.pcap
	fi
	EXE=$(find -iname *.exe)
	if [ "$EXE" ]; then
		echo "[!] microsoft executable file found in:"
		find -iname *.exe
	fi
	JPG=$(find -iname *.jpg)
	if [ "$JPG" ]; then
		echo "[!] pictures found in:"
		find -iname *.jpg
	fi
	ZIP=$(find -iname *.zip)
	if [ "$ZIP" ]; then
		echo "[!] zip file fond in:"
		find -iname *.zip
	fi
	cd /root/Desktop/HDD_project
	MEM_CHECK
}

#automatically carving th provided file and saving itno their respective directory
function CARVING(){
	echo "[#] starting to carve data from $file: "
	foremost $file -o /root/Desktop/$ANS1/foremost_output >/dev/null 2>&1
	echo "[#] Foremost carving done."
	strings $file > /root/Desktop/$ANS1/strings_output.txt 
	echo "[#] strings reading done. "
	bulk_extractor $file -o /root/Desktop/$ANS1/bulk_output >/dev/null 2>&1 
	echo "[#] bulk extractor carving done. "
	binwalk -e $file -C /root/Desktop/$ANS1/binwalk_output --run-as=root >/dev/null 2>&1
	echo "[#] binwalk carving done. "	
	SCANNING
}

#installing the needed carvers
function INSTALL_DEPS()
{
	for package in "${REQS[@]}"; do
		dpkg -s "$package" >/dev/null 2>&1 ||
		(echo -e "[!] installing $package..." &&
		sudo apt-get install "$package" -y >/dev/null 2>&1)
		done
}

#making a directory to save all the results and the report
function MAKE_DIR()
{
	read -p "[?] Please name the directory to store all the carving results: " ANS1
	if ! [ -d /root/Desktop/$ANS1 ]; then
		echo "[#] Making a directory named $ANS1 on your desktop."
		mkdir /root/Desktop/$ANS1
		sleep 2
		INSTALL_DEPS
		CARVING
	else
		echo "[/] Directry already exists."
		MAKE_DIR
	fi
}
MAKE_DIR
