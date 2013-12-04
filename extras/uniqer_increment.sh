#!/bin/bash
#    Created by Glenn P. Edwards Jr.
#	http://hiddenillusion.blogspot.com
# 			@hiddenillusion
# Version 0.1
# Date: 10-11-2012

f=$1

echo "[+] Determining how many total files there are..."
total=(`ls $1 | wc -l`)
echo "[-] Total files pre-uniq   : ($total)"
echo "[+] Determining how many duplicates there are"
dups=(`ls $1 | grep ".\." | wc -l`)
echo "[-] Total duplicates found : ($dups)"
echo "[+] Getting rid of duplicates..."
ls $1 | grep ".\." | while read line; do
	rm -rf "$1/$line"
done
wait
total2=(`ls $1 | wc -l`)
echo "[+] Total files post-uniq: ($total2)"
echo "[+] Total uniq: (`expr $total - $dups`)"

#if [ -z "$1" ];
#	echo "[-] This script takes the good/bad individual hash file as the first argument and determines if there's any duplicates and then deletes them"
#fi
