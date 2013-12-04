#!/bin/bash
#    Created by Glenn P. Edwards Jr.
#	http://hiddenillusion.blogspot.com
# 			@hiddenillusion
# Version 0.1
# Date: 10-11-2012

f=$1

echo "[+] Determining how many total files there are..."
total=(`cat $1 | wc -l`)
echo "[-] Total files pre-uniq   : ($total)"
echo "[+] Determining how many duplicates there are"
dups=(`cat $1 | sort | uniq -c | sort -nr | awk '{if($1 > 1) print $2}' | wc -l`)
echo "[-] Total duplicates found : ($dups)"
echo "[+] Getting rid of duplicates..."
cat $1 | sort | uniq -c | sort -nr | awk '{if($1 > 1) print $2}' | while read line; do
	rm -rf "$1/$line"
done
wait
total2=(`cat $1 | wc -l`)
echo "[+] Total files post-uniq: ($total2)"
echo "[+] Total uniq: (`expr $total - $dups`)"

#if [ -z "$1" ];
#	echo "[-] This script takes the combined file of good/bad file hashes as the first argument and determines how many duplicates there are then deletes them"
#fi
