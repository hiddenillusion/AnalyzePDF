#!/bin/bash
#    Created by Glenn P. Edwards Jr.
#	http://hiddenillusion.blogspot.com
# 			@hiddenillusion
# Version 0.1
# Date: 10-11-2012

f=$1
o="sha256_uniq.txt"

initial_count=(`cat $f | grep "^\[-\] Sha256:" | wc -l`)
echo "[-] Initial count before de-dup: ($initial_count)"

cat $f | while read line; do
	grep "^\[-\] Sha256:" | awk '{print $3}' | sort | uniq -c | sort -nr | awk '{if($1 > 1) print}'
done >> $o

dup_count=(`cat $o | awk '{s+=$1}END{print s}'`)
echo "[-] Dup count: ($dup_count)"
final_count=(`expr $initial_count - $dup_count`)
echo "[-] Final count after de-dup: ($final_count)"


if [ -z "$1" ]; 
        echo "[-] This script takes a file as the first argument and looks for all occurences of duplicates which it will output to a seperate file ($o)"
fi

