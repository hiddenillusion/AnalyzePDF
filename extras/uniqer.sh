#!/bin/bash
#    Created by Glenn P. Edwards Jr.
#	http://hiddenillusion.blogspot.com
# 			@hiddenillusion
# Version 0.1
# Date: 10-11-2012

f=$1
o="sha256_all.txt"

cat $f | while read line; do
	grep -B 1 "^\[-\] Sha256:"
done >> $o

if [ -z "$1" ];
	echo "[-] This script takes a file as the first argument and greps out every filename and hash into a seperate file ($o)"
fi
