#    Created by Glenn P. Edwards Jr.
#	http://hiddenillusion.blogspot.com
# 			@hiddenillusion
# Version 0.1
# Date: 10-11-2012

import os
import subprocess
import sys
import argparse
import re
import collections
from decimal import Decimal

# Initialize the list(s) where PDF attribs will be added to
keys= []

def main():
    parser = argparse.ArgumentParser(description='Takes pdfid/pdfinfo output and produces a summary to show the most common and least common keywords/attributes with their values/counts')
    parser.add_argument('Path', help='Path to pdfid/pdfinfo output file(s)')
    args = vars(parser.parse_args())

    # Verify supplied path exists or die
    if not os.path.exists(args['Path']):
        print "[!] The supplied path does not exist"
        sys.exit()

	# Set the path to file(s)
    f = args['Path']
    if os.path.isfile(f):
        details(f)
    elif os.path.isdir(f):
        fwalk(f)	
		
def fwalk(floc):
    # Recursivly walk the supplied path and process files accordingly
    for root, dirs, files in os.walk(floc):
        for name in files: 
            fname = os.path.join(root, name)
            details(fname)
	
def details(f):
    l = open(f).read()
    for line in l.split('\n'):
        if not re.findall('===', line) and not re.findall('Analyzing:', line) and not re.findall('Sha256:', line) and not re.findall('[eE]ntropy', line) and not re.findall('PDFiD 0.0', line):
           keys.append(line)
    print "\n[+] PDF keywords/attributes"
    print "[-] Sorted by highest count"
    print "   Count | Keyword/Attribute"
    print "-" * 40
    c = collections.Counter(keys)
    for key,count in c.most_common():
        print "%8s | %s" % (count, key)

    print "[-] Sorted per keywords/attributes"
    print "   Count | Keyword/Attribute"
    print "-" * 40
    for key,count in sorted(c.most_common()):
        print "%8s | %s" % (count, key)

#    for e in sorted(keys):
#        print e


if __name__ == "__main__":
	main()  
