#    Created by Glenn P. Edwards Jr.
#	http://hiddenillusion.blogspot.com
# 			@hiddenillusion
# Version 0.1
# Date: 10-11-2012
#
# Requirements:
# 	- pdfid (http://blog.didierstevens.com/programs/pdf-tools/)
#	- pdfinfo (http://poppler.freedesktop.org/)

import os
import subprocess
import shutil
import sys
import datetime
import time
import argparse
import binascii
import re
import zipfile
import shutil 
import hashlib
import pdfid 

dup_counter = []

def main():
    # Get program args
    parser = argparse.ArgumentParser(description='Runs pdfid/pdfinfo on PDF files.')
    parser.add_argument('Path', help='Path to directory/file(s) to be scanned')
    args = vars(parser.parse_args())	

    # Verify supplied path exists or die
    if not os.path.exists(args['Path']):
        print "[!] The supplied path does not exist"
        sys.exit()

    # Set the path to file(s)
    ploc = args['Path']
    if os.path.isfile(ploc):
        fileID(ploc)
    elif os.path.isdir(ploc):
        pwalk(ploc)	

# Quote idea credited to: https://github.com/marpaia/jadPY ... helps on Windows...		
def q(s):
	quote = "\""
	s = quote + s + quote
	return s

def sha256(pdf):
    try:
        f = open(pdf, "rb")
        data = f.read()
        sha256 =  hashlib.sha256(data).hexdigest()
        f.close()
    except Exception, msg:
        print msg
		
    return sha256
    
	
def fileID(pdf):
    """
	Generally this will within the first 4 bytes but since the PDF specs say it 
	can be within the first 1024 bytes I'd rather check for atleast (1) instance 
	of it within that large range.  This limits the chance of the PDF using a header 
	evasion trick and then won't end up getting analyzed.  This behavior could later 
	be detected with a YARA rule.
    """
    f = open(pdf,'rb')
    s = f.read(1024)
    if '\x25\x50\x44\x46' in s:
        print ("=" * 20)	
        print "[+] Analyzing: %s" % pdf
        print "[-] Sha256: %s" % sha256(pdf)
        print ("=" * 20)	
        info(pdf)
    elif os.path.isdir(pdf): pwalk(pdf)
    f.close()
	
def pwalk(ploc):
    # Recursivly walk the supplied path and process files accordingly
    for root, dirs, files in os.walk(ploc):
        for name in files: 
            f = os.path.join(root, name)
            fileID(f)
		
def info(pdf):
    command = "pdfinfo " + q(pdf)
    try:
        p = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        for line in p.stdout:
            if "PDF version:" in line:
                print line			
        for line in p.stderr:
            if re.search('Unexpected end of file in flate stream|End of file inside array', line):
                print "[-] EoF problem" 
            elif re.search('Unterminated hex string|Loop in Pages tree|Illegal digit in hex char in name', line):
                print "[-] Sketchyness detected" 
            elif re.search('Invalid XRef entry|No valid XRef size in trailer|Invalid XRef entry|Couldn\'t read xref table', line):
                print "[-] Invalid XREF"
                break
    except Exception, msg:
        print "[!] pdfinfo error: %s" % msg
        pass

    id(pdf)

def id(pdf):
    try:
        #(dir, allNames, extraData, disarm, force), force)
        command = pdfid.PDFiD2String(pdfid.PDFiD(pdf, True, True, False, True), True)
        print command		
    except Exception:
        # I've observed some files raising errors with the 'extraData' switch
        command = pdfid.PDFiD2String(pdfid.PDFiD(pdf, True, False, False, True), True)
        print "[!] PDFiD couldn\'t parse extra data"	
        print command		

if __name__ == "__main__":
	main()  
