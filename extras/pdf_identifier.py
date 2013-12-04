#    Created by Glenn P. Edwards Jr.
#	http://hiddenillusion.blogspot.com
# 			@hiddenillusion
# Version 0.1
# Date: 10-11-2012

import os
import sys
import argparse
import binascii
import shutil 
import hashlib

def main():
    # Get program args
    parser = argparse.ArgumentParser(description='Looks for PDF files and copies them to specified directory named as their Sha256 hash')
    parser.add_argument('-d','--dir', help='Directory to move the identified PDF files to', required=True)	
    parser.add_argument('Path', help='Path to directory/file(s) to be scanned')
    args = vars(parser.parse_args())	

    # Verify supplied path(s) exists or die
    if not os.path.exists(args['Path']):
        print "[!] The supplied path does not exist"
        sys.exit()

    global mdir	
    mdir = args['dir']	
    if not os.path.exists(args['dir']):	
        try:			
            os.makedirs(mdir)		
        except Exception, msg:
            print msg
            sys.exit()			
		
    # Set the path to file(s)
    ploc = args['Path']
    if os.path.isfile(ploc):
        fileID(ploc)
    elif os.path.isdir(ploc):
        pwalk(ploc)	

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
        print "[+] Found: %s" % pdf
        print "[-] Sha256: %s" % sha256(pdf)	
        mover(pdf)
    elif os.path.isdir(pdf): pwalk(pdf)
    f.close()
	
def pwalk(ploc):
    # Recursivly walk the supplied path and process files accordingly
    for root, dirs, files in os.walk(ploc):
        for name in files: 
            f = os.path.join(root, name)
            fileID(f)

def mover(pdf):
    output_dir = os.path.join(mdir,sha256(pdf))
    dir = os.path.abspath(output_dir)

	# If the output directory already exists, increment its name
    count = 0
    if os.path.exists(output_dir):
        while os.path.exists(output_dir):
            count += 1
            output_dir = dir + '.' + str(count)
            continue
    try:
        shutil.copyfile(pdf, output_dir)
    except Exception, msg:
        print msg	

if __name__ == "__main__":
	main()  
