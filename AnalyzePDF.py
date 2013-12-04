"""
Analyzes PDF files by looking at their characteristics in order to add some intelligence into the determination of them being malicious or benign.

Usage:
$ AnalyzePDF.py [-h] [-m MOVE] [-y YARARULES] Path

Produces a high level overview of a PDF to quickly determine if further
analysis is needed based on it's characteristics

positional arguments:
  Path                  Path to directory/file(s) to be scanned

optional arguments:
  -h, --help            show this help message and exit
  -m MOVE, --move MOVE  Directory to move files triggering YARA hits to
  -y YARARULES, --yararules YARARULES
                        Path to YARA rules. Rules should contain a weighted
                        score in the metadata section. (i.e. weight = 3)

example: python AnalyzePDF.py -m tmp/badness -y foo/pdf.yara bar/getsome.pdf            
"""

# AnalyzePDF.py was created by Glenn P. Edwards Jr.
#	 	http://hiddenillusion.blogspot.com
# 				@hiddenillusion
# Version 0.2 
# Date: 10-11-2012
# Requirements:
#	- Python 2.x
#	- YARA (http://plusvic.github.io/yara/)
#	- pdfid (http://blog.didierstevens.com/programs/pdf-tools/)
# Optional:	
#	* This script will work without these but may miss some conditions to evaluate based on the missing data they would provide (i.e. - # of Pages) *
#	- pdfinfo (www.foolabs.com/xpdf/download.html)
#	- a "weight" field within the YARA's rule meta should be added to help in the final evaluation
#		i.e. - rule pdf_example {meta: weight = 3 strings: $s = "evil" condition: $s}
# To-Do:
#	- suppress pdfid's output log
#	- be able to print out which conditions it met in the rules

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
from decimal import Decimal

"""
Chose to _import_ PDFiD instead of just using subprocess to spawn it so it can be statically compiled for use on Windows.  
If you don't have it installed on your system, you can just download it and have it in the same directory as this script.
"""
try:
    import pdfid 
except ImportError:
    print "[!] PDFiD not installed"
    sys.exit()
try:
    import yara
except ImportError:
    print "[!] Yara not installed"
    sys.exit()	
	
# Initialize the list(s) where PDF attribs will be added to
counter = []
page_counter = []
# Initialize the YARA scoring count
yscore = []
ydir = False

# Misc. formatting
trailer = ("=" * 35)
filler = ("-" * 35)

parser = argparse.ArgumentParser(description='Produces a high level overview of a PDF to quickly determine if further analysis is needed based on it\'s characteristics')
parser.add_argument('-m','--move', help='Directory to move files triggering YARA hits to', required=False)
parser.add_argument('-y','--yararules', help='Path to YARA rules.  Rules should contain a weighted score in the metadata section. (i.e. weight = 3)', required=False)
parser.add_argument('Path', help='Path to directory/file(s) to be scanned')
args = vars(parser.parse_args())

# Verify supplied path exists or die
if not os.path.exists(args['Path']):
    print "[!] The supplied path does not exist"
    sys.exit()
		
# Configure YARA rules
if args['yararules']:
    rules = args['yararules']
else:
    rules = '/usr/local/etc/capabilities.yara' # REMnux location
	
if not os.path.exists(rules):
    print "[!] Correct path to YARA rules?"
    sys.exit()
else:
    try:	
        r = yara.compile(rules)
        if args['move']:
            ydir = args['move']
    except Exception, msg:
        print "[!] YARA compile error: %s" % msg
        sys.exit()

def main():
    # Set the path to file(s)
    ploc = args['Path']
    if os.path.isfile(ploc):
        fileID(ploc)
    elif os.path.isdir(ploc):
        pwalk(ploc)	

# Quote idea credited to: https://github.com/marpaia/jadPY ... useful for Windows, what can I say...
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
	Generally the PDF header will be within the first (4) bytes but since the PDF specs say it 
	can be within the first (1024) bytes I'd rather check for atleast (1) instance 
	of it within that large range.  This limits the chance of the PDF using a header 
	evasion trick and then won't end up getting analyzed.  This evasion behavior could later 
	be detected with a YARA rule.
    """
    f = open(pdf,'rb')
    s = f.read(1024)
    if '\x25\x50\x44\x46' in s:
        print "\n" + trailer
        print "[+] Analyzing: %s" % pdf
        print filler
        print "[-] Sha256: %s" % sha256(pdf)
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
        #for line in p.stdout:
        #    if re.match('Pages:\s+(0|1)$', line):
        #        counter.append("pages")
        #         print "[-] (1) page PDF"  
        for line in p.stderr:
            if re.search('Unterminated hex string|Loop in Pages tree|Illegal digit in hex char in name', line):
                counter.append("sketchy")
                print "[-] Sketchyness detected" 
            elif re.search('Unexpected end of file in flate stream|End of file inside array', line):
                counter.append("eof")
                print "[-] EoF problem" 
            elif re.search('Couldn\'t find trailer dictionary', line):
                counter.append("trailer")			
            elif re.search('Invalid XRef entry|No valid XRef size in trailer|Invalid XRef entry|Couldn\'t read xref table', line):
                counter.append("xref")
                print "[-] Invalid XREF"
                break
    except Exception, msg:
        print "[!] pdfinfo error: %s" % msg
        pass

    id(pdf)

def id(pdf):
    try:
        # (dir, allNames, extraData, disarm, force), force)
        command = pdfid.PDFiD2String(pdfid.PDFiD(pdf, True, True, False, True), True)
        extra = True
    except Exception:
        # I've observed some files raising errors with the 'extraData' switch
        command = pdfid.PDFiD2String(pdfid.PDFiD(pdf, True, False, False, True), True)
        print "[!] PDFiD couldn\'t parse extra data"
        extra = False

    for line in command.split('\n'):
        count = re.split(r'[\s]+', line)
        if "PDF Header" in line and not re.match('%PDF-1\.\d', count[3]):
            counter.append("header")
            print "[-] Invalid version number : \"%s\"" % count[3]
        elif "/Page " in line:
            page_counter.append(count[2])
        elif "/Pages " in line:
            page_counter.append(count[2])
        elif "/JS " in line and not re.match('0', count[2]):
            counter.append("js")
            print "[-] JavaScript count.......: %s" % count[2]
            if count[2] > "1":
                counter.append("mucho_javascript")
                print "\t[*] That\'s a lot of js ..."
        elif "/AcroForm " in line and not re.match('0', count[2]):
            counter.append("acroform")
            print "[-] AcroForm...............: %s" % count[2]
        elif "/AA " in line and not re.match('0', count[2]):
            counter.append("aa")
            print "[-] Additional Action......: %s" % count[2]
        elif "/OpenAction " in line and not re.match('0', count[2]):
            counter.append("oa")
            print "[-] Open Action............: %s" % count[2]
        elif "/Launch " in line and not re.match('0', count[2]):
            counter.append("launch")
            print "[-] Launch Action..........: %s" % count[2]
        elif "/EmbeddedFiles " in line and not re.match('0', count[2]):
            counter.append("embed")
            print "[-] Embedded File..........: %s" % count[2]
        #elif "trailer" in line and not re.match('0|1', count[2]):
        #    print "[-] Trailer count..........: %s" % count[2]
        #    print "\t[*] Multiple versions detected"
        elif "Total entropy:" in line:
            tentropy = count[3]		
            print "[-] Total Entropy..........: %7s" % count[3]
        elif "Entropy inside streams:" in line:
            ientropy = count[4]
            print "[-] Entropy inside streams : %7s" % count[4]
        elif "Entropy outside streams:" in line:
            oentropy = count[4]	
            print "[-] Entropy outside streams: %7s" % count[4]
    """
	Entropy levels:
	0 = orderly, 8 = random
	ASCII text file = ~2/4
	ZIP archive = ~ 7/8
    PDF Malicious
            - total   : 6.3
            - inside  : 6.6
            - outside : 4.9
    PDF Benign
            - total   : 6.7
            - inside  : 7.2
            - outside : 5.1
	Determine if Total Entropy & Entropy Inside Stream are significantly different than Entropy Outside Streams -> i.e. might indicate a payload w/ long, uncompressed NOP-sled
	ref = http://blog.didierstevens.com/2009/05/14/malformed-pdf-documents
    """		
    if not extra == False:	
        te_long = Decimal(tentropy)
        te_short = Decimal(tentropy[0:3])
        ie_long = Decimal(ientropy)	
        ie_short = Decimal(ientropy[0:3])	
        oe_long = Decimal(oentropy)	
        oe_short = Decimal(oentropy[0:3])	
        ent = (te_short + ie_short) / 2
        # I know 'entropy' might get added twice to the counter (doesn't matter) but I wanted to separate these to be alerted on them individually
        togo = (8 - oe_long) # Don't want to apply this if it goes over the max of 8
        if togo > 2:
            if oe_long + 2 > te_long:
                counter.append("entropy")		
                print "\t[*] Entropy of outside stream is questionable:"
                print "\t[-] Outside (%s) +2 (%s) > Total (%s)" % (oe_long,oe_long +2,te_long)
        elif oe_long > te_long:
            counter.append("entropy")		
            print "\t[*] Entropy of outside stream is questionable:"
            print "\t[-] Outside (%s) > Total (%s)" % (oe_long,te_long)
        if str(te_short) <= "2.0" or str(ie_short) <= "2.0":
            counter.append("entropy")		
            print "\t[*] LOW entropy detected:"
            print "\t[-] Total (%s) or Inside (%s) <= 2.0" % (te_short,ie_short)

    # Process the /Page(s) results here just to make sure they were both read
    if re.match('0', page_counter[0]) and re.match('0', page_counter[1]):
        counter.append("page")
        print "[-] Page count suspicious:"  
        print "\t[*] Both /Page (%s) and /Pages (%s) = 0" % (page_counter[0],page_counter[1])
    elif re.match('0', page_counter[0]) and not re.match('0', page_counter[1]):
        counter.append("page")
        print "[-] Page count suspicious, no individual pages defined:"  
        print "\t[*] /Page = (%s) , /Pages = (%s)" % (page_counter[0],page_counter[1])
    elif re.match('1$', page_counter[0]):
        counter.append("page")
        print "[-] (1) page PDF"  
            
    yarascan(pdf)

def yarascan(pdf):
    try:
        ymatch = r.match(pdf)
        if len(ymatch):
            print "[-] YARA hit(s): %s" % ymatch
            for rule in ymatch:
                meta = rule.meta
                for key, value in meta.iteritems():
                    # If the YARA rule has a weight in it's metadata then parse that for later calculation
                    if "weight" in key:
                      yscore.append(value)
                if not ydir == False:
                    print "[-] Moving malicious file to:",ydir
                    # This will move the file if _any_ YARA rule triggers...which might trick you if the
                    # rule that triggers on it doesn't have a weight or is displayed in the output
                    if not os.path.exists(ydir):
                        os.makedirs(ydir)
                    try:
                        shutil.move(pdf, ydir)
                    except Exception, msg:
                        continue
    except Exception, msg:
        print msg
    
    eval(counter)
	
def eval(counter):
    """ 
    Evaluate the discovered contents of the PDF and assign a severity rating
    based on the conditions configured below.

    Rating system: 0 (benign), >=2 (sketchy), >=3 (medium), >=5 (high)
    """
    print filler	
    ytotal = sum(yscore)
    print "[-] Total YARA score.......: %s" % ytotal
    sev = 0

    # Below are various combinations used to add some intelligence and help evaluate if a file is malicious or benign.  
    # This is where you can add your own thoughts or modify existing checks.
	
    # HIGH
    if "page" in counter and "launch" in counter and "js" in counter: sev = 5
    elif "page" in counter and "xref" in counter: sev += 5
    elif "page" in counter and "aa" in counter and "js" in counter: sev += 5
    elif "page" in counter and "oa" in counter and "js" in counter: sev += 5

    # MEDIUM
    if "header" in counter and "xref" in counter: sev += 3
    elif "header" in counter and "js" in counter and "page" in counter: sev += 3
    elif "header" in counter and "launch" in counter and "page" in counter: sev += 3
    elif "header" in counter and "aa" in counter and "page" in counter: sev += 3

    if "page" in counter and "mucho_javascript" in counter: sev += 3
    elif "page" in counter and "acroform" in counter and "embed" in counter: sev += 3
    elif "page" in counter and "acroform" in counter and "js" in counter: sev += 3

    if "entropy" in counter and "page" in counter: sev += 3	
    elif "entropy" in counter and "aa" in counter: sev += 3	
    elif "entropy" in counter and "oa" in counter: sev += 3	
    elif "entropy" in counter and "js" in counter: sev += 3	

    if "oa" in counter and "js" in counter: sev += 3
    if "aa" in counter and "mucho_javascript" in counter: sev += 3

    # Heuristically sketchy
    if "page" in counter and "js" in counter: sev += 2
    if "sketchy" in counter and "page" in counter: sev += 2
    elif "sketchy" in counter and "aa" in counter: sev += 2
    elif "sketchy" in counter and "oa" in counter: sev += 2
    elif "sketchy" in counter and "launch" in  counter: sev += 2
    elif "sketchy" in counter and "eof" in counter: sev += 1

    if "page" in counter and "aa" in counter: sev += 1
    if "page" in counter and "header" in counter: sev += 1	
    if "header" in counter and "embed" in counter: sev += 1
	
    print "[-] Total severity score...: %s" % sev
    sev = (ytotal + sev)
    print "[-] Overall score..........: %s" % sev
    
    if sev >= 5: print trailer + "\n[!] HIGH probability of being malicious"
    elif sev >= 3: print trailer + "\n[!] MEDIUM probability of being malicious"
    elif sev >= 2: print trailer + "\n[!] Heuristically sketchy"
    elif sev >= 0: print trailer + "\n[-] Scanning didn't determine anything warranting suspicion"

    # Clear out the scores to start fresh for the next analysis
    del counter[:]
    del page_counter[:]	
    del yscore[:]

if __name__ == "__main__":
	main()  
