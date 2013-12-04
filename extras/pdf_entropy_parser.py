#    Created by Glenn P. Edwards Jr.
#	http://hiddenillusion.blogspot.com
# 			@hiddenillusion
# Version 0.1
# Date: 10-11-2012

"""
To-Do:
    - Parse on individual base to determine frequency of inside vs. outside , total vs. outside etc.
"""

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
import collections
from decimal import Decimal

combined = []
all_entropy = []
out_higher = []
combined_less = []
tentropy = []
te = []
ientropy = []
ie = []
oentropy = []
oe = []

def main():
    parser = argparse.ArgumentParser(description='Extracts entropy stats from PDFiD output')
    parser.add_argument('Path', help='Path to directory/file(s) to be scanned')
    args = vars(parser.parse_args())

    # Verify supplied path exists or die
    if not os.path.exists(args['Path']):
        print "[!] The supplied path does not exist"
        sys.exit()
	
    file = args['Path']   
	
    find_entropy(file)
		
def find_entropy(file):    
    #print "[+] Processing: %s" % file
    f = open(file,'r')
    for line in f:	
        num = re.split(r'[\s]+', line)        
        if "Total entropy:" in line:
            all_entropy.append(line)					
        elif "Entropy inside" in line:
            all_entropy.append(line)			
        elif "Entropy outside" in line:
            all_entropy.append(line)					

    all_o_over_t = []
    all_o_over_t_count = 0
    all_low = []
    all_low_count = 0
    all_o_over_i_count = 0
    #all_o_over_ti = []
    all_o_over_t2 = []
    all_o_over_t2_count = 0
    for e in all_entropy:	
        c = len(all_entropy) /3
        lines = [line for line in all_entropy]
        for l in lines:		
            l = l.strip()					
            line = re.split('[\s]+', l)	
            if "Total" in line:		
                tentropy.append(line[2])			
                combined.append(line[2])
            elif "inside" in line:
                ientropy.append(line[5])			
                combined.append(line[5])
            elif "outside" in line:
                oentropy.append(line[4])
                combined.append(line[4])
            if len(combined) == 3:
                print "[i] combined: %s" % combined
                print "[i] 0 : %s " % combined[0]
                print "[i] 1 : %s " % combined[1]
                print "[i] 2 : %s " % combined[2]
                tindiv = Decimal(combined[0])
                iindiv = Decimal(combined[1])
                oindiv = Decimal(combined[2])
                if str(oindiv)[0:3] > str(tindiv)[0:3]: 
                    add0 = (oindiv, tindiv)
                    all_o_over_t.append(add0)
                    all_o_over_t_count += 1
                if str(oindiv)[0:3] > str(iindiv)[0:3]: 
                    #add1 = (oindiv, iindiv)
                    #all_o_over_i.append(add1)
                    all_o_over_i_count += 1
                if oindiv > tindiv + 2: 
                    add2 = (oindiv, tindiv)
                    all_o_over_t2.append(add2)
                    all_o_over_t2_count += 1
                if str(tindiv)[0:3] <= "2.0" or str(iindiv)[0:3] <= "2.0": 
                    add3 = (tindiv, iindiv)
                    all_low.append(add3)
                    all_low_count += 1
                del combined[:]	
        eval(tentropy, ientropy, oentropy, all_o_over_t, all_o_over_t_count, all_o_over_i_count, all_o_over_t2, all_o_over_t2_count, all_low, all_low_count) 

def eval(tentropy, ientropy, oentropy, all_o_over_t, all_o_over_t_count, all_o_over_i_count, all_o_over_t2, all_o_over_t2_count, all_low, all_low_count):      
    # Total Stats
    print "=" * 25
    print "[+] Total Stats"
    print "=" * 25
    for t in tentropy:
        t = t.strip()					
        te.append(t[0:3])

    tcount = collections.Counter(te)
    print "[-] Total count (%s)" % len(te)
    print "[-] Entropy | Occurence"
    print "-" * 25
    tt = 0
    tavg_high = []
    tavg_eq = []
    tavg_low = []
    for val, occur in tcount.most_common():
        tt += Decimal(val)
    tavg = str(tt / len(tcount))[0:3]
    for val, occur in tcount.most_common():
        print "%11s : %s" % (val, occur)
        if val > tavg: tavg_high.append(occur)
        elif val == tavg: tavg_eq.append(occur)
        elif val < tavg: tavg_low.append(occur)
    print "-" * 25
    print "%11s\n" % tt

    twhole = 0
    for val in tcount.elements():
        twhole += Decimal(val)
    twhole_avg = str(twhole / len(te))[0:3]

    # Inside Stats
    print "=" * 25
    print "[+] Inside Stats"
    print "=" * 25
    for i in ientropy:
        i = i.strip()					
        ie.append(i[0:3])

    icount = collections.Counter(ie)
    print "[-] Inside count (%s)" % len(ie)
    print "[-] Entropy | Occurence"
    print "-" * 25
    it = 0
    iavg_high = []
    iavg_eq = []
    iavg_low = []
    for val, occur in icount.most_common():
        it += Decimal(val)
    iavg = str(it / len(icount))[0:3]
    for val, occur in icount.most_common():
        print "%11s : %s" % (val, occur)
        if val > iavg: iavg_high.append(occur)
        elif val == iavg: iavg_eq.append(occur)
        elif val < iavg: iavg_low.append(occur)
    print "-" * 25
    print "%11s\n" % it

    iwhole = 0
    for val in icount.elements():
        iwhole += Decimal(val)
    iwhole_avg = str(iwhole / len(ie))[0:3]

    # Outside Stats
    print "=" * 25
    print "[+] Outside Stats"
    print "=" * 25
    for o in oentropy:
        o = o.strip()					
        oe.append(o[0:3])

    ocount = collections.Counter(oe)
    print "[-] Outside count (%s)" % len(oe)
    print "[-] Entropy | Occurence"
    print "-" * 25
    ot = 0
    oavg_high = []
    oavg_eq = []
    oavg_low = []
    for val, occur in ocount.most_common():
        ot += Decimal(val)
    oavg = str(ot / len(ocount))[0:3]
    for val, occur in ocount.most_common():
        print "%11s : %s" % (val, occur)
        if val > oavg: oavg_high.append(occur)
        elif val == oavg: oavg_eq.append(occur)
        elif val < oavg: oavg_low.append(occur)
    print "-" * 25
    print "%11s\n" % ot

    owhole = 0
    for val in ocount.elements():
        owhole += Decimal(val)
    owhole_avg = str(owhole / len(oe))[0:3]
 
    # Do work...
    print "=" * 30
    print "[+] Total unique   | Total whole"
    print "\t" + "-" * 16
    print "\tAvg.: %4s | %4s" % (tavg,twhole_avg)
    print "\tHigher: %s" % sum(tavg_high)
    print "\tExact: %4s" % sum(tavg_eq)
    print "\tLower: %4s" % sum(tavg_low)
    print "\t" + "-" * 16
    print "\tOverall: %7s" % sum(tavg_high + tavg_eq + tavg_low)
    print "[+] Inside unique  | Inside whole"
    print "\t" + "-" * 16
    print "\tAvg.: %4s | %4s" % (iavg,iwhole_avg)
    print "\tHigher: %s" % sum(iavg_high)
    print "\tExact: %4s" % sum(iavg_eq)
    print "\tLower: %4s" % sum(iavg_low)
    print "\t" + "-" * 16
    print "\tOverall: %7s" % sum(iavg_high + iavg_eq + iavg_low)
    print "[+] Outside unique | Outside whole"
    print "\t" + "-" * 16
    print "\tAvg.: %4s | %4s" % (oavg,owhole_avg)
    print "\tHigher: %s" % sum(oavg_high)
    print "\tExact: %4s" % sum(oavg_eq)
    print "\tLower: %4s" % sum(oavg_low)
    print "\t" + "-" * 16
    print "\tOverall: %7s" % sum(oavg_high + oavg_eq + oavg_low)
    print "\t" + "-" * 16
    all_low_perc = 100 * float(all_low_count) / float((len(te)))
    print "[+] LOW Total or Inside: %s (%s%%)" % (all_low_count,str(all_low_perc)[0:4])
    print "[-] Total   | Inside"
    all_l = collections.Counter(all_low)
    for t, i in all_l: 
        t = Decimal(t)
        i = Decimal(i)
        print "%11s or %s" % (str(t)[0:3],str(i)[0:3])
    all_o_over_t_perc = 100 * float(all_o_over_t_count) / float((len(te)))
    print "[+] Outside > Total: %6s (%s%%)" % (all_o_over_t_count,str(all_o_over_t_perc)[0:4])
    print "[-] Outside | Total"
    all_t = collections.Counter(all_o_over_t)
    for o, t in all_t: 
        o = Decimal(o)
        t = Decimal(t)
        print "%11s vs. %s" % (str(o)[0:3],str(t)[0:3])
    all_o_over_t2_perc = 100 * float(all_o_over_t2_count) / float((len(te)))
    print "[+] Outside > Total +2: %3s (%s%%)" % (all_o_over_t2_count,str(all_o_over_t2_perc)[0:4])
    all_t2 = collections.Counter(all_o_over_t2)
    for o, t in all_t2: 
        o = Decimal(o)
        t = Decimal(t)
        print "%11s vs. %s (+2)" % (str(o)[0:3],str(t)[0:3])
    all_o_over_i_perc = 100 * float(all_o_over_i_count) / float((len(te)))
    print "[+] Outside > Inside: %5s (%s%%)" % (all_o_over_i_count,str(all_o_over_i_perc)[0:4])

    del all_entropy[:]	
    del out_higher[:]
    del combined_less[:]		
	
if __name__ == "__main__":
	main()  		
