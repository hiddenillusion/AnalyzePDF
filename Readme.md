AnalyzePDF.py
=============

Analyzes PDF files by looking at their characteristics in order to add some intelligence into the determination of them being malicious or benign.

Requirements
------------
	* pdfid
	* pdfinfo
	* yara
	
Usage
-----
$ python AnalyzePDF.py -h
usage: AnalyzePDF.py [-h] [-m MOVE] [-y YARARULES] Path

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

Restrictions
------------
Free to use for non-commercial.  Give credit where credit is due.
