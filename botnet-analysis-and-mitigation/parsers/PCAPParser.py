# PCAP File Parser


import sys
sys.path.append('../models')

import PCAPRecord
import csv

# Extract PCAP Records from PCAP CSV File
def extractPCAPRecords(filePath):
	pcapRecords = []
	pcapLines = []
	
	with open(filePath, 'rU') as pcapCsvFile:
			reader = csv.reader(pcapCsvFile)
			pcapLines = list(reader)


	for line in pcapLines:
			record = PCAPRecord.PCAPRecord(line[0],line[1],line[2],line[3],line[4],line[5],line[6],line[7])
			pcapRecords.append(record)
	  	
	return pcapRecords
	
