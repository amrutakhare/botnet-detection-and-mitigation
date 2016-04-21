# Driver Program

import sys
sys.path.append('../parsers')
sys.path.append('../detectors')
import os

import ConfigParser
import PCAPParser as pcapParser
import TcpSynFloodingDetector as tcpDetector
import IcmpEchoFloodingDetector as icmpDetector
import MaliciousHttpRequestFloodingDetector as httpEndpointDetector
import MaliciousDomainDetector as domainDetector
import MaliciousDestinationAddressDetector as destinationDetector

def processPcapCSV(fileName):

	print '\n********************************************************************************' 
	print '\n\nStarting Analysis for: ' + fileName 

	# Parse PCAP File.
	pcapRecords = pcapParser.extractPCAPRecords('../testFiles/' + fileName)

	#for record in pcapRecords:
	#	print record.sourceIp + ', ' + record.timestamp


	print '\n\nReading Configurations.... '

	# Read All Detector Configs
	config = ConfigParser.ConfigParser()
	config.read('./configuration/main.config.ini')


	# TCP SYN Packet Threshold per Window Size.
	tcpSynThreshold = int(config.get('TCP Detector Config', 'thresholdPercentage'))

	# TCP Window Size in Seconds.
	tcpWindowSize = int(config.get('TCP Detector Config', 'windowSize'))


	# ICMP Echo Packet Threshold per Window Size.
	icmpEchoThreshold = int(config.get('ICMP Detector Config', 'thresholdPercentage'))

	# ICMP Echo in Seconds.
	icmpWindowSize = int(config.get('ICMP Detector Config', 'windowSize'))


	# HTTP Request Endpoint Flooding Threshold per Window Size.
	httpEndpointThreshold = int(config.get('HTTP Endpoint Flooding Detector Config', 'thresholdPercentage'))

	# HTTP Request Endpoint Flooding Window Size in Seconds.
	httpEndpointWindowSize = int(config.get('HTTP Endpoint Flooding Detector Config', 'windowSize'))

	# Malicious Domain Detector Batch Size.
	virusTotalBatchSize = int(config.get('Malicious Domain Detector Config', 'batchSize'))

	# Malicious Domain Detector VirusTotalUrl for Domain.
	virusTotalUrl = config.get('Malicious Domain Detector Config', 'virusTotalUrl')

	# Malicious Domain Detector VirusTotalUrl for IP.
	virusTotalUrlIpReport = config.get('Malicious Domain Detector Config', 'virusTotalUrlIpReport')

	# Malicious Domain Detector VirusTotalApiKey.
	virusTotalApiKey = config.get('Malicious Domain Detector Config', 'virusTotalApiKey')



	# Run Detectors against extracted PCAP Records.

	print 'Detection Technique: TCP SYN Flooding'
	print 'Start detecting....'
	tcpDetector.detectTCPSynFlooding(pcapRecords, tcpSynThreshold, tcpWindowSize)
	print 'Finished detecting....\n'

	print 'Detection Technique: ICMP Echo Flooding'
	print 'Start detecting....'
	icmpDetector.detectICMPEchoFlooding(pcapRecords, icmpEchoThreshold, icmpWindowSize)
	print 'Finished detecting....\n'

	print 'Detection Technique: HTTP Request Endpoint Flooding'
	print 'Start detecting....'
	httpEndpointDetector.detectMaliciousHttpRequests(pcapRecords, httpEndpointThreshold, httpEndpointWindowSize)
	print 'Finished detecting....\n'

	print 'Detection Technique: Malicious Domains'
	print 'Start detecting....'
	domainDetector.detectMaliciousDomains(pcapRecords, virusTotalBatchSize, virusTotalUrl, virusTotalApiKey)
	print 'Finished detecting....\n'

	print 'Detection Technique: Malicious Destination IP (HTTP POST, TCP, DNS)'
	print 'Start detecting....'
	destinationDetector.detectMaliciousDestinationAddresses(pcapRecords, 1, virusTotalUrlIpReport, virusTotalApiKey)
	print 'Finished detecting....\n'

	print '\n\nEnded Analysis for: ' + fileName 
	print '\n********************************************************************************' 

for file in os.listdir("../testFiles"):
    if file.endswith(".csv"):
        processPcapCSV(file)
