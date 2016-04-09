# Driver Program

import sys
sys.path.append('../parsers')
sys.path.append('../detectors')

import ConfigParser
import PCAPParser as pcapParser
import TcpSynFloodingDetector as tcpDetector
import IcmpEchoFloodingDetector as icmpDetector
import MaliciousHttpRequestFloodingDetector as httpEndpointDetector
import MaliciousDomainDetector as domainDetector


# Parse PCAP File.
pcapRecords = pcapParser.extractPCAPRecords('../testFiles/sample_pcap.csv')

#for record in pcapRecords:
#	print record.sourceIp + ', ' + record.timestamp


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

# Malicious Domain Detector VirusTotalUrl.
virusTotalUrl = config.get('Malicious Domain Detector Config', 'virusTotalUrl')

# Malicious Domain Detector VirusTotalApiKey.
virusTotalApiKey = config.get('Malicious Domain Detector Config', 'virusTotalApiKey')



# Run Detectors against extracted PCAP Records.

print 'Start detecting TCP SYN Flooding....'
tcpDetector.detectTCPSynFlooding(pcapRecords, tcpSynThreshold, tcpWindowSize)
print 'Finished detecting TCP SYN Flooding.'

print 'Start detecting ICMP Echo Flooding....'
icmpDetector.detectICMPEchoFlooding(pcapRecords, icmpEchoThreshold, icmpWindowSize)
print 'Finished detecting ICMP Echo Flooding.'

print 'Start detecting HTTP Request Endpoint Flooding....'
httpEndpointDetector.detectMaliciousHttpRequests(pcapRecords, httpEndpointThreshold, httpEndpointWindowSize)
print 'Finished detecting HTTP Request Endpoint Flooding.'

print 'Start detecting Malicious Domains....'
domainDetector.detectMaliciousDomains(pcapRecords, virusTotalBatchSize, virusTotalUrl, virusTotalApiKey)
print 'Finished detecting Malicious Domains.'
