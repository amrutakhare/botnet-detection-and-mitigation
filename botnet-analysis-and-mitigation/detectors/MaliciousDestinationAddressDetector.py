# Malicious Destination I/P Addresses Detector (verifying against VirusTotal Database)

import json
import urllib
import urllib2
import re

def detectMaliciousDestinationAddresses(pcapRecords, batchSize, virusTotalUrl, virusTotalApiKey):
	maliciousDestinationIps = extractMaliciousDestinationAddresses(pcapRecords)
	destinationIpCount = len(maliciousDestinationIps)
	print 'Total Destination I/Ps detected in PCAP: ' + str(destinationIpCount)
	
	for index, ip in enumerate(maliciousDestinationIps):
		request = createRequest(maliciousDestinationIps, index, virusTotalApiKey)
		sendAndAnalyze(request, virusTotalUrl, maliciousDestinationIps[index])
		
	print 'Analyzed ' + str(destinationIpCount) + ' Malicious Destination Addresses.'


def extractMaliciousDestinationAddresses(pcapRecords):
	allDestinationIps = [record.destinationIp for record in pcapRecords if record.protocol in ['TCP','DNS'] or (record.protocol=='HTTP' and 'POST' in record.info)]	
	maliciousDestinationIps = filter(lambda ip: ip!='', allDestinationIps)
	maliciousDestinationIps = filter(lambda ip: isIPAddress(ip), maliciousDestinationIps)
	maliciousDestinationIps = list(set(maliciousDestinationIps))
	return maliciousDestinationIps


def isIPAddress(domain):
	match = re.match('(([0-9]\.)*[0-9]+\:*[0-9]*)', domain)
	if match:
		return True
	return False


def createRequest(maliciousDestinationIps, index, virusTotalApiKey):
	ip = maliciousDestinationIps[index]
	batch = {
		"ip": ip,
		"apikey": virusTotalApiKey
	}
	return batch


def isValidJson(myjson):
  try:
    json_object = json.loads(myjson)
  except ValueError, e:
    return False
  return True


def sendAndAnalyze(request, virusTotalUrl, destinationIpAddress):
	response = urllib.urlopen('%s?%s' % (virusTotalUrl, urllib.urlencode(request))).read()
	try:
		batchResponse = json.loads(response)
		if 'detected_urls' in batchResponse:
			count = 0
			for detection in batchResponse['detected_urls']:
				if count > 2:
					break
				try:
					if  int(detection['positives']) > 0:
						print 'Found ' + str(detection['positives']) + ' virus alerts from Virus Analysis Sites, out of ' + str(detection['total']) + ' for IP Address (' + destinationIpAddress + ') resolving to: ' + detection['url']
						count = count + 1
				except TypeError, e:
					pass
	except ValueError, e:
		pass
