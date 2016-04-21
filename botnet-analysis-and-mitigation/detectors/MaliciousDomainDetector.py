# Malicious Domain Detector (verifying against VirusTotal Database)

import json
import urllib
import urllib2
import re

def detectMaliciousDomains(pcapRecords, batchSize, virusTotalUrl, virusTotalApiKey):
	maliciousDomains = extractMaliciousDomains(pcapRecords)
	domainCount = len(maliciousDomains)
	print 'Total Domains detected in PCAP: ' + str(domainCount)
	
	batchStart = 0
	while batchStart < domainCount:
		batchRequest = createRequestBatch(maliciousDomains, batchStart, batchStart + batchSize, virusTotalApiKey)
		sendAndAnalyze(batchRequest, virusTotalUrl)
		print 'Analyzed Domains ' + str(batchStart) + ' to ' + str(batchStart + batchSize) + '.'
		batchStart = batchStart + batchSize


def extractMaliciousDomains(pcapRecords):
	allDomains = [record.domain for record in pcapRecords]	
	maliciousDomains = filter(lambda domain: domain!='', allDomains)
	maliciousDomains = filter(lambda domain: isNotIPAddress(domain), maliciousDomains)	
	maliciousDomains = filter(lambda domain: ':' not in domain, maliciousDomains)
	maliciousDomains = list(set(maliciousDomains))
	return maliciousDomains


def isNotIPAddress(domain):
	match = re.match('(([0-9]\.)*[0-9]+\:*[0-9]*)', domain)
	if match:
		return False
	return True


def createRequestBatch(maliciousDomains, batchStart, batchEnd, virusTotalApiKey):
	resources = '\n'.join(maliciousDomains[batchStart:batchEnd])
	batch = {
		"resource": resources,
		"apikey": virusTotalApiKey
	}
	return batch


def isValidJson(myjson):
  try:
    json_object = json.loads(myjson)
  except ValueError, e:
    return False
  return True

def is_number(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

def sendAndAnalyze(batchRequest, virusTotalUrl):
	data = urllib.urlencode(batchRequest)
	req = urllib2.Request(virusTotalUrl, data)
	response = urllib2.urlopen(req)
	try:
	    batchResponse = json.loads(response.read())
	    for response in batchResponse:
	        try:
	            if 'positives' in response and is_number(response['positives']) and int(response['positives']) > 0:
	                print 'Found ' + str(response['positives']) + ' virus alerts from Virus Analysis Sites, out of ' + str(response['total']) + ' for Domain: ' + response['resource']
	        except TypeError, e:
	            print ''
	except ValueError, e:
	    print ''	
