# Malicious HTTP Requests Flooding to Same Endpoint Detector

import re

def detectMaliciousHttpRequests(pcapRecords, thresholdPercentage, windowSize):
	for index, record in enumerate(pcapRecords):
		if record.protocol=='HTTP':		
			checkWindowFrame(index, pcapRecords, windowSize, thresholdPercentage)

				
# Check how many HTTP Requests are sent to the same endpoint within the WindowSize.				
def checkWindowFrame(index, pcapRecords, windowSize, thresholdPercentage):
	requestEndpoint = extractRequestEndpoint(pcapRecords[index].info)
	if requestEndpoint != '':
		requestDomain = pcapRecords[index].domain
		windowStart = index + 1
		countInWindow = 0
		while windowStart < index + windowSize and windowStart < len(pcapRecords):
				if isSameRequestEndpoint(pcapRecords[windowStart].protocol, pcapRecords[windowStart].info, pcapRecords[windowStart].domain, requestEndpoint, requestDomain):
						countInWindow = countInWindow + 1
				windowStart = windowStart + 1
		if (countInWindow*100/windowSize) >= thresholdPercentage and index + windowSize < len(pcapRecords):
				print 'Detected HTTP Request Endpoint Flooding between ' + str(pcapRecords[index].timestamp) + ' and ' + str(pcapRecords[index + windowSize].timestamp) + ': ' + str(countInWindow*100/windowSize) + '%'


def extractRequestEndpoint(httpPacketInfo):
	matcher = re.match('((GET|PUT|POST|DELETE|PATCH)+\s(\/\w+)*(\.\w+)*)', httpPacketInfo)
	if matcher:
		return matcher.group()
	return ''
	

def isSameRequestEndpoint(protocol, httpRequestInfo, httpRequestDomain, requestEndpoint, requestDomain):
	if protocol=='HTTP' and requestEndpoint==extractRequestEndpoint(httpRequestInfo) and httpRequestDomain==requestDomain:
		return True
	return False