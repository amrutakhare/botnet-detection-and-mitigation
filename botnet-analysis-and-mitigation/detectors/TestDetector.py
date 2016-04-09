import json
import urllib
import urllib2

virusTotalUrl = "https://www.virustotal.com/vtapi/v2/url/report"
virusTotalApiKey = "312844992042de515f1b6f50d64afaa0361a447599ac55995c82b25f70c30a85"

resources = 'www.google.com\nmewgost.com'
batch = {
	"resource": resources,
	"apikey": virusTotalApiKey
}
data = urllib.urlencode(batch)
req = urllib2.Request(virusTotalUrl, data)
response = urllib2.urlopen(req)
batchResponse = json.loads(response.read())
for response in batchResponse:
	print str(response['positives']) + ',' + str(response['total'])
