class PCAPRecord:
	
	# PCAP Record Variables
	
	sourceIp = ""
	destinationIp = ""
	sourcePort = ""
	destinationPort = ""
	protocol = ""
	timestamp = 0
	domain = ""
	info = ""
	
	# PCAP Methods
	
	def __init__(self, sourceIp, destinationIp, sourcePort, destinationPort, protocol, timestamp, domain, info):
	  self.sourceIp = sourceIp
	  self.destinationIp = destinationIp
	  self.sourcePort = sourcePort
	  self.destinationPort = destinationPort
	  self.protocol = protocol
	  self.timestamp = timestamp
	  self.domain = domain
	  self.info = info
