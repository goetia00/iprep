'''
goetia@sentineldr.com
simple and quick OSINT about ipv4 addresses
'''
import urllib.request as req
import re
import json
import sys

def main(args):
	if len(sys.argv) > 1:
		ipregx = re.compile('^([0-9]{1,3}\.){3}[0-9]{1,3}$')
		ip = ipregx.match(sys.argv[1])
		torl = ""
		if ip:
			try:
				r1 = req.urlopen('https://otx.alienvault.com/api/v1/indicators/IPv4/' + ip[0] + '/reputation', timeout=5)
				d1 = json.loads(r1.read().decode())
			except:
				print("Error occured. Please try again.")
				sys.exit(1)
			try:
				r2 = req.urlopen('https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1', timeout=5)
				torl = '\n'.join(r2.read().decode().split('\n')[3:])
			except:
				pass
			rep = d1["reputation"]
			if rep:
				repd = {"address": "", "threat_score": "", "city": "N/A", "country": "N/A", "organization": "N/A", "first_seen": "N/A", \
				"last_seen": "N/A","matched_bl": ['None'], "Tor exit node: ": "N/A"}
				for key in rep:
					if key in repd:
						repd[key] = rep[key]
				print("Address: " + repd["address"])
				print("Threat score: " + str(repd["threat_score"]) + " (out of 7)")
				print("Location: " + str(repd["city"]) + ", " + repd["country"])
				print("Organization: " + repd["organization"])
				print("First seen: " + repd["first_seen"].replace('T',', '))		
				print("Last seen: " + repd["last_seen"].replace('T',', '))
				print("Blacklists: " + ' '.join(repd["matched_bl"]))
			else:
				print("No reputation info found")
				sys.exit(1)
			if torl is not "":
				if ip[0] in torl:
					print("Tor exit node: Yes")
				else:
					print("Tor exit node: No")
			else:
				print("Tor exit node: N/A")
		else:
			print("Address specified is invalid.")
	else:
		print("Need an IP address as argument.")

if __name__ == '__main__':
	main(sys.argv)
