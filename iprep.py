'''
goetia@mindcore.es
simple and quick OSINT about ipv4 addresses
'''
import urllib.request as req
import ssl
import re
import json
import sys

def main(args):
	if len(sys.argv) > 1:
		ipregx = re.compile('^([0-9]{1,3}\.){3}[0-9]{1,3}$')
		ip = ipregx.match(sys.argv[1])
		torl = ""
		if ip:
			context=ssl._create_unverified_context()
			repd = [{"otx": {}}, {"tor": 0}]
			d1 = {}
			try:
				r1 = req.urlopen('https://otx.alienvault.com/api/v1/indicators/IPv4/' + ip[0] + '/reputation', context=context, timeout=5)
				d1 = json.loads(r1.read().decode())
			except Exception as e:
        			print(str(e))
			try:
				r2 = req.urlopen('https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1', context=context, timeout=5)
				torl = '\n'.join(r2.read().decode().split('\n')[3:])
			except Exception as e:
        			print(str(e))			
				
			if 'reputation' in d1 and d1['reputation'] is not None:
        			rep = d1["reputation"]
        			repd[0]["otx"] = {"address": "", "threat_score": "", "city": "N/A", "country": "N/A", "organization": "N/A", "first_seen": "N/A", \
        			"last_seen": "N/A", "matched_bl": ['None']}
        			for key in rep:
            				if key in repd[0]["otx"]:
                				repd[0]["otx"][key] = rep[key]	
			if torl is not "":
				if ip[0] in torl:
					repd[1]["tor"] = 'yes'
				else:
					repd[1]["tor"] = 'No'
			print(json.dumps(repd))
		else:
			print("Address specified is invalid.")
	else:
		print("Need an IP address as argument.")

if __name__ == '__main__':
	main(sys.argv)
